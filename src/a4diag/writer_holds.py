"""Durable stop obligations and cross-process service mutation exclusion.

Only trusted admission/finalization code may construct bindings. Wire fields
are references; callers must first authenticate them against the original job.
"""
from contextlib import contextmanager
import hashlib
import json
import os
import stat
import time
from types import SimpleNamespace

from a4diag.domain import Plan, canonical_json_bytes
from a4diag.policy_engine import canonical_operation_digest
from a4diag.repair_store import RepairLimitError


def stop_binding(request):
    dep = request.preparation_dependency
    if dep is None or request.step_id != dep.stop_step_id:
        raise RepairLimitError('writer_hold_binding_mismatch')
    return dict(controller_id=request.controller_id, target_id=request.target_id,
        target_fingerprint=request.target_fingerprint, transaction_id=request.transaction_id,
        plan_digest=request.plan_digest, step_id=request.step_id,
        profile_id=request.binding.profile_id, profile_digest=request.binding.profile_digest,
        operation_digest=canonical_operation_digest(request.operation),
        resource=request.operation.resource,
        marker_digest=hashlib.sha256(canonical_json_bytes(request.marker)).hexdigest(),
        preparation_dependency=dep.identity())


def controller_stop_binding(claim, operation, marker):
    """Use authenticated core HMAC claims, never model annotations."""
    if claim.operation_digest != canonical_operation_digest(operation):
        raise RepairLimitError('writer_hold_binding_mismatch')
    return stop_binding(SimpleNamespace(controller_id='a4diag-core',
        target_id=claim.target_id, target_fingerprint=claim.target_fingerprint,
        transaction_id=claim.transaction_id, plan_digest=claim.plan_digest,
        step_id=claim.step_id, binding=claim.binding, operation=operation,
        marker=marker, preparation_dependency=claim.preparation_dependency))


@contextmanager
def controller_mutation_guard(deps, state, target, operation, step_id, marker, ticket):
    """Narrow shared V10/V11 dispatch hook; D1c supplies frozen dependencies."""
    from a4diag.repair_store import RepairStore
    if operation.capability != 'services':
        yield
        return
    holds = WriterHolds(RepairStore(deps.transactions.path))
    with holds.resource_guard(target.id, operation.resource):
        claim = deps.tickets.inspect_for_recovery(ticket)
        dependency = getattr(claim, 'preparation_dependency', None)
        if dependency is None:
            holds.require_unheld(target.id, operation.resource)
        else:
            if (claim.target_id != target.id or claim.transaction_id != state['transaction_id']
                    or claim.step_id != step_id):
                raise RepairLimitError('writer_hold_binding_mismatch')
            binding = controller_stop_binding(claim, operation, marker)
            if claim.phase == 'apply':
                holds.protect(binding)
            elif claim.phase == 'undo':
                holds.require_owner(binding, job_id=dependency.stop_job_id)
            else:
                raise RepairLimitError('writer_hold_binding_mismatch')
        yield


def bind_controller_stop_job(deps, state, job):
    from a4diag.repair_store import RepairStore
    from a4diag.repair_workflow import job_origin
    hold = WriterHolds(RepairStore(deps.transactions.path)).get(state['target_id'],
        Plan.model_validate(state['plan']).operations[int(job.step_id)].resource)
    if hold is None:
        return
    _, operation, claim = job_origin(deps, state, job.step_id)
    if claim.preparation_dependency is None:
        raise RepairLimitError('writer_hold_binding_mismatch')
    prepared = next(s for s in deps.transactions.get_steps(state['transaction_id']) if s.step_id == job.step_id)
    binding = controller_stop_binding(claim, operation, json.loads(prepared.plugin_marker_json))
    holds = WriterHolds(RepairStore(deps.transactions.path))
    with holds.resource_guard(claim.target_id, operation.resource):
        holds.protect(binding, job_id=job.id)


def record_controller_restoration(deps, state, step_id, *, phase, result):
    """D1c calls after currently authorized UNDO or independent restored check."""
    from a4diag.repair_store import RepairStore
    from a4diag.repair_workflow import job_origin
    job, operation, claim = job_origin(deps, state, step_id)
    prepared = next(s for s in deps.transactions.get_steps(state['transaction_id']) if s.step_id == step_id)
    binding = controller_stop_binding(claim, operation, json.loads(prepared.plugin_marker_json))
    holds = WriterHolds(RepairStore(deps.transactions.path))
    with holds.resource_guard(claim.target_id, operation.resource):
        if phase == 'undo':
            holds.record_undo(binding, job_id=job.id, succeeded=result.ok)
        elif phase == 'verify_restored':
            if result.ok:
                holds.restored(binding, job_id=job.id)
        else:
            raise RepairLimitError('writer_hold_binding_mismatch')


class WriterHolds:
    def __init__(self, store):
        self.store = store

    @contextmanager
    def resource_guard(self, target_id, resource, *, wait_seconds=0):
        """Guard spans invocation; independent workers may wait a bounded lease."""
        import fcntl
        path = self.store.path.resolve()
        digest = hashlib.sha256(canonical_json_bytes([path.name, target_id, resource])).hexdigest()
        fd = os.open(path.parent / ('.writer-'+digest),
                     os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 or st.st_nlink != 1:
                raise RepairLimitError('unprotected_writer_guard')
            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise RepairLimitError('resource_busy') from error
                    time.sleep(min(.01, remaining))
            yield
        finally:
            os.close(fd)

    def get(self, target_id, resource):
        with self.store._transaction() as db:
            row = db.execute('SELECT * FROM writer_holds WHERE target_id=? AND resource=? AND restored=0',
                             (target_id, resource)).fetchone()
            return dict(row) if row is not None else None

    def protect(self, binding, *, job_id=None):
        """Called under resource_guard before stop dispatch; no quota bypass."""
        encoded = canonical_json_bytes(binding).decode()
        with self.store._transaction() as db:
            row = db.execute('SELECT * FROM writer_holds WHERE target_id=? AND resource=? AND restored=0',
                             (binding['target_id'], binding['resource'])).fetchone()
            if row is not None:
                if row['binding'] != encoded or row['job_id'] not in (None, job_id):
                    raise RepairLimitError('writer_hold_binding_mismatch')
                if job_id is not None:
                    db.execute('UPDATE writer_holds SET job_id=? WHERE id=?', (job_id, row['id']))
                return
            reservation = db.execute('SELECT * FROM repair_reservations WHERE target_id=? AND resource=? AND transaction_id=? AND outcome IS NULL',
                (binding['target_id'], binding['resource'], binding['transaction_id'])).fetchone()
            if reservation is None or (job_id is not None and reservation['job_id'] != job_id):
                raise RepairLimitError('writer_hold_reservation_missing')
            db.execute('INSERT INTO writer_holds (target_id,resource,transaction_id,binding,job_id) VALUES (?,?,?,?,?)',
                       (binding['target_id'], binding['resource'], binding['transaction_id'], encoded, job_id))

    def require_owner(self, binding, *, job_id, allow_restored=False):
        with self.store._transaction() as db:
            rows = db.execute('SELECT * FROM writer_holds WHERE target_id=? AND resource=? AND job_id=?',
                (binding['target_id'], binding['resource'], job_id)).fetchall()
        row = dict(rows[0]) if len(rows) == 1 else None
        if (row is None or row['binding'] != canonical_json_bytes(binding).decode()
                or row['job_id'] != job_id or (row['restored'] and not allow_restored)):
            raise RepairLimitError('writer_hold_binding_mismatch')
        return row

    def require_unheld(self, target_id, resource):
        if self.get(target_id, resource) is not None:
            raise RepairLimitError('resource_busy')

    def record_undo(self, binding, *, job_id, succeeded):
        row = self.require_owner(binding, job_id=job_id)
        with self.store._transaction() as db:
            db.execute('UPDATE writer_holds SET undo_succeeded=? WHERE id=? AND restored=0',
                       (int(succeeded is True), row['id']))

    def restored(self, binding, *, job_id):
        """Trusted caller has independently verified restoration under the guard."""
        row = self.require_owner(binding, job_id=job_id, allow_restored=True)
        if row['restored']:
            return
        with self.store._transaction() as db:
            hold = db.execute('SELECT * FROM writer_holds WHERE id=?', (row['id'],)).fetchone()
            if not hold['undo_succeeded']:
                raise RepairLimitError('writer_restore_not_dispatched')
            job = self.store._job(db, job_id)
            if job is None or job['state'] != 'succeeded':
                raise RepairLimitError('writer_stop_not_succeeded')
            db.execute('UPDATE writer_holds SET restored=1 WHERE id=?', (row['id'],))
            db.execute('UPDATE repair_reservations SET outcome=? WHERE target_id=? AND resource=? AND transaction_id=? AND job_id=? AND outcome IS NULL',
                (job['state'], binding['target_id'], binding['resource'], binding['transaction_id'], job_id))

"""Bounded read-only inspection of the fixed protected service job database."""
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import stat

from a4diag.domain import canonical_json_bytes
from a4diag.plugin_api.target_protocol import SignedTargetRequest, TargetRequestV11
from a4diag.policy_engine import canonical_operation_digest
from a4diag.writer_holds import stop_binding
from a4diag_target.repair_disk import _writer_snapshot
from a4diag_target.repair_jobs import JobStore
from a4diag_builtin_plugins.capability_services import ServiceMarker

SERVICE_JOB_DATABASE = Path('/var/lib/a4diag-target/executor/repair-jobs.sqlite3')


@dataclass(frozen=True)
class StopProof:
    job_id: str
    original: TargetRequestV11
    marker: dict
    writer_snapshot: tuple


def _record(job_id):
    path = SERVICE_JOB_DATABASE
    # This path is compiled, never accepted from the request/profile/model.
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('stop_proof_unprotected')
    for item in (path, path.parent):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('stop_proof_unprotected')
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('stop_proof_unprotected')
    try:
        with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=2) as db:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            budget = 1000
            def bounded():
                nonlocal budget
                budget -= 1
                return int(budget <= 0)
            db.set_progress_handler(bounded, 1000)
            columns = {row[1] for row in db.execute('PRAGMA table_info(repair_jobs)')}
            if 'signed_request' not in columns:
                raise ValueError('stop_proof_missing')
            row = db.execute('''SELECT * FROM repair_jobs WHERE id=?
                AND length(request)<=1048576 AND length(signed_request)<=2097152
                AND length(result)<=196608''', (job_id,)).fetchone()
            if row is None or row['signed_request'] is None:
                raise ValueError('stop_proof_missing')
            hold = db.execute('SELECT * FROM writer_holds WHERE job_id=? AND restored=0 LIMIT 2',
                              (job_id,)).fetchall()
            if len(hold) != 1:
                raise ValueError('stop_proof_hold_missing')
            return dict(row), dict(hold[0])
    except sqlite3.Error as error:
        raise ValueError('stop_proof_unavailable') from error


def _read_stop_records(request: TargetRequestV11, *, verifier, current_policy, writer_unit: str) -> StopProof:
    """Historical signature inspection never authorizes a fresh effect."""
    request = TargetRequestV11.model_validate(request.model_dump())
    dep = request.preparation_dependency
    if dep is None or dep.stop_job_id is None:
        raise ValueError('stop_proof_missing')
    row, hold = _record(dep.stop_job_id)
    envelope = SignedTargetRequest.model_validate_json(row['signed_request'])
    if envelope.key_fingerprint != current_policy.controller_key_fingerprint:
        raise ValueError('stop_proof_key_mismatch')
    original = verifier.inspect_for_proof(envelope, expected_target=current_policy.target_id)
    if not isinstance(original, TargetRequestV11):
        raise ValueError('stop_proof_binding_mismatch')
    stored = TargetRequestV11.model_validate_json(row['request'])
    job = JobStore._model(row)
    if (original != stored or original.lifecycle != 'apply'
            or original.preparation_dependency is None
            or original.preparation_dependency.identity() != dep.identity()
            or any(getattr(original, name) != getattr(request, name) for name in
                   ('controller_id', 'target_id', 'target_fingerprint', 'transaction_id', 'plan_digest'))
            or original.target_fingerprint != current_policy.target_fingerprint
            or original.operation.resource != writer_unit
            or job.transaction_id != original.transaction_id or job.step_id != original.step_id
            or job.profile_digest != original.binding.profile_digest
            or job.operation_digest != canonical_operation_digest(original.operation)
            or job.state != 'succeeded' or job.changed is None or job.result.get('ok') is not True
            or hold['binding'] != canonical_json_bytes(stop_binding(original)).decode()
            or hold['transaction_id'] != request.transaction_id
            or hold['target_id'] != request.target_id or hold['resource'] != writer_unit
            or row['controller_key'] != envelope.key_fingerprint):
        raise ValueError('stop_proof_binding_mismatch')
    marker = ServiceMarker.model_validate(original.marker)
    if marker.unit != writer_unit or marker.action != 'stop':
        raise ValueError('stop_proof_marker_mismatch')
    return StopProof(job.id, original, json.loads(canonical_json_bytes(original.marker)), ())


def read_stop_proof(request: TargetRequestV11, *, verifier, current_policy, writer_unit: str) -> StopProof:
    """Authenticate protected history AND independently inspect current writer."""
    proof = _read_stop_records(request, verifier=verifier, current_policy=current_policy, writer_unit=writer_unit)
    return StopProof(proof.job_id, proof.original, proof.marker, _writer_snapshot(writer_unit))

"""Target-owned durable jobs. An ambiguous launch is never executed again."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from a4diag.domain import canonical_json_bytes
from a4diag.repair_jobs import RepairJob, MAX_JOB_RESULT_BYTES, TERMINAL_JOB_STATES


class RepairJobError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def process_identity(pid: int) -> tuple[str, str] | None:
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        # comm can contain spaces and parentheses; starttime is field 22.
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z':
            return None
        return boot, fields[19]
    except (OSError, IndexError):
        return None


def process_exited(pid: int, saved: tuple[str, str]) -> bool:
    """Positive exit evidence only; an unavailable observation proves nothing."""
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if str(uuid.UUID(boot)) != boot:
            return False
        try:
            record = Path(f'/proc/{pid}/stat').read_text()
        except FileNotFoundError:
            # Missing proc mount itself is not evidence about this process.
            return Path('/proc/self/stat').is_file()
        fields = record.rsplit(')', 1)[1].split()
        if len(fields) < 20 or not fields[19].isdigit() or len(fields[0]) != 1:
            return False
        return fields[0] == 'Z' or (boot, fields[19]) != saved
    except (OSError, IndexError, ValueError):
        return False


class JobStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS repair_jobs (
                id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, step_id TEXT NOT NULL,
                profile_digest TEXT NOT NULL, operation_digest TEXT NOT NULL,
                state TEXT NOT NULL, changed INTEGER, result TEXT NOT NULL DEFAULT '{}',
                started_at INTEGER, finished_at INTEGER, request TEXT,
                pid INTEGER, boot_id TEXT, starttime TEXT, controller_key TEXT,
                UNIQUE(transaction_id, step_id))''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(repair_jobs)')}
            if 'signed_request' not in columns:
                db.execute('ALTER TABLE repair_jobs ADD COLUMN signed_request TEXT')

    @contextmanager
    def _transaction(self):
        db = None
        try:
            db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except sqlite3.Error as error:
            raise RepairJobError('job_store_unavailable') from error
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def _model(row):
        if row is None:
            raise RepairJobError('job_missing')
        fields = {key: row[key] for key in RepairJob.model_fields}
        fields['result'] = json.loads(fields['result'])
        fields['changed'] = None if fields['changed'] is None else bool(fields['changed'])
        return RepairJob.model_validate(fields)

    def ensure(self, transaction_id: str, step_id: str, operation_digest: str,
               *, profile_digest: str) -> RepairJob:
        candidate = RepairJob(id=uuid.uuid4().hex, transaction_id=transaction_id,
            step_id=step_id, operation_digest=operation_digest,
            profile_digest=profile_digest, state='prepared')
        with self._transaction() as db:
            row = db.execute('SELECT * FROM repair_jobs WHERE transaction_id=? AND step_id=?', (transaction_id, step_id)).fetchone()
            if row is not None:
                job = self._model(row)
                if (job.operation_digest, job.profile_digest) != (operation_digest, profile_digest):
                    raise RepairJobError('job_binding_mismatch')
                return job
            db.execute('INSERT INTO repair_jobs (id, transaction_id, step_id, profile_digest, operation_digest, state) VALUES (?, ?, ?, ?, ?, ?)',
                (candidate.id, transaction_id, step_id, profile_digest, operation_digest, 'prepared'))
        return candidate


    def get(self, job_id: str) -> RepairJob:
        with self._transaction() as db:
            return self._model(db.execute('SELECT * FROM repair_jobs WHERE id=?', (job_id,)).fetchone())

    def bind_request(self, job_id, request, *, controller_key_fingerprint: str, envelope=None) -> None:
        payload = canonical_json_bytes(request.model_dump(mode='json')).decode()
        with self._transaction() as db:
            row = db.execute('SELECT request, controller_key FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
            if row is None:
                raise RepairJobError('job_missing')
            if row[0] is not None:
                self._check_owner(json.loads(row[0]), request)
                if row[1] != controller_key_fingerprint:
                    raise RepairJobError('job_binding_mismatch')
                return
            db.execute('UPDATE repair_jobs SET request=?, controller_key=? WHERE id=?', (payload, controller_key_fingerprint, job_id))
            if envelope is not None:
                from a4diag.plugin_api.target_protocol import TargetRequestV11
                if (envelope.key_fingerprint != controller_key_fingerprint
                        or TargetRequestV11.model_validate_json(envelope.payload) != request):
                    raise RepairJobError('job_binding_mismatch')
                db.execute('UPDATE repair_jobs SET signed_request=? WHERE id=?',
                           (envelope.model_dump_json(), job_id))

    def signed_request(self, job_id):
        from a4diag.plugin_api.target_protocol import SignedTargetRequest
        with self._transaction() as db:
            row = db.execute('SELECT signed_request FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
            if row is None or row[0] is None:
                raise RepairJobError('job_signed_proof_missing')
            return SignedTargetRequest.model_validate_json(row[0])

    def controller_key(self, job_id):
        with self._transaction() as db:
            row = db.execute('SELECT controller_key FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
            if row is None or row[0] is None:
                raise RepairJobError('job_binding_missing')
            return row[0]

    @staticmethod
    def _check_owner(original, request):
        from a4diag.preparation import PreparationDependency
        saved = original.get('preparation_dependency')
        current = request.preparation_dependency
        if (saved is None) != (current is None) or (saved is not None and
                PreparationDependency.model_validate(saved).identity() != current.identity()):
            raise RepairJobError('job_binding_mismatch')
        if (saved is not None and request.step_id == current.dependent_step_id
                and saved['stop_job_id'] != current.stop_job_id):
            raise RepairJobError('job_binding_mismatch')
        expected = (original['controller_id'], original['target_id'], original['target_fingerprint'],
            original['transaction_id'], original['step_id'], original['plan_digest'],
            original['binding']['profile_id'], original['binding']['profile_digest'],
            original['authorization_kind'], original['authorization_id'], original['operation'])
        actual = (request.controller_id, request.target_id, request.target_fingerprint,
            request.transaction_id, request.step_id, request.plan_digest,
            request.binding.profile_id, request.binding.profile_digest,
            request.authorization_kind, request.authorization_id, request.operation.model_dump(mode='json'))
        if expected != actual:
            raise RepairJobError('job_binding_mismatch')

    def lookup(self, request) -> RepairJob:
        from a4diag.policy_engine import canonical_operation_digest
        with self._transaction() as db:
            row = db.execute('SELECT * FROM repair_jobs WHERE id=?', (request.job_id,)).fetchone()
            job = self._model(row)
            if row['request'] is None:
                raise RepairJobError('job_binding_missing')
            self._check_owner(json.loads(row['request']), request)
            dependency = request.preparation_dependency
            if (dependency is not None and request.step_id == dependency.stop_step_id
                    and dependency.stop_job_id != job.id):
                raise RepairJobError('job_binding_mismatch')
            if job.profile_digest != request.binding.profile_digest or job.operation_digest != canonical_operation_digest(request.operation):
                raise RepairJobError('job_binding_mismatch')
            return job

    def request(self, job_id):
        from a4diag.plugin_api.target_protocol import TargetRequestV11
        with self._transaction() as db:
            row = db.execute('SELECT request FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
            if row is None or row[0] is None:
                raise RepairJobError('job_binding_missing')
            return TargetRequestV11.model_validate_json(row[0])

    def start(self, job_id: str, *, now: int) -> bool:
        if type(now) is not int or now < 0:
            raise RepairJobError('invalid_clock')
        with self._transaction() as db:
            return db.execute("UPDATE repair_jobs SET state='running', started_at=? WHERE id=? AND state='prepared'", (now, job_id)).rowcount == 1

    def claim(self, job_id: str) -> bool:
        identity = process_identity(os.getpid())
        if identity is None:
            raise RepairJobError('worker_identity_unavailable')
        with self._transaction() as db:
            return db.execute("UPDATE repair_jobs SET pid=?, boot_id=?, starttime=? WHERE id=? AND state='running' AND pid IS NULL",
                (os.getpid(), *identity, job_id)).rowcount == 1

    @contextmanager
    def _launch_lock(self, job_id: str, *, blocking: bool):
        """A kernel-held launch lease disappears on launcher death, not time."""
        import fcntl
        if not re.fullmatch(r'[0-9a-f]{32}', job_id):
            raise RepairJobError('invalid_job_id')
        descriptor = os.open(self.path.parent / f'.repair-launch-{job_id}',
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                yield False
            else:
                yield True
        finally:
            os.close(descriptor)

    @contextmanager
    def launching(self, job_id: str):
        # Acquire before committing running; queries cannot misclassify the
        # gap before systemd accepts the unit. This is not the resource lock.
        with self._launch_lock(job_id, blocking=True):
            yield

    def reconcile(self, job_id: str, *, startup_probe=None) -> RepairJob:
        with self._launch_lock(job_id, blocking=False) as acquired:
            if not acquired:
                return self.get(job_id)
            return self._reconcile_unlocked(job_id, startup_probe=startup_probe)

    def _reconcile_unlocked(self, job_id: str, *, startup_probe) -> RepairJob:
        with self._transaction() as db:
            row = db.execute('SELECT * FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
            job = self._model(row)
            if job.state == 'running':
                live = process_identity(row['pid']) if row['pid'] is not None else None
                if row['pid'] is None and startup_probe is not None:
                    # systemd-run acknowledges exec, before Python's DB claim.
                    # Probe the fixed root-managed unit while holding the launch
                    # lease, then independently check boot ID and PID starttime.
                    startup = startup_probe()
                    if startup is not None and process_identity(startup[0]) == startup[1:]:
                        return job
                if live is None or live != (row['boot_id'], row['starttime']):
                    db.execute("UPDATE repair_jobs SET state='unknown', changed=NULL, result=? WHERE id=? AND state='running'",
                        ('{"reason":"worker_unobserved"}', job_id))
            row = db.execute('SELECT * FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
            return self._model(row)

    def complete(self, job_id: str, *, state: str, changed: bool | None,
                 result: dict, now: int) -> RepairJob:
        if state not in TERMINAL_JOB_STATES | {'unknown'}:
            raise RepairJobError('invalid_job_state')
        oversized = False
        try:
            encoded = canonical_json_bytes(result, max_bytes=MAX_JOB_RESULT_BYTES).decode()
        except ValueError:
            oversized = True
            state, changed, encoded = 'unknown', None, '{"reason":"result_too_large"}'
        with self._transaction() as db:
            old = self._model(db.execute('SELECT * FROM repair_jobs WHERE id=?', (job_id,)).fetchone())
            if old.state not in ('running', 'unknown'):
                raise RepairJobError('invalid_job_transition')
            values = old.model_dump()
            values.update(state=state, changed=changed, result=json.loads(encoded),
                finished_at=now if state in TERMINAL_JOB_STATES else None)
            candidate = RepairJob.model_validate(values)
            db.execute('UPDATE repair_jobs SET state=?, changed=?, result=?, finished_at=? WHERE id=?',
                (state, changed, encoded, candidate.finished_at, job_id))
        if oversized:
            raise RepairJobError('result_too_large')
        return candidate

    def claimed_worker_exited(self, job_id):
        """A known claimed worker identity is gone; unclaimed starts stay unknown."""
        with self._launch_lock(job_id, blocking=False) as acquired:
            if not acquired:
                return False
            with self._transaction() as db:
                row=db.execute('SELECT pid,boot_id,starttime,state FROM repair_jobs WHERE id=?',(job_id,)).fetchone()
                return bool(row is not None and row['state']=='unknown' and row['pid'] is not None
                    and process_exited(row['pid'], (row['boot_id'],row['starttime'])))



async def run_job(store: JobStore, job_id: str, *, policy, identity_probe, adapter,
                  clock=lambda: int(time.time()), plugins=None, request_guard=None) -> None:
    """Claim once and execute only the persisted, locally authorized operation."""
    from a4diag_target.executor import TargetExecutor, ExecutorError
    from a4diag.repair_store import RepairStore
    from a4diag_target.policy import PolicyDenied
    from a4diag_target.repair_admission import admit_effect, EffectAdmissionRejected
    if not store.claim(job_id):
        return
    request = store.request(job_id)

    def current_authorization():
        current = policy()
        if request_guard is not None:
            request_guard(request)
        if current.controller_key_fingerprint != store.controller_key(job_id):
            raise ExecutorError('controller_key_mismatch')
        if identity_probe() != request.target_fingerprint or current.target_fingerprint != request.target_fingerprint or current.target_id != request.target_id:
            raise ExecutorError('target_identity_mismatch')
        if clock() >= request.expires_at:
            raise ExecutorError('request_expired_before_start')
        current.authorize_repair(request.binding, request.operation,
            authorization_kind=request.authorization_kind,
            authorization_id=request.authorization_id, now=clock())
        TargetExecutor._verify_effect_digest(request)
        if request.marker is None:
            raise ExecutorError('marker_required')
        return current

    try:
        current = current_authorization()
    except (ExecutorError, PolicyDenied, OSError, ValueError) as error:
        store.complete(job_id, state='failed', changed=False,
            result={'reason': str(error)}, now=clock())
    else:
        # Reuse the same closed plugin dispatch as the short-action executor.
        executor = TargetExecutor(verifier=None, policy=current,
            identity_probe=identity_probe, adapter=adapter, plugins=plugins)
        plugin = executor._plugins[request.operation.capability]
        deadline = time.monotonic() + request.operation.timeout_seconds
        try:
            admit_effect(plugin, request, deadline=deadline)
        except EffectAdmissionRejected as error:
            store.complete(job_id, state='failed', changed=False,
                result={'reason':str(error)[:512], 'admission_rejected':True,
                        'change_verified':True}, now=clock())
            RepairStore(store.path).finish_job(job_id, 'failed')
            return
        try:
            from a4diag.writer_holds import WriterHolds, stop_binding
            from contextlib import nullcontext
            import asyncio
            holds = WriterHolds(RepairStore(store.path))
            service = request.operation.capability == 'services'
            started = time.monotonic()
            wait = min(15, request.operation.timeout_seconds, max(0, request.expires_at-clock()))
            with holds.resource_guard(request.target_id, request.operation.resource, wait_seconds=wait) if service else nullcontext():
                # Admission may still own the short lease. Never act on auth
                # cached before waiting, including a freshly revoked profile.
                current_authorization()
                if request.operation.capability == 'services':
                    if request.preparation_dependency is None:
                        holds.require_unheld(request.target_id, request.operation.resource)
                    else:
                        holds.require_owner(stop_binding(request), job_id=job_id)
                        # Historical unsigned admissions are never stop proof.
                        store.signed_request(job_id)
                if service:
                    remaining = request.operation.timeout_seconds-(time.monotonic()-started)
                    if remaining <= 0:
                        raise ExecutorError('worker_admission_budget_exceeded')
                    result = await asyncio.wait_for(executor._dispatch(plugin, request), timeout=remaining)
                elif request.operation.capability == 'containers':
                    result = await executor._dispatch(plugin, request, deadline=deadline)
                else:
                    result = await executor._dispatch(plugin, request)
            payload = result.model_dump(mode='json')
            changed = result.changed
            state = 'succeeded' if result.ok else 'partial'
            if not result.ok and not result.changed:
                # A nonzero command can follow a successful stop/write. The
                # legacy adapter's default False is not no-change evidence.
                state, changed = 'unknown', None
                payload.update(changed=None, change_verified=False)
            store.complete(job_id, state=state, changed=changed,
                result=payload, now=clock())
        except Exception:
            # An exception cannot prove whether the effect happened.
            if store.get(job_id).state == 'running':
                store.complete(job_id, state='unknown', changed=None,
                    result={'reason': 'worker_execution_unknown'}, now=clock())
    job = store.get(job_id)
    if job.state in TERMINAL_JOB_STATES:
        RepairStore(store.path).finish_job(job_id, job.state)


class SystemdJobLauncher:
    """A separate service/cgroup with the executor's fixed privilege sandbox."""
    def __init__(self, store: Path, *, policy_path: Path, identity_root: Path = Path('/'), helper_id: str | None = None):
        self.store = Path(store)
        self.policy_path = Path(policy_path)
        self.identity_root = Path(identity_root)
        self.helper_id = helper_id

    def __call__(self, job_id: str) -> None:
        import subprocess
        if not re.fullmatch(r'[0-9a-f]{32}', job_id):
            raise RepairJobError('invalid_job_id')
        properties = (
            'User=root', 'Group=a4diag-target', 'Restart=no',
            'NoNewPrivileges=yes', 'PrivateTmp=yes', 'PrivateDevices=yes',
            'ProtectSystem=strict', 'ProtectHome=yes', 'ProtectKernelTunables=yes',
            'ProtectKernelModules=yes', 'ProtectKernelLogs=yes', 'ProtectControlGroups=yes',
            'RestrictRealtime=yes', 'LockPersonality=yes', 'MemoryDenyWriteExecute=yes',
            'RestrictAddressFamilies=AF_UNIX',
            'ReadOnlyPaths=/etc/a4diag-target /opt/a4diag-target/current',
            'ReadWritePaths=/run/a4diag-target /var/lib/a4diag-target/executor',
            'MemoryMax=256M', 'TasksMax=32', 'LimitNOFILE=1024',
            'StandardOutput=null', 'StandardError=journal',
        )
        if self.helper_id is not None:
            from a4diag_target.repair_install import load_binding, sandbox_properties
            binding = load_binding(self.helper_id)
            if self.store != binding.state / 'repair-jobs.sqlite3':
                raise RepairJobError('helper_store_mismatch')
            properties = sandbox_properties(binding)
        argv = ['/usr/bin/systemd-run', '--quiet', '--collect',
            f'--unit=a4diag-repair-{job_id}.service', '--service-type=exec']
        argv.extend(f'--property={value}' for value in properties)
        if self.helper_id is None:
            argv.extend(['/opt/a4diag-target/current/venv/bin/python', '-m', 'a4diag_target.repair_jobs',
                '--store', str(self.store), '--job', job_id,
                '--policy', str(self.policy_path), '--identity-root', str(self.identity_root)])
        else:
            argv.extend(['/opt/a4diag-target/current/venv/bin/python', '-m', 'a4diag_target.repair_helper',
                '--helper', self.helper_id, '--job', job_id])
        subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)

    def worker_identity(self, job_id: str) -> tuple[int, str, str] | None:
        """Only the exact protected systemd unit can attest unclaimed startup."""
        import subprocess
        if not re.fullmatch(r'[0-9a-f]{32}', job_id):
            raise RepairJobError('invalid_job_id')
        try:
            response = subprocess.run(['/usr/bin/systemctl', 'show',
                f'a4diag-repair-{job_id}.service', '--property=MainPID', '--value'],
                check=True, capture_output=True, text=True, timeout=5)
            pid = int(response.stdout.strip())
            identity = process_identity(pid) if pid > 0 else None
            return None if identity is None else (pid, *identity)
        except (OSError, ValueError, subprocess.SubprocessError):
            return None


def main() -> int:
    import argparse
    import asyncio
    from a4diag_target.server import load_policy, target_fingerprint
    from a4diag_builtin_plugins.capability_common import LocalFileAdapter
    parser = argparse.ArgumentParser()
    parser.add_argument('--store', type=Path, required=True)
    parser.add_argument('--job', required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--identity-root', type=Path, default=Path('/'))
    args = parser.parse_args()
    asyncio.run(run_job(JobStore(args.store), args.job,
        policy=lambda: load_policy(args.policy),
        identity_probe=lambda: target_fingerprint(args.identity_root),
        adapter=LocalFileAdapter()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

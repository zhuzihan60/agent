"""Opt-in real signed stop, independent worker, hold and finally restoration."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import site
import sqlite3
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('A4DIAG_TEST_SYSTEMD') != '1', reason='requires disposable systemd lab')


def test_signed_stop_holds_real_unit_until_verified_finally():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from a4diag.domain import Operation, RepairBinding, canonical_json_bytes
    from a4diag.preparation import PreparationDependency
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag.plugin_api.target_protocol import TargetRequestV11, TargetSigner, TargetVerifier
    from a4diag.plugin_api.ticket import effect_payload_digest
    from a4diag.repair_profiles import RepairProfile, profile_digest
    from a4diag.repair_store import RepairStore
    from a4diag_target.executor import TargetExecutor, ExecutorError
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.repair_jobs import JobStore, SystemdJobLauncher
    from a4diag_target.replay import SqliteReplayLedger
    from a4diag_target.server import target_fingerprint
    from a4diag_target.preparation_proof import read_stop_proof, SERVICE_JOB_DATABASE
    from a4diag_builtin_plugins.capability_common import LocalFileAdapter

    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert os.uname().nodename == 'a4diag-remediation-test'
    token = uuid.uuid4().hex
    base = Path('/opt/a4diag-target')
    base.mkdir(exist_ok=True)
    current, stage = base/'current', base/('d1b-'+token)
    assert not current.exists() and not current.is_symlink()
    root = SERVICE_JOB_DATABASE.parent/('d1b-'+token)
    root.mkdir(parents=True, mode=0o700)
    stage.mkdir()
    Path('/run/a4diag-target').mkdir(exist_ok=True)
    Path('/etc/a4diag-target').mkdir(exist_ok=True)
    subprocess.run(['/usr/sbin/groupadd', '-f', 'a4diag-target'], check=True)
    unit = 'a4diag-d1b-'+token+'.service'
    unit_path = Path('/run/systemd/system')/unit
    unit_path.write_text('[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n')
    job_id = None
    try:
        subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(stage/'venv')], check=True)
        repo = Path(__file__).resolve().parents[2]
        paths = site.getsitepackages()+[str(repo/'src'), str(repo/'packages/a4diag-target-runtime/src'),
                                      str(repo/'packages/a4diag-builtin-plugins/src')]
        (stage/'venv/lib/python3.11/site-packages/d1b.pth').write_text('\n'.join(paths)+'\n')
        current.symlink_to(stage, target_is_directory=True)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
        subprocess.run(['/usr/bin/systemctl', 'start', unit], check=True)
        fingerprint, now = target_fingerprint(), int(time.time())
        profile = RepairProfile(id='writer', target_id='lab', capability='services', resource=unit,
            actions=('stop',), constraints={}, recovery_check_ids=('health',),
            expires_at=now+240, standing_authorization=True)
        operation = Operation(capability='services', action='stop', resource=unit, parameters={'unit':unit},
            model_risk='high', verify={'recovery_check_ids':['health']}, undo={'restore':True})
        dep = PreparationDependency(stop_step_id='0', stop_profile_id='writer',
            stop_profile_digest=profile_digest(profile), stop_operation_digest=canonical_operation_digest(operation),
            dependent_step_id='1', dependent_profile_id='cache', dependent_profile_digest='c'*64,
            dependent_operation_digest='e'*64)
        key = Ed25519PrivateKey.generate()
        signer = TargetSigner(key)
        request = TargetRequestV11(controller_id='controller', target_id='lab', target_fingerprint=fingerprint,
            transaction_id='live-'+token, step_id='0', lifecycle='prepare', operation=operation,
            marker=None, undo=None, plan_digest='d'*64, effect_payload_digest=effect_payload_digest({}), risk='high',
            binding=RepairBinding(profile_id='writer', profile_digest=profile_digest(profile)),
            authorization_kind='standing', authorization_id='writer', preparation_dependency=dep,
            issued_at=now, expires_at=now+180, nonce='prepare-'+token)
        policy = TargetPolicy(target_id='lab', target_fingerprint=fingerprint,
            controller_key_fingerprint=signer.sign(request).key_fingerprint, repair_profiles=(profile,))
        policy_path = root/'policy.json'
        policy_path.write_text(policy.model_dump_json())
        policy_path.chmod(0o600)
        jobs, limits = JobStore(SERVICE_JOB_DATABASE), RepairStore(SERVICE_JOB_DATABASE)
        def executor():
            verifier = TargetVerifier(key.public_key(), replay_store=SqliteReplayLedger(root/'replay.db'), clock=lambda:int(time.time()))
            instance = TargetExecutor(verifier=verifier, policy=policy, identity_probe=lambda:fingerprint, adapter=LocalFileAdapter())
            instance.configure_jobs(jobs, limits, SystemdJobLauncher(SERVICE_JOB_DATABASE, policy_path=policy_path))
            return instance
        first = executor()
        marker = asyncio.run(first.execute(signer.sign(request)))['marker']
        values = request.model_dump()
        values.update(lifecycle='apply', marker=marker, nonce='apply-'+token,
            binding=request.binding.model_copy(update={'preconditions_digest':hashlib.sha256(canonical_json_bytes(marker)).hexdigest()}),
            effect_payload_digest=effect_payload_digest({'marker':marker}))
        apply = TargetRequestV11.model_validate(values)
        accepted = asyncio.run(first.execute(signer.sign(apply)))
        job_id = accepted['job']['id']
        deadline = time.monotonic()+30
        while jobs.get(job_id).state == 'running' and time.monotonic() < deadline:
            time.sleep(.1)
        assert jobs.get(job_id).state == 'succeeded'
        assert subprocess.run(['/usr/bin/systemctl', 'is-active', unit], capture_output=True, text=True).stdout.strip() == 'inactive'
        restarted = executor()
        bound = dep.model_copy(update={'stop_job_id':job_id})
        def request_for(phase, **extra):
            fields = {'marker':marker}
            if phase == 'undo':
                fields['undo'] = operation.undo
            return TargetRequestV11.model_validate({**apply.model_dump(), 'lifecycle':phase,
                'preparation_dependency':bound, 'nonce':phase+'-'+uuid.uuid4().hex,
                'undo':operation.undo if phase == 'undo' else None,
                'effect_payload_digest':effect_payload_digest(fields), **extra})
        proof = read_stop_proof(request_for('verify'), verifier=restarted._verifier,
                              current_policy=policy, writer_unit=unit)
        assert proof.marker == marker
        with pytest.raises(ExecutorError, match='writer_hold_unresolved'):
            asyncio.run(restarted.execute(signer.sign(request_for('confirm_job', job_id=job_id,
                effect_payload_digest=effect_payload_digest({})))))
        assert asyncio.run(restarted.execute(signer.sign(request_for('undo'))))['ok']
        assert asyncio.run(restarted.execute(signer.sign(request_for('verify', verify_restored=True))))['ok']
        assert subprocess.run(['/usr/bin/systemctl', 'is-active', unit], capture_output=True, text=True).stdout.strip() == 'active'
        from a4diag.writer_holds import WriterHolds
        assert WriterHolds(limits).get('lab', unit) is None
        print(json.dumps({'systemd':subprocess.check_output(['/usr/bin/systemctl','--version'], text=True).splitlines()[0],
                          'job':job_id, 'signed_stop':'succeeded', 'proof':'verified', 'finally':'restored'}))
    finally:
        if job_id:
            subprocess.run(['/usr/bin/systemctl', 'stop', 'a4diag-repair-'+job_id+'.service'], capture_output=True)
        subprocess.run(['/usr/bin/systemctl', 'stop', unit], capture_output=True)
        unit_path.unlink(missing_ok=True)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
        if current.is_symlink() and current.resolve() == stage:
            current.unlink()
        # Preserve earlier protected lab history; remove only this fixture's rows.
        if job_id:
            with sqlite3.connect(SERVICE_JOB_DATABASE) as db:
                db.execute('DELETE FROM writer_holds WHERE job_id=? AND transaction_id=?', (job_id,'live-'+token))
                db.execute('DELETE FROM repair_reservations WHERE job_id=? AND transaction_id=?', (job_id,'live-'+token))
                db.execute('DELETE FROM repair_jobs WHERE id=? AND transaction_id=?', (job_id,'live-'+token))
        guard = hashlib.sha256(canonical_json_bytes([SERVICE_JOB_DATABASE.name,'lab',unit])).hexdigest()
        (SERVICE_JOB_DATABASE.parent/('.writer-'+guard)).unlink(missing_ok=True)
        if job_id:
            (SERVICE_JOB_DATABASE.parent/('.repair-launch-'+job_id)).unlink(missing_ok=True)
        shutil.rmtree(root)
        shutil.rmtree(stage)

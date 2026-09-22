"""Opt-in real systemd worker/cgroup survival in the disposable remediation lab."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import site
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('A4DIAG_TEST_SYSTEMD') != '1', reason='requires disposable systemd lab')


def test_systemd_worker_finishes_after_dispatcher_exit():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from a4diag.domain import Operation, RepairBinding, canonical_json_bytes
    from a4diag.plugin_api.target_protocol import TargetRequestV11, TargetSigner, TargetVerifier
    from a4diag.plugin_api.ticket import effect_payload_digest
    from a4diag.repair_profiles import RepairProfile, profile_digest
    from a4diag_target.executor import TargetExecutor
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.replay import SqliteReplayLedger
    from a4diag_target.repair_jobs import JobStore
    from a4diag_target.server import target_fingerprint
    from a4diag_builtin_plugins.capability_common import LocalFileAdapter
    import hashlib

    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert os.uname().nodename == 'a4diag-remediation-test'
    token = uuid.uuid4().hex
    base = Path('/opt/a4diag-target')
    base.mkdir(exist_ok=True)
    current = base / 'current'
    assert not current.exists() and not current.is_symlink(), 'preexisting installation must not be replaced'
    stage = base / f'f3-test-{token}'
    stage.mkdir()
    root = Path('/var/lib/a4diag-target/executor') / f'f3-test-{token}'
    root.mkdir(parents=True, mode=0o700)
    Path('/run/a4diag-target').mkdir(exist_ok=True)
    Path('/etc/a4diag-target').mkdir(exist_ok=True)
    subprocess.run(['/usr/sbin/groupadd', '-f', 'a4diag-target'], check=True)
    demo = f'a4diag-f3-{token}.service'
    unit = Path('/run/systemd/system') / demo
    unit.write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sleep 6\n')
    worker_unit = None
    try:
        subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(stage/'venv')], check=True)
        packages = stage / 'venv/lib/python3.11/site-packages'
        repo = Path(__file__).resolve().parents[2]
        paths = site.getsitepackages() + [str(repo/'src'), str(repo/'packages/a4diag-target-runtime/src'), str(repo/'packages/a4diag-builtin-plugins/src')]
        (packages/'f3-test.pth').write_text('\n'.join(paths)+'\n')
        current.symlink_to(stage, target_is_directory=True)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True)
        subprocess.run(['/usr/bin/systemctl', 'start', demo], check=True, timeout=15)
        now = int(time.time())
        fingerprint = target_fingerprint()
        key = Ed25519PrivateKey.generate()
        signer = TargetSigner(key)
        profile = RepairProfile(id='demo', target_id='lab', capability='services', resource=demo,
            actions=('restart',), constraints={}, recovery_check_ids=('health',), expires_at=now+240, standing_authorization=True)
        operation = Operation(capability='services', action='restart', resource=demo,
            parameters={'unit':demo}, model_risk='high', verify={'recovery_check_ids':['health']}, undo=None)
        request = TargetRequestV11(controller_id='controller', target_id='lab', target_fingerprint=fingerprint,
            transaction_id='tx-live', step_id='0', lifecycle='prepare', operation=operation,
            marker=None, undo=None, plan_digest='d'*64, effect_payload_digest=effect_payload_digest({}), risk='high',
            binding=RepairBinding(profile_id='demo', profile_digest=profile_digest(profile)),
            authorization_kind='standing', authorization_id='demo', issued_at=now, expires_at=now+180,
            nonce='nonce-live-prepare-001')
        policy = TargetPolicy(target_id='lab', target_fingerprint=fingerprint,
            controller_key_fingerprint=signer.sign(request).key_fingerprint, repair_profiles=(profile,))
        policy_path = root/'policy.json'
        policy_path.write_text(policy.model_dump_json())
        executor = TargetExecutor(verifier=TargetVerifier(key.public_key(), replay_store=SqliteReplayLedger(root/'replay.db'), clock=lambda:int(time.time())),
            policy=policy, identity_probe=lambda:fingerprint, adapter=LocalFileAdapter())
        marker = asyncio.run(executor.execute(signer.sign(request)))['marker']
        request = request.model_copy(update={'lifecycle':__import__('a4diag.plugin_api.target_protocol', fromlist=['TargetLifecycleV11']).TargetLifecycleV11.APPLY,
            'marker':marker, 'binding':request.binding.model_copy(update={'preconditions_digest':hashlib.sha256(canonical_json_bytes(marker)).hexdigest()}),
            'effect_payload_digest':effect_payload_digest({'marker':marker}), 'nonce':'nonce-live-apply-0001'})
        # The dispatcher process persists acceptance, launches a separate unit,
        # then exits while systemctl start remains blocked in the worker.
        request_path = root/'request.json'
        request_path.write_text(request.model_dump_json())
        child = root/'dispatch.py'
        child.write_text('''import sys, json, time
from pathlib import Path
from a4diag_target.repair_jobs import JobStore, SystemdJobLauncher
from a4diag.repair_store import RepairStore
from a4diag.plugin_api.target_protocol import TargetRequestV11
from a4diag.policy_engine import canonical_operation_digest
root=Path(sys.argv[1]); request=TargetRequestV11.model_validate_json((root/'request.json').read_text())
jobs=JobStore(root/'jobs.db'); limits=RepairStore(root/'jobs.db')
job=jobs.ensure(request.transaction_id,request.step_id,canonical_operation_digest(request.operation),profile_digest=request.binding.profile_digest)
jobs.bind_request(job.id,request,controller_key_fingerprint=json.loads((root/'policy.json').read_text())['controller_key_fingerprint'])
reservation=limits.reserve(request.target_id,request.operation.resource,request.transaction_id,int(time.time()),600,2)
limits.bind_job(reservation,job.id); limits.mark_started(reservation,int(time.time())); jobs.start(job.id,now=int(time.time()))
SystemdJobLauncher(jobs.path,policy_path=root/'policy.json')(job.id)
(root/'job-id').write_text(job.id)
''')
        subprocess.run([str(current/'venv/bin/python'), str(child), str(root)], check=True, timeout=25)
        job_id = (root/'job-id').read_text()
        worker_unit = f'a4diag-repair-{job_id}.service'
        jobs = JobStore(root/'jobs.db')
        assert jobs.get(job_id).state == 'running'
        properties = subprocess.run(['/usr/bin/systemctl', 'show', worker_unit, '-p', 'MainPID', '-p', 'ControlGroup', '-p', 'ProtectSystem', '-p', 'NoNewPrivileges'], check=True, capture_output=True, text=True).stdout
        assert 'ProtectSystem=strict' in properties and 'NoNewPrivileges=yes' in properties
        deadline = time.monotonic()+20
        while jobs.get(job_id).state == 'running' and time.monotonic() < deadline:
            time.sleep(0.2)
        job = jobs.get(job_id)
        assert job.state == 'succeeded', job
        assert subprocess.run(['/usr/bin/systemctl','is-active',demo], capture_output=True, text=True).stdout.strip() == 'active'
        evidence = {'dispatcher_exited':True, 'worker_properties':properties, 'job':job.model_dump(mode='json')}
        (Path.cwd().parent/'systemd-worker-evidence.json').write_text(json.dumps(evidence, indent=2))
    finally:
        for name in (worker_unit, demo):
            if name:
                subprocess.run(['/usr/bin/systemctl','stop',name], capture_output=True)
        unit.unlink(missing_ok=True)
        subprocess.run(['/usr/bin/systemctl','daemon-reload'], check=True)
        if current.is_symlink() and current.resolve() == stage.resolve():
            current.unlink()
        assert stage.parent == base and stage.name == f'f3-test-{token}'
        shutil.rmtree(stage)
        assert root.parent == Path('/var/lib/a4diag-target/executor') and root.name == f'f3-test-{token}'
        shutil.rmtree(root)

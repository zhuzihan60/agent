from __future__ import annotations

import pytest

from tests.target_runtime.test_repair_protocol import (
    prepared_repair, _request, _operation, _binding, FINGERPRINT,
)
from a4diag.plugin_api.target_protocol import TargetLifecycleV11
import asyncio


def test_duplicate_job_reuses_identity_and_requires_exact_digests(tmp_path):
    from a4diag_target.repair_jobs import JobStore, RepairJobError
    path = tmp_path / 'jobs.db'
    first = JobStore(path).ensure('tx1', '0', 'a' * 64, profile_digest='b' * 64)
    second = JobStore(path).ensure('tx1', '0', 'a' * 64, profile_digest='b' * 64)
    assert first.id == second.id
    assert second.state == 'prepared'
    for operation, profile in (('c' * 64, 'b' * 64), ('a' * 64, 'c' * 64)):
        with pytest.raises(RepairJobError, match='job_binding_mismatch'):
            JobStore(path).ensure('tx1', '0', operation, profile_digest=profile)
    with pytest.raises(TypeError):
        JobStore(path).ensure('tx2', '0', 'a' * 64)


def test_lost_worker_is_unknown_and_cannot_start_again(tmp_path):
    from a4diag_target.repair_jobs import JobStore, RepairJobError
    store = JobStore(tmp_path / 'jobs.db')
    job = store.ensure('tx1', '0', 'a' * 64, profile_digest='b' * 64)
    assert store.start(job.id, now=100)
    assert not store.start(job.id, now=101)
    recovered = JobStore(tmp_path / 'jobs.db').reconcile(job.id)
    assert recovered.state == 'unknown'
    assert recovered.changed is None
    assert not store.start(job.id, now=102)


def test_terminal_job_releases_resource_but_unknown_retains_it(tmp_path):
    from a4diag_target.repair_jobs import JobStore
    from a4diag.repair_store import RepairStore, RepairLimitError
    path = tmp_path / 'jobs.db'
    jobs, limits = JobStore(path), RepairStore(path)
    job = jobs.ensure('tx1', '0', 'a' * 64, profile_digest='b' * 64)
    reservation = limits.reserve('demo', 'web.service', 'tx1', 100, 600, 2)
    limits.bind_job(reservation, job.id)
    limits.mark_started(reservation, 100)
    jobs.start(job.id, now=100)
    with pytest.raises(RepairLimitError, match='job_not_terminal'):
        limits.finish(reservation, 'succeeded')
    jobs.complete(job.id, state='partial', changed=True, result={'reason': 'failed_after_effect'}, now=102)
    limits.finish(reservation, 'partial')
    assert limits.reserve('demo', 'web.service', 'tx2', 700, 600, 2)


def test_oversized_result_preserves_unknown_state_and_bounded_record(tmp_path):
    from a4diag_target.repair_jobs import JobStore, RepairJobError
    store = JobStore(tmp_path / 'jobs.db')
    job = store.ensure('tx1', '0', 'a' * 64, profile_digest='b' * 64)
    store.start(job.id, now=100)
    with pytest.raises(RepairJobError, match='result_too_large'):
        store.complete(job.id, state='succeeded', changed=True, result={'data': 'x' * 262144}, now=101)
    assert store.get(job.id).state == 'unknown'
    assert store.get(job.id).result == {'reason': 'result_too_large'}


def _wire(prepared, tmp_path):
    from a4diag_target.repair_jobs import JobStore
    from a4diag.repair_store import RepairStore
    jobs = JobStore(tmp_path / 'jobs.db')
    limits = RepairStore(tmp_path / 'jobs.db')
    launches = []
    prepared.executor.configure_jobs(jobs, limits, launches.append)
    return jobs, limits, launches


def _apply(prepared, nonce='nonce-apply-job-0001'):
    return _request(prepared.profile, TargetLifecycleV11.APPLY, nonce, marker=prepared.marker)


def test_apply_persists_running_before_launch_and_deduplicates(prepared_repair, tmp_path):
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    request = _apply(prepared_repair)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))
    assert result['protocol_version'] == '1.1'
    assert jobs.get(result['job']['id']).state == 'running'
    assert launches == [result['job']['id']]
    retry = _apply(prepared_repair, 'nonce-apply-job-0002')
    again = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(retry)))
    assert again['job']['id'] == result['job']['id']
    assert len(launches) == 1
    assert prepared_repair.effect_calls == []


def test_revoked_query_is_read_only_and_ownership_bound(prepared_repair, tmp_path):
    from a4diag_target.executor import ExecutorError
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    job_id = result['job']['id']
    prepared_repair.target.revoke('web')
    request = _request(prepared_repair.profile, TargetLifecycleV11.QUERY_JOB, 'nonce-query-revoked', job_id=job_id)
    queried = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))
    assert queried['job']['id'] == job_id
    assert queried['job']['state'] == 'unknown'
    assert queried['job']['result']['target_observation']['state'] == 'not_applied'
    for index, change in enumerate(({'transaction_id':'other'}, {'step_id':'1'}, {'controller_id':'other'}, {'plan_digest':'e'*64}, {'binding':_binding(prepared_repair.profile).model_copy(update={'profile_digest':'f'*64})}, {'operation':_operation(resource='other.service', parameters={'unit':'other.service'})})):
        forged = request.model_copy(update={**change, 'nonce': f'nonce-cross-query-{index:04d}'})
        with pytest.raises(ExecutorError, match='job_binding_mismatch'):
            asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(forged)))
    assert prepared_repair.effect_calls == []


def test_confirm_only_acknowledges_terminal_and_requires_current_grant(prepared_repair, tmp_path):
    from a4diag_target.executor import ExecutorError
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    request = _request(prepared_repair.profile, TargetLifecycleV11.CONFIRM_JOB, 'nonce-confirm-job-0001', job_id=result['job']['id'])
    with pytest.raises(ExecutorError, match='job_not_terminal'):
        asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))
    jobs.complete(result['job']['id'], state='partial', changed=True, result={}, now=151)
    request = request.model_copy(update={'nonce':'nonce-confirm-job-0002'})
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))
    assert result['job']['state'] == 'partial'
    # Simulate worker death after terminal persistence but before lock release.
    assert limits.reserve('demo', 'demo.service', 'next-tx', 750, 600, 2)
    prepared_repair.target.revoke('web')
    request = request.model_copy(update={'nonce':'nonce-confirm-job-0003'})
    with pytest.raises(ExecutorError, match='profile_revoked'):
        asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))


def test_unconfigured_apply_and_failed_launch_stay_closed(prepared_repair, tmp_path):
    from a4diag_target.executor import ExecutorError
    with pytest.raises(ExecutorError, match='job_store_required'):
        asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    def fail(job):
        raise OSError('systemd unavailable')
    prepared_repair.executor.configure_jobs(jobs, limits, fail)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair, 'nonce-failed-launch-1'))))
    assert result['job']['state'] == 'unknown'
    from a4diag.repair_store import RepairLimitError
    with pytest.raises(RepairLimitError, match='resource_busy'):
        limits.reserve('demo', 'demo.service', 'other', 9999, 600, 2)


@pytest.mark.parametrize('revoked', (False, True))
def test_worker_claims_once_and_rechecks_policy_before_effect(prepared_repair, tmp_path, revoked):
    from a4diag_target.repair_jobs import run_job
    from tests.target_runtime.test_repair_protocol import RecordingServicesAdapter
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    if revoked:
        prepared_repair.target.revoke('web')
    adapter = RecordingServicesAdapter()
    for _ in range(2):
        asyncio.run(run_job(jobs, result['job']['id'],
            policy=prepared_repair.executor._current_policy, identity_probe=lambda: FINGERPRINT,
            adapter=adapter, clock=lambda: 151))
    job = jobs.get(result['job']['id'])
    assert job.state == ('failed' if revoked else 'succeeded')
    assert len(adapter.effect_calls) == (0 if revoked else 1)
    assert limits.reserve('demo', 'demo.service', 'other', 751, 600, 2)


def test_worker_identity_keeps_active_job_running(prepared_repair, tmp_path):
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    assert jobs.claim(result['job']['id'])
    assert jobs.reconcile(result['job']['id']).state == 'running'
    assert not jobs.claim(result['job']['id'])


def test_worker_rejects_rotated_controller_key_before_effect(prepared_repair, tmp_path):
    from a4diag_target.repair_jobs import run_job
    from tests.target_runtime.test_repair_protocol import RecordingServicesAdapter
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    replacement = prepared_repair.executor._current_policy().model_copy(update={'controller_key_fingerprint':'sha256:'+'f'*64})
    adapter = RecordingServicesAdapter()
    asyncio.run(run_job(jobs, result['job']['id'], policy=lambda:replacement,
        identity_probe=lambda:FINGERPRINT, adapter=adapter, clock=lambda:151))
    assert jobs.get(result['job']['id']).state == 'failed'
    assert adapter.effect_calls == []


def test_target_enforces_registered_cooldown_after_terminal_job(prepared_repair, tmp_path):
    from a4diag_target.executor import ExecutorError
    from a4diag_target.repair_jobs import run_job
    from tests.target_runtime.test_repair_protocol import RecordingServicesAdapter
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    result = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    asyncio.run(run_job(jobs, result['job']['id'], policy=prepared_repair.executor._current_policy,
        identity_probe=lambda: FINGERPRINT, adapter=RecordingServicesAdapter(), clock=lambda: 151))
    request = _apply(prepared_repair, 'nonce-local-limit-0001').model_copy(update={'transaction_id':'tx-other'})
    with pytest.raises(ExecutorError, match='cooldown'):
        asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))
    assert len(launches) == 1


def test_second_step_cannot_reenter_same_transaction_resource(prepared_repair, tmp_path):
    from a4diag_target.executor import ExecutorError
    jobs, limits, launches = _wire(prepared_repair, tmp_path)
    asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    request = _apply(prepared_repair, 'nonce-second-step-001').model_copy(update={'step_id':'1'})
    with pytest.raises(ExecutorError, match='job_binding_mismatch'):
        asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(request)))
    assert len(launches) == 1


@pytest.mark.parametrize('bad', ('foreign', 'oversized', 'truncated', 'legacy'))
def test_transport_rejects_unbound_or_oversized_job_response(bad):
    import json
    from a4diag.repair_jobs import RepairJob, RepairJobResponse
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag_builtin_plugins.transport_common import TransportApplyParams, RunOutcome
    from tests.contract.test_transport_plugins import FakeIdentity, FakeRunner, local_transport, identity_fingerprint
    from tests.target_runtime.test_repair_protocol import _profile
    from a4diag.plugin_api.target_protocol import TargetSigner
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    identity, runner = FakeIdentity(), FakeRunner()
    request = _request(_profile(), TargetLifecycleV11.APPLY, 'nonce-transport-0001', marker={}).model_copy(update={'target_fingerprint':identity_fingerprint(identity.target_identity())})
    job = RepairJob(id='job1', transaction_id=request.transaction_id, step_id='0',
        profile_digest=request.binding.profile_digest, operation_digest=canonical_operation_digest(request.operation),
        state='running', started_at=100)
    response = RepairJobResponse(job=job).model_dump(mode='json')
    if bad == 'foreign':
        response['job']['transaction_id'] = 'other'
    if bad == 'oversized':
        response['job']['result'] = {'data':'x'*262144}
    if bad == 'legacy':
        response = {'ok':True, 'changed':True}
    runner.outcome = RunOutcome(started=True, timed_out=False, returncode=0,
        stdout=json.dumps(response), stdout_truncated=bad=='truncated')
    params = TransportApplyParams(transaction_id=request.transaction_id, step_id='0',
        target_id=request.target_id, target_fingerprint=request.target_fingerprint, operation=request.operation,
        plan_digest=request.plan_digest, risk=request.risk, approval_id=request.authorization_id,
        marker={}, envelope=TargetSigner(Ed25519PrivateKey.generate()).sign(request))
    result = asyncio.run(local_transport(identity=identity, runner=runner).apply_typed(params, None))
    assert not result.ok

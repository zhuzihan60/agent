"""Authenticated stop admission and durable finally protection regressions."""
import asyncio
import json

import pytest

from tests.target_runtime.test_repair_jobs import _wire, _apply
from tests.target_runtime.test_repair_protocol import prepared_repair, _profile, _operation


def dependency(profile, operation, **changes):
    from a4diag.preparation import PreparationDependency
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag.repair_profiles import profile_digest
    values = dict(stop_step_id='0', stop_profile_id=profile.id,
                  stop_profile_digest=profile_digest(profile),
                  stop_operation_digest=canonical_operation_digest(operation),
                  dependent_step_id='1', dependent_profile_id='cache',
                  dependent_profile_digest='c'*64, dependent_operation_digest='e'*64)
    values.update(changes)
    return PreparationDependency(**values)


def test_dependency_signature_and_absence_compatibility(prepared_repair):
    from a4diag.plugin_api.target_protocol import TargetRequestV11, TargetProtocolError
    request = _apply(prepared_repair)
    ordinary = prepared_repair.signer.sign(request)
    assert 'preparation_dependency' not in json.loads(ordinary.payload)
    stop = _operation(action='stop')
    dep = dependency(prepared_repair.profile, stop)
    bound = TargetRequestV11.model_validate({**request.model_dump(), 'operation':stop,
                                          'preparation_dependency':dep})
    envelope = prepared_repair.signer.sign(bound)
    parsed = prepared_repair.executor._verifier.verify(envelope, expected_target='demo')
    assert parsed.preparation_dependency == dep
    tampered = json.loads(envelope.payload)
    tampered['preparation_dependency']['dependent_step_id'] = '9'
    with pytest.raises(TargetProtocolError, match='invalid_signature'):
        prepared_repair.executor._verifier.verify(
            envelope.model_copy(update={'payload':json.dumps(tampered)}), expected_target='demo')


@pytest.mark.parametrize('changes', [dict(step_id='9'), dict(operation=_operation()),
                                    dict(lifecycle='undo'), dict(lifecycle='verify')])
def test_dependency_rejects_wrong_phase_or_stop_identity(prepared_repair, changes):
    from a4diag.plugin_api.target_protocol import TargetRequestV11
    stop = _operation(action='stop')
    request = _apply(prepared_repair)
    values = {**request.model_dump(), 'operation':stop,
              'preparation_dependency':dependency(prepared_repair.profile, stop), **changes}
    with pytest.raises(ValueError, match='preparation_dependency'):
        TargetRequestV11.model_validate(values)


def test_hmac_expectation_binds_dependency():
    from a4diag.plugin_api.ticket import (TicketIssuer, TicketVerifier, TicketError,
        OperationTicketRequestV11, OperationTicketExpectationV11)
    from a4diag.policy_engine import issue_repair_policy_authorization
    from tests.test_repair_authorization import _Replay
    from tests.target_runtime.test_repair_protocol import FINGERPRINT
    profile, operation = _profile(actions=('stop',)), _operation(action='stop')
    authorization = issue_repair_policy_authorization(profile, operation,
        target_fingerprint=FINGERPRINT, plan_digest='d'*64, authorization_kind='standing',
        authorization_id='web', now=150, key=b'a'*32)
    request = OperationTicketRequestV11(transaction_id='txn-1', step_id='0', target_id='demo',
        target_fingerprint=FINGERPRINT, operation=operation, plan_digest='d'*64,
        binding=authorization.binding, authorization_kind='standing', authorization_id='web',
        preparation_dependency=dependency(profile, operation))
    issuer = TicketIssuer(b'k'*32, authorization_key=b'a'*32, clock=lambda:150)
    token = issuer.issue(request, authorization)
    expected = OperationTicketExpectationV11.model_validate(request.model_dump(exclude={'ttl_seconds'}))
    assert TicketVerifier(b'k'*32, _Replay(), clock=lambda:151).verify(token, expected=expected)
    with pytest.raises(TicketError, match='preparation_dependency_mismatch'):
        TicketVerifier(b'k'*32, _Replay(), clock=lambda:151).verify(token,
            expected=expected.model_copy(update={'preparation_dependency':None}))


def test_stop_requires_explicit_profile_action():
    from a4diag.repair_profiles import authorize_profile, profile_digest, RepairAuthorizationError
    profile = _profile(actions=('stop',))
    authorize_profile(profile, _operation(action='stop'), now=150,
                      presented_digest=profile_digest(profile))
    other = _profile()
    with pytest.raises(RepairAuthorizationError, match='profile_action_not_allowed'):
        authorize_profile(other, _operation(action='stop'), now=150,
                          presented_digest=profile_digest(other))


def test_new_admission_persists_exact_signed_envelope(prepared_repair, tmp_path):
    from a4diag_target.repair_jobs import JobStore
    jobs, _, _ = _wire(prepared_repair, tmp_path)
    envelope = prepared_repair.signer.sign(_apply(prepared_repair))
    response = asyncio.run(prepared_repair.executor.execute(envelope))
    assert JobStore(jobs.path).signed_request(response['job']['id']) == envelope


def test_old_unsigned_record_still_queries_but_is_ineligible_as_proof(prepared_repair, tmp_path):
    from a4diag_target.repair_jobs import RepairJobError
    jobs, _, _ = _wire(prepared_repair, tmp_path)
    request = _apply(prepared_repair)
    job = jobs.ensure(request.transaction_id, request.step_id, 'a'*64,
                      profile_digest=request.binding.profile_digest)
    jobs.bind_request(job.id, request,
                      controller_key_fingerprint=prepared_repair.signer.sign(request).key_fingerprint)
    assert jobs.request(job.id) == request
    with pytest.raises(RepairJobError, match='job_signed_proof_missing'):
        jobs.signed_request(job.id)


@pytest.fixture
def stopped_writer(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from a4diag.plugin_api.target_protocol import TargetSigner, TargetVerifier
    from a4diag_target.executor import TargetExecutor
    from a4diag_target.repair_jobs import JobStore, run_job
    from a4diag.repair_store import RepairStore
    from tests.target_runtime.test_repair_protocol import (
        MutableTarget, RecordingServicesAdapter, ReplayStore, FINGERPRINT, _request)
    from a4diag_builtin_plugins.capability_common import CommandOutcome
    from types import SimpleNamespace

    class Adapter(RecordingServicesAdapter):
        active = True
        fail_restore = False
        async def run_command(self, argv, **kwargs):
            if argv[1] == 'show':
                return CommandOutcome(returncode=0, stdout=(
                    f'ActiveState={"active" if self.active else "inactive"}\n'
                    f'SubState={"running" if self.active else "dead"}\n'
                    'UnitFileState=enabled\nInvocationID=before\n'))
            self.effect_calls.append(tuple(argv))
            if self.fail_restore and argv[1] == 'start':
                return CommandOutcome(returncode=1)
            self.active = argv[1] == 'start'
            return CommandOutcome(returncode=0)

    profile, operation = _profile(actions=('stop', 'restart')), _operation(action='stop')
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    request = _request(profile, 'prepare', 'nonce-stop-prepare', operation=operation)
    request = type(request).model_validate({**request.model_dump(), 'preparation_dependency':dependency(profile, operation)})
    target = MutableTarget(profile)
    policy = lambda: target.policy(signer.sign(request).key_fingerprint)
    adapter = Adapter()
    verifier = TargetVerifier(key.public_key(), replay_store=ReplayStore(), clock=lambda:150)
    executor = TargetExecutor(verifier=verifier, policy=policy,
        identity_probe=lambda:FINGERPRINT, adapter=adapter)
    jobs, limits = JobStore(tmp_path/'jobs.db'), RepairStore(tmp_path/'jobs.db')
    executor.configure_jobs(jobs, limits, lambda job_id:None)
    marker = asyncio.run(executor.execute(signer.sign(request)))['marker']
    apply = _request(profile, 'apply', 'nonce-stop-apply-01', marker=marker, operation=operation)
    apply = type(apply).model_validate({**apply.model_dump(), 'preparation_dependency':request.preparation_dependency})
    response = asyncio.run(executor.execute(signer.sign(apply)))
    job_id = response['job']['id']
    asyncio.run(run_job(jobs, job_id, policy=policy,
        identity_probe=lambda:FINGERPRINT, adapter=adapter, clock=lambda:151))
    return SimpleNamespace(profile=profile, operation=operation, key=key, signer=signer,
        request=apply, target=target, policy=policy, adapter=adapter, verifier=verifier,
        executor=executor, jobs=jobs, limits=limits, job_id=job_id)


def finalizer(stopped, phase, **changes):
    from a4diag.plugin_api.target_protocol import TargetRequestV11
    from a4diag.plugin_api.ticket import effect_payload_digest
    values = stopped.request.model_dump()
    values.update(lifecycle=phase, nonce='nonce-finalizer-'+phase,
        preparation_dependency=stopped.request.preparation_dependency.model_copy(update={'stop_job_id':stopped.job_id}),
        undo=stopped.operation.undo if phase == 'undo' else None,
        effect_payload_digest=effect_payload_digest({'marker':stopped.request.marker,
            **({'undo':stopped.operation.undo} if phase == 'undo' else {})}))
    values.update(changes)
    return TargetRequestV11.model_validate(values)


def test_successful_stop_retains_hold_across_restart_and_confirm(stopped_writer):
    from a4diag.repair_store import RepairStore, RepairLimitError
    from a4diag_target.executor import ExecutorError
    from a4diag.plugin_api.ticket import effect_payload_digest
    stopped = stopped_writer
    assert stopped.jobs.get(stopped.job_id).state == 'succeeded'
    assert not stopped.adapter.active
    limits = RepairStore(stopped.jobs.path)
    with pytest.raises(RepairLimitError, match='resource_busy'):
        limits.reserve('demo', 'demo.service', 'other', 9999, 600, 2)
    request = finalizer(stopped, 'confirm_job', job_id=stopped.job_id,
                        effect_payload_digest=effect_payload_digest({}))
    with pytest.raises(ExecutorError, match='writer_hold_unresolved'):
        asyncio.run(stopped.executor.execute(stopped.signer.sign(request)))


def test_only_original_signed_undo_and_independent_verified_restoration_releases(stopped_writer):
    from a4diag_target.executor import ExecutorError
    stopped = stopped_writer
    verify = finalizer(stopped, 'verify', verify_restored=True)
    with pytest.raises(ExecutorError, match='writer_restore_not_dispatched'):
        asyncio.run(stopped.executor.execute(stopped.signer.sign(verify)))
    undo = finalizer(stopped, 'undo')
    assert asyncio.run(stopped.executor.execute(stopped.signer.sign(undo)))['ok']
    verify = verify.model_copy(update={'nonce':'nonce-restored-check-2'})
    assert asyncio.run(stopped.executor.execute(stopped.signer.sign(verify)))['ok']
    assert stopped.limits.reserve('demo', 'demo.service', 'other', 9999, 600, 2)


def test_failed_restoration_and_foreign_finalizer_remain_held(stopped_writer):
    from a4diag_target.executor import ExecutorError
    from a4diag.repair_store import RepairLimitError
    stopped = stopped_writer
    foreign = finalizer(stopped, 'undo', transaction_id='other', nonce='nonce-foreign-undo-1')
    with pytest.raises(ExecutorError, match='writer_hold_binding_mismatch'):
        asyncio.run(stopped.executor.execute(stopped.signer.sign(foreign)))
    stopped.adapter.fail_restore = True
    assert not asyncio.run(stopped.executor.execute(stopped.signer.sign(finalizer(stopped, 'undo'))))['ok']
    with pytest.raises(RepairLimitError, match='resource_busy'):
        stopped.limits.reserve('demo', 'demo.service', 'other', 9999, 600, 2)


def test_installer_drains_ordinary_terminal_writer_hold(stopped_writer, tmp_path):
    import shutil
    from a4diag_target.repair_install import ensure_drained
    path = tmp_path/'root/var/lib/a4diag-target/executor/repair-jobs.sqlite3'
    path.parent.mkdir(parents=True)
    shutil.copyfile(stopped_writer.jobs.path, path)
    with pytest.raises(ValueError, match='repair_helpers_require_drain'):
        ensure_drained(tmp_path/'root')


@pytest.mark.parametrize('version', ['1.0', '1.1'])
@pytest.mark.parametrize('phase', ['apply', 'undo'])
def test_held_writer_blocks_foreign_cross_version_mutations(stopped_writer, version, phase):
    from a4diag.plugin_api.target_protocol import TargetRequest, TargetRequestV11
    from a4diag_target.executor import ExecutorError
    from a4diag.plugin_api.ticket import effect_payload_digest
    stopped = stopped_writer
    stopped.executor._policy_source = stopped.policy().model_copy(update={'allowed_units':('demo.service',)})
    values = stopped.request.model_dump(exclude={'preparation_dependency'})
    values.update(transaction_id='foreign', controller_id='foreign-controller', lifecycle=phase,
                  nonce='nonce-cross-version-'+phase, undo=stopped.operation.undo if phase == 'undo' else None,
                  effect_payload_digest=effect_payload_digest({'marker':values['marker'],
                      **({'undo':stopped.operation.undo} if phase == 'undo' else {})}))
    if version == '1.0':
        for name in ('binding', 'authorization_kind', 'authorization_id', 'job_id'):
            values.pop(name)
        values.update(protocol_version='1.0', approval_id='approval')
    request = (TargetRequest if version == '1.0' else TargetRequestV11).model_validate(values)
    effects = list(stopped.adapter.effect_calls)
    with pytest.raises(ExecutorError, match='resource_busy'):
        asyncio.run(stopped.executor.execute(stopped.signer.sign(request)))
    assert stopped.adapter.effect_calls == effects


def test_read_only_stop_proof_checks_signature_context_and_current_unit(stopped_writer, monkeypatch):
    from a4diag_target import preparation_proof
    from a4diag.plugin_api.target_protocol import TargetVerifier
    from tests.target_runtime.test_repair_protocol import ReplayStore
    stopped = stopped_writer
    monkeypatch.setattr(preparation_proof, 'SERVICE_JOB_DATABASE', stopped.jobs.path)
    monkeypatch.setattr(preparation_proof, '_writer_snapshot', lambda unit: ('inactive', unit))
    request = finalizer(stopped, 'verify')
    # Expiry and replay do not erase history, but this cannot authorize UNDO.
    historical = TargetVerifier(stopped.key.public_key(), replay_store=ReplayStore(), clock=lambda:9999)
    proof = preparation_proof.read_stop_proof(request, verifier=historical,
        current_policy=stopped.policy(), writer_unit='demo.service')
    assert proof.marker == stopped.request.marker
    for name, value in [('controller_id','foreign'), ('transaction_id','foreign'), ('plan_digest','0'*64)]:
        with pytest.raises(ValueError, match='stop_proof'):
            preparation_proof.read_stop_proof(request.model_copy(update={name:value}), verifier=historical,
                current_policy=stopped.policy(), writer_unit='demo.service')
    monkeypatch.setattr(preparation_proof, '_writer_snapshot', lambda unit: (_ for _ in ()).throw(ValueError('writer_boundary_unproven')))
    with pytest.raises(ValueError, match='writer_boundary_unproven'):
        preparation_proof.read_stop_proof(request, verifier=historical,
            current_policy=stopped.policy(), writer_unit='demo.service')


def test_trusted_pre_effect_rejection_is_known_no_change_but_effect_exception_unknown(prepared_repair, tmp_path):
    from a4diag_target.repair_jobs import run_job
    from a4diag_target.repair_admission import EffectAdmissionRejected
    from tests.target_runtime.test_repair_protocol import FINGERPRINT
    jobs, _, _ = _wire(prepared_repair, tmp_path)
    class ClosedAdapter:
        def admit_effect(self, request):
            raise EffectAdmissionRejected('effect_not_implemented')
        async def apply(self, params):
            pytest.fail('admission rejection must precede any invocation')
    response = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    asyncio.run(run_job(jobs, response['job']['id'], policy=prepared_repair.executor._current_policy,
        identity_probe=lambda:FINGERPRINT, adapter=None, plugins={'services':ClosedAdapter()}, clock=lambda:151))
    job = jobs.get(response['job']['id'])
    assert (job.state, job.changed) == ('failed', False)
    assert job.result['admission_rejected'] is True


def test_verified_finally_is_observable_after_response_loss(stopped_writer):
    stopped = stopped_writer
    asyncio.run(stopped.executor.execute(stopped.signer.sign(finalizer(stopped, 'undo'))))
    first = finalizer(stopped, 'verify', verify_restored=True)
    assert asyncio.run(stopped.executor.execute(stopped.signer.sign(first)))['ok']
    retry = first.model_copy(update={'nonce':'nonce-after-lost-verification'})
    assert asyncio.run(stopped.executor.execute(stopped.signer.sign(retry)))['ok']


@pytest.mark.parametrize('mutation', ['envelope', 'missing', 'profile', 'operation', 'result', 'reference'])
def test_stop_proof_rejects_spoofed_or_foreign_protected_record(stopped_writer, monkeypatch, mutation):
    import sqlite3
    from a4diag_target import preparation_proof
    stopped = stopped_writer
    monkeypatch.setattr(preparation_proof, 'SERVICE_JOB_DATABASE', stopped.jobs.path)
    monkeypatch.setattr(preparation_proof, '_writer_snapshot', lambda unit: ('inactive', unit))
    request = finalizer(stopped, 'verify')
    if mutation == 'reference':
        request = request.model_copy(update={'preparation_dependency':request.preparation_dependency.model_copy(update={'stop_job_id':'foreign-job'})})
    else:
        with sqlite3.connect(stopped.jobs.path) as db:
            if mutation == 'envelope':
                envelope = stopped.jobs.signed_request(stopped.job_id).model_dump()
                envelope['signature'] = 'A'*86
                db.execute('UPDATE repair_jobs SET signed_request=? WHERE id=?', (json.dumps(envelope), stopped.job_id))
            elif mutation == 'missing':
                db.execute('UPDATE repair_jobs SET signed_request=NULL WHERE id=?', (stopped.job_id,))
            elif mutation in ('profile','operation'):
                column = 'profile_digest' if mutation == 'profile' else 'operation_digest'
                db.execute(f'UPDATE repair_jobs SET {column}=? WHERE id=?', ('0'*64, stopped.job_id))
            else:
                db.execute('UPDATE repair_jobs SET result=? WHERE id=?', ('{"ok":false}', stopped.job_id))
    with pytest.raises(ValueError):
        preparation_proof.read_stop_proof(request, verifier=stopped.verifier,
            current_policy=stopped.policy(), writer_unit='demo.service')


def test_independent_worker_waits_for_admission_guard(prepared_repair, tmp_path):
    import multiprocessing
    from a4diag.writer_holds import WriterHolds
    from tests.target_runtime.test_repair_jobs import _paused_worker
    jobs, limits, _ = _wire(prepared_repair, tmp_path)
    response = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    job_id = response['job']['id']
    ctx = multiprocessing.get_context('spawn')
    ready, proceed = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_paused_worker, args=(jobs.path,
        prepared_repair.executor._current_policy().model_dump_json(), job_id, ready, proceed))
    try:
        with WriterHolds(limits).resource_guard('demo', 'demo.service'):
            process.start()
            assert ready.wait(10)
            proceed.set()
            process.join(1)
            assert process.is_alive(), 'worker must wait for admission lease, not become unknown'
        process.join(10)
        assert process.exitcode == 0
        assert jobs.get(job_id).state == 'succeeded'
    finally:
        if process.is_alive():
            process.terminate()
        process.join(10)


@pytest.mark.parametrize('phase', ['verify', 'reconcile'])
def test_service_read_dependency_requires_actual_original_job(stopped_writer, phase):
    from a4diag_target.executor import ExecutorError
    stopped = stopped_writer
    request = finalizer(stopped, phase)
    request = request.model_copy(update={'preparation_dependency':
        request.preparation_dependency.model_copy(update={'stop_job_id':'foreign-job'})})
    with pytest.raises(ExecutorError, match='writer_hold_binding_mismatch'):
        asyncio.run(stopped.executor.execute(stopped.signer.sign(request)))


def _authorization_wait_worker(path, policy_path, job_id, ready, effects):
    from pathlib import Path
    from a4diag_target.repair_jobs import JobStore, run_job
    from a4diag_target.policy import TargetPolicy
    from tests.target_runtime.test_repair_protocol import RecordingServicesAdapter, FINGERPRINT
    adapter = RecordingServicesAdapter()
    asyncio.run(run_job(JobStore(path), job_id,
        policy=lambda:TargetPolicy.model_validate_json(Path(policy_path).read_text()),
        identity_probe=lambda:FINGERPRINT, adapter=adapter, request_guard=lambda _:ready.set(), clock=lambda:151))
    Path(effects).write_text(json.dumps(adapter.effect_calls))


def test_worker_revalidates_revocation_after_admission_wait(prepared_repair, tmp_path):
    import multiprocessing
    from a4diag.writer_holds import WriterHolds
    jobs, limits, _ = _wire(prepared_repair, tmp_path)
    response = asyncio.run(prepared_repair.executor.execute(prepared_repair.signer.sign(_apply(prepared_repair))))
    job_id = response['job']['id']
    policy = prepared_repair.executor._current_policy()
    policy_path, effects = tmp_path/'policy.json', tmp_path/'effects.json'
    policy_path.write_text(policy.model_dump_json())
    ctx = multiprocessing.get_context('spawn')
    ready = ctx.Event()
    process = ctx.Process(target=_authorization_wait_worker,
        args=(jobs.path, policy_path, job_id, ready, effects))
    try:
        with WriterHolds(limits).resource_guard('demo', 'demo.service'):
            process.start()
            assert ready.wait(10)
            policy_path.write_text(policy.model_copy(update={'repair_profiles':()}).model_dump_json())
        process.join(10)
        assert process.exitcode == 0
        assert jobs.get(job_id).state == 'unknown'
        assert json.loads(effects.read_text()) == []
    finally:
        if process.is_alive():
            process.terminate()
        process.join(10)

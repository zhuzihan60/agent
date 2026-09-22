"""Actual graph -> tickets -> PluginHost -> transport -> signed target path.

Only the network runner and systemd effect/worker are fixtures.
"""
import json
import os
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.plugin_api.protocol import PluginHost, RpcRequest
from a4diag.plugin_api.target_protocol import SignedTargetRequest, TargetSigner, TargetVerifier
from a4diag.plugin_api.ticket import TicketVerifier
from a4diag.plugin_ports import _RpcExecutorPort
from a4diag.repair_store import RepairStore
from a4diag.workflow import build_graph, run_event
from a4diag_target.executor import TargetExecutor
from a4diag_target.policy import TargetPolicy
from a4diag_target.repair_jobs import JobStore, process_identity
from a4diag_builtin_plugins.transport_common import build_transport_bindings, RunOutcome, identity_fingerprint
from contract.test_transport_plugins import FakeIdentity, local_transport, ReplayStore as TicketReplay
from tests.target_runtime.test_repair_protocol import RecordingServicesAdapter, ReplayStore
from test_workflow_v3 import deps_factory, TICKET_KEY
from test_repair_workflow import repair_deps, event


def wire(deps, tmp_path):
    identity = FakeIdentity()
    fingerprint = identity_fingerprint(identity.target_identity())
    deps.plugins.collector.fingerprint = fingerprint
    deps.plugins.model.plan_result = deps.plugins.model.plan_result.model_copy(update={'target_fingerprint': fingerprint})
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    from a4diag.plugin_api.target_protocol import _public_fingerprint
    target_policy = [TargetPolicy(target_id='target-1', target_fingerprint=fingerprint,
        controller_key_fingerprint=_public_fingerprint(key.public_key()),
        repair_profiles=deps.settings.targets[0].repair_profiles)]
    adapter = RecordingServicesAdapter()
    target = TargetExecutor(verifier=TargetVerifier(key.public_key(), replay_store=ReplayStore(), clock=deps.clock),
        policy=lambda: target_policy[0], identity_probe=lambda: fingerprint, adapter=adapter)
    jobs = JobStore(tmp_path/'target-jobs.db')
    launches = []
    class Launcher:
        def __call__(self, job_id):
            launches.append(job_id)
        def worker_identity(self, job_id):
            return (os.getpid(), *process_identity(os.getpid()))
    target.configure_jobs(jobs, RepairStore(jobs.path), Launcher())
    requests = []
    class Runner:
        async def run(self, argv, *, payload, output_limit_bytes):
            envelope = SignedTargetRequest.model_validate_json(payload)
            requests.append(json.loads(envelope.payload))
            try:
                result = await target.execute(envelope)
            except Exception as error:
                print('target rejection', str(error))
                raise
            return RunOutcome(started=True, timed_out=False, returncode=0, stdout=json.dumps(result))
    host = PluginHost(build_transport_bindings(local_transport(identity=identity, runner=Runner())),
        ticket_verifier=TicketVerifier(TICKET_KEY, TicketReplay(), clock=deps.clock))
    class Client:
        async def call(self, method, params, *, ticket=None):
            result = await host.dispatch(RpcRequest(jsonrpc='2.0', api_version='1.0', id='rpc',
                method=method, params=params, ticket=ticket))
            if result.error:
                print(result.error)
                raise ValueError(result.error)
            return result.result
    port = _RpcExecutorPort({'target-1': Client()}, signer_resolver=lambda t: signer, clock=deps.clock)
    deps = replace(deps, plugins=replace(deps.plugins, executor=port))
    return deps, jobs, launches, requests, target_policy, host


@pytest.mark.parametrize('recreated', [False, True])
def test_held_stop_historical_claim_observes_own_job_and_read_context(deps_factory, tmp_path, recreated):
    from a4diag.plugin_api.ticket import OperationPhase, OperationTicketRequestV11, effect_payload_digest
    from a4diag.policy_engine import issue_repair_policy_authorization, bind_repair_preconditions
    from a4diag.runtime import RuntimeFailure
    from tests.target_runtime.test_preparation_dependency import dependency
    from tests.test_repair_authorization import _operation
    from test_workflow_v3 import POLICY_KEY
    deps = repair_deps(deps_factory, tmp_path)
    target = deps.settings.targets[0]
    profile = target.repair_profiles[0].model_copy(update={'actions':('stop',)})
    target = target.model_copy(update={'repair_profiles':(profile,)})
    settings = deps.settings.model_copy(update={'targets':(target,)})
    deps = replace(deps, settings=settings, policy=deps.policy.with_settings(settings))
    deps, jobs, launches, requests, policies, host = wire(deps, tmp_path)
    port = deps.plugins.executor
    port.bind_transaction('repair-1')
    operation = _operation(action='stop')
    dep = dependency(profile, operation)
    def ticket(phase, marker=None):
        auth = issue_repair_policy_authorization(profile, operation,
            target_fingerprint=policies[0].target_fingerprint, plan_digest='d'*64,
            authorization_kind='standing', authorization_id=profile.id, now=100, key=POLICY_KEY)
        if marker is not None:
            auth = bind_repair_preconditions(auth, marker, key=POLICY_KEY)
        return deps.tickets.issue(OperationTicketRequestV11(transaction_id='repair-1', step_id='0',
            target_id=target.id, target_fingerprint=policies[0].target_fingerprint,
            operation=operation, phase=phase, plan_digest='d'*64, binding=auth.binding,
            authorization_kind='standing', authorization_id=profile.id, preparation_dependency=dep,
            effect_payload_digest=effect_payload_digest({} if marker is None else {'marker':marker})), auth)
    prepared = port.prepare(target, '0', operation, ticket(OperationPhase.PREPARE))
    apply_ticket = ticket(OperationPhase.APPLY, prepared.marker)
    response = port.apply(target, '0', operation, prepared.marker, apply_ticket)
    claim = deps.tickets.inspect_for_recovery(apply_ticket)
    before = claim.model_dump_json()
    assert claim.preparation_dependency.stop_job_id is None
    jobs.complete(response.job.id, state='succeeded', changed=True, result={'ok':True}, now=101)
    if recreated:
        port = _RpcExecutorPort(port.clients, signer_resolver=port.signer_resolver, clock=deps.clock)
        port.bind_transaction('repair-1')
    else:
        # Normal APPLY response is sufficient to bind immediate VERIFY.
        assert port.verify(target, '0', operation, prepared.marker).status == 'state_mismatch'
    deps.clock.value = 150  # original APPLY HMAC is expired; observation is read-only
    observed = port.query_job(target, '0', operation, response.job.id, claim)
    assert observed.job.id == response.job.id
    assert requests[-1]['preparation_dependency']['stop_job_id'] == response.job.id
    assert claim.model_dump_json() == before
    foreign_request = jobs.request(response.job.id).model_copy(update={
        'transaction_id':'foreign-transaction', 'nonce':'foreign-original-stop'})
    foreign = jobs.ensure(foreign_request.transaction_id, '0', response.job.operation_digest,
        profile_digest=response.job.profile_digest)
    envelope = port.signer_resolver(target).sign(foreign_request)
    jobs.bind_request(foreign.id, foreign_request, envelope=envelope,
        controller_key_fingerprint=envelope.key_fingerprint)
    with pytest.raises(RuntimeFailure):
        port.query_job(target, '0', operation, foreign.id, claim)
    assert port.verify(target, '0', operation, prepared.marker).status == 'state_mismatch'
    assert port.reconcile(target, '0', operation, 'apply', 'dispatch', prepared.marker).outcome == 'not_applied'
    assert all(r['preparation_dependency']['stop_job_id'] == response.job.id for r in requests
               if r['lifecycle'] in ('verify','reconcile'))
    assert len(launches) == 1


@pytest.mark.parametrize('revoked', [False, True])
def test_pending_job_signed_observation_never_undoes_or_reapplies(deps_factory, tmp_path, revoked):
    deps = repair_deps(deps_factory, tmp_path)
    current = [deps.settings]
    deps = replace(deps, settings_loader=lambda: current[0])
    deps, jobs, launches, requests, policy, host = wire(deps, tmp_path)
    graph = build_graph(deps)
    first = run_event(graph, event())
    assert first['status'] == 'execution_unknown'
    saved = deps.transactions.repair_jobs('repair-1')
    assert len(saved) == 1 and saved[0].state == 'running', (first.get('error'), requests)
    if revoked:
        current[0] = current[0].model_copy(update={'global_mode': 'read_only', 'targets': (
            current[0].targets[0].model_copy(update={'repair_profiles': (), 'write_enabled': False}),)})
        policy[0] = policy[0].model_copy(update={'repair_profiles': ()})
    # Original APPLY ticket expired; fresh signed observation remains usable.
    deps.clock.value = 150
    second = run_event(graph, {'resume': True, 'transaction_id': 'repair-1'})
    assert second['status'] == 'execution_unknown'
    assert requests[-1]['lifecycle'] == 'query_job'
    assert requests[-1]['issued_at'] == 150
    assert requests[-1]['job_id'] == saved[0].id
    assert len(launches) == 1
    assert [r['lifecycle'] for r in requests].count('apply') == 1
    assert not any(r['lifecycle'] == 'undo' for r in requests)
    jobs.complete(saved[0].id, state='succeeded', changed=True, result={'ok': True}, now=151)
    deps.clock.value = 151
    third = run_event(graph, {'resume': True, 'transaction_id': 'repair-1'})
    assert third['status'] == ('execution_unknown' if revoked else 'succeeded')
    assert deps.transactions.repair_jobs('repair-1')[0].state == 'succeeded'
    assert len(launches) == 1


def test_job_transport_methods_registered_with_fixed_security_kinds(deps_factory, tmp_path):
    from a4diag.plugin_api.protocol import MethodKind
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    assert host.methods['query_job_typed'].kind is MethodKind.RECONCILE
    assert host.methods['confirm_job_typed'].kind.is_effect
    from a4diag.plugin_api.manifest import PluginManifest
    from pathlib import Path
    for name in ('local', 'ssh'):
        manifest = PluginManifest.model_validate_json(Path(
            f'packages/a4diag-builtin-plugins/manifests/transport-{name}.json').read_bytes())
        assert set(manifest.rpc_methods) == set(host.methods)


def test_readonly_query_method_cannot_relay_apply_or_confirm(deps_factory, tmp_path):
    import asyncio
    from a4diag.plugin_api.target_protocol import TargetRequestV11
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    run_event(build_graph(deps), event())
    apply = next(r for r in requests if r['lifecycle'] == 'apply')
    target = deps.settings.targets[0]
    signer = deps.plugins.executor.signer_resolver(target)
    for lifecycle in ('apply', 'confirm_job'):
        raw = {**apply, 'lifecycle': lifecycle, 'nonce': 'fresh-forged-query-' + lifecycle}
        if lifecycle == 'confirm_job':
            raw.update(job_id=launches[0], marker=None)
        envelope = signer.sign(TargetRequestV11.model_validate(raw))
        result = asyncio.run(host.dispatch(RpcRequest(jsonrpc='2.0', api_version='1.0', id='query',
            method='query_job_typed', params={'transaction_id': 'repair-1', 'step_id': '0',
                'operation': apply['operation'], 'job_id': launches[0], 'envelope': envelope.model_dump(mode='json')})))
        assert result.result['ok'] is False
    assert len(launches) == 1
    assert not any(r['lifecycle'] == 'confirm_job' for r in requests)


@pytest.mark.parametrize('cancelled', [False, True])
def test_lost_apply_response_does_not_use_legacy_reconciliation(deps_factory, tmp_path, cancelled):
    import asyncio
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    original = deps.plugins.executor.apply
    from unittest.mock import patch
    def lost(*args):
        original(*args)
        if cancelled:
            raise asyncio.CancelledError()
        raise TimeoutError('lost-response')
    graph = build_graph(deps)
    with patch.object(type(deps.plugins.executor), 'apply', lambda self, *args: lost(*args)):
        if cancelled:
            from langgraph.errors import NodeCancelledError
            with pytest.raises(NodeCancelledError):
                run_event(graph, event())
        else:
            assert run_event(graph, event())['status'] == 'execution_unknown'
    second = run_event(graph, {'resume': True, 'transaction_id': 'repair-1'})
    assert second['status'] == 'execution_unknown'
    assert len(launches) == 1
    assert [r['lifecycle'] for r in requests] == ['prepare', 'apply']


@pytest.mark.parametrize('revoked', [False, True])
def test_confirm_terminal_job_is_live_authorized_and_not_recovery(deps_factory, tmp_path, revoked):
    from a4diag.repair_workflow import confirm_job, observe_job
    deps = repair_deps(deps_factory, tmp_path)
    current = [deps.settings]
    deps = replace(deps, settings_loader=lambda: current[0])
    deps, jobs, launches, requests, policy, host = wire(deps, tmp_path)
    graph = build_graph(deps)
    state = run_event(graph, event())
    with pytest.raises(PermissionError, match='job_not_terminal'):
        confirm_job(deps, state, current[0].targets[0], '0', now=100)
    job = deps.transactions.repair_jobs('repair-1')[0]
    jobs.complete(job.id, state='partial', changed=True, result={'ok': False}, now=100)
    observe_job(deps, state, current[0].targets[0], '0', now=100)
    if revoked:
        current[0] = current[0].model_copy(update={'targets': (
            current[0].targets[0].model_copy(update={'repair_profiles': ()}),)})
        with pytest.raises(ValueError, match='profile_not_registered'):
            confirm_job(deps, state, current[0].targets[0], '0', now=100)
        assert requests[-1]['lifecycle'] == 'query_job'
    else:
        confirmed = confirm_job(deps, state, current[0].targets[0], '0', now=100)
        assert confirmed.state == 'partial'
        assert requests[-1]['lifecycle'] == 'confirm_job'
        assert state['status'] == 'execution_unknown'


def test_controller_resource_reservation_survives_unknown_job(deps_factory, tmp_path):
    from a4diag.repair_store import RepairLimitError
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    run_event(build_graph(deps), event())
    store = RepairStore(deps.transactions.path)
    with pytest.raises(RepairLimitError, match='resource_busy'):
        store.reserve('target-1', 'demo.service', 'other', 9999, 600, 2)

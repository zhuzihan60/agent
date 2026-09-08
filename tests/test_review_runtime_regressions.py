from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.approval_cli import ApprovalCli, Authorizer
from a4diag.domain import Plan, Risk, StepResult, canonical_json_bytes, plan_digest
from a4diag.plugin_api.target_protocol import TargetRequest, TargetSigner
from a4diag.plugin_api.ticket import OperationPhase, TicketError
from a4diag.plugin_ports import _RpcExecutorPort, _RpcModelPort
from a4diag.runtime import Runtime, RuntimePlanSource
from a4diag.workflow import build_graph, run_event
from test_workflow_v3 import SimulatedCrash, deps_factory, event_for, make_plan, resume_for
from test_plugin_ports_remote import RecordingTransport, operation, target


def runtime_for(deps, graph):
    runtime = object.__new__(Runtime)
    runtime._deps = deps
    runtime._graph = graph
    return runtime


def test_cli_can_show_and_approve_a_pending_checkpoint_before_prepare(deps_factory):
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)
    state = run_event(graph, event_for())
    assert state['status'] == 'pending_approval'
    assert deps.transactions.incomplete_transaction_ids() == ()
    cli = ApprovalCli(
        approvals=deps.approvals, plans=RuntimePlanSource(runtime_for(deps, graph)),
        notifier=SimpleNamespace(send=lambda event: None),
        identity=SimpleNamespace(probe_fingerprint=lambda target_id: 'machine-1'),
        authorizer=Authorizer(is_admin=True), clock=deps.clock,
        stdin_isatty=lambda: True, signing_key=b'c' * 32,
    )
    assert cli.show('event-1').plan.plan_digest == state['digest']
    receipt = cli.approve('event-1', state['digest'])
    assert receipt.status == 'approved'
    assert run_event(graph, resume_for('event-1'))['status'] == 'succeeded'


def test_pending_plan_source_rejects_checkpoint_content_with_stale_digest(deps_factory):
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)
    run_event(graph, event_for())
    graph.update_state({'configurable': {'thread_id': 'event-1'}},
                       {'plan': make_plan(count=2, risk=Risk.HIGH).model_dump(mode='json')})
    assert RuntimePlanSource(runtime_for(deps, graph)).plan_for('event-1') is None


def test_request_context_reaches_real_model_port_and_is_redacted(deps_factory):
    deps = deps_factory()
    calls = []
    class Client:
        async def call(self, method, params):
            calls.append((method, params))
            return {'cause': 'disk full'}
    deps.plugins.model.diagnose = _RpcModelPort(Client()).diagnose
    request = {'alertname': 'DiskFull', 'labels': {'mountpoint': '/data'},
               'annotations': {'summary': 'Disk /data is full'}, 'api_key': 'never-send-me'}
    state = run_event(build_graph(deps), {**event_for(), 'request': request})
    observations = calls[0][1]['evidence']['observations']
    assert {'kind': 'request', 'content': {**request, 'api_key': '[REDACTED]'}} in observations
    assert 'never-send-me' not in json.dumps(state)


def test_resume_rehydrates_authenticated_dispatches_into_fresh_executor(deps_factory):
    deps = deps_factory()
    deps.plugins.executor.apply_error = TimeoutError()
    graph = build_graph(deps)
    assert run_event(graph, event_for())['status'] == 'execution_unknown'
    calls = []
    class FreshExecutor(type(deps.plugins.executor)):
        def restore_read_context(self, selected, plan, claims):
            calls.extend(claims)
            assert selected.id == plan.target_id == 'target-1'
        def reconcile(self, *args):
            assert calls, 'restore must precede reconcile'
            return super().reconcile(*args)
    executor = FreshExecutor()
    executor.reconcile_result = 'applied'
    resumed_deps = replace(deps, plugins=replace(deps.plugins, executor=executor))
    deps.clock.value += 100  # Old effect tickets have expired; observation is still safe.
    result = run_event(build_graph(resumed_deps), resume_for('event-1'))
    assert result['status'] == 'succeeded'
    assert len(calls) == 2
    assert executor.apply_count == 0


def test_rpc_restored_context_only_enables_bound_reads():
    from test_operation_ticket import make_issuer, make_request, authorization_for
    transport = RecordingTransport()
    signer = TargetSigner(Ed25519PrivateKey.generate())
    port = _RpcExecutorPort({'lab': transport}, signer_resolver=lambda _: signer,
                            clock=lambda: 200, nonce_factory=lambda: 'nonce-00000000001')
    port.bind_transaction('tx-1')
    op = operation()
    plan = Plan(target_id='lab', target_fingerprint='sha256:' + 'a' * 64, operations=(op,))
    request = make_request(step_id='0', operation=op, target_fingerprint=plan.target_fingerprint,
                           plan_digest=plan_digest(plan))
    issuer = make_issuer()
    token = issuer.issue(request, authorization_for(request))
    claims = issuer.inspect_for_recovery(token)
    port.restore_read_context(target(), plan, (claims,))
    assert port.reconcile(target(), '0', op, OperationPhase.APPLY, 'dispatch-1', {}).outcome == 'applied'
    envelope = transport.calls[-1][1]['envelope']
    signed = TargetRequest.model_validate_json(envelope['payload'])
    assert signed.plan_digest == plan_digest(plan)
    assert signed.issued_at == 200
    assert [call[0] for call in transport.calls] == ['reconcile_typed']
    with pytest.raises(Exception, match='context_mismatch'):
        port.verify(target(), '0', op.model_copy(update={'resource': '/srv/other'}), {})


def test_recovery_inspection_rejects_forged_ticket_but_does_not_renew_it():
    from test_operation_ticket import make_issuer, make_request, authorization_for, expectation_for, MemoryReplayStore
    from a4diag.plugin_api.ticket import TicketVerifier
    issuer = make_issuer()
    request = make_request()
    token = issuer.issue(request, authorization_for(request))
    assert issuer.inspect_for_recovery(token).expires_at == 130
    with pytest.raises(TicketError, match='expired'):
        TicketVerifier(b'k' * 32, MemoryReplayStore(), clock=lambda: 200).verify(token, expectation_for(request))
    payload, signature = token.split('.')
    signature = ('A' if signature[0] != 'A' else 'B') + signature[1:]
    with pytest.raises(TicketError, match='invalid_signature'):
        issuer.inspect_for_recovery(payload + '.' + signature)


@pytest.mark.parametrize('restored, reason, status', [
    (True, None, 'restored'),
    (False, 'state_mismatch', 'state_mismatch'),
    (False, 'state_unavailable', 'unknown'),
])
def test_rpc_restoration_verification_is_a_signed_target_read(restored, reason, status):
    from test_plugin_ports_remote import ticket
    class Transport(RecordingTransport):
        async def call(self, method, params, *, ticket=None):
            if method == 'verify_typed':
                self.calls.append((method, params, ticket))
                request = TargetRequest.model_validate_json(params['envelope']['payload'])
                assert request.verify_restored is True
                return {'ok': True, 'data': {'result': {'ok': restored, 'reason': reason}}}
            return await super().call(method, params, ticket=ticket)
    transport = Transport()
    port = _RpcExecutorPort({'lab': transport}, signer_resolver=lambda _: TargetSigner(Ed25519PrivateKey.generate()),
                            clock=lambda: 100, nonce_factory=lambda: 'nonce-00000000001')
    port.bind_transaction('tx-1')
    op, marker = operation(), {'before_sha256': 'b' * 64}
    port.undo(target(), '0', op, marker, op.undo,
              ticket(op, phase=OperationPhase.UNDO, effect={'marker': marker, 'undo': op.undo}))
    with pytest.raises(Exception, match='restoration_marker_mismatch'):
        port.verify_restored(target(), '0', op, marker, {'before_sha256': 'c' * 64})
    assert [call[0] for call in transport.calls] == ['undo_typed']
    result = port.verify_restored(target(), '0', op, marker, marker)
    assert result.ok is restored
    assert result.status == status
    assert [call[0] for call in transport.calls] == ['undo_typed', 'verify_typed']


@pytest.mark.parametrize('phase', ['apply', 'undo'])
@pytest.mark.parametrize('corruption', ['marker', 'operation'])
def test_recovery_rejects_durable_payload_changed_after_ticket_issuance(
    deps_factory, phase, corruption,
):
    deps = deps_factory()
    executor = deps.plugins.executor
    if phase == 'apply':
        executor.apply_error = TimeoutError()
        assert run_event(build_graph(deps), event_for())['status'] == 'execution_unknown'
    else:
        executor.verify_fail_step = '0'
        executor.undo_crash_step = '0'
        with pytest.raises(SimulatedCrash):
            run_event(build_graph(deps), event_for())

    with sqlite3.connect(deps.transactions._path) as connection:
        if corruption == 'marker':
            forged = canonical_json_bytes({'marker': 'forged-current-state'}).decode()
            connection.execute(
                'UPDATE plugin_markers SET marker_json = ? WHERE transaction_id = ?',
                (forged, 'event-1'),
            )
            connection.execute(
                'UPDATE transaction_steps SET pre_state_json = ? WHERE transaction_id = ?',
                (forged, 'event-1'),
            )
        else:
            forged = make_plan().operations[0].model_copy(update={'undo': {'restore_backup': False}})
            connection.execute(
                'UPDATE transaction_steps SET operation_json = ? WHERE transaction_id = ?',
                (canonical_json_bytes(forged.model_dump(mode='json')).decode(), 'event-1'),
            )

    restored_claims = []
    class FreshExecutor(type(executor)):
        def restore_read_context(self, selected, plan, claims):
            restored_claims.extend(claims)
    fresh = FreshExecutor()
    fresh.reconcile_result = 'applied' if phase == 'apply' else 'not_applied'
    resumed_deps = replace(deps, plugins=replace(deps.plugins, executor=fresh))
    resumed = run_event(build_graph(resumed_deps), resume_for('event-1'))

    assert resumed['status'] == 'execution_unknown'
    assert resumed['error'] == 'invalid_recovery_context'
    assert restored_claims == []
    assert fresh.calls == []


@pytest.mark.parametrize('forward_state', ['applied', 'not_applied', 'unknown'])
@pytest.mark.parametrize('proof', ['restored', 'mismatch', 'unavailable'])
def test_uncertain_noop_undo_requires_restoration_proof_without_replaying_write(
    deps_factory, forward_state, proof,
):
    deps = deps_factory()
    executor = deps.plugins.executor
    executor.verify_fail_step = '0'
    executor.undo_crash_step = '0'
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    # An unchanged file satisfies both pre/post state. Forward reconciliation
    # alone cannot distinguish whether the undo restored the original state.
    executor.reconcile_result = forward_state
    if proof == 'unavailable':
        def unavailable(*args):
            executor.calls.append('verify_restored:0')
            raise TimeoutError()
        executor.verify_restored = unavailable
    else:
        executor.restore_result = StepResult(
            ok=proof == 'restored', status='restored' if proof == 'restored' else 'mismatch',
        )
    resumed = run_event(build_graph(deps), resume_for('event-1'))

    assert resumed['status'] == ('rollback_succeeded' if proof == 'restored' else 'rollback_unknown')
    assert executor.calls.count('undo:0') == 1
    assert executor.calls.count('verify_restored:0') == 1

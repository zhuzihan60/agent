from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from a4diag.domain import CapabilityGrant, Plan, Risk, StepResult
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.policy_engine import PolicyEngine
from a4diag.recovery import RecoveryCheck
from a4diag.workflow import build_graph, run_event
from test_workflow_v3 import deps_factory, POLICY_KEY
from test_repair_authorization import _profile, _operation


def repair_deps(deps_factory, tmp_path, *, standing=True, effect_kind=None):
    deps = deps_factory()
    manifest = json.loads(Path('packages/a4diag-builtin-plugins/manifests/capability-services.json').read_text())
    if effect_kind is not None:
        for contract in manifest['operations']:
            contract['effect_kind'] = effect_kind
    root = tmp_path / 'services-registry'
    root.mkdir()
    content = json.dumps(manifest).encode()
    (root / 'capability-services.json').write_bytes(content)
    (root / 'plugin.whl').write_bytes(b'pinned-fixture')
    registry = PluginRegistry.load((PluginPin(name='capability-services', version='1.1.0', api_version='1.0',
        artifact_path='plugin.whl', artifact_sha256=hashlib.sha256(b'pinned-fixture').hexdigest(),
        manifest_sha256=hashlib.sha256(content).hexdigest(), enabled=True),), root, core_api='1.0')
    profile = _profile(target_id='target-1', standing_authorization=standing)
    target = deps.settings.targets[0].model_copy(update={
        'repair_profiles': (profile,),
        'recovery_checks': (RecoveryCheck(id='health', kind='service_active', resource='demo.service'),),
        'capabilities': (CapabilityGrant(name='services', actions=('restart', 'start'), resources=('demo.service',)),),
    })
    settings = deps.settings.model_copy(update={'targets': (target,)})
    deps.plugins.model.plan_result = Plan(target_id=target.id, target_fingerprint='machine-1', operations=(_operation(),))
    return replace(deps, settings=settings, registry=registry,
                   service_observer=lambda *args: ('ready' if args[-1]=='preflight' else 'legacy', {'unit_fixture':'authorization and transport only'}),
                   policy=PolicyEngine(settings, registry, authorization_key=POLICY_KEY))


def event():
    return {'event_id': 'repair-1', 'target_id': 'target-1'}


def test_standing_workflow_issues_bound_high_v11_tickets(deps_factory, tmp_path):
    deps = repair_deps(deps_factory, tmp_path)
    # Effect fixture only: exercise graph, policy, durable dispatch and ticket issuance.
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'succeeded'
    claims = [deps.tickets.inspect_for_recovery(d.ticket) for d in deps.transactions.get_dispatches('repair-1')]
    assert all(c.protocol_version == '1.1' and c.risk is Risk.HIGH for c in claims)
    by_phase = {c.phase.value: c for c in claims}
    assert by_phase['prepare'].binding.preconditions_digest is None
    assert by_phase['apply'].binding.preconditions_digest is not None
    assert deps.approvals.for_transaction('repair-1') is None


@pytest.mark.parametrize('change', ['revoked', 'expired', 'readonly', 'observe', 'identity', 'grant', 'digest', 'invalid_config'])
def test_mutation_rechecks_current_config_after_prepare(deps_factory, tmp_path, change):
    deps = repair_deps(deps_factory, tmp_path)
    current = [deps.settings]
    original = deps.plugins.executor.prepare
    def prepare(*args):
        prepared = original(*args)
        target = current[0].targets[0]
        if change == 'revoked':
            target = target.model_copy(update={'repair_profiles': ()})
        elif change == 'expired':
            deps.clock.value = 200
        elif change == 'observe':
            target = target.model_copy(update={'write_enabled': False})
        elif change == 'identity':
            target = target.model_copy(update={'identity_ref': 'target/changed'})
        elif change == 'grant':
            target = target.model_copy(update={'capabilities': ()})
        elif change == 'digest':
            target = target.model_copy(update={'repair_profiles': (target.repair_profiles[0].model_copy(update={'expires_at': 201}),)})
        current[0] = current[0].model_copy(update={'targets': (target,),
            **({'global_mode': 'read_only'} if change == 'readonly' else {})})
        return prepared
    deps.plugins.executor.prepare = prepare
    def loader():
        if change == 'invalid_config' and 'prepare' in deps.plugins.executor.calls:
            raise ValueError('invalid_configuration')
        return current[0]
    deps = replace(deps, settings_loader=loader)
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'execution_unknown'
    assert 'apply' not in deps.plugins.executor.calls


def test_one_shot_requires_real_approval_not_event_claim(deps_factory, tmp_path):
    deps = repair_deps(deps_factory, tmp_path, standing=False)
    graph = build_graph(deps)
    result = run_event(graph, {**event(), 'approval_id': 'made-up'})
    assert result['status'] == 'pending_approval'
    assert not deps.plugins.executor.calls
    approval = deps.approvals.for_transaction('repair-1')
    deps.approvals.approve(approval.id, actor='local:operator', approved_digest=approval.plan_digest, now=100)
    result = run_event(graph, {'resume': True, 'transaction_id': 'repair-1'})
    assert result['status'] == 'succeeded'
    claim = deps.tickets.inspect_for_recovery(deps.transactions.get_dispatches('repair-1')[0].ticket)
    assert claim.authorization_kind == 'one_shot' and claim.authorization_id == approval.id


@pytest.mark.parametrize('change', ['revoked', 'readonly'])
def test_mixed_repair_plan_revalidates_profiles_before_legacy_mutation(deps_factory, tmp_path, change):
    deps = repair_deps(deps_factory, tmp_path)
    target = deps.settings.targets[0]
    target = target.model_copy(update={'capabilities': (
        target.capabilities[0].model_copy(update={'resources': ('demo.service', 'other.service')}),)})
    settings = deps.settings.model_copy(update={'targets': (target,)})
    current = [settings]
    deps = replace(deps, settings=settings, settings_loader=lambda: current[0],
        policy=PolicyEngine(settings, deps.registry, authorization_key=POLICY_KEY))
    plan = deps.plugins.model.plan_result
    deps.plugins.model.plan_result = plan.model_copy(update={'operations': (
        plan.operations[0], plan.operations[0].model_copy(update={'resource': 'other.service',
            'parameters': {'unit': 'other.service'}, 'verify': {'active': True}}))})
    original = deps.plugins.executor.prepare
    def prepare(*args):
        prepared = original(*args)
        current[0] = settings.model_copy(update={'global_mode': 'read_only'} if change == 'readonly'
            else {'targets': (target.model_copy(update={'repair_profiles': ()}),)})
        return prepared
    deps.plugins.executor.prepare = prepare
    graph = build_graph(deps)
    assert run_event(graph, event())['status'] == 'pending_approval'
    approval = deps.approvals.for_transaction('repair-1')
    deps.approvals.approve(approval.id, actor='local:operator', approved_digest=approval.plan_digest, now=100)
    assert run_event(graph, {'resume': True, 'transaction_id': 'repair-1'})['status'] == 'execution_unknown'
    assert deps.plugins.executor.calls.count('prepare') == 1


@pytest.mark.parametrize('kind', ['irreversible', 'compensatable'])
def test_workflow_never_reports_compensation_as_full_restoration(deps_factory, tmp_path, kind):
    deps = repair_deps(deps_factory, tmp_path, effect_kind=kind)
    deps.plugins.collector.final_result = StepResult(ok=False, status='unhealthy')
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'rollback_partial'
    if kind == 'irreversible':
        assert 'undo:0' not in deps.plugins.executor.calls


def test_profile_scope_cannot_fall_back_to_legacy(deps_factory, tmp_path):
    deps = repair_deps(deps_factory, tmp_path)
    deps.plugins.model.plan_result = deps.plugins.model.plan_result.model_copy(update={
        'operations': (_operation(action='start'),)})
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'policy_denied'
    assert not deps.plugins.executor.calls


def test_ambiguous_profiles_require_explicit_registered_candidate(deps_factory, tmp_path):
    from a4diag.repair_workflow import resolve_repair_profile
    deps = repair_deps(deps_factory, tmp_path)
    target = deps.settings.targets[0]
    target = target.model_copy(update={'repair_profiles': (*target.repair_profiles,
        target.repair_profiles[0].model_copy(update={'id': 'second'}))})
    with pytest.raises(ValueError, match='ambiguous'):
        resolve_repair_profile(target, _operation(), now=100)
    assert resolve_repair_profile(target, _operation(), now=100, candidate_id='second').id == 'second'


def test_production_service_manifest_reports_compensation_not_memory_restoration(deps_factory, tmp_path):
    from a4diag.report import build_runtime_report
    deps = repair_deps(deps_factory, tmp_path)
    deps.plugins.collector.final_result = StepResult(ok=False, status='unhealthy')
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'rollback_partial'
    report = build_runtime_report(result, deps)
    assert report['effects']['0'] == {'kind': 'compensatable', 'changed': True, 'restoration_verified': False}


def test_no_change_irreversible_step_needs_no_undo(deps_factory, tmp_path):
    deps = repair_deps(deps_factory, tmp_path, effect_kind='irreversible')
    deps.plugins.executor.apply_result = StepResult(ok=True, status='no_change', data={'changed': False})
    deps.plugins.collector.final_result = StepResult(ok=False, status='unhealthy')
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'rollback_succeeded'
    assert not any(call.startswith('undo') for call in deps.plugins.executor.calls)


def test_failed_restoration_is_partial_for_changed_service(deps_factory, tmp_path):
    deps = repair_deps(deps_factory, tmp_path)
    deps.plugins.collector.final_result = StepResult(ok=False, status='unhealthy')
    deps.plugins.executor.restore_result = StepResult(ok=False, status='different')
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'rollback_partial'
    assert deps.transactions.repair_effects('repair-1')['0'].restoration_verified is False


def test_audit_failure_preserves_partial_effect_report_and_blocks_next_write(deps_factory, tmp_path):
    from a4diag.audit import AuditWriter, AuditError
    from a4diag.runtime import Runtime
    deps = repair_deps(deps_factory, tmp_path)
    deps.plugins.collector.final_result = StepResult(ok=False, status='unhealthy')
    class FailedFinishAudit(AuditWriter):
        def append(self, entry):
            if entry.get('event') == 'runtime_finished':
                raise AuditError('disk_failed')
            return super().append(entry)
    audit = FailedFinishAudit(tmp_path/'audit.jsonl')
    runtime = Runtime(settings=deps.settings, registry=deps.registry, policy=deps.policy,
        approvals=deps.approvals, transactions=deps.transactions, tickets=deps.tickets,
        checkpointer=deps.checkpointer, plugins=deps.plugins, audit=audit, clock=deps.clock, service_observer=deps.service_observer)
    result = runtime.handle(event())
    assert result.status == 'rollback_partial'
    assert result.report['effects']['0']['kind'] == 'compensatable'
    before = list(deps.plugins.executor.calls)
    assert runtime.handle({**event(), 'event_id': 'other'}).status == 'read_only'
    assert deps.plugins.executor.calls == before


def test_mixed_plan_partial_apply_only_undoes_restorable_steps(deps_factory, tmp_path):
    from test_workflow_v3 import make_plan
    deps = deps_factory()
    root = tmp_path/'registry-0'
    path = root/'capability-files.json'
    manifest = json.loads(path.read_text())
    manifest['operations'].append({**manifest['operations'][0], 'name': 'files.append',
        'reversible': False, 'effect_kind': 'irreversible', 'supports_undo': False})
    content = json.dumps(manifest).encode()
    path.write_bytes(content)
    registry = PluginRegistry.load((replace(deps.registry.pins[0], manifest_sha256=hashlib.sha256(content).hexdigest()),), root, core_api='1.0')
    target = deps.settings.targets[0]
    grant = target.capabilities[0].model_copy(update={'actions': ('replace', 'append')})
    target = target.model_copy(update={'capabilities': (grant,)})
    settings = deps.settings.model_copy(update={'targets': (target,)})
    deps = replace(deps, settings=settings, registry=registry,
        policy=PolicyEngine(settings, registry, authorization_key=POLICY_KEY))
    plan = make_plan(count=2, risk=Risk.HIGH)
    deps.plugins.model.plan_result = plan.model_copy(update={'operations': (
        plan.operations[0], plan.operations[1].model_copy(update={'action': 'append'}))})
    original = deps.plugins.executor.apply
    def apply(target, step_id, *args):
        result = original(target, step_id, *args)
        return result if step_id == '0' else StepResult(ok=False, status='partial', data={'changed': True})
    deps.plugins.executor.apply = apply
    graph = build_graph(deps)
    run_event(graph, event())
    approval = deps.approvals.for_transaction('repair-1')
    deps.approvals.approve(approval.id, actor='local:operator', approved_digest=approval.plan_digest, now=100)
    result = run_event(graph, {'resume': True, 'transaction_id': 'repair-1'})
    assert result['status'] == 'rollback_partial'
    assert [c for c in deps.plugins.executor.calls if c.startswith('undo:')] == ['undo:0']

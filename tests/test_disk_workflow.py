"""Compiled disk plan reaches the production graph and registered contracts."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import pytest

from a4diag.domain import CapabilityGrant, Operation, Plan, Risk
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.repair_profiles import RepairProfile
from a4diag.workflow import build_graph, run_event
from test_workflow_v3 import deps_factory
from test_repair_workflow import repair_deps, event


def disk_profile(root='/var/cache/demo'):
    return RepairProfile.model_validate(dict(id='demo-cache', target_id='target-1',
        capability='disk', resource=root, actions=['cleanup'], constraints={
            'writer_unit':'demo.service', 'min_age_seconds':60, 'max_files':100,
            'max_bytes':1048576, 'min_free_bytes':4096, 'min_free_inodes':10},
        recovery_check_ids=['health'], expires_at=200, standing_authorization=True))


def disk_deps(deps_factory, tmp_path):
    deps = repair_deps(deps_factory, tmp_path)
    profile = disk_profile()
    root = tmp_path/'disk-registry'
    root.mkdir()
    (root/'plugins.whl').write_bytes(b'pinned-fixture')
    pins = []
    for name in ('capability-services', 'capability-disk', 'transport-local'):
        data = Path(f'packages/a4diag-builtin-plugins/manifests/{name}.json').read_bytes()
        (root/f'{name}.json').write_bytes(data)
        pins.append(PluginPin(name=name, version='1.1.0', api_version='1.0',
            artifact_path='plugins.whl', artifact_sha256=hashlib.sha256(b'pinned-fixture').hexdigest(),
            manifest_sha256=hashlib.sha256(data).hexdigest(), enabled=True))
    registry = PluginRegistry.load(tuple(pins), root, core_api='1.0')
    target = deps.settings.targets[0]
    service = target.repair_profiles[0].model_copy(update={'actions':('stop',)})
    target = target.model_copy(update={'repair_profiles':(service, profile), 'capabilities':(
        CapabilityGrant(name='services', actions=('stop',), resources=('demo.service',)),
        CapabilityGrant(name='disk', actions=('cleanup',), resources=(profile.resource,)))})
    settings = deps.settings.model_copy(update={'targets':(target,)})
    operations = (Operation(capability='services', action='stop', resource='demo.service',
        parameters={'unit':'demo.service'}, model_risk=Risk.HIGH,
        verify={'recovery_check_ids':['health']}, undo={'restore_state':True}),
        Operation(capability='disk', action='cleanup', resource=profile.resource,
        parameters={}, model_risk=Risk.HIGH, verify={'recovery_check_ids':['health']}, undo=None))
    deps.plugins.model.plan_result = Plan(target_id=target.id, target_fingerprint='machine-1', operations=operations)
    from a4diag.policy_engine import PolicyEngine
    from test_workflow_v3 import POLICY_KEY
    return replace(deps, settings=settings, registry=registry,
        policy=PolicyEngine(settings, registry, authorization_key=POLICY_KEY))


def test_production_disk_plan_stops_before_preparing_candidates(deps_factory, tmp_path):
    deps = disk_deps(deps_factory, tmp_path)
    calls = []
    executor = deps.plugins.executor
    original_prepare = executor.prepare
    def prepare(target, step, operation, ticket):
        calls.append(('prepare', step))
        if step == '1':
            assert ('apply','0') in calls, 'disk PREPARE ran before stopping writer'
        return original_prepare(target, step, operation, ticket)
    executor.prepare = prepare
    from a4diag.repair_jobs import RepairJob, RepairJobResponse
    def apply(target, step, operation, marker, ticket):
        calls.append(('apply',step))
        claim = deps.tickets.inspect_for_recovery(ticket)
        return RepairJobResponse(job=RepairJob(id=f'job-{step}', transaction_id='repair-1', step_id=step,
            profile_digest=claim.binding.profile_digest, operation_digest=claim.operation_digest,
            state='succeeded', changed=True, started_at=100, finished_at=100))
    executor.apply = apply
    result = run_event(build_graph(deps), event())
    assert result['status'] == 'succeeded', result.get('error')
    assert calls == [('prepare','0'), ('apply','0'), ('prepare','1'), ('apply','1')]
    assert 'undo:0' in executor.calls
    assert 'verify_restored:0' in executor.calls


def test_completed_stop_apply_reconstructed_port_queries_before_verify(deps_factory,tmp_path):
    from test_repair_workflow_transport import wire
    from a4diag.plugin_ports import _RpcExecutorPort
    deps,jobs,launches,requests,policies,host=wire(disk_deps(deps_factory,tmp_path),tmp_path)
    graph=build_graph(deps)
    assert run_event(graph,event())['status']=='execution_unknown'
    job=deps.transactions.repair_jobs('repair-1')[0]
    jobs.complete(job.id,state='succeeded',changed=True,result={'ok':True},now=100)
    port=deps.plugins.executor
    from test_workflow_v3 import SimulatedCrash
    def interrupted(*_):raise SimulatedCrash('interrupted_after_apply_completion')
    class Interrupted:
        def __getattr__(self,name):return getattr(port,name)
        verify=staticmethod(interrupted)
    changed=replace(deps,plugins=replace(deps.plugins,executor=Interrupted()))
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(changed),{'resume':True,'transaction_id':'repair-1'})
    assert [d for d in deps.transactions.get_dispatches('repair-1') if d.phase.value=='apply'][0].status.value=='completed'
    fresh=_RpcExecutorPort(port.clients,signer_resolver=port.signer_resolver,clock=deps.clock)
    changed=replace(deps,plugins=replace(deps.plugins,executor=fresh))
    from test_repair_scheduler import runtime_for
    resumed=runtime_for(changed,tmp_path).resume('repair-1')
    # Fixture service never stopped, so its independent verification fails and
    # authorized compensation completes. No disk deletion is fabricated.
    assert resumed.status=='rollback_partial',resumed.report
    assert [r['lifecycle'] for r in requests].count('apply')==1
    assert [r['lifecycle'] for r in requests].count('query_job')>=2
    assert [r['lifecycle'] for r in requests].count('undo')==1


@pytest.mark.parametrize('boundary',['initial_stop_saved','verifying','rollback_running'])
def test_disk_owned_initial_and_terminal_crash_frontiers(deps_factory,tmp_path,monkeypatch,boundary):
    from a4diag import repair_workflow
    from a4diag.domain import StepResult
    from a4diag.repair_jobs import RepairJob, RepairJobResponse
    from test_repair_scheduler import runtime_for
    from test_workflow_v3 import SimulatedCrash
    deps=disk_deps(deps_factory,tmp_path)
    executor=deps.plugins.executor
    applied=[]
    def apply(target,step,operation,marker,ticket):
        applied.append(step)
        claim=deps.tickets.inspect_for_recovery(ticket)
        return RepairJobResponse(job=RepairJob(id=f'job-{step}',transaction_id='repair-1',step_id=step,
            profile_digest=claim.binding.profile_digest,operation_digest=claim.operation_digest,
            state='succeeded',changed=True,started_at=100,finished_at=100))
    executor.apply=apply
    executor.query_job=lambda target,step,*args:RepairJobResponse(job=next(
        j for j in deps.transactions.repair_jobs('repair-1') if j.step_id==step))
    original_record=repair_workflow.record_job
    original_transition=deps.transactions.transition
    tripped=[]
    def record(*args,**kwargs):
        result=original_record(*args,**kwargs)
        if boundary=='initial_stop_saved' and not tripped:
            tripped.append(True)
            raise SimulatedCrash()
        return result
    def transition(tx,status,**kwargs):
        result=original_transition(tx,status,**kwargs)
        if status.value==boundary and not tripped:
            tripped.append(True)
            raise SimulatedCrash()
        return result
    monkeypatch.setattr(repair_workflow,'record_job',record)
    monkeypatch.setattr(deps.transactions,'transition',transition)
    if boundary=='rollback_running':
        deps.plugins.collector.final_verify=lambda *a:StepResult(ok=False,status='http_failed')
    with pytest.raises(SimulatedCrash):runtime_for(deps,tmp_path).handle(event())
    if boundary=='initial_stop_saved':
        checkpoint=build_graph(deps).get_state({'configurable':{'thread_id':'repair-1'}}).values
        assert checkpoint['status']=='policy_allowed'
        assert deps.transactions.get('repair-1').status.value=='executing'
    resumed=runtime_for(deps,tmp_path).resume('repair-1')
    expected='rollback_partial' if boundary=='rollback_running' else 'succeeded'
    assert resumed.status==expected,resumed.report
    assert applied==['0','1']
    assert executor.calls.count('undo:0')==1
    assert runtime_for(deps,tmp_path).resume('repair-1').status==expected


@pytest.mark.parametrize('denial',['cancel','revoked','expired'])
def test_disk_staged_current_denial_only_observes_and_retains_obligation(deps_factory,tmp_path,denial):
    from test_repair_workflow_transport import wire
    deps=disk_deps(deps_factory,tmp_path)
    current=[deps.settings]
    deps=replace(deps,settings_loader=lambda:current[0])
    deps,jobs,launches,requests,policies,host=wire(deps,tmp_path)
    assert run_event(build_graph(deps),event())['status']=='execution_unknown'
    job=deps.transactions.repair_jobs('repair-1')[0]
    jobs.complete(job.id,state='succeeded',changed=True,result={'ok':True},now=100)
    if denial=='cancel':deps.transactions.cancel_repair('repair-1',now=100)
    elif denial=='expired':deps.clock.value=201
    else:
        current[0]=current[0].model_copy(update={'targets':(current[0].targets[0].model_copy(update={'repair_profiles':()}),)})
        policies[0]=policies[0].model_copy(update={'repair_profiles':()})
    resumed=run_event(build_graph(deps),{'resume':True,'transaction_id':'repair-1'})
    assert resumed['status']=='execution_unknown'
    assert requests[-1]['lifecycle']=='query_job'
    assert deps.transactions.repair_jobs('repair-1')[0].state=='succeeded'
    assert len(launches)==1 and all(r['lifecycle']!='undo' for r in requests)
    from a4diag.disk_workflow import DiskJournal
    snapshot=build_graph(deps).get_state({'configurable':{'thread_id':'repair-1'}}).values
    row=DiskJournal(deps.transactions,snapshot,current[0].targets[0]).row()
    assert row['finally_required']==1 and row['restored']==0


@pytest.mark.parametrize('boundary',['before_undo','after_undo','after_restoration_verify'])
def test_recreated_runtime_finally_crash_never_duplicates_undo(deps_factory,tmp_path,boundary):
    from test_repair_workflow_transport import wire
    from test_repair_scheduler import runtime_for
    from test_workflow_v3 import SimulatedCrash
    from a4diag.plugin_ports import _RpcExecutorPort
    deps,jobs,launches,requests,policies,host=wire(disk_deps(deps_factory,tmp_path),tmp_path)
    runtime_for(deps,tmp_path).handle(event())
    jobs.complete(launches[0],state='succeeded',changed=True,result={'ok':True},now=100)
    port=deps.plugins.executor
    class Interrupted:
        def __getattr__(self,name):return getattr(port,name)
        def undo(self,*args):
            if boundary=='before_undo':raise SimulatedCrash()
            result=port.undo(*args)
            if boundary=='after_undo':raise SimulatedCrash()
            return result
        def verify_restored(self,*args):
            result=port.verify_restored(*args)
            if boundary=='after_restoration_verify':raise SimulatedCrash()
            return result
    changed=replace(deps,plugins=replace(deps.plugins,executor=Interrupted()))
    with pytest.raises(SimulatedCrash):runtime_for(changed,tmp_path).resume('repair-1')
    fresh=_RpcExecutorPort(port.clients,signer_resolver=port.signer_resolver,clock=deps.clock)
    changed=replace(deps,plugins=replace(deps.plugins,executor=fresh))
    resumed=runtime_for(changed,tmp_path).resume('repair-1')
    assert resumed.status==('execution_unknown' if boundary=='before_undo' else 'rollback_partial'),resumed.report
    assert [r['lifecycle'] for r in requests].count('undo')==(0 if boundary=='before_undo' else 1)
    assert [r['lifecycle'] for r in requests].count('apply')==1

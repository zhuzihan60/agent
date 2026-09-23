import pytest


def sample(t, **changes):
    from a4diag.repair_verification import HealthSample
    return HealthSample(elapsed_seconds=t,resource_identity='web:abc',healthy=True,restart_count=0,**changes)


def test_single_healthy_sample_cannot_prove_recovery():
    from a4diag.repair_verification import observation_passed
    assert not observation_passed([sample(0)])


def test_real_fractional_gaps_are_not_rounded_away():
    from a4diag.repair_verification import observation_passed
    assert observation_passed([sample(t) for t in range(0,61,5)])
    assert not observation_passed([sample(t*5.001) for t in range(13)])


@pytest.mark.parametrize('change', ['identity','restarts','unhealthy','empty','duplicate','backwards'])
def test_discontinuous_or_failed_samples_never_prove_recovery(change):
    from a4diag.repair_verification import observation_passed
    samples=[sample(t) for t in range(0,61,5)]
    if change=='identity':samples[5]=samples[5].model_copy(update={'resource_identity':'web:def'})
    if change=='restarts':samples[5]=samples[5].model_copy(update={'restart_count':1})
    if change=='unhealthy':samples[5]=samples[5].model_copy(update={'healthy':False})
    if change=='empty':samples=[]
    if change=='duplicate':samples[5]=samples[4]
    if change=='backwards':samples.reverse()
    assert not observation_passed(samples)


def test_durable_budget_includes_probe_duration_and_restart_never_renews(tmp_path):
    from a4diag.repair_verification import ServiceObservations
    clock=[100., 1000.]
    store=ServiceObservations(tmp_path/'state.db',monotonic=lambda:clock[0],wall=lambda:clock[1],process='one')
    data=store.load('tx',budget_seconds=300)
    clock[:]=[110.,1010.]
    store.save('tx',data)
    other=ServiceObservations(tmp_path/'state.db',monotonic=lambda:clock[0],wall=lambda:clock[1],process='two')
    data=other.load('tx',budget_seconds=720)
    assert data['deadline']==1300.
    assert data['samples']=={}
    clock[:]=[401.,1301.]
    assert other.expired(data)


def test_backward_wall_clock_fails_closed(tmp_path):
    from a4diag.repair_verification import ServiceObservations
    clock=[1000.]
    store=ServiceObservations(tmp_path/'state.db',wall=lambda:clock[0])
    data=store.load('tx',budget_seconds=300);store.save('tx',data)
    clock[0]=999.
    assert store.expired(store.load('tx',budget_seconds=300))


def test_rpc_duration_is_inside_total_budget(tmp_path):
    from a4diag.repair_verification import ServiceObservations
    clock=[0.]
    store=ServiceObservations(tmp_path/'state.db',wall=lambda:clock[0],monotonic=lambda:clock[0])
    data=store.load('tx',budget_seconds=300)
    clock[0]=301.
    assert store.expired(data)


def test_default_core_preflight_waits_without_prepare_then_accepts_continuous_failure(deps_factory,tmp_path,monkeypatch):
    from dataclasses import replace
    from test_repair_workflow import repair_deps,event
    from test_repair_scheduler import runtime_for
    import a4diag.repair_verification as verification
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    from test_service_fault_evidence import RAW
    ticks=[100.]
    monkeypatch.setattr(verification,'monotonic',lambda:ticks[0])
    monkeypatch.setattr(verification,'wall_time',lambda:1000.+ticks[0])
    deps=replace(repair_deps(deps_factory,tmp_path),service_observer=None)
    deps.plugins.collector.service_health=lambda *args,**kwargs:(parse_service_fault_snapshot(RAW,100),False,{'ok':False})
    runtime=runtime_for(deps,tmp_path)
    assert runtime.handle(event()).status=='service_observing'
    assert 'prepare' not in deps.plugins.executor.calls
    for tick in (104.,108.):
        ticks[0]=tick
        assert runtime.poll_repair_jobs()[0].status=='service_observing'
        assert 'prepare' not in deps.plugins.executor.calls
    ticks[0]=112.
    runtime.poll_repair_jobs()
    assert 'prepare' in deps.plugins.executor.calls


from test_workflow_v3 import deps_factory


def service_runtime(deps_factory,tmp_path,monkeypatch):
    from dataclasses import replace
    from test_repair_workflow import repair_deps,event
    from test_repair_scheduler import runtime_for
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    from test_service_fault_evidence import RAW
    import a4diag.repair_verification as verification
    ticks=[100.]
    monkeypatch.setattr(verification,'monotonic',lambda:ticks[0])
    monkeypatch.setattr(verification,'wall_time',lambda:1000.+ticks[0])
    deps=replace(repair_deps(deps_factory,tmp_path),service_observer=None)
    snapshot=parse_service_fault_snapshot(RAW,100)
    deps.plugins.collector.service_health=lambda *args,**kwargs:(snapshot, bool(deps.plugins.executor.apply_count),{'ok':bool(deps.plugins.executor.apply_count)})
    runtime=runtime_for(deps,tmp_path)
    assert runtime.handle(event()).status=='service_observing'
    return deps,runtime,ticks


def test_immediate_failed_service_verification_never_issues_another_start_as_undo(deps_factory,tmp_path,monkeypatch):
    deps,runtime,ticks=service_runtime(deps_factory,tmp_path,monkeypatch)
    deps.plugins.executor.verify_fail_step='0'
    for value in (104.,108.,112.):
        ticks[0]=value;result=runtime.poll_repair_jobs()[0]
    assert result.status=='rollback_partial'
    assert deps.plugins.executor.apply_count==1
    assert not any(call.startswith('undo') for call in deps.plugins.executor.calls)


def test_default_core_requires_complete_window_and_records_only_observed_health(deps_factory,tmp_path,monkeypatch):
    deps,runtime,ticks=service_runtime(deps_factory,tmp_path,monkeypatch)
    for value in (104.,108.,112.):
        ticks[0]=value;result=runtime.poll_repair_jobs()[0]
    assert result.status=='service_observing'
    for value in range(116,172,4):
        ticks[0]=float(value)
        assert runtime.poll_repair_jobs()[0].status=='service_observing'
    ticks[0]=172.
    result=runtime.poll_repair_jobs()[0]
    assert result.status=='succeeded'
    assert deps.plugins.executor.apply_count==1
    assert result.report['residual_risk']!='none'
    failures=result.report['recovery_result']['preflight']['samples']['0']
    assert len(failures)>=3 and all(s['healthy'] is False for s in failures)
    assert failures[-1]['elapsed_seconds']-failures[0]['elapsed_seconds']>=10


@pytest.mark.parametrize('change',['identity','restarts','unhealthy'])
def test_default_core_stops_on_relapse_without_new_mutation(deps_factory,tmp_path,monkeypatch,change):
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    from test_service_fault_evidence import RAW
    deps,runtime,ticks=service_runtime(deps_factory,tmp_path,monkeypatch)
    for value in (104.,108.,112.):
        ticks[0]=value;runtime.poll_repair_jobs()
    snapshot=parse_service_fault_snapshot(RAW,100)
    if change=='identity':snapshot=snapshot.model_copy(update={'invocation_id':'different'})
    if change=='restarts':snapshot=snapshot.model_copy(update={'n_restarts':4})
    deps.plugins.collector.service_health=lambda *args,**kwargs:(snapshot,change!='unhealthy',{})
    ticks[0]=116.
    assert runtime.poll_repair_jobs()[0].status=='rollback_partial'
    assert deps.plugins.executor.apply_count==1
    assert not any(call.startswith('undo') for call in deps.plugins.executor.calls)


@pytest.mark.parametrize('change',['removed','replaced_checks','read_denied'])
def test_accepted_service_observation_survives_profile_revocation(deps_factory,tmp_path,monkeypatch,change):
    from dataclasses import replace
    from test_repair_scheduler import runtime_for
    from a4diag.policy_engine import PolicyEngine
    from test_workflow_v3 import POLICY_KEY
    deps,runtime,ticks=service_runtime(deps_factory,tmp_path,monkeypatch)
    for value in (104.,108.,112.):
        ticks[0]=value;runtime.poll_repair_jobs()
    original_target=deps.settings.targets[0]
    changed_target=original_target.model_copy(update={'repair_profiles':()})
    if change=='replaced_checks':
        changed_target=changed_target.model_copy(update={'recovery_checks':(original_target.recovery_checks[0].model_copy(update={'resource':'other.service'}),)})
    original_health=deps.plugins.collector.service_health
    def read(target,*args,**kwargs):
        assert target.recovery_checks==original_target.recovery_checks
        if change=='read_denied':raise PermissionError('unit_not_granted')
        return original_health(target,*args,**kwargs)
    deps.plugins.collector.service_health=read
    settings=deps.settings.model_copy(update={'targets':(changed_target,)})
    resumed=runtime_for(replace(deps,settings=settings,policy=PolicyEngine(settings,deps.registry,authorization_key=POLICY_KEY)),tmp_path)
    for value in range(116,173,4):
        ticks[0]=float(value);result=resumed.poll_repair_jobs()[0]
        if change=='read_denied':break
    assert result.status==('rollback_unknown' if change=='read_denied' else 'succeeded')
    assert deps.plugins.executor.apply_count==1
    assert not any(call.startswith('undo') for call in deps.plugins.executor.calls)

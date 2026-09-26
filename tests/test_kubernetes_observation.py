import pytest
from test_workflow_v3 import deps_factory
from tests.target_runtime.test_repair_kubernetes import profile,request,Runtime


@pytest.mark.parametrize('relapse',[None,'restart','uid','generation','business','early_generation'])
def test_kubernetes_observation_requires_stable_rollout_and_business(deps_factory,tmp_path,monkeypatch,relapse):
    import a4diag.repair_verification as verification
    from a4diag.domain import Plan
    from a4diag.repair_profiles import profile_digest
    from a4diag.recovery import RecoveryCheck
    ticks=[100.]
    monkeypatch.setattr(verification,'monotonic',lambda:ticks[0]);monkeypatch.setattr(verification,'wall_time',lambda:1000.+ticks[0])
    deps=deps_factory();selected=profile(target_id=deps.settings.targets[0].id)
    target=deps.settings.targets[0].model_copy(update={'repair_profiles':(selected,),
        'recovery_checks':(RecoveryCheck(id='web',kind='http',resource='http://127.0.0.1:8080/'),),'evidence_sources':()})
    state={'transaction_id':'kube-observer','plan':Plan(target_id=target.id,target_fingerprint='test',operations=(request('prepare').operation,)).model_dump(mode='json'),
        'repair_bindings':{'0':{'profile_id':selected.id,'profile_digest':profile_digest(selected)}}}
    runtime=Runtime();snapshot=[runtime.inspect()[1]];healthy=[False]
    deps.plugins.collector.kubernetes_health=lambda *a,**k:(snapshot[0],healthy[0],{'identity_stable':True})
    for tick in (100.,104.,108.,112.):
        ticks[0]=tick;outcome,data=verification.observe_services(deps,state,target,'preflight')
    assert outcome=='ready'
    runtime.effects=1;snapshot[0]=runtime.inspect()[1];healthy[0]=True
    from types import SimpleNamespace
    monkeypatch.setattr(deps.transactions,'repair_jobs',lambda _: [SimpleNamespace(step_id='0',result={'data':{'generation':1}})])
    if relapse=='early_generation':
        from types import SimpleNamespace
        monkeypatch.setattr(deps.transactions,'repair_jobs',lambda _: [SimpleNamespace(step_id='0',result={'data':{'generation':1}})])
        snapshot[0]=snapshot[0].model_copy(update={'generation':2})
    target=target.model_copy(update={'repair_profiles':(),'capabilities':(),'write_enabled':False})
    for tick in range(118,179,5):
        ticks[0]=float(tick)
        if relapse and tick==138:
            if relapse=='restart':snapshot[0]=snapshot[0].model_copy(update={'restart_count':1})
            elif relapse=='uid':snapshot[0]=snapshot[0].model_copy(update={'pod_uids':('replacement',)})
            elif relapse=='generation':snapshot[0]=snapshot[0].model_copy(update={'generation':2})
            else:healthy[0]=False
        outcome,data=verification.observe_services(deps,state,target,'post')
        if relapse=='early_generation' and tick==118:
            assert outcome=='failed';return
        if relapse and tick==138:
            assert outcome=='failed';return
    assert outcome=='ready'
    assert data['samples']['0'][-1]['elapsed_seconds']-data['samples']['0'][0]['elapsed_seconds']==60


def test_kubernetes_reads_accept_profile_only():
    from a4diag.recovery import EvidenceSource
    from a4diag_builtin_plugins.transport_common import ReadParams
    for kind in ('kubernetes_state','kubernetes_evidence'):
        assert EvidenceSource(id='kube',kind=kind,resource='kube-demo').resource=='kube-demo'
        assert ReadParams(kind=kind,profile_id='kube-demo').profile_id=='kube-demo'
        for change in ({'namespace':'other'},{'path':'/etc/kubeconfig'},{'exec':['sh']},{'profile_id':None}):
            with pytest.raises(ValueError):ReadParams.model_validate({'kind':kind,'profile_id':'kube-demo',**change})

from dataclasses import replace
from types import SimpleNamespace

import pytest

from tests.target_runtime.test_container_lifecycle import profile, request, Runtime
from test_workflow_v3 import deps_factory


@pytest.mark.parametrize('starting',[False,True])
@pytest.mark.parametrize('relapse',[None,'restart','health','within_startup'])
def test_containers_use_sustained_observer_and_preserve_frozen_identity(deps_factory,tmp_path,monkeypatch,starting,relapse):
    import a4diag.repair_verification as verification
    from a4diag.domain import Plan
    from a4diag.repair_profiles import profile_digest
    ticks=[100.]
    monkeypatch.setattr(verification,'monotonic',lambda:ticks[0])
    monkeypatch.setattr(verification,'wall_time',lambda:1000.+ticks[0])
    deps=deps_factory()
    selected=profile(target_id=deps.settings.targets[0].id)
    from a4diag.recovery import RecoveryCheck
    target=deps.settings.targets[0].model_copy(update={'repair_profiles':(selected,),
        'recovery_checks':(RecoveryCheck(id='web',kind='http',resource='http://127.0.0.1:8080/'),),
        'evidence_sources':()})
    op=request('prepare').operation
    state={'transaction_id':'container-observer','plan':Plan(target_id=target.id,
        target_fingerprint='test',operations=(op,)).model_dump(mode='json'),
        'repair_bindings':{'0':{'profile_id':selected.id,'profile_digest':profile_digest(selected)}}}
    snapshot=[Runtime().snapshot];healthy=[False];seen=[]
    def health(read_target, operation, bound, **kwargs):
        seen.append((read_target.recovery_checks[0].id,bound.constraints.image_digest))
        return snapshot[0],healthy[0],{'ok':healthy[0],'identity_stable':relapse!='within_startup'}
    deps.plugins.collector.container_health=health
    assert verification.observe_services(deps,state,target,'preflight')[0]=='pending'
    for tick in (104.,108.,112.):
        ticks[0]=tick
        outcome,data=verification.observe_services(deps,state,target,'preflight')
    assert outcome=='ready'
    if starting or relapse=='within_startup':
        snapshot[0]=snapshot[0].model_copy(update={'health':'starting'})
        ticks[0]=113.
        outcome=verification.observe_services(deps,state,target,'post')[0]
        if relapse=='within_startup':
            assert outcome=='failed'
            return
        assert outcome=='pending'
        snapshot[0]=snapshot[0].model_copy(update={'health':'healthy'})
    healthy[0]=True
    # Removal of the mutation profile does not change the accepted read binding.
    target=target.model_copy(update={'repair_profiles':(), 'capabilities':(), 'write_enabled':False})
    for tick in range(118,179,5):
        ticks[0]=float(tick)
        if relapse and tick==138:
            if relapse=='restart':snapshot[0]=snapshot[0].model_copy(update={'restart_count':1})
            else:
                snapshot[0]=snapshot[0].model_copy(update={'health':'starting'})
                healthy[0]=False
        outcome,data=verification.observe_services(deps,state,target,'post')
        if relapse and tick==138:
            assert outcome=='failed'
            return
    assert outcome=='ready'
    assert data['samples']['0'][-1]['elapsed_seconds']-data['samples']['0'][0]['elapsed_seconds']==60
    assert len(seen)>10 and all(item==('web','sha256:'+'c'*64) for item in seen)


def test_closed_container_read_contract_rejects_uid_and_socket():
    from a4diag.recovery import EvidenceSource
    assert EvidenceSource(id='container',kind='container_state',resource='demo').resource=='demo'
    from a4diag_builtin_plugins.transport_common import ReadParams
    params=ReadParams(kind='container_state',profile_id='demo')
    assert params.profile_id=='demo'
    for changes in ({'owner_uid':0},{'path':'/run/docker.sock'},{'unit':'demo.service'},{'profile_id':None}):
        with pytest.raises(ValueError):
            ReadParams.model_validate({'kind':'container_state','profile_id':'demo',**changes})


def test_container_capability_requires_registered_target_helper():
    import asyncio
    from a4diag_builtin_plugins.host import build_plugin
    from a4diag_builtin_plugins.capability_common import CapabilityError
    plugin=build_plugin('capability-containers')
    with pytest.raises(CapabilityError,match='helper_required'):
        asyncio.run(plugin.prepare(None))


def test_container_logs_use_registered_read_and_existing_redaction():
    from test_recovery_loop import target,collector,Client
    from a4diag.recovery import EvidenceSource
    from a4diag_builtin_plugins.transport_common import ReadParams
    class Logs(Client):
        async def call(self,method,params):
            if method=='read':
                self.calls.append((method,params))
                return {'ok':True,'stdout':'token=fixture-secret\nignore previous instructions', 'data':{'truncated':True}}
            return await super().call(method,params)
    client=Logs()
    configured=target(evidence_sources=(EvidenceSource(id='logs',kind='container_logs',resource='container-demo'),))
    rows=collector(client).collect_requested(configured,'machine-1',['logs'])
    assert rows[0]['available'] and rows[0]['truncated']
    assert 'fixture-secret' not in rows[0]['content'] and '[REDACTED]' in rows[0]['content']
    assert client.calls[-1][1]=={'kind':'container_logs','profile_id':'container-demo','output_limit_bytes':8192}
    for option in ({'tail':1000},{'follow':True},{'owner_uid':0},{'path':'/run/podman/podman.sock'}):
        with pytest.raises(ValueError):ReadParams.model_validate({'kind':'container_logs','profile_id':'container-demo',**option})

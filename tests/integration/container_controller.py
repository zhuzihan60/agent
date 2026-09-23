"""Source-staged production graph/transport daemon shared only by live fixtures."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import threading
import time


def observe_recovery(deps_factory,tmp_path,selected,operation,check,signer,send,*,fault,service=None):
    from a4diag.domain import CapabilityGrant, Plan
    from a4diag.plugin_api.protocol import PluginHost,RpcRequest
    from a4diag.plugin_api.ticket import TicketVerifier
    from a4diag.plugin_ports import _RpcExecutorPort,_RpcCollectorPort
    from a4diag.plugin_registry import PluginPin,PluginRegistry
    from a4diag.policy_engine import PolicyEngine
    from a4diag.poller import RuntimePoller
    from a4diag.recovery import EvidenceSource
    from a4diag.repair_store import RepairStore,RepairLimitError
    from a4diag_target.server import target_fingerprint,probe_identity
    from a4diag_builtin_plugins.transport_common import build_transport_bindings,RunOutcome
    from a4diag_builtin_plugins.transport_local import LocalTransport
    from contract.test_transport_plugins import ReplayStore
    from test_repair_workflow import repair_deps
    from test_repair_scheduler import runtime_for
    from test_workflow_v3 import TICKET_KEY,POLICY_KEY
    import pytest
    deps=repair_deps(deps_factory,tmp_path)
    target=deps.settings.targets[0].model_copy(update={'id':selected.target_id,'identity_ref':'target/'+selected.target_id,
        'repair_profiles':(selected,) if service is None else (selected,service), 'recovery_checks':(check,),
        'evidence_sources':(EvidenceSource(id='container',kind='kubernetes_state' if selected.capability=='kubernetes' else 'container_state',resource=selected.id),),
        'capabilities':(CapabilityGrant(name=selected.capability,actions=selected.actions,resources=(selected.resource,)),)+
            (() if service is None else (CapabilityGrant(name='services',actions=service.actions,resources=(service.resource,)),))})
    fingerprint=target_fingerprint()
    deps.plugins.model.plan_result=Plan(target_id=target.id,target_fingerprint=fingerprint,operations=(operation,))
    directory=tmp_path/'container-registry';directory.mkdir()
    (directory/'fixture.whl').write_bytes(b'container-source-staged');pins=[]
    repo=Path(__file__).resolve().parents[2]
    for name in ('capability-'+selected.capability,'capability-services','transport-local'):
        content=(repo/'packages/a4diag-builtin-plugins/manifests'/f'{name}.json').read_bytes()
        (directory/f'{name}.json').write_bytes(content)
        pins.append(PluginPin(name=name,version='1.0.0',api_version='1.0',artifact_path='fixture.whl',
            artifact_sha256=hashlib.sha256(b'container-source-staged').hexdigest(),manifest_sha256=hashlib.sha256(content).hexdigest(),enabled=True))
    registry=PluginRegistry.load(tuple(pins),directory,core_api='1.0')
    requests=[]
    class Identity:
        async def probe(self):return probe_identity()
    class Runner:
        async def run(self,argv,*,payload,output_limit_bytes):
            message=json.loads(payload)
            if 'payload' in message:requests.append(json.loads(message['payload']))
            response=await send(payload)
            return RunOutcome(started=True,timed_out=False,returncode=0,stdout=response.decode())
    clock=lambda:int(time.time());deps.clock.value=clock()
    host=PluginHost(build_transport_bindings(LocalTransport(identity=Identity(),runner=Runner())),
        ticket_verifier=TicketVerifier(TICKET_KEY,ReplayStore(),clock=clock))
    class Client:
        async def call(self,method,params,*,ticket=None):
            result=await host.dispatch(RpcRequest(jsonrpc='2.0',api_version='1.0',id='container-live',method=method,params=params,ticket=ticket))
            if result.error:raise ValueError(result.error)
            return result.result
    client=Client();settings=deps.settings.model_copy(update={'targets':(target,)})
    executor=_RpcExecutorPort({target.id:client},signer_resolver=lambda _:signer,clock=clock)
    collector=_RpcCollectorPort(registry,lambda _:client)
    deps=replace(deps,settings=settings,registry=registry,policy=PolicyEngine(settings,registry,authorization_key=POLICY_KEY),
        plugins=replace(deps.plugins,executor=executor,collector=collector),service_observer=None)
    runtime=runtime_for(deps,tmp_path);stop=threading.Event();daemon=None
    transaction='live-'+selected.id
    try:
        poller=RuntimePoller(runtime,state_path=tmp_path/'poller.db',report_root=tmp_path/'reports')
        started=time.monotonic();result=runtime.handle({'event_id':transaction,'target_id':target.id})
        daemon=threading.Thread(target=poller.run_forever,args=(stop,),daemon=True);daemon.start()
        while time.monotonic()-started<120:
            time.sleep(.2);deps.clock.value=clock()
            checkpoint=runtime._graph.get_state({'configurable':{'thread_id':transaction}})
            report=checkpoint.values
            if report['status'] in ('succeeded','failed','rollback_partial','rollback_unknown','rollback_succeeded') and not checkpoint.next:break
            if report['status']=='execution_unknown' and not checkpoint.next:
                current=deps.transactions.repair_jobs(transaction)
                if current and all(j.state=='unknown' for j in current):break
        stop.set();daemon.join(10)
        jobs=deps.transactions.repair_jobs(transaction)
        applies=[r for r in requests if r['lifecycle']=='apply']
        evidence={'status':report['status'],'state':report,'jobs':[j.model_dump(mode='json') for j in jobs],
            'apply_count':len(applies),'requests':requests,'wall_duration':time.monotonic()-started}
        (Path.cwd().parent/f'{selected.id}-{fault}-evidence.json').write_text(json.dumps(evidence,indent=2,default=str))
        assert not daemon.is_alive()
        assert len(applies)==1,evidence
        assert not any(r['lifecycle']=='undo' for r in requests),evidence
        if fault in ('exited','hung','oom','unhealthy','managed','bad-image'):
            assert report['status']=='succeeded',evidence
            samples=report['recovery_result']['samples']['0']
            assert samples[-1]['elapsed_seconds']-samples[0]['elapsed_seconds']>=60
            assert max(b['elapsed_seconds']-a['elapsed_seconds'] for a,b in zip(samples,samples[1:]))<=5
        else:
            assert report['status'] in ('rollback_partial','rollback_unknown','execution_unknown'),evidence
        limit_reason = 'resource_busy' if any(job.changed is None for job in jobs) else 'cooldown'
        with pytest.raises(RepairLimitError,match=limit_reason):
            RepairStore(deps.transactions.path).reserve(target.id,service.resource if service else selected.resource,'duplicate',clock(),600,2)
        if service is not None:
            assert all(r['operation']['capability']=='services' and r['operation']['resource']==service.resource for r in requests)
            assert applies[0]['binding']['profile_id']==service.id
        return evidence
    finally:
        stop.set()
        if daemon:daemon.join(10)
        runtime.close()

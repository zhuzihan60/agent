"""Real systemd/HTTP, signed production controller and detached target worker.

Source-staged runtime evidence, not built-package/SSH or provider acceptance.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import site
import socket
import subprocess
import sys
import time
import threading
import uuid

import pytest
from test_workflow_v3 import deps_factory, TICKET_KEY, POLICY_KEY

pytestmark=pytest.mark.skipif(os.environ.get('A4DIAG_TEST_SYSTEMD')!='1',reason='requires disposable systemd lab')


@pytest.mark.parametrize('fault',['hung','startlimit','slow','exit_loop','relapse','unrecovered'])
def test_signed_service_recovery_through_actual_daemon(deps_factory,tmp_path,fault):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from a4diag.domain import CapabilityGrant, Plan
    from a4diag.plugin_api.protocol import PluginHost,RpcRequest
    from a4diag.plugin_api.ticket import TicketVerifier
    from a4diag.plugin_api.target_protocol import TargetSigner,_public_fingerprint
    from a4diag.plugin_ports import _RpcExecutorPort,_RpcCollectorPort
    from a4diag.plugin_registry import PluginPin,PluginRegistry
    from a4diag.policy_engine import PolicyEngine
    from a4diag.poller import RuntimePoller
    from a4diag.recovery import RecoveryCheck,EvidenceSource,check_http
    from a4diag.repair_store import RepairStore,RepairLimitError
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.server import TargetSocketServer,target_fingerprint,probe_identity
    from a4diag_builtin_plugins.transport_common import build_transport_bindings,RunOutcome
    from a4diag_builtin_plugins.transport_local import LocalTransport
    from contract.test_transport_plugins import ReplayStore as TicketReplay
    from test_repair_workflow import repair_deps
    from test_repair_scheduler import runtime_for

    assert os.uname().nodename=='a4diag-remediation-test'
    token=uuid.uuid4().hex[:12];transaction='service-'+token
    base=Path('/opt/a4diag-target');base.mkdir(exist_ok=True)
    current=base/'current'
    assert not current.exists() and not current.is_symlink()
    stage=base/('service-'+token);stage.mkdir()
    root=Path('/var/lib/a4diag-target/executor')/('service-'+token);root.mkdir(mode=0o700,parents=True)
    Path('/run/a4diag-target').mkdir(exist_ok=True)
    Path('/etc/a4diag-target').mkdir(exist_ok=True)
    subprocess.run(['groupadd','-f','a4diag-target'],check=True)
    unit='a4diag-service-'+token+'.service';unit_path=Path('/run/systemd/system')/unit
    old_umask=os.umask(0o077);runtime=None;job_ids=[];result=None;daemon=None;stop=threading.Event()
    try:
        repo=Path(__file__).resolve().parents[2]
        subprocess.run([sys.executable,'-m','venv','--without-pip',str(stage/'venv')],check=True)
        paths=site.getsitepackages()+[str(repo/'src'),str(repo/'packages/a4diag-target-runtime/src'),str(repo/'packages/a4diag-builtin-plugins/src')]
        (stage/'venv/lib/python3.11/site-packages/service.pth').write_text('\n'.join(paths)+'\n')
        current.symlink_to(stage,target_is_directory=True)
        script=stage/'service.py';shutil.copyfile(repo/'tests/e2e/fixtures/flapping_service.py',script)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        extra='ExecStartPre=/bin/sleep 20\n' if fault=='slow' else ''
        restart='on-failure' if fault in ('startlimit','exit_loop') else 'no'
        unit_path.write_text(f'[Unit]\nStartLimitIntervalSec=300\nStartLimitBurst=3\n[Service]\nType=exec\nRestart={restart}\nRestartSec=0.1\nNetworkNamespacePath=/run/netns/a4diag-remediation\n{extra}ExecStart={sys.executable} {script} {stage} {fault} {port}\n')
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','start','--no-block',unit],check=True)
        def state():
            return subprocess.run(['systemctl','show',unit,'--property=ActiveState,SubState,InvocationID,MainPID,ExecMainStatus,Result,NRestarts'],capture_output=True,text=True,check=True).stdout
        end=time.monotonic()+10
        while time.monotonic()<end:
            raw=state()
            if (fault=='slow' and 'ActiveState=activating' in raw or
                fault in ('startlimit','exit_loop') and 'ActiveState=failed' in raw and 'NRestarts=3' in raw or
                fault not in ('slow','startlimit','exit_loop') and 'ActiveState=active' in raw):break
            time.sleep(.1)
        before=state()
        denied_start=None
        if fault in ('startlimit','exit_loop'):
            denied_start=subprocess.run(['systemctl','start',unit],capture_output=True,text=True)
            assert denied_start.returncode!=0 and (stage/'starts').read_text()=='3',before
            before=state()
        if fault=='hung':assert 'ActiveState=active' in before and 'MainPID=0\n' not in before
        deps=repair_deps(deps_factory,tmp_path)
        target=deps.settings.targets[0];now=int(time.time())
        action='reset-failed-start' if fault in ('startlimit','exit_loop') else 'restart'
        actions=(action,'reset-failed','start') if action.startswith('reset') else (action,)
        profile=target.repair_profiles[0].model_copy(update={'resource':unit,'actions':actions,'expires_at':now+600})
        check=RecoveryCheck(id='health',kind='http',resource=f'http://127.0.0.1:{port}/health',timeout_seconds=1,attempts=1)
        target=target.model_copy(update={'repair_profiles':(profile,), 'recovery_checks':(check,),
            'evidence_sources':(EvidenceSource(id='state',kind='service_state',resource=unit),),
            'capabilities':(CapabilityGrant(name='services',actions=actions,resources=(unit,)),)})
        fingerprint=target_fingerprint()
        op=deps.plugins.model.plan_result.operations[0].model_copy(update={'action':action,'resource':unit,'parameters':{'unit':unit},'undo':None if action.startswith('reset') else {'restore':True}})
        deps.plugins.model.plan_result=Plan(target_id=target.id,target_fingerprint=fingerprint,operations=(op,))
        # Real manifest verification and strict transport contracts, source artifact fixture.
        registry_dir=tmp_path/'live-registry';registry_dir.mkdir();pins=[]
        (registry_dir/'fixture.whl').write_bytes(b'source-staged-test')
        for name in ('capability-services','transport-local'):
            content=(repo/'packages/a4diag-builtin-plugins/manifests'/f'{name}.json').read_bytes()
            (registry_dir/f'{name}.json').write_bytes(content)
            pins.append(PluginPin(name=name,version='1.1.0',api_version='1.0',artifact_path='fixture.whl',artifact_sha256=hashlib.sha256(b'source-staged-test').hexdigest(),manifest_sha256=hashlib.sha256(content).hexdigest(),enabled=True))
        registry=PluginRegistry.load(tuple(pins),registry_dir,core_api='1.0')
        settings=deps.settings.model_copy(update={'targets':(target,)})
        key=Ed25519PrivateKey.generate();signer=TargetSigner(key)
        policy=TargetPolicy(target_id=target.id,target_fingerprint=fingerprint,controller_key_fingerprint=_public_fingerprint(key.public_key()),allowed_units=(unit,),repair_profiles=(profile,))
        policy_path=root/'policy.json';policy_path.write_text(policy.model_dump_json());policy_path.chmod(0o600)
        key_path=root/'public.pem';key_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        server=TargetSocketServer(policy_path=policy_path,public_key_path=key_path,replay_path=root/'replay.sqlite3')
        requests=[]
        class Identity:
            async def probe(self):return probe_identity()
        class Runner:
            async def run(self,argv,*,payload,output_limit_bytes):
                message=json.loads(payload)
                if 'payload' in message:requests.append(json.loads(message['payload']))
                response=await server.handle(payload)
                return RunOutcome(started=True,timed_out=False,returncode=0,stdout=response.decode())
        clock=lambda:int(time.time())
        # TicketIssuer is the original fixture issuer with live clock updated below.
        deps.clock.value=clock()
        host=PluginHost(build_transport_bindings(LocalTransport(identity=Identity(),runner=Runner())),ticket_verifier=TicketVerifier(TICKET_KEY,TicketReplay(),clock=clock))
        class Client:
            async def call(self,method,params,*,ticket=None):
                response=await host.dispatch(RpcRequest(jsonrpc='2.0',api_version='1.0',id='service-live',method=method,params=params,ticket=ticket))
                if response.error:raise ValueError(response.error)
                return response.result
        client=Client()
        executor=_RpcExecutorPort({target.id:client},signer_resolver=lambda _:signer,clock=clock)
        collector=_RpcCollectorPort(registry,lambda _:client)
        deps=replace(deps,settings=settings,registry=registry,policy=PolicyEngine(settings,registry,authorization_key=POLICY_KEY),
            plugins=replace(deps.plugins,executor=executor,collector=collector),service_observer=None)
        runtime=runtime_for(deps,tmp_path)
        poller=RuntimePoller(runtime,state_path=tmp_path/'poller.db',report_root=tmp_path/'reports')
        started=time.monotonic();result=runtime.handle({'event_id':transaction,'target_id':target.id})
        # Run the actual production daemon scheduler. The test only watches its
        # persisted status; it never manually resumes or invents sample times.
        daemon=threading.Thread(target=poller.run_forever,args=(stop,),daemon=True)
        daemon.start()
        end=started+115
        terminal={'succeeded','failed','rollback_partial','rollback_unknown','rollback_succeeded'}
        while time.monotonic()<end:
            time.sleep(.2);deps.clock.value=clock()
            checkpoint=runtime._graph.get_state({'configurable':{'thread_id':transaction}})
            snapshot=checkpoint.values
            result=type(result)(status=snapshot['status'],transaction_id=transaction,report=snapshot)
            # Concurrent graph checkpoints include intermediate policy_allowed /
            # prepared states. Only a completed pass can establish its outcome.
            if result.status in terminal and not checkpoint.next:
                break
        stop.set();daemon.join(10)
        assert not daemon.is_alive()
        jobs=deps.transactions.repair_jobs(transaction);job_ids=[job.id for job in jobs]
        applies=[r for r in requests if r['lifecycle']=='apply']
        evidence={'fault':fault,'before':before,'after':state(),'wall_duration':time.monotonic()-started,
            'start_limit_refusal':None if denied_start is None else {'returncode':denied_start.returncode,'stderr':denied_start.stderr},
            'status':result.status,'state':result.report,'jobs':[j.model_dump(mode='json') for j in jobs],
            'apply_count':len(applies),'systemd':subprocess.run(['systemctl','--version'],capture_output=True,text=True).stdout.splitlines()[0]}
        (Path.cwd().parent/f'service-{fault}-evidence.json').write_text(json.dumps(evidence,indent=2,default=str))
        if fault in ('hung','startlimit'):
            assert result.status=='succeeded',evidence
            samples=result.report['recovery_result']['samples']['0']
            assert samples[-1]['elapsed_seconds']-samples[0]['elapsed_seconds']>=60
            assert max(b['elapsed_seconds']-a['elapsed_seconds'] for a,b in zip(samples,samples[1:]))<=5
            assert len(applies)==len(jobs)==1
            assert check_http(check)['ok']
            with pytest.raises(RepairLimitError,match='cooldown'):
                RepairStore(deps.transactions.path).reserve(target.id,unit,'duplicate-'+token,clock(),600,2)
        elif fault=='slow':
            assert result.status=='failed' and not applies,evidence
            assert 'service_not_eligible' in result.report.get('error',''),evidence
        else:
            assert result.status in ('rollback_partial','execution_unknown'),evidence
            assert len(applies)==1
            assert not any(r['lifecycle']=='undo' for r in requests),evidence
    finally:
        stop.set()
        if daemon is not None:daemon.join(10)
        if runtime is not None:runtime.close()
        for name in [unit]+['a4diag-repair-'+job+'.service' for job in job_ids]:
            subprocess.run(['systemctl','stop',name],capture_output=True)
        unit_path.unlink(missing_ok=True)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        if current.is_symlink() and current.resolve()==stage:current.unlink()
        assert stage.parent==base and stage.name=='service-'+token
        shutil.rmtree(stage)
        assert root.parent==Path('/var/lib/a4diag-target/executor') and root.name=='service-'+token
        shutil.rmtree(root)
        os.umask(old_umask)

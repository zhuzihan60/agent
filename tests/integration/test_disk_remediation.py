"""Opt-in bounded ext4 effects and production signed disk workflow acceptance."""
from dataclasses import replace
import os
from pathlib import Path
import time

import pytest

from tests.e2e.fixtures.disk_fault import disk_image, exhaust
from test_workflow_v3 import deps_factory

pytestmark=pytest.mark.skipif(os.environ.get('A4DIAG_TEST_DISK')!='1', reason='requires disposable ext4/systemd lab')


def audit_marker(cache, state, monkeypatch, *, target):
    from a4diag_target import repair_disk_cleanup as cleanup
    from a4diag_target.repair_disk import DiskLimits, _scan_candidates
    limits=DiskLimits(str(cache),60,1024,64*1024*1024,target,0,'disk-lab.service')
    state.mkdir(mode=0o700,exist_ok=True)
    (state/'cache').mkdir(mode=0o700,exist_ok=True)
    monkeypatch.setattr(cleanup,'STATE_ROOT',state)
    monkeypatch.setattr(cleanup,'check_writer_boundary',lambda _:None)
    marker=_scan_candidates(limits,now_ns=time.time_ns())
    return cleanup.prepare_audit(marker,limits,profile_id='cache',request={},writer={}),limits


def test_unlinked_open_file_is_not_proof_of_recovery(monkeypatch):
    from a4diag_target.repair_disk import apply_cleanup
    with disk_image() as cache:
        # One real open inode owns all available blocks, including after unlink.
        held=(cache/'held').open('w+b')
        try:
            while True:
                try:
                    held.write(b'x'*(1024*1024));held.flush()
                except OSError:
                    break
            os.utime(cache/'held',(time.time()-3600,)*2)
            marker,limits=audit_marker(cache,cache.parent.parent/'audit',monkeypatch,target=1024*1024)
            result=apply_cleanup(marker,limits)
            assert result['removed_files']==1
            assert result['target_met'] is False
            assert held.readable()
            assert os.statvfs(cache).f_bavail*os.statvfs(cache).f_frsize<1024*1024
        finally:
            held.close()
        assert os.statvfs(cache).f_bavail>0


def test_preallocated_audit_survives_own_filesystem_full(monkeypatch):
    from a4diag_target.repair_disk import apply_cleanup
    with disk_image() as cache:
        # Reserve this transaction's audit before exhausting its filesystem.
        path=cache/'old'
        path.write_bytes(b'x'*1024*1024)
        os.utime(path,(time.time()-3600,)*2)
        marker,limits=audit_marker(cache,cache.parent/'audit',monkeypatch,target=512*1024)
        exhaust(cache,'blocks')
        result=apply_cleanup(marker,limits)
        assert result['removed_files']==1 and result['target_met']


@pytest.mark.parametrize('fault',['blocks','inodes','http_failure','replacement','crash_before_unlink','crash_after_unlink','controller_disconnect','initially_inactive'])
def test_production_signed_graph_ext4_writer_http(deps_factory, tmp_path,fault):
    import asyncio
    import hashlib
    import json
    import shutil
    import site
    import socket
    import sqlite3
    import subprocess
    import sys
    import uuid
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from a4diag.domain import CapabilityGrant, StepResult, Plan, canonical_json_bytes
    from a4diag.plugin_api.protocol import PluginHost, RpcRequest
    from a4diag.plugin_api.target_protocol import SignedTargetRequest, TargetSigner, TargetVerifier, _public_fingerprint
    from a4diag.plugin_api.ticket import TicketVerifier
    from a4diag.plugin_ports import _RpcExecutorPort
    from a4diag.recovery import RecoveryCheck, check_http
    from a4diag.repair_store import RepairStore
    from a4diag.workflow import build_graph, run_event
    from a4diag_target.executor import TargetExecutor
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.repair_jobs import JobStore, SystemdJobLauncher
    from a4diag_target.replay import SqliteReplayLedger
    from a4diag_target.server import target_fingerprint, probe_identity
    from a4diag_target.repair_helper import RepairHelper
    from a4diag_target.repair_install import HelperBinding
    from a4diag_target.preparation_proof import SERVICE_JOB_DATABASE
    from a4diag_builtin_plugins.capability_common import LocalFileAdapter
    from a4diag_builtin_plugins.transport_common import build_transport_bindings, RunOutcome
    from a4diag_builtin_plugins.transport_local import LocalTransport
    from contract.test_transport_plugins import ReplayStore as TicketReplay
    from test_disk_workflow import disk_deps
    from test_workflow_v3 import TICKET_KEY, POLICY_KEY
    from a4diag.policy_engine import PolicyEngine

    token=uuid.uuid4().hex[:12]
    original_umask=os.umask(0o077)
    unit=f'a4diag-disk-{token}.service'
    unit_path=Path('/etc/systemd/system')/unit
    base=Path('/opt/a4diag-target')
    base.mkdir(exist_ok=True)
    stage=base/('disk-'+token)
    current=base/'current'
    assert not current.exists() and not current.is_symlink()
    stage.mkdir()
    etc=Path('/etc/a4diag-target')
    etc.mkdir(exist_ok=True)
    saved={p:p.read_bytes() for p in etc.glob('*') if p.is_file()}
    Path('/run/a4diag-target').mkdir(exist_ok=True)
    subprocess.run(['/usr/sbin/groupadd','-f','a4diag-target'],check=True)
    state=None
    job_ids=[]
    transaction='live-disk-'+token
    with disk_image() as cache:
      try:
        subprocess.run([sys.executable,'-m','venv','--without-pip',str(stage/'venv')],check=True)
        repo=Path(__file__).resolve().parents[2]
        paths=site.getsitepackages()+[str(repo/'src'),str(repo/'packages/a4diag-target-runtime/src'),
            str(repo/'packages/a4diag-builtin-plugins/src')]
        (stage/'venv/lib/python3.11/site-packages/disk.pth').write_text('\n'.join(paths)+'\n')
        if fault.startswith('crash_'):
            packages=stage/'venv/lib/python3.11/site-packages'
            when='intent' if fault=='crash_before_unlink' else 'removed'
            (packages/'disk_crash_fixture.py').write_text(f'''import os
from a4diag_target import repair_disk_cleanup as cleanup
original=cleanup.write_slot
def write(fd,index,value):
 if value=={when!r}:
  if value=='intent':original(fd,index,value)
  os._exit(73)
 return original(fd,index,value)
cleanup.write_slot=write
''')
            with (packages/'disk.pth').open('a') as stream:stream.write('import disk_crash_fixture\n')
        current.symlink_to(stage,target_is_directory=True)
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        script=stage/'writer.py'
        script.write_text('''import http.server,os,sys
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  st=os.statvfs(sys.argv[1]);ok=st.f_bavail*st.f_frsize>=1048576 and st.f_favail>=10 and not os.path.exists(sys.argv[3])
  self.send_response(200 if ok else 503);self.end_headers();self.wfile.write(b'healthy' if ok else b'full')
http.server.HTTPServer(('127.0.0.1',int(sys.argv[2])),Handler).serve_forever()
''')
        force_failure=stage/'http-failure'
        if fault=='http_failure':force_failure.touch()
        unit_path.write_text(f'[Service]\nType=simple\nNetworkNamespacePath=/run/netns/a4diag-remediation\nExecStart={sys.executable} {script} {cache} {port} {force_failure}\n')
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','start',unit],check=True)
        if fault=='initially_inactive':subprocess.run(['systemctl','stop',unit],check=True)
        before=exhaust(cache,'inodes' if fault=='inodes' else 'blocks')
        check=RecoveryCheck(id='health',kind='http',resource=f'http://127.0.0.1:{port}/health',attempts=3)
        for _ in range(30):
            initial=check_http(check)
            if initial.get('status')!='http_unavailable':break
            time.sleep(.1)
        assert not initial['ok'],initial
        before.update(service=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip(),http=initial)
        deps=disk_deps(deps_factory,tmp_path)
        now=int(time.time());deps.clock.value=now
        target=deps.settings.targets[0]
        stop,disk=target.repair_profiles
        stop=stop.model_copy(update={'id':'stop-'+token,'resource':unit,'expires_at':now+600})
        disk=disk.model_copy(update={'id':'cache-'+token,'resource':str(cache),'expires_at':now+600,
            'constraints':disk.constraints.model_copy(update={'writer_unit':unit,'max_files':1024,
                'max_bytes':64*1024*1024,'min_free_bytes':1048576,'min_free_inodes':10})})
        target=target.model_copy(update={'repair_profiles':(stop,disk),'recovery_checks':(check,),
            'capabilities':(CapabilityGrant(name='services',actions=('stop',),resources=(unit,)),
                CapabilityGrant(name='disk',actions=('cleanup',),resources=(str(cache),)))})
        settings=deps.settings.model_copy(update={'targets':(target,)})
        fingerprint=target_fingerprint()
        operations=list(deps.plugins.model.plan_result.operations)
        operations[0]=operations[0].model_copy(update={'resource':unit,'parameters':{'unit':unit}})
        operations[1]=operations[1].model_copy(update={'resource':str(cache)})
        deps.plugins.model.plan_result=Plan(target_id=target.id,target_fingerprint=fingerprint,operations=tuple(operations))
        deps.plugins.collector.fingerprint=fingerprint
        def final_verify(*_):
            health=check_http(check)
            active=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()=='active'
            return StepResult(ok=health['ok'] and active,status='healthy' if health['ok'] and active else 'unhealthy',data=health)
        deps.plugins.collector.final_verify=final_verify
        deps=replace(deps,settings=settings,policy=PolicyEngine(settings,deps.registry,authorization_key=POLICY_KEY))
        key=Ed25519PrivateKey.generate();signer=TargetSigner(key)
        policy=TargetPolicy(target_id=target.id,target_fingerprint=fingerprint,
            controller_key_fingerprint=_public_fingerprint(key.public_key()),repair_profiles=(stop,disk))
        (etc/'policy.json').write_text(policy.model_dump_json());(etc/'policy.json').chmod(0o600)
        (etc/'operation-public.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        (etc/'operation-public.pem').chmod(0o600)
        binding=HelperBinding(adapter='disk-cache',profile=disk,peer_uid=0)
        (etc/'repair-helpers').mkdir(mode=0o700,exist_ok=True)
        (etc/'repair-helpers'/f'{disk.id}.json').write_text(binding.model_dump_json())
        state=binding.state;state.parent.mkdir(mode=0o700,parents=True,exist_ok=True);state.mkdir(mode=0o700)
        jobs=JobStore(SERVICE_JOB_DATABASE)
        ordinary=TargetExecutor(verifier=TargetVerifier(key.public_key(),replay_store=SqliteReplayLedger(stage/'replay.db'),clock=lambda:int(time.time())),
            policy=lambda:policy,identity_probe=target_fingerprint,adapter=LocalFileAdapter())
        ordinary.configure_jobs(jobs,RepairStore(jobs.path),SystemdJobLauncher(jobs.path,policy_path=etc/'policy.json'))
        helper=RepairHelper(disk.id)
        requests=[]
        class Identity:
            async def probe(self):return probe_identity()
        class Runner:
            async def run(self,argv,*,payload,output_limit_bytes):
                envelope=SignedTargetRequest.model_validate_json(payload)
                request=json.loads(envelope.payload);requests.append(request)
                if request['operation']['capability']=='disk':
                    result=json.loads(await helper.handle(payload,peer_uid=0))
                    if fault=='replacement' and request['lifecycle']=='prepare' and 'marker' in result:
                        candidate=cache/result['marker']['entries'][0]['relative_path']
                        candidate.rename(cache/'replaced-saved')
                        candidate.write_bytes(b'new retained cache')
                else:
                    try:
                        result=await ordinary.execute(envelope)
                    except Exception:
                        import traceback
                        traceback.print_exc()
                        raise
                return RunOutcome(started=True,timed_out=False,returncode=0,stdout=json.dumps(result))
        host=PluginHost(build_transport_bindings(LocalTransport(identity=Identity(),runner=Runner())),
            ticket_verifier=TicketVerifier(TICKET_KEY,TicketReplay(),clock=deps.clock))
        class Client:
            async def call(self,method,params,*,ticket=None):
                result=await host.dispatch(RpcRequest(jsonrpc='2.0',api_version='1.0',id='live',method=method,params=params,ticket=ticket))
                if result.error:raise ValueError(result.error)
                return result.result
        executor=_RpcExecutorPort({target.id:Client()},signer_resolver=lambda _:signer,clock=deps.clock)
        deps=replace(deps,plugins=replace(deps.plugins,executor=executor))
        graph=build_graph(deps)
        if fault=='controller_disconnect':
            # Terminate a real controller process after durable cleanup admission.
            # The independently owned systemd worker must finish without it.
            child=os.fork()
            if child==0:
                try:
                    run_event(graph,{'event_id':transaction,'target_id':target.id})
                    end=time.monotonic()+30
                    while len(deps.transactions.repair_jobs(transaction))<2 and time.monotonic()<end:
                        time.sleep(.1);deps.clock.value=int(time.time())
                        run_event(graph,{'resume':True,'transaction_id':transaction})
                    os._exit(0 if len(deps.transactions.repair_jobs(transaction))==2 else 72)
                except BaseException:
                    os._exit(71)
            waited,code=os.waitpid(child,0)
            assert waited==child and os.waitstatus_to_exitcode(code)==0
            result={'status':'execution_unknown'}
        else:
            result=run_event(graph,{'event_id':transaction,'target_id':target.id})
        deadline=time.monotonic()+45
        while result['status']=='execution_unknown' and time.monotonic()<deadline:
            time.sleep(.2);deps.clock.value=int(time.time())
            # Reconstruct the production graph and transport read context.
            executor=_RpcExecutorPort(executor.clients,signer_resolver=executor.signer_resolver,clock=deps.clock)
            deps=replace(deps,plugins=replace(deps.plugins,executor=executor))
            graph=build_graph(deps)
            result=run_event(graph,{'resume':True,'transaction_id':transaction})
            if result['status']=='execution_unknown' and 'disk_job_pending_observe_only' not in result.get('error',''):
                break
        job_ids=[j.id for j in deps.transactions.repair_jobs(transaction)]
        detail=[j.model_dump(mode='json') for j in deps.transactions.repair_jobs(transaction)]
        after=os.statvfs(cache)
        evidence={'before':before,'after':{'available_bytes':after.f_bavail*after.f_frsize,'free_inodes':after.f_favail,
            'service':subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip(),
            'http':check_http(check)},'jobs':detail,'outcome':result['status'],'error':result.get('error'),
            'requests':[(r['operation']['capability'],r['lifecycle']) for r in requests]}
        from a4diag.disk_workflow import DiskJournal
        evidence['journal']=DiskJournal(deps.transactions,dict(graph.get_state({'configurable':{'thread_id':transaction}}).values),target).row()
        (repo.parent/f'disk-workflow-{fault}-evidence.json').write_text(json.dumps(evidence,indent=2))
        print(json.dumps(evidence))
        partial=fault in ('http_failure','initially_inactive') or fault.startswith('crash_')
        assert result['status']==('rollback_partial' if partial else 'succeeded'),evidence
        assert len(job_ids)==2
        assert before['service']==('inactive' if fault=='initially_inactive' else 'active')
        assert evidence['after']['service']==before['service']
        assert evidence['after']['http']['ok']==(fault not in ('http_failure','crash_before_unlink','initially_inactive'))
        if fault!='crash_before_unlink':assert evidence['after']['available_bytes']>=1048576
        assert evidence['after']['free_inodes']>=10
        if fault.startswith('crash_'):
            cleanup=deps.transactions.repair_jobs(transaction)[1]
            assert cleanup.state=='partial' and cleanup.changed is None
            assert cleanup.result['data']['uncertain']==1
            assert cleanup.result['data']['removed_files']==0
            assert cleanup.result['data']['removed_logical_bytes']==0
            assert sum(r['lifecycle']=='apply' and r['operation']['capability']=='disk' for r in requests)==1
            # Terminal observation is stable; no lost-intent replay/counting.
            observed=executor.query_job(target,'1',operations[1],cleanup.id,
                deps.tickets.inspect_for_recovery(next(d.ticket for d in deps.transactions.get_dispatches(transaction) if d.step_id=='1' and d.phase.value=='apply')))
            assert observed.job==cleanup
        if fault=='replacement':
            assert (cache/'filler-0000').read_bytes()==b'new retained cache'
            assert deps.transactions.repair_jobs(transaction)[1].result['data']['skipped_changed']==1
        if fault=='initially_inactive':
            assert deps.transactions.repair_jobs(transaction)[0].changed is False
            assert deps.transactions.repair_effects(transaction)['0'].changed is False
      finally:
        for job_id in job_ids:
            subprocess.run(['systemctl','stop','a4diag-repair-'+job_id+'.service'],capture_output=True)
        subprocess.run(['systemctl','stop',unit],capture_output=True)
        unit_path.unlink(missing_ok=True)
        if state and state.exists():shutil.rmtree(state)
        for path in (etc/'repair-helpers').glob('cache-'+token+'.json'):path.unlink()
        for p in etc.glob('*'):
            if p.is_file() and p not in saved:p.unlink()
        for p,body in saved.items():p.write_bytes(body)
        if SERVICE_JOB_DATABASE.exists():
            with sqlite3.connect(SERVICE_JOB_DATABASE) as db:
                for table in ('writer_holds','repair_reservations','repair_jobs'):
                    db.execute(f'DELETE FROM {table} WHERE transaction_id=?',(transaction,))
        if current.is_symlink() and current.resolve()==stage:current.unlink()
        shutil.rmtree(stage)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        os.umask(original_umask)

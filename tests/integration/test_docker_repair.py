"""Opt-in real Docker faults through the signed exact helper and detached job."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import site
import socket
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('A4DIAG_TEST_DOCKER') != '1', reason='requires disposable Docker lab')
IMAGE = 'a4diag-lab-python:3.11.16'


def run_signed_container_recovery(tmp_path, runtime="docker", uid=0, *, deps_factory=None, fault="early"):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from a4diag.plugin_api.target_protocol import TargetSigner, TargetLifecycleV11, _public_fingerprint
    from a4diag_target.repair_install import install_helpers
    from a4diag_target.repair_helper import RepairHelper
    from a4diag_target.repair_docker import DockerAdapter
    from a4diag_target.repair_podman import PodmanAdapter
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.server import target_fingerprint
    from tests.target_runtime.test_repair_protocol import _request, _operation
    from tests.target_runtime.test_container_lifecycle import profile
    assert os.uname().nodename == 'a4diag-remediation-test'
    token = uuid.uuid4().hex[:10]
    base = Path('/opt/a4diag-target'); base.mkdir(exist_ok=True)
    stage = base / ('containers-'+token); stage.mkdir(mode=0o755)
    current = base/'current'
    assert not current.exists() and not current.is_symlink()
    etc = Path('/etc/a4diag-target'); etc.mkdir(exist_ok=True)
    saved = {p:(p.read_bytes(),p.stat().st_mode & 0o777) for p in etc.glob('*') if p.is_file()}
    units=Path('/etc/systemd/system')
    templates={units/name:((units/name).read_bytes() if (units/name).exists() else None) for name in ('a4diag-repair-helper@.service','a4diag-repair-helper@.socket')}
    old_umask=os.umask(0o077)
    cid=None; selected=None; jobs=[]; extra=[]; root_other=None; managed_unit=None; service=None; service_state=None
    def docker(*args):
        prefix=['docker'] if runtime=='docker' else (['podman'] if uid==0 else ['runuser','--user','a4diag-podman-test','--','env','XDG_RUNTIME_DIR=/run/user/22001','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/22001/bus','podman'])
        result=subprocess.run([*prefix,*args],capture_output=True,text=True,timeout=30,cwd='/')
        assert result.returncode==0,result.stderr
        return result.stdout.strip()
    try:
        repo=Path(__file__).resolve().parents[2]
        subprocess.run([sys.executable,'-m','venv','--without-pip',str(stage/'venv')],check=True)
        packages=stage/'venv/lib/python3.11/site-packages'
        for source,name in ((repo/'src/a4diag','a4diag'),(repo/'packages/a4diag-target-runtime/src/a4diag_target','a4diag_target'),(repo/'packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins','a4diag_builtin_plugins')):
            shutil.copytree(source,packages/name)
        (packages/'containers.pth').write_text('\n'.join(site.getsitepackages())+'\n')
        for folder in [stage/'venv',*list((stage/'venv').rglob('*'))]:
            if folder.is_dir():folder.chmod(0o755)
            elif folder.is_file() and not folder.is_symlink():folder.chmod(0o755 if '/bin/' in str(folder) else 0o644)
        executable=stage/'venv/bin/a4diag-repair-helper'
        executable.write_text(f'#!{stage}/venv/bin/python\nfrom a4diag_target.repair_helper import main\nraise SystemExit(main())\n');executable.chmod(0o755)
        for path in templates:shutil.copyfile(repo/'deploy'/path.name,path)
        subprocess.run(['groupadd','-f','a4diag-target'],check=True)
        Path('/run/a4diag-target').mkdir(exist_ok=True)
        current.symlink_to(stage,target_is_directory=True)
        with socket.socket() as channel:
            channel.bind(('127.0.0.1',0)); port=channel.getsockname()[1]
        script="""import http.server,os,pathlib,signal,sys,threading,time
path=pathlib.Path('/tmp/start-count');count=int(path.read_text())+1 if path.exists() else 1;path.write_text(str(count))
fault=sys.argv[1];port=int(sys.argv[2])
print('a4diag-container-log token=container-fixture-secret',flush=True)
if count==1 and fault=='exited':sys.exit(7)
if count==1 and fault=='oom':
 blocks=[]
 while True:blocks.append(bytearray(1024*1024))
signal.signal(signal.SIGTERM,signal.SIG_IGN if fault=='timeout' else lambda *_:sys.exit(0))
if count>1 and fault in ('relapse','managed-relapse'):threading.Timer(12,lambda:os._exit(42)).start()
if count>1 and fault=='managed-unready':time.sleep(8)
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  ok=not ((count==1 and fault in ('hung','unhealthy','relapse','timeout','managed','managed-relapse','managed-unready')) or fault=='unrecovered')
  self.send_response(200 if ok else 503);self.end_headers();self.wfile.write(b'ok' if ok else b'broken')
 def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',port),Handler).serve_forever()
"""
        flags=[]
        if fault=='oom':flags=['--memory','64m','--memory-swap','64m']
        if fault=='unhealthy':flags=['--health-cmd',"python3.11 -c \"import pathlib,sys;sys.exit(0 if int(pathlib.Path('/tmp/start-count').read_text())>1 else 1)\"",'--health-interval','1s','--health-retries','1']
        cid=docker('create','--name','a4diag-container-'+token,'--publish',f'127.0.0.1:{port}:{port}',*flags,IMAGE if runtime=='docker' else 'docker.io/library/'+IMAGE,'python3.11','-c',script,fault,str(port))
        if runtime=='podman' and uid==22001:
            duplicate=subprocess.run(['podman','create','--name','a4diag-container-'+token,'--network','none','docker.io/library/'+IMAGE,'python3.11','-c','import time;time.sleep(120)'],capture_output=True,text=True,check=True,cwd='/')
            root_other=duplicate.stdout.strip();assert root_other!=cid
        adapter=DockerAdapter() if runtime=='docker' else PodmanAdapter(uid,Path('/run/podman/podman.sock') if uid==0 else Path('/run/user/22001/podman/podman.sock'))
        if fault.startswith('managed'):
            managed_unit='a4diag-container-managed-'+token+'.service'
            unit_path=units/managed_unit
            ready=stage/'listener-ready.py'
            ready.write_text("import socket,sys,time\nfor attempt in range(200):\n try:\n  channel=socket.create_connection(('127.0.0.1',int(sys.argv[1])),.2);channel.close();sys.exit(0)\n except OSError:time.sleep(.05)\nsys.exit(1)\n")
            ready.chmod(0o644)
            unit_path.write_text('[Service]\nType=exec\nExecStart=/usr/bin/nsenter --net=/run/netns/a4diag-remediation /usr/bin/podman start --attach '+cid+'\nExecStartPost=/usr/bin/nsenter --net=/run/netns/a4diag-remediation /usr/bin/python3 '+str(ready)+' '+str(port)+'\nExecStop=/usr/bin/nsenter --net=/run/netns/a4diag-remediation /usr/bin/podman stop -t 2 '+cid+'\n')
            if fault=='managed-unready':
                unit_path.write_text('\n'.join(line for line in unit_path.read_text().splitlines() if not line.startswith('ExecStartPost='))+'\n')
            subprocess.run(['systemctl','daemon-reload'],check=True)
            subprocess.run(['systemctl','start',managed_unit],check=True)
        if fault not in ('early','unauthorized','replacement'):
            if not fault.startswith('managed'):docker('start',cid)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                snap=adapter.inspect(cid)
                if (fault in ('exited','oom') and not snap.running) or (fault=='unhealthy' and snap.health=='unhealthy') or (fault not in ('exited','oom','unhealthy') and snap.running):break
                time.sleep(.2)
        before=adapter.inspect(cid)
        if fault in ('early','exited','oom'):assert not before.running
        if fault=='oom':assert before.oom_killed
        if fault=='unhealthy':assert before.health=='unhealthy'
        now=int(time.time()); fingerprint=target_fingerprint()
        selected=profile(id='container-'+token, resource=f'{runtime}/{uid}/'+cid,
            constraints={'image_digest':before.identity.image_digest},expires_at=now+600,standing_authorization=True)
        if service is None and managed_unit:
            from tests.target_runtime.test_repair_protocol import _profile
            service=_profile(id='managed-'+token,target_id='demo',resource=managed_unit,actions=('start','restart'),recovery_check_ids=('web',),expires_at=now+600)
            selected=profile(**{**selected.model_dump(mode='json'),'constraints':{**selected.constraints.model_dump(),'service_unit':managed_unit,'service_profile_id':service.id}})
        key=Ed25519PrivateKey.generate(); signer=TargetSigner(key)
        policy=TargetPolicy(target_id='demo',target_fingerprint=fingerprint,
            controller_key_fingerprint=_public_fingerprint(key.public_key()),repair_profiles=(selected,) if service is None else (selected,service),allowed_container_profiles=(selected.id,),allowed_units=() if service is None else (managed_unit,))
        (etc/'policy.json').write_text(policy.model_dump_json()); (etc/'policy.json').chmod(0o600)
        (etc/'operation-public.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        install_helpers({'repair_profiles':[p.model_dump(mode='json') for p in policy.repair_profiles],
            'repair_helpers':[{'profile_id':selected.id,'adapter':runtime}],'confirm_repair_helpers':'ENABLE'},root=Path('/'),peer_uid=0)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','start',f'a4diag-repair-helper@{selected.id}.socket'],check=True)
        def relay(payload):
            import io
            from a4diag_target.helper import run_helper
            output=io.BytesIO();run_helper(io.BytesIO(payload),output,env={})
            return output.getvalue()
        operation=_operation(capability='containers',action='start' if not before.running else 'restart',resource=selected.resource,parameters={},undo=None,verify={'recovery_check_ids':['web']})
        def call(lifecycle,**kwargs):
            request=_request(selected,TargetLifecycleV11(lifecycle),'container-'+uuid.uuid4().hex,
                authorization_id=selected.id,operation=operation,**kwargs).model_copy(update={
                    'issued_at':int(time.time()),'expires_at':int(time.time())+120,'target_fingerprint':fingerprint})
            return json.loads(relay(signer.sign(request).model_dump_json().encode()))
        from a4diag.recovery import RecoveryCheck,check_http
        check=RecoveryCheck(id='web',kind='http',resource=f'http://127.0.0.1:{port}/',attempts=1)
        if deps_factory is not None:
            from tests.integration.container_controller import observe_recovery
            ordinary=None
            if service:
                denied=call('prepare');assert denied.get('reason')=='service_route_required:'+service.id,denied
                from a4diag_target.server import TargetSocketServer
                service_state=Path('/var/lib/a4diag-target/executor')/('container-'+token);service_state.mkdir(mode=0o700,parents=True)
                ordinary=TargetSocketServer(replay_path=service_state/'replay.sqlite3')
            async def send(payload):
                message=json.loads(payload)
                if ordinary and (message.get('method')=='read' and message.get('kind')=='service_state' or 'payload' in message and json.loads(message['payload'])['operation']['capability']=='services'):
                    return await ordinary.handle(payload)
                return await asyncio.to_thread(relay,payload)
            if fault=='timeout':operation=operation.model_copy(update={'timeout_seconds':2})
            evidence=observe_recovery(deps_factory,tmp_path,selected,operation,check,signer,send,fault=fault,service=service)
            jobs.extend(j['id'] for j in evidence['jobs'])
            details={'before':before.model_dump(mode='json'),'after':adapter.inspect(cid).model_dump(mode='json')}
            if service:
                count_file=tmp_path/'container-start-count'
                docker('cp',cid+':/tmp/start-count',str(count_file))
                assert count_file.read_text()=='2'
                details['container_start_count']=2
                details['service_state']=subprocess.run(['systemctl','show',managed_unit,'--property=InvocationID,ActiveState,NRestarts'],capture_output=True,text=True,check=True).stdout
                assert evidence['state']['effect_kinds']=={'0':'compensatable'}
            (Path.cwd().parent/f'{selected.id}-{fault}-snapshots.json').write_text(json.dumps(details,indent=2))
            return
        if fault=='unauthorized':
            other=docker('create',IMAGE if runtime=='docker' else 'docker.io/library/'+IMAGE,'python3.11','-c','import time;time.sleep(120)');extra.append(other)
            operation=operation.model_copy(update={'resource':f'{runtime}/{uid}/'+other})
            denied=call('prepare');assert denied.get('reason')=='helper_scope_mismatch',denied
            assert not adapter.inspect(other).running
            return
        prepared=call('prepare'); assert 'marker' in prepared, prepared
        if fault=='replacement':
            docker('rm','-f',cid)
            cid=docker('create','--name','a4diag-container-'+token,IMAGE if runtime=='docker' else 'docker.io/library/'+IMAGE,'python3.11','-c','import time;time.sleep(120)')
        accepted=call('apply',marker=prepared['marker']); assert 'job' in accepted, accepted
        job=accepted['job']; jobs.append(job['id'])
        end=time.monotonic()+30
        while time.monotonic()<end:
            observed=call('query_job',marker=prepared['marker'],job_id=job['id'])
            if observed['job']['state'] in ('succeeded','failed','partial'):break
            time.sleep(.2)
        (Path.cwd().parent/f'{runtime}-{uid}-early-job.json').write_text(json.dumps(observed,indent=2))
        if fault=='replacement':
            assert observed['job']['state']=='failed' and observed['job']['changed'] is False,observed
            assert not adapter.inspect(cid).running
            return
        assert observed['job']['state']=='succeeded',(observed,docker('inspect',cid))
        if runtime=='podman':
            execution=observed['job']['result']['data']['execution']
            assert execution['euid']==execution['peer_uid']==uid
            assert execution['caps']=={'CapEff':0,'CapPrm':0,'CapInh':0,'CapAmb':0}
            assert all(path.stat().st_uid==0 and not path.stat().st_mode&0o077 for path in (Path('/var/lib/a4diag-target/repair-helpers')/selected.id).iterdir())
        from a4diag.recovery import RecoveryCheck,check_http
        check=RecoveryCheck(id='web',kind='http',resource=f'http://127.0.0.1:{port}/',attempts=1)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            health=check_http(check)
            if health['ok']:break
            time.sleep(.1)
        assert health['ok'],health
        logs=json.loads(relay(json.dumps({'method':'read','kind':'container_logs','profile_id':selected.id,'limit':8192}).encode()))
        assert 'a4diag-container-log' in logs.get('content',''),logs
        assert logs['truncated'] is False
        from a4diag.redaction import redact
        (Path.cwd().parent/f'{runtime}-{uid}-logs.json').write_text(json.dumps(redact(logs),indent=2))
        assert adapter.inspect(cid).identity==before.identity
        if root_other:
            assert not PodmanAdapter(0,Path('/run/podman/podman.sock')).inspect(root_other).running
            denied=subprocess.run(['runuser','--user','a4diag-podman-test','--','test','-r','/etc/a4diag-target/policy.json'],cwd='/',capture_output=True)
            assert denied.returncode==1
        (Path.cwd().parent/f'{runtime}-{uid}-early-signed-evidence.json').write_text(json.dumps({
            'before':before.model_dump(mode='json'),'after':adapter.inspect(cid).model_dump(mode='json'),
            'job':observed,'version':docker('version')}))
    finally:
        if managed_unit:
            subprocess.run(['systemctl','stop',managed_unit],capture_output=True)
            (units/managed_unit).unlink(missing_ok=True)
        if service_state and service_state.exists():shutil.rmtree(service_state)
        if root_other:subprocess.run(['podman','rm','-f',root_other],capture_output=True,cwd='/')
        for other in extra:docker('rm','-f',other)
        for job in jobs:subprocess.run(['systemctl','stop','a4diag-repair-'+job+'.service'],capture_output=True)
        if cid:docker('rm','-f',cid)
        if selected:
            subprocess.run(['systemctl','stop',f'a4diag-repair-helper@{selected.id}.socket',f'a4diag-repair-helper@{selected.id}.service'],capture_output=True)
            (etc/'repair-helpers'/f'{selected.id}.json').unlink(missing_ok=True)
            state=Path('/var/lib/a4diag-target/repair-helpers')/selected.id
            if state.exists():shutil.rmtree(state)
            drop=Path('/etc/systemd/system')/f'a4diag-repair-helper@{selected.id}.service.d'
            if drop.exists():shutil.rmtree(drop)
        for p in etc.glob('*'):
            if p.is_file() and p not in saved:p.unlink()
        for p,(body,mode) in saved.items():p.write_bytes(body);p.chmod(mode)
        for path,body in templates.items():
            if body is None:path.unlink(missing_ok=True)
            else:path.write_bytes(body)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        if current.is_symlink() and current.resolve()==stage:current.unlink()
        shutil.rmtree(stage)
        os.umask(old_umask)


def test_signed_docker_exited_recovery(tmp_path):
    run_signed_container_recovery(tmp_path)

from test_workflow_v3 import deps_factory

@pytest.mark.parametrize('fault',['exited','hung','unhealthy','oom','relapse','unrecovered','timeout'])
def test_docker_fault_daemon(deps_factory,tmp_path,fault):
    run_signed_container_recovery(tmp_path,deps_factory=deps_factory,fault=fault)

@pytest.mark.parametrize('fault',['replacement','unauthorized'])
def test_docker_scope_negative(tmp_path,fault):
    run_signed_container_recovery(tmp_path,fault=fault)

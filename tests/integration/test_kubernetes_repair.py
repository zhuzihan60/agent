"""Real k3s acceptance: admin fixture provisioning, Agent scoped ServiceAccount."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import site
import subprocess
import sys
import time
import uuid
import pytest

pytestmark=pytest.mark.skipif(os.environ.get('A4DIAG_TEST_KUBERNETES')!='1',reason='requires disposable Kubernetes lab')
IMAGE='docker.io/library/a4diag-lab-python@sha256:c80b17d26d171aea81c392ef5e316e5124695c220212b68914e9ce563e4e17c5'


def kubectl(*args,body=None,check=True):
    result=subprocess.run(['/usr/local/bin/k3s','kubectl',*args],input=body,capture_output=True,text=True,timeout=40)
    if check:assert result.returncode==0,result.stderr[:2000]
    return result.stdout.strip()


@pytest.fixture
def cluster(tmp_path,request):
    fault=getattr(request,"param","bad-image")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from a4diag.plugin_api.target_protocol import TargetSigner,TargetLifecycleV11,_public_fingerprint
    from a4diag_target.repair_install import install_helpers
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.server import target_fingerprint
    from tests.target_runtime.test_repair_protocol import _request,_operation
    from tests.target_runtime.test_repair_kubernetes import profile
    token=uuid.uuid4().hex[:10];namespace='a4diag-c3-'+token;helper='kube-'+token
    repo=Path(__file__).resolve().parents[2];base=Path('/opt/a4diag-target');base.mkdir(exist_ok=True)
    stage=base/('kubernetes-'+token);current=base/'current';assert not current.exists() and not current.is_symlink()
    etc=Path('/etc/a4diag-target');etc.mkdir(exist_ok=True)
    saved={p:(p.read_bytes(),p.stat().st_mode&0o777) for p in etc.glob('*') if p.is_file()}
    units=Path('/etc/systemd/system');templates={units/n:((units/n).read_bytes() if (units/n).exists() else None) for n in ('a4diag-repair-helper@.service','a4diag-repair-helper@.socket')}
    namespace_created=False
    jobs=[];selected=None;old_umask=os.umask(0o077);credential=etc/'kubernetes'/f'{helper}.json'
    try:
        kubectl('create','namespace',namespace)
        namespace_created=True
        manifest=(repo/'deploy/kubernetes/repair-agent.yaml').read_text().replace('a4diag-remediation',namespace)
        kubectl('apply','-f','-',body=manifest)
        script="""import http.server,os,sys
if os.environ.get('FAULT')=='crash':sys.exit(42)
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):self.send_response(503 if os.environ.get('FAULT')=='hung' and not os.environ.get('TRANSACTION') else 200);self.end_headers();self.wfile.write(b'ok')
 def log_message(self,*args):pass
print('a4diag-kubernetes-log token=fixture-secret',flush=True)
http.server.HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
"""
        deployment={'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'http-demo','namespace':namespace},
            'spec':{'replicas':1,'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxUnavailable':0,'maxSurge':1}},
                'selector':{'matchLabels':{'app':'http-demo'}},'template':{'metadata':{'labels':{'app':'http-demo'}},
                    'spec':{'automountServiceAccountToken':False,'terminationGracePeriodSeconds':1,
                        'containers':[{'name':'web','image':IMAGE if fault in ('hung','crash','schedule') else 'a4diag-missing:bad','imagePullPolicy':'Never',
                            'command':['python3.11','-c',script],'env':[{'name':'FAULT','value':fault},{'name':'TRANSACTION','valueFrom':{'fieldRef':{'fieldPath':"metadata.annotations['a4diag.io/restart-transaction']"}}}],'ports':[{'containerPort':8080}],
                            'readinessProbe':{'httpGet':{'path':'/','port':8080},'periodSeconds':1}}]}}}}
        if fault=='schedule':deployment['spec']['template']['spec']['containers'][0]['resources']={'requests':{'cpu':'1000000'}}
        kubectl('apply','-f','-',body=json.dumps(deployment))
        end=time.monotonic()+20
        while time.monotonic()<end:
            obj=json.loads(kubectl('-n',namespace,'get','deployment','http-demo','-o','json'))
            pods=json.loads(kubectl('-n',namespace,'get','pods','-o','json'))['items']
            if obj.get('status',{}).get('observedGeneration')==1 and any(p.get('status',{}).get('containerStatuses') or fault=='schedule' and any(c.get('reason')=='Unschedulable' for c in p.get('status',{}).get('conditions',[])) for p in pods):break
            time.sleep(.2)
        service={'apiVersion':'v1','kind':'Service','metadata':{'name':'http-demo','namespace':namespace},
                 'spec':{'selector':{'app':'http-demo'},'ports':[{'port':8080,'targetPort':8080}]}}
        kubectl('apply','-f','-',body=json.dumps(service))
        ip=json.loads(kubectl('-n',namespace,'get','service','http-demo','-o','json'))['spec']['clusterIP']
        credential.parent.mkdir(exist_ok=True,mode=0o700)
        credentials={'endpoint':'https://127.0.0.1:6443','ca_pem':Path('/var/lib/rancher/k3s/server/tls/server-ca.crt').read_text(),
                     'token':kubectl('-n',namespace,'create','token','a4diag-repair','--duration=30m')}
        credential.write_text(json.dumps(credentials));credential.chmod(0o600)
        subject='system:serviceaccount:'+namespace+':a4diag-repair'
        for verb,resource in (('get','secrets'),('create','pods/exec'),('get','nodes')):
            assert kubectl('auth','can-i',verb,resource,'--as='+subject,'-n',namespace,check=False)=='no'
        subprocess.run([sys.executable,'-m','venv','--without-pip',str(stage/'venv')],check=True)
        packages=stage/'venv/lib/python3.11/site-packages'
        for source,name in ((repo/'src/a4diag','a4diag'),(repo/'packages/a4diag-target-runtime/src/a4diag_target','a4diag_target'),(repo/'packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins','a4diag_builtin_plugins')):
            shutil.copytree(source,packages/name)
        (packages/'kubernetes.pth').write_text('\n'.join(site.getsitepackages())+'\n')
        # Lab-only placement override; production sandbox properties remain intact.
        launcher=packages/'a4diag_target/repair_jobs.py';source=launcher.read_text()
        needle="argv.extend(f'--property={value}' for value in properties)";assert needle in source
        launcher.write_text(source.replace(needle,needle+"\n        argv.append('--property=NetworkNamespacePath=/run/netns/a4diag-remediation')"))
        executable=stage/'venv/bin/a4diag-repair-helper'
        executable.write_text(f'#!{stage}/venv/bin/python\nfrom a4diag_target.repair_helper import main\nraise SystemExit(main())\n');executable.chmod(0o755)
        for path in templates:shutil.copyfile(repo/'deploy'/path.name,path)
        subprocess.run(['groupadd','-f','a4diag-target'],check=True)
        Path('/run/a4diag-target').mkdir(exist_ok=True);current.symlink_to(stage,target_is_directory=True)
        selected=profile(id=helper,standing_authorization=True,resource=f'lab/{namespace}/http-demo/'+obj['metadata']['uid'],
            constraints={**profile().constraints.model_dump(),'known_image':IMAGE,'credential_id':helper,'rollout_timeout_seconds':15 if fault=='crash' else 120},expires_at=int(time.time())+900)
        key=Ed25519PrivateKey.generate();signer=TargetSigner(key);fingerprint=target_fingerprint()
        policy=TargetPolicy(target_id='demo',target_fingerprint=fingerprint,controller_key_fingerprint=_public_fingerprint(key.public_key()),repair_profiles=(selected,),allowed_kubernetes_profiles=(selected.id,))
        (etc/'policy.json').write_text(policy.model_dump_json());(etc/'policy.json').chmod(0o600)
        (etc/'operation-public.pem').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        install_helpers({'repair_profiles':[selected.model_dump(mode='json')],'repair_helpers':[{'profile_id':helper,'adapter':'kubernetes'}],
                         'confirm_repair_helpers':'ENABLE'},root=Path('/'),peer_uid=0)
        (units/f'a4diag-repair-helper@{helper}.service.d'/'lab.conf').write_text('[Service]\nNetworkNamespacePath=/run/netns/a4diag-remediation\n')
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','start',f'a4diag-repair-helper@{helper}.socket'],check=True)
        operation=_operation(capability='kubernetes',action='restart' if fault in ('hung','crash') else 'restore-image',resource=selected.resource,parameters={},undo=None,verify={'recovery_check_ids':['web']})
        def relay(payload):
            import io
            from a4diag_target.helper import run_helper
            output=io.BytesIO();run_helper(io.BytesIO(payload),output,env={});return output.getvalue()
        def call(lifecycle,**kwargs):
            request=_request(selected,TargetLifecycleV11(lifecycle),'kube-'+uuid.uuid4().hex,authorization_id=helper,operation=operation,**kwargs).model_copy(update={
                'issued_at':int(time.time()),'expires_at':int(time.time())+120,'target_fingerprint':fingerprint})
            result=json.loads(relay(signer.sign(request).model_dump_json().encode()))
            if 'job' in result and result['job']['id'] not in jobs:jobs.append(result['job']['id'])
            return result
        yield dict(call=call,namespace=namespace,selected=selected,operation=operation,signer=signer,relay=relay,ip=ip,credential=credential,policy=policy,etc=etc,stage=stage,jobs=jobs,fault=fault,deployment=deployment)
    finally:
        import sqlite3
        database=Path('/var/lib/a4diag-target/repair-helpers')/helper/'repair-jobs.sqlite3'
        if database.exists():
            with sqlite3.connect(database) as db:
                jobs.extend(row[0] for row in db.execute('SELECT id FROM repair_jobs') if row[0] not in jobs)
        for job in jobs:subprocess.run(['systemctl','stop','a4diag-repair-'+job+'.service'],capture_output=True)
        subprocess.run(['systemctl','stop',f'a4diag-repair-helper@{helper}.socket',f'a4diag-repair-helper@{helper}.service'],capture_output=True)
        (etc/'repair-helpers'/f'{helper}.json').unlink(missing_ok=True)
        for path in (Path('/var/lib/a4diag-target/repair-helpers')/helper,units/f'a4diag-repair-helper@{helper}.service.d'):
            if path.exists():shutil.rmtree(path)
        credential.unlink(missing_ok=True)
        for p in etc.glob('*'):
            if p.is_file() and p not in saved:p.unlink()
        for p,(body,mode) in saved.items():p.write_bytes(body);p.chmod(mode)
        for path,body in templates.items():
            if body is None:path.unlink(missing_ok=True)
            else:path.write_bytes(body)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        if current.is_symlink() and current.resolve()==stage:current.unlink()
        if stage.exists():shutil.rmtree(stage)
        if namespace_created:kubectl('delete','namespace',namespace,'--wait=false',check=False)
        os.umask(old_umask)


def test_signed_bad_image_recovery(cluster):
    call=cluster['call'];prepared=call('prepare');assert 'marker' in prepared,prepared
    accepted=call('apply',marker=prepared['marker']);assert 'job' in accepted,accepted
    job=accepted['job'];deadline=time.monotonic()+130
    while time.monotonic()<deadline:
        observed=call('query_job',marker=prepared['marker'],job_id=job['id'])
        if observed['job']['state'] in ('succeeded','failed','partial','unknown'):break
        time.sleep(.5)
    (Path.cwd().parent/'kubernetes-early-job.json').write_text(json.dumps(observed,indent=2))
    assert observed['job']['state']=='succeeded',observed
    from a4diag.recovery import RecoveryCheck,check_http
    health_attempts=[];http_started=time.monotonic();http_deadline=min(deadline,http_started+5)
    while time.monotonic()<http_deadline:
        check=RecoveryCheck(id='web',kind='http',resource=f"http://{cluster['ip']}:8080/",attempts=1,timeout_seconds=2)
        health=check_http(check.model_copy(update={'timeout_seconds':min(2,max(.01,http_deadline-time.monotonic()))}))
        health_attempts.append({'elapsed':time.monotonic()-http_started,**health})
        if health['ok']:break
        time.sleep(min(.1,max(0,http_deadline-time.monotonic())))
    pods=json.loads(kubectl('-n',cluster['namespace'],'get','pods','-o','json'))['items']
    addresses=[p.get('status',{}).get('podIP') for p in pods]
    diagnostic={'service_ip':cluster['ip'],'health':health,'health_attempts':health_attempts,'pod_health':[
        {'ip':ip,'health':check_http(RecoveryCheck(id='web',kind='http',resource=f'http://{ip}:8080/',attempts=1))} for ip in addresses if ip],
        'pods':[{'uid':p['metadata']['uid'],'phase':p.get('status',{}).get('phase'),'conditions':p.get('status',{}).get('conditions')} for p in pods],
        'endpoints':json.loads(kubectl('-n',cluster['namespace'],'get','endpointslices','-o','json'))['items']}
    (Path.cwd().parent/'kubernetes-early-http.json').write_text(json.dumps(diagnostic,indent=2))
    assert health['ok'],diagnostic
    assert_redacted_evidence(cluster)


from test_workflow_v3 import deps_factory


@pytest.mark.parametrize('cluster',['bad-image','hung','crash'],indirect=True)
def test_kubernetes_fault_daemon(cluster,deps_factory,tmp_path):
    from tests.integration.container_controller import observe_recovery
    from a4diag.recovery import RecoveryCheck
    async def send(payload):return await asyncio.to_thread(cluster['relay'],payload)
    check=RecoveryCheck(id='web',kind='http',resource=f"http://{cluster['ip']}:8080/",attempts=1)
    result=observe_recovery(deps_factory,tmp_path,cluster['selected'],cluster['operation'],check,cluster['signer'],send,fault=cluster['fault'])
    cluster['jobs'].extend(j['id'] for j in result['jobs'] if j['id'] not in cluster['jobs'])
    if cluster['fault']=='bad-image':assert_redacted_evidence(cluster)


def assert_redacted_evidence(cluster):
    evidence=json.loads(cluster['relay'](json.dumps({'method':'read','kind':'kubernetes_evidence','profile_id':cluster['selected'].id,'limit':16384}).encode()))
    assert 'a4diag-kubernetes-log' in evidence.get('content',''),evidence
    assert 'fixture-secret' not in evidence['content']
    assert json.loads(evidence['content'])['untrusted'] is True
    (Path.cwd().parent/'kubernetes-redacted-evidence.json').write_text(json.dumps(evidence,indent=2))


def poll(cluster,prepared,accepted):
    assert 'job' in accepted,accepted
    deadline=time.monotonic()+130
    while time.monotonic()<deadline:
        result=cluster['call']('query_job',marker=prepared['marker'],job_id=accepted['job']['id'])
        if result['job']['state'] in ('succeeded','failed','partial','unknown'):return result['job']
        time.sleep(.2)
    raise AssertionError('job deadline')


@pytest.mark.parametrize('case',['quota','concurrent','uid','rbac','namespace'])
def test_kubernetes_closed_scope_negatives(cluster,case):
    ns=cluster['namespace'];call=cluster['call']
    before=json.loads(kubectl('-n',ns,'get','deployment','http-demo','-o','json'))
    if case=='quota':
        quota={'apiVersion':'v1','kind':'ResourceQuota','metadata':{'name':'capacity','namespace':ns},'spec':{'hard':{'pods':'1'}}}
        kubectl('apply','-f','-',body=json.dumps(quota))
        end=time.monotonic()+10
        while time.monotonic()<end:
            status=json.loads(kubectl('-n',ns,'get','resourcequota','capacity','-o','json')).get('status',{})
            if status.get('used',{}).get('pods')=='1':break
            time.sleep(.2)
        result=call('prepare');assert 'capacity' in result.get('reason',''),result
    elif case=='namespace':
        from a4diag_target.repair_kubernetes import KubernetesAdapter,KubernetesAPIError
        from tests.target_runtime.test_repair_kubernetes import profile
        alternate=profile(**{**cluster['selected'].model_dump(mode='json'),'resource':cluster['selected'].resource.replace('/'+ns+'/', '/default/')})
        with pytest.raises(KubernetesAPIError) as error:KubernetesAdapter(alternate).deployment()
        assert error.value.status==403
        result={'reason':'kubernetes_http_403'}
    else:
        prepared=call('prepare');assert 'marker' in prepared,prepared
        if case=='concurrent':kubectl('-n',ns,'annotate','deployment','http-demo','other-controller=changed')
        if case=='uid':
            kubectl('-n',ns,'delete','deployment','http-demo','--wait=true')
            kubectl('apply','-f','-',body=json.dumps(cluster['deployment']))
        if case=='rbac':
            role=json.loads(kubectl('-n',ns,'get','role','a4diag-repair','-o','json'));role['rules'][0]['verbs']=['get']
            kubectl('apply','-f','-',body=json.dumps(role))
        result=poll(cluster,prepared,call('apply',marker=prepared['marker']))
        if case=='rbac':assert result['state']=='failed' and result['changed'] is False and '403' in str(result),result
        else:assert result['state']=='failed' and result['changed'] is False,result
    after=json.loads(kubectl('-n',ns,'get','deployment','http-demo','-o','json'))
    assert after['spec']['template']['spec']['containers'][0]['image']==before['spec']['template']['spec']['containers'][0]['image']
    (Path.cwd().parent/f"{cluster['selected'].id}-{case}.json").write_text(json.dumps({'result':result,'before_uid':before['metadata']['uid'],'after_uid':after['metadata']['uid']}))


@pytest.mark.parametrize('cluster',['schedule'],indirect=True)
def test_kubernetes_actual_unschedulable_refused(cluster):
    result=cluster['call']('prepare')
    assert 'capacity_unschedulable' in result.get('reason',''),result


def test_disconnected_dispatcher_does_not_kill_rollout(cluster):
    call=cluster['call'];prepared=call('prepare');assert 'marker' in prepared,prepared
    accepted=call('apply',marker=prepared['marker']);assert 'job' in accepted,accepted
    unit='a4diag-repair-'+accepted['job']['id']+'.service'
    facts=subprocess.run(['systemctl','show',unit,'--property=MainPID,ControlGroup,ProtectSystem,NoNewPrivileges,RestrictAddressFamilies,IPAddressDeny,IPAddressAllow'],capture_output=True,text=True,check=True).stdout
    assert 'MainPID=0\n' not in facts and 'ProtectSystem=strict' in facts,facts
    subprocess.run(['systemctl','stop',f"a4diag-repair-helper@{cluster['selected'].id}.service"],check=True)
    job=poll(cluster,prepared,accepted)
    assert job['state']=='succeeded',job
    (Path.cwd().parent/'kubernetes-disconnected-worker.json').write_text(json.dumps({'unit':unit,'properties':facts,'job':job},indent=2))


def test_real_cas_rejection_and_compensation_conflict(cluster):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,KubernetesAPIError
    adapter=KubernetesAdapter(cluster['selected']);before=adapter.deployment()
    # Another controller changes metadata after the exact read. The production
    # adapter's ordinary image action must receive the real API CAS rejection.
    kubectl('-n',cluster['namespace'],'annotate','deployment','http-demo','other-controller=changed')
    with pytest.raises(KubernetesAPIError) as error:adapter.change(before,'restore-image','test')
    assert error.value.status in (409,422)
    assert adapter.deployment()['spec']['template']['spec']['containers'][0]['image']==before['spec']['template']['spec']['containers'][0]['image']
    prepared=cluster['call']('prepare');assert 'marker' in prepared,prepared
    job=poll(cluster,prepared,cluster['call']('apply',marker=prepared['marker']))
    assert job['state']=='succeeded',job
    kubectl('-n',cluster['namespace'],'set','image','deployment/http-demo','web=a4diag-other-controller:bad')
    compensation=cluster['call']('undo',marker=prepared['marker'])
    assert compensation['ok'] is False and 'compensation_conflict' in str(compensation),compensation
    assert adapter.deployment()['spec']['template']['spec']['containers'][0]['image']=='a4diag-other-controller:bad'
    (Path.cwd().parent/'kubernetes-cas-compensation.json').write_text(json.dumps({'cas_status':error.value.status,'job':job,'compensation':compensation},indent=2))

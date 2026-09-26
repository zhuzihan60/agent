import copy

import pytest


IMAGE = 'demo@sha256:' + 'b' * 64


def profile(**changes):
    from a4diag.repair_profiles import RepairProfile
    value=dict(id='kube-demo', target_id='demo', capability='kubernetes',
        resource='lab/demo/web/u1', actions=['restore-image', 'restart'],
        constraints=dict(endpoint='https://127.0.0.1:6443', credential_id='lab',
                         container_name='web', known_image=IMAGE, min_available=1,
                         max_unavailable=0, capacity_replicas=2),
        recovery_check_ids=['web'], expires_at=253402300799)
    return RepairProfile.model_validate({**value,**changes})


def test_rollout_requires_exact_rs_lineage_and_old_pods_exited():
    from a4diag_target.repair_kubernetes import rollout_snapshot
    d=deployment();d['status'].update(availableReplicas=1)
    rs={'metadata':{'uid':'rs1','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]},
        'spec':{'template':copy.deepcopy(d['spec']['template'])}}
    pod={'metadata':{'uid':'p1','ownerReferences':[{'uid':'rs1','kind':'ReplicaSet','controller':True}]},
        'status':{'conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':'web','ready':True,'restartCount':0}]}}
    assert rollout_snapshot(profile(),d,[rs],[pod]).complete
    old=copy.deepcopy(rs);old['metadata']['uid']='rs0';old['spec']['template']['spec']['containers'][0]['image']='old'
    oldpod=copy.deepcopy(pod);oldpod['metadata'].update(uid='p0',deletionTimestamp='now');oldpod['metadata']['ownerReferences'][0]['uid']='rs0'
    assert not rollout_snapshot(profile(),d,[rs,old],[pod,oldpod]).complete
    pod['status']['containerStatuses'][0]['restartCount']=2
    assert rollout_snapshot(profile(),d,[rs],[pod]).restart_count==2


def test_scoped_client_has_no_arbitrary_patch_or_credential_exec(tmp_path):
    from a4diag_target.repair_kubernetes import KubernetesCredentials,KubernetesAdapter
    with pytest.raises(ValueError):
        KubernetesCredentials(endpoint='https://127.0.0.1:6443',ca_pem='bad',token='secret',exec=['sh'])
    assert not hasattr(KubernetesAdapter,'patch')
    assert not hasattr(KubernetesAdapter,'exec')


def test_quota_and_unschedulable_capacity_fail_closed():
    from a4diag_target.repair_kubernetes import check_capacity
    p=profile();d=deployment()
    with pytest.raises(ValueError,match='capacity'):
        check_capacity(p,d,[],[{'status':{'hard':{'pods':'1'},'used':{'pods':'1'}}}])
    with pytest.raises(ValueError,match='unsupported_quota'):
        check_capacity(p,d,[],[{'status':{'hard':{'requests.cpu':'1'},'used':{'requests.cpu':'0'}}}])
    with pytest.raises(ValueError,match='capacity'):
        check_capacity(p,d,[{'status':{'conditions':[{'type':'PodScheduled','status':'False','reason':'Unschedulable'}]}}],[])


def deployment():
    return dict(metadata=dict(uid='u1', resourceVersion='42', generation=1, labels={}),
        spec=dict(replicas=1, selector={'matchLabels':{'app':'web'}}, strategy=dict(type='RollingUpdate', rollingUpdate=dict(maxUnavailable=0,maxSurge=1)),
            template=dict(metadata=dict(annotations={}),spec=dict(containers=[dict(name='web',image='demo:broken')]))),
        status=dict(observedGeneration=1,updatedReplicas=1,availableReplicas=0,replicas=1))


def test_image_repair_checks_concurrent_rollout():
    from a4diag_target.repair_kubernetes import deployment_patch
    patch=deployment_patch(uid='u1',resource_version='42',container_index=0,
                           prior_image='demo:broken',desired_image=IMAGE)
    assert patch==[{'op':'test','path':'/metadata/uid','value':'u1'},
        {'op':'test','path':'/metadata/resourceVersion','value':'42'},
        {'op':'test','path':'/spec/template/spec/containers/0/image','value':'demo:broken'},
        {'op':'replace','path':'/spec/template/spec/containers/0/image','value':IMAGE}]
    for bad in ('demo:latest','demo:stable','demo@sha256:bad'):
        with pytest.raises(ValueError):
            deployment_patch(uid='u1',resource_version='42',container_index=0,prior_image='demo:broken',desired_image=bad)


@pytest.mark.parametrize('change,reason',[
    (lambda d:d['metadata'].update(uid='other'),'identity'),
    (lambda d:d['spec'].update(replicas=0),'replicas'),
    (lambda d:d['spec'].update(paused=True),'paused'),
    (lambda d:d['metadata']['labels'].update({'argocd.argoproj.io/instance':'app'}),'gitops'),
    (lambda d:d['metadata'].update(generation=2),'concurrent'),
    (lambda d:d['spec']['strategy']['rollingUpdate'].update(maxUnavailable=1),'availability'),
    (lambda d:d['spec']['strategy']['rollingUpdate'].update(maxSurge=2),'capacity'),
])
def test_prepare_rejects_unsafe_deployment(change,reason):
    from a4diag_target.repair_kubernetes import prepare_deployment
    value=deployment();change(value)
    with pytest.raises(ValueError,match=reason):prepare_deployment(profile(),value)


def test_profile_requires_digest_numeric_tls_endpoint_and_exact_resource():
    selected=profile()
    for key,value in [('known_image','demo:latest'),('endpoint','http://127.0.0.1:6443'),
                      ('endpoint','https://api.example.com'),('credential_id','../admin')]:
        with pytest.raises(ValueError):profile(constraints={**selected.constraints.model_dump(),key:value})
    for resource in ('lab/demo/web','lab/*/web/u1','lab/demo/../u1'):
        with pytest.raises(ValueError):profile(resource=resource)


def test_restart_patch_tests_only_owned_annotation_and_does_not_replace_map():
    from a4diag_target.repair_kubernetes import restart_patch
    patch=restart_patch(deployment(), 'tx1')
    assert patch[-1]=={'op':'add','path':'/spec/template/metadata/annotations/a4diag.io~1restart-transaction','value':'tx1'}
    assert patch[2]=={'op':'test','path':'/spec/template/metadata/annotations','value':{}}
    assert all(p['path'] not in ('/spec','/spec/template') for p in patch)


def test_registered_kubernetes_sandbox_is_scoped_to_api_and_manager_denied():
    from a4diag_target.repair_install import HelperBinding,sandbox_properties
    value=sandbox_properties(HelperBinding(adapter='kubernetes',profile=profile(),peer_uid=0))
    assert 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' in value
    assert 'IPAddressDeny=any' in value and 'IPAddressAllow=127.0.0.1' in value
    assert 'TemporaryFileSystem=/run:ro' in value and 'CapabilityBoundingSet=' in value


@pytest.fixture
def protected_state():
    import tempfile,shutil
    from pathlib import Path
    path=Path(tempfile.mkdtemp(prefix='a4diag-kube-',dir='/var/lib'))
    try:yield path
    finally:shutil.rmtree(path)


class Runtime:
    def __init__(self):
        self.value=deployment();self.effects=0

    def inspect(self,*,capacity=False):
        from a4diag_builtin_plugins.capability_kubernetes import DeploymentSnapshot
        snapshot=DeploymentSnapshot(identity={'cluster_id':'lab','namespace':'demo','name':'web','uid':self.value['metadata']['uid']},
            generation=self.value['metadata']['generation'],observed_generation=self.value['metadata']['generation'],
            replicas=1,updated=1,available=int(self.effects>0),complete=self.effects>0,pod_uids=('p1',),restart_count=0,
            image=self.value['spec']['template']['spec']['containers'][0]['image'])
        return copy.deepcopy(self.value),snapshot

    def deployment(self):return copy.deepcopy(self.value)

    def change(self,value,action,transaction):
        self.effects+=1
        self.value['metadata'].update(resourceVersion='43',generation=2)
        self.value['spec']['template']['spec']['containers'][0]['image']=IMAGE
        return copy.deepcopy(self.value)


def request(lifecycle,marker=None):
    from types import SimpleNamespace
    from a4diag.domain import Operation
    return SimpleNamespace(transaction_id='tx1',step_id='0',lifecycle=lifecycle,marker=marker,
        operation=Operation(capability='kubernetes',action='restore-image',resource=profile().resource,
            parameters={},verify={'recovery_check_ids':['web']},model_risk='high',undo=None))


def test_durable_cas_is_one_effect_and_replay_returns_record(protected_state):
    import asyncio
    from a4diag_target.repair_kubernetes import KubernetesPlugin
    runtime=Runtime();plugin=KubernetesPlugin(profile(),adapter=runtime,state=protected_state)
    marker=asyncio.run(plugin.dispatch(request('prepare'))).marker
    assert 'spec' not in marker and 'token' not in str(marker)
    effect=asyncio.run(plugin.dispatch(request('apply',marker)))
    assert effect.ok and effect.changed and effect.data['snapshot']['complete']
    assert asyncio.run(plugin.dispatch(request('apply',marker)))==effect
    assert runtime.effects==1
    assert asyncio.run(plugin.dispatch(request('reconcile',marker))).state=='applied'


def test_prepared_rv_change_rejected_before_effect(protected_state):
    import asyncio
    from a4diag_target.repair_kubernetes import KubernetesPlugin
    from a4diag_target.repair_admission import EffectAdmissionRejected
    runtime=Runtime();plugin=KubernetesPlugin(profile(),adapter=runtime,state=protected_state)
    marker=asyncio.run(plugin.dispatch(request('prepare'))).marker
    runtime.value['metadata']['resourceVersion']='44'
    with pytest.raises(EffectAdmissionRejected):plugin.admit_effect(request('apply',marker))
    assert runtime.effects==0


def test_unknown_patch_never_retries_and_reports_uncertain(protected_state):
    import asyncio
    from a4diag_target.repair_kubernetes import KubernetesPlugin
    runtime=Runtime();plugin=KubernetesPlugin(profile(),adapter=runtime,state=protected_state)
    marker=asyncio.run(plugin.dispatch(request('prepare'))).marker
    def timeout(*args):runtime.effects+=1;raise TimeoutError()
    runtime.change=timeout
    with pytest.raises(TimeoutError):asyncio.run(plugin.dispatch(request('apply',marker)))
    assert asyncio.run(plugin.dispatch(request('reconcile',marker))).state=='unknown'
    with pytest.raises(ValueError):asyncio.run(plugin.dispatch(request('apply',marker)))
    assert runtime.effects==1


def test_capability_manifest_host_and_closed_executor_are_registered(protected_state):
    import asyncio,json
    from pathlib import Path
    from a4diag_builtin_plugins.host import build_plugin
    from a4diag_target.repair_kubernetes import KubernetesPlugin
    from a4diag_target.executor import TargetExecutor
    from tests.target_runtime.test_repair_protocol import _request,_operation
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11
    capability=build_plugin('capability-kubernetes')
    manifest=json.loads((Path(__file__).resolve().parents[2]/'packages/a4diag-builtin-plugins/manifests/capability-kubernetes.json').read_text())
    assert {o['name'] for o in manifest['operations']}=={'kubernetes.restart','kubernetes.restore-image'}
    selected=profile();runtime=Runtime();plugin=KubernetesPlugin(selected,adapter=runtime,state=protected_state)
    op=_operation(capability='kubernetes',action='restore-image',resource=selected.resource,parameters={},undo=None)
    req=_request(selected,TargetLifecycleV11.PREPARE,'kube-unit-nonce-0001',operation=op)
    executor=TargetExecutor(verifier=None,policy=lambda:None,identity_probe=None,adapter=None,plugins={'kubernetes':plugin})
    assert asyncio.run(executor._dispatch(plugin,req)).marker['uid']=='u1'


@pytest.fixture
def tls_api(protected_state):
    import datetime,ipaddress,json,socket,ssl,threading,time,uuid
    from pathlib import Path
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .sign(key,hashes.SHA256()))
    pem=cert.public_bytes(serialization.Encoding.PEM).decode()
    certpath=protected_state/'server.crt';keypath=protected_state/'server.key'
    certpath.write_text(pem);keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(.1)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certpath,keypath)
    credential_id='test-'+uuid.uuid4().hex
    root=Path('/etc/a4diag-target/kubernetes');root.mkdir(parents=True,exist_ok=True,mode=0o700)
    credentials=root/(credential_id+'.json')
    selected=profile(constraints={**profile().constraints.model_dump(),'credential_id':credential_id,
                                 'endpoint':f'https://127.0.0.1:{listener.getsockname()[1]}'})
    credentials.write_text(json.dumps({'endpoint':selected.constraints.endpoint,'ca_pem':pem,'token':'fixture-token'}));credentials.chmod(0o600)
    state={'status':200,'response':deployment(),'slow':False,'requests':[]};stop=threading.Event()
    def serve():
        while not stop.is_set():
            try:raw,_=listener.accept()
            except TimeoutError:continue
            except OSError:break
            try:
                with context.wrap_socket(raw,server_side=True) as channel:
                    data=b''
                    while b'\r\n\r\n' not in data:data+=channel.recv(4096)
                    header,body=data.split(b'\r\n\r\n',1)
                    length=int(next(x.split(b':')[1] for x in header.split(b'\r\n') if x.lower().startswith(b'content-length:')))
                    while len(body)<length:body+=channel.recv(4096)
                    state['requests'].append((header.splitlines()[0].decode(),json.loads(body) if body else None))
                    payload=json.dumps(state['response']).encode()
                    reply=f"HTTP/1.1 {state['status']} Test\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()+payload
                    if state['slow']:
                        for byte in reply:channel.sendall(bytes([byte]));time.sleep(.025)
                    else:channel.sendall(reply)
            except (OSError,ssl.SSLError):raw.close()
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:yield selected,state,credentials
    finally:stop.set();listener.close();thread.join(3);credentials.unlink(missing_ok=True)


@pytest.mark.parametrize('status',[403,409,422,302])
def test_tls_client_preserves_rejection_without_retry_or_server_secrets(tls_api,status):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,KubernetesAPIError
    selected,state,_=tls_api;state.update(status=status,response={'message':'token=server-secret'})
    adapter=KubernetesAdapter(selected)
    with pytest.raises(KubernetesAPIError) as error:adapter.deployment()
    assert error.value.status==status and 'server-secret' not in str(error.value)
    assert len(state['requests'])==1


def test_tls_client_uses_one_slow_header_deadline(tls_api):
    import time
    from a4diag_target.repair_kubernetes import KubernetesAdapter
    selected,state,_=tls_api;state['slow']=True
    adapter=KubernetesAdapter(selected);adapter.timeout_seconds=.15
    start=time.monotonic()
    with pytest.raises(TimeoutError):adapter.deployment()
    assert time.monotonic()-start<.5


def test_tls_client_enforces_certificate_and_closed_patch(tls_api):
    import json,ssl
    from a4diag_target.repair_kubernetes import KubernetesAdapter
    selected,state,path=tls_api;adapter=KubernetesAdapter(selected)
    adapter.change(deployment(),'restore-image','tx')
    assert len(state['requests'])==1 and state['requests'][0][0].startswith('PATCH /apis/apps/v1/namespaces/demo/deployments/web ')
    assert state['requests'][0][1][-1]['value']==IMAGE
    raw=json.loads(path.read_text());raw['ca_pem']='not-a-cert';path.write_text(json.dumps(raw))
    with pytest.raises((ValueError,ssl.SSLError)):KubernetesAdapter(selected)


def test_compensation_cannot_overwrite_controller_image_or_renamed_container(tls_api):
    from a4diag_target.repair_kubernetes import KubernetesAdapter
    selected,state,_=tls_api;adapter=KubernetesAdapter(selected)
    value=deployment();value['spec']['template']['spec']['containers'][0]['image']=IMAGE
    record={'index':0,'written':IMAGE,'prior':'demo:broken'}
    adapter.compensate(value,record)
    assert state['requests'][-1][1][-2:]==[
        {'op':'test','path':'/spec/template/spec/containers/0/image','value':IMAGE},
        {'op':'replace','path':'/spec/template/spec/containers/0/image','value':'demo:broken'}]
    value['spec']['template']['spec']['containers'][0]['name']='another'
    with pytest.raises(ValueError,match='compensation_conflict'):adapter.compensate(value,record)
    assert len(state['requests'])==1


@pytest.mark.parametrize('delay_at',[1,2])
def test_kubernetes_worker_admission_and_patch_share_deadline(protected_state,delay_at):
    import asyncio,time
    from types import SimpleNamespace
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11 as L
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag.repair_profiles import profile_digest
    from a4diag.repair_store import RepairStore
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.repair_kubernetes import KubernetesPlugin
    from a4diag_target.repair_jobs import JobStore,run_job
    from tests.target_runtime.test_repair_protocol import _request,FINGERPRINT
    selected=profile(standing_authorization=True);runtime=Runtime()
    operation=request('prepare').operation.model_copy(update={'timeout_seconds':1})
    plugin=KubernetesPlugin(selected,adapter=runtime,state=protected_state)
    prepare=_request(selected,L.PREPARE,'kubernetes-worker-prepare',operation=operation,authorization_id=selected.id)
    marker=asyncio.run(plugin.dispatch(prepare)).marker
    apply=_request(selected,L.APPLY,'kubernetes-worker-apply',operation=operation,marker=marker,authorization_id=selected.id)
    key='sha256:'+'e'*64
    policy=TargetPolicy(target_id='demo',target_fingerprint=FINGERPRINT,controller_key_fingerprint=key,repair_profiles=(selected,))
    jobs=JobStore(protected_state/'jobs.db');limits=RepairStore(jobs.path)
    job=jobs.ensure(apply.transaction_id,apply.step_id,canonical_operation_digest(operation),profile_digest=profile_digest(selected))
    jobs.bind_request(job.id,apply,controller_key_fingerprint=key)
    reservation=limits.reserve('demo',selected.resource,apply.transaction_id,151,600,2)
    limits.bind_job(reservation,job.id);limits.mark_started(reservation,151);jobs.start(job.id,now=151)
    original=runtime.inspect;reads=[]
    def slow(**kwargs):
        reads.append(runtime.timeout_seconds);time.sleep((1.1 if len(reads)==1 else 0) if delay_at==1 else .6)
        return original(**kwargs)
    runtime.inspect=slow
    asyncio.run(run_job(jobs,job.id,policy=lambda:policy,identity_probe=lambda:FINGERPRINT,adapter=None,plugins={'kubernetes':plugin},clock=lambda:151))
    result=jobs.get(job.id)
    assert runtime.effects==0 and reads[0]<=1
    if delay_at==1:assert result.state=='failed' and result.changed is False and result.result['change_verified']
    else:assert len(reads)==2 and reads[1]<.5 and result.state=='unknown' and result.changed is None


def test_service_profile_cannot_acquire_kubernetes_action():
    from tests.target_runtime.test_repair_protocol import _profile
    with pytest.raises(ValueError):_profile(actions=('restore-image',))


def test_stateless_and_gitops_constraints_fail_closed():
    from a4diag_target.repair_kubernetes import prepare_deployment
    for field in ('persistentVolumeClaim','hostPath'):
        value=deployment();value['spec']['template']['spec']['volumes']=[{'name':'data',field:{}}]
        with pytest.raises(ValueError,match='stateless'):prepare_deployment(profile(),value)
    value=deployment();value['metadata']['managedFields']=[{'manager':'argocd-controller'}]
    with pytest.raises(ValueError,match='gitops'):prepare_deployment(profile(),value)


def test_kubernetes_read_grant_is_independent_and_revocable(monkeypatch):
    import asyncio,json
    import a4diag_target.repair_helper as helper
    from a4diag_target.repair_install import HelperBinding
    from a4diag_target.policy import TargetPolicy
    binding=HelperBinding(adapter='kubernetes',profile=profile(),peer_uid=0)
    server=object.__new__(helper.RepairHelper);server.binding=binding
    policy=TargetPolicy(target_id='demo',target_fingerprint='sha256:'+'b'*64,controller_key_fingerprint='sha256:'+'a'*64)
    monkeypatch.setattr(helper,'load_binding',lambda _:binding)
    monkeypatch.setattr(helper,'current_policy',lambda:policy)
    response=json.loads(asyncio.run(server.handle(json.dumps({'method':'read','kind':'kubernetes_state','profile_id':binding.id,'limit':8192}).encode(),peer_uid=0)))
    assert response['reason']=='kubernetes_read_not_granted'


@pytest.mark.parametrize('status',[403,409,422])
def test_explicit_patch_rejection_is_durable_no_retry(protected_state,status):
    import asyncio
    from a4diag_target.repair_kubernetes import KubernetesPlugin,KubernetesAPIError,KubernetesPatchRejected
    runtime=Runtime();plugin=KubernetesPlugin(profile(),adapter=runtime,state=protected_state)
    marker=asyncio.run(plugin.dispatch(request('prepare'))).marker
    def denied(*args):runtime.effects+=1;raise KubernetesAPIError(status)
    runtime.change=denied
    with pytest.raises(KubernetesPatchRejected):asyncio.run(plugin.dispatch(request('apply',marker)))
    assert asyncio.run(plugin.dispatch(request('reconcile',marker))).state=='not_applied'
    with pytest.raises(ValueError):asyncio.run(plugin.dispatch(request('apply',marker)))
    assert runtime.effects==1


@pytest.mark.parametrize('status',[500,503])
def test_uncertain_patch_error_remains_unknown_after_reload_without_retry(protected_state,status):
    import asyncio
    from a4diag_target.repair_kubernetes import KubernetesPlugin,KubernetesAPIError
    runtime=Runtime();plugin=KubernetesPlugin(profile(),adapter=runtime,state=protected_state)
    marker=asyncio.run(plugin.dispatch(request('prepare'))).marker
    def uncertain(*args):runtime.effects+=1;raise KubernetesAPIError(status)
    runtime.change=uncertain
    with pytest.raises(KubernetesAPIError):asyncio.run(plugin.dispatch(request('apply',marker)))
    reloaded=KubernetesPlugin(profile(),adapter=runtime,state=protected_state)
    result=asyncio.run(reloaded.dispatch(request('reconcile',marker)))
    assert result.state=='unknown' and result.data['operation_stage']=='intent'
    with pytest.raises(ValueError,match='kubernetes_operation_uncertain'):
        asyncio.run(reloaded.dispatch(request('apply',marker)))
    assert runtime.effects==1


def test_deleted_old_replicaset_does_not_hide_terminating_pod():
    from a4diag_target.repair_kubernetes import rollout_snapshot
    d=deployment();d['status'].update(availableReplicas=1)
    rs={'metadata':{'uid':'new-rs','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]},
        'spec':{'template':copy.deepcopy(d['spec']['template'])}}
    current={'metadata':{'uid':'new-pod','ownerReferences':[{'uid':'new-rs','kind':'ReplicaSet','controller':True}]},
        'status':{'conditions':[{'type':'Ready','status':'True'}]}}
    old={'metadata':{'uid':'old-pod','deletionTimestamp':'now','ownerReferences':[{'uid':'deleted-rs','kind':'ReplicaSet','controller':True}]},'status':{}}
    snapshot=rollout_snapshot(profile(),d,[rs],[current,old],prior_replica_set_uids=('deleted-rs',))
    assert not snapshot.complete and set(snapshot.pod_uids)=={'new-pod','old-pod'}
    assert rollout_snapshot(profile(),d,[rs],[current],prior_replica_set_uids=('deleted-rs',)).complete


def test_adapter_remembers_verified_replicaset_uids_across_rollout_reads(monkeypatch):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    d=deployment();d['status'].update(availableReplicas=1)
    new={'metadata':{'uid':'new-rs','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]},'spec':{'template':copy.deepcopy(d['spec']['template'])}}
    old=copy.deepcopy(new);old['metadata']['uid']='old-rs';old['spec']['template']['spec']['containers'][0]['image']='other'
    pods=[{'metadata':{'uid':name,'ownerReferences':[{'uid':owner,'kind':'ReplicaSet','controller':True}]},'status':{'conditions':[{'type':'Ready','status':'True'}]}} for name,owner in [('new-pod','new-rs'),('old-pod','old-rs')]]
    data={'deployment':d,'replicasets':{'items':[new,old]},'pods':{'items':pods}}
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    monkeypatch.setattr(adapter,'_request',lambda kind,**kwargs:copy.deepcopy(data[kind]))
    assert not adapter.inspect()[1].complete
    data['replicasets']['items']=[new]
    assert not adapter.inspect()[1].complete
    data['pods']['items']=pods[:1]
    assert adapter.inspect()[1].complete


def test_evidence_collects_owned_replica_and_pod_events_not_unrelated_events(monkeypatch):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    d=deployment();d['spec']['selector']={'matchLabels':{'app':'web'}}
    rs={'metadata':{'uid':'rs1','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]}}
    pod={'metadata':{'uid':'p1','name':'web-1','ownerReferences':[{'uid':'rs1','kind':'ReplicaSet','controller':True}]},
         'status':{'conditions':[{'type':'PodScheduled','status':'False','reason':'Unschedulable'}]}}
    events={'u1':[{'reason':'ScalingReplicaSet','involvedObject':{'uid':'u1'},'eventTime':'2026-01-01T00:00:00Z'}],
            'rs1':[{'reason':'FailedCreate','involvedObject':{'uid':'rs1'}}],
            'p1':[{'reason':'FailedScheduling','message':'Insufficient cpu','involvedObject':{'uid':'p1'}},
                  {'reason':'Unrelated','involvedObject':{'uid':'other'}}]}
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    calls=[]
    def request(kind,**kwargs):
        calls.append((kind,kwargs))
        if kind=='deployment':return copy.deepcopy(d)
        if kind=='replicasets':return {'items':[copy.deepcopy(rs)]}
        if kind=='pods':return {'items':[copy.deepcopy(pod)]}
        if kind=='events':return {'items':copy.deepcopy(events[kwargs['event_uid']])}
        if kind=='logs':return 'failed to start'
        raise AssertionError(kind)
    monkeypatch.setattr(adapter,'_request',request)
    result=adapter.evidence()
    assert {e['reason'] for e in result['events']}=={'ScalingReplicaSet','FailedCreate','FailedScheduling'}
    assert {e['source_uid'] for e in result['events']}=={'u1','rs1','p1'}
    assert next(e for e in result['events'] if e['source_uid']=='u1')['event_time']=='2026-01-01T00:00:00Z'
    assert {kwargs['event_uid'] for kind,kwargs in calls if kind=='events'}=={'u1','rs1','p1'}
    assert all(kwargs['label_selector']=='app=web' for kind,kwargs in calls if kind in ('pods','replicasets'))


def test_inspect_uses_selector_and_fails_closed_on_incomplete_list(monkeypatch):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    d=deployment();d['spec']['selector']={'matchLabels':{'app':'web'}}
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    calls=[]
    def request(kind,**kwargs):
        calls.append((kind,kwargs))
        if kind=='deployment':return copy.deepcopy(d)
        if kind=='replicasets':return {'items':[]}
        if kind=='pods':raise ValueError('kubernetes_list_too_large')
        raise AssertionError(kind)
    monkeypatch.setattr(adapter,'_request',request)
    with pytest.raises(ValueError,match='list_too_large'):adapter.inspect(capacity=True)
    assert ('replicasets',{'label_selector':'app=web'}) in calls
    assert ('pods',{'label_selector':'app=web'}) in calls


def test_pod_pagination_is_bounded_and_preserves_selector(monkeypatch):
    import io,json
    from types import SimpleNamespace
    from urllib.parse import parse_qs,urlsplit
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    adapter.credentials=SimpleNamespace(endpoint='https://127.0.0.1:6443',token=SimpleNamespace(get_secret_value=lambda:'fixture-token'))
    paths=[];endless=False
    class Channel:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):pass
        def sendall(self,wire):
            path=wire.split(b' ',2)[1].decode();paths.append(path)
            query=parse_qs(urlsplit(path).query)
            assert query['labelSelector']==['app=web']
            page=int(query.get('continue',['0'])[0])
            payload={'items':[{'metadata':{'uid':f'pod-{page}'}}],
                     'metadata':{'continue':str(page+1) if endless or page==0 else ''}}
            body=json.dumps(payload).encode()
            self.stream=io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        def recv_into(self,target):return self.stream.readinto(target)
    channel=Channel();adapter.context=SimpleNamespace(wrap_socket=lambda raw,**kwargs:raw)
    monkeypatch.setattr('socket.create_connection',lambda *args,**kwargs:channel)
    assert [p['metadata']['uid'] for p in adapter._request('pods',label_selector='app=web')['items']]==['pod-0','pod-1']
    paths.clear();endless=True
    with pytest.raises(ValueError,match='list_too_large'):adapter._request('pods',label_selector='app=web')
    assert len(paths)==8


def test_evidence_uid_budget_prioritizes_anomalous_pod(monkeypatch):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    d=deployment()
    sets=[{'metadata':{'uid':f'rs-{n}','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]}} for n in range(16)]
    pod={'metadata':{'uid':'bad-pod','name':'web-bad','ownerReferences':[{'uid':'rs-0','kind':'ReplicaSet','controller':True}]},
         'status':{'containerStatuses':[{'state':{'waiting':{'reason':'ImagePullBackOff'}}}]}}
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    queried=[]
    def request(kind,**kwargs):
        if kind=='deployment':return copy.deepcopy(d)
        if kind=='replicasets':return {'items':copy.deepcopy(sets)}
        if kind=='pods':return {'items':[copy.deepcopy(pod)]}
        if kind=='events':
            queried.append(kwargs['event_uid']);return {'items':[]}
        if kind=='logs':return 'image pull denied'
        raise AssertionError(kind)
    monkeypatch.setattr(adapter,'_request',request)
    evidence=adapter.evidence()
    assert 'bad-pod' in queried
    assert evidence['partial'] and evidence['truncated']


def test_evidence_benign_event_flood_does_not_hide_owned_pod_failure(monkeypatch):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    d=deployment()
    rs={'metadata':{'uid':'rs1','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]}}
    pod={'metadata':{'uid':'p1','name':'web-1','ownerReferences':[{'uid':'rs1','kind':'ReplicaSet','controller':True}]},
         'status':{'containerStatuses':[{'state':{'waiting':{'reason':'ImagePullBackOff'}}}]}}
    benign=lambda uid,n:{'type':'Normal','reason':'Scheduled','message':f'normal-{n}',
                         'involvedObject':{'uid':uid},'eventTime':f'2026-01-01T00:00:{n:02d}Z'}
    events={'u1':[benign('u1',n) for n in range(20)],
            'rs1':[{'type':'Warning','reason':'FailedCreate','involvedObject':{'uid':'rs1'},
                    'eventTime':'2026-01-01T00:01:00Z'}],
            'p1':[benign('p1',n) for n in range(21)]+[
                {'type':'Warning','reason':'FailedScheduling','message':'Insufficient cpu',
                 'involvedObject':{'uid':'p1'},'eventTime':'2026-01-01T00:02:00Z'}]}
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    queried=[]
    def request(kind,**kwargs):
        if kind=='deployment':return copy.deepcopy(d)
        if kind=='replicasets':return {'items':[copy.deepcopy(rs)]}
        if kind=='pods':return {'items':[copy.deepcopy(pod)]}
        if kind=='events':
            queried.append(kwargs['event_uid']);return {'items':copy.deepcopy(events[kwargs['event_uid']])}
        if kind=='logs':return 'image pull denied'
        raise AssertionError(kind)
    monkeypatch.setattr(adapter,'_request',request)
    evidence=adapter.evidence()
    assert set(queried)=={'u1','rs1','p1'}
    assert evidence['events'][0]['reason']=='FailedScheduling'
    assert {'FailedScheduling','FailedCreate'} <= {event['reason'] for event in evidence['events']}
    assert len(evidence['events'])==20 and evidence['partial'] and evidence['truncated']


def test_read_only_evidence_without_deployment_selector_is_partial(monkeypatch):
    from a4diag_target.repair_kubernetes import KubernetesAdapter,identity
    d={'metadata':{'uid':'u1','generation':1}}
    rs={'metadata':{'uid':'rs1','ownerReferences':[{'uid':'u1','kind':'Deployment','controller':True}]}}
    pod={'metadata':{'uid':'p1','name':'web-1','ownerReferences':[{'uid':'rs1','kind':'ReplicaSet','controller':True}]}}
    adapter=object.__new__(KubernetesAdapter);adapter.profile=profile();adapter.identity=identity(profile());adapter.timeout_seconds=5
    def request(kind,**kwargs):
        if kind=='deployment':return copy.deepcopy(d)
        if kind=='replicasets':return {'items':[copy.deepcopy(rs)]}
        if kind=='pods':return {'items':[copy.deepcopy(pod)]}
        if kind=='events':return {'items':[{'reason':'FailedScheduling','involvedObject':{'uid':'p1'}}] if kwargs['event_uid']=='p1' else []}
        if kind=='logs':return ''
        raise AssertionError(kind)
    monkeypatch.setattr(adapter,'_request',request)
    evidence=adapter.evidence()
    assert evidence['partial']
    assert any(e['reason']=='FailedScheduling' for e in evidence['events'])

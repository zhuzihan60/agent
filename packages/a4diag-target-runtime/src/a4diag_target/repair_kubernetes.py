"""Exact namespace Deployment CAS; credentials and API paths are never model input."""
import math
import re

from a4diag.repair_profiles import kubernetes_scope
from a4diag_builtin_plugins.capability_kubernetes import DeploymentIdentity, DeploymentSnapshot

RESTART = 'a4diag.io/restart-transaction'
RESTART_PATH = '/spec/template/metadata/annotations/a4diag.io~1restart-transaction'

class KubernetesRefusal(ValueError):
    """A closed adapter diagnostic code, never an API response message."""
    def __init__(self,code):
        self.code=code
        super().__init__(code)



def identity(profile):
    return DeploymentIdentity(**dict(zip(('cluster_id','namespace','name','uid'),kubernetes_scope(profile.resource))))


def _tests(uid, resource_version):
    if not isinstance(uid,str) or not uid or not isinstance(resource_version,str) or not resource_version:
        raise ValueError('deployment_precondition_required')
    return [{'op':'test','path':'/metadata/uid','value':uid},
            {'op':'test','path':'/metadata/resourceVersion','value':resource_version}]


def deployment_patch(*,uid,resource_version,container_index,prior_image,desired_image):
    if type(container_index) is not int or not 0 <= container_index <= 127:
        raise ValueError('invalid_container_index')
    if not isinstance(desired_image,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}',desired_image):
        raise ValueError('registered_image_digest_required')
    path=f'/spec/template/spec/containers/{container_index}/image'
    return [*_tests(uid,resource_version),{'op':'test','path':path,'value':prior_image},
            {'op':'replace','path':path,'value':desired_image}]


def restart_patch(deployment, transaction):
    metadata=deployment['metadata']; template=deployment['spec']['template']['metadata']
    patch=_tests(metadata['uid'],metadata['resourceVersion'])
    # Test the enclosing map to prove absence as JSON Patch has no absent test.
    # Never replace that map when present; preserve other controllers' keys.
    if 'annotations' not in template:
        patch += [{'op':'test','path':'/spec/template/metadata','value':template},
                  {'op':'add','path':'/spec/template/metadata/annotations','value':{RESTART:transaction}}]
    else:
        annotations=template['annotations']
        patch += [{'op':'test','path':'/spec/template/metadata/annotations','value':annotations},
                  {'op':'add','path':RESTART_PATH,'value':transaction}]
    return patch


def _count(value, replicas, *, surge=False):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value,str) and re.fullmatch(r'(?:0|[1-9][0-9]?|100)%',value):
        count=replicas*int(value[:-1])/100
        return math.ceil(count) if surge else math.floor(count)
    raise KubernetesRefusal('invalid_rollout_budget')


def prepare_deployment(profile, deployment):
    expected=identity(profile); meta=deployment['metadata']; spec=deployment['spec']; status=deployment.get('status',{})
    if meta['uid'] != expected.uid:
        raise KubernetesRefusal('deployment_identity_changed')
    replicas=spec.get('replicas',1)
    if type(replicas) is not int or not 1 <= replicas <= 1000:
        raise KubernetesRefusal('deployment_replicas_denied')
    if meta.get('deletionTimestamp'):
        raise KubernetesRefusal('deployment_deleting')
    if any('persistentVolumeClaim' in v or 'hostPath' in v for v in spec['template']['spec'].get('volumes',[])):
        raise KubernetesRefusal('stateless_deployment_required')
    if any('argocd' in m.get('manager','').lower() or 'flux' in m.get('manager','').lower() for m in meta.get('managedFields',[])):
        raise KubernetesRefusal('deployment_gitops_managed')
    if spec.get('paused'):
        raise KubernetesRefusal('deployment_paused')
    for metadata in (meta,spec['template'].get('metadata',{})):
        labels={**metadata.get('labels',{}),**metadata.get('annotations',{})}
        if any('argocd' in k.lower() or 'fluxcd' in k.lower() for k in labels):
            raise KubernetesRefusal('deployment_gitops_managed')
    if status.get('observedGeneration',0) != meta['generation']:
        raise KubernetesRefusal('deployment_concurrent_generation')
    strategy=spec.get('strategy',{})
    if strategy.get('type') != 'RollingUpdate':
        raise KubernetesRefusal('rolling_update_required')
    rollout=strategy.get('rollingUpdate',{})
    unavailable=_count(rollout.get('maxUnavailable','25%'),replicas)
    surge=_count(rollout.get('maxSurge','25%'),replicas,surge=True)
    limits=profile.constraints
    if unavailable>limits.max_unavailable or replicas-unavailable<limits.min_available or not unavailable+surge:
        raise KubernetesRefusal('deployment_availability_budget')
    if replicas+surge>limits.capacity_replicas:
        raise KubernetesRefusal('deployment_capacity_budget')
    containers=spec['template']['spec']['containers']
    matches=[i for i,c in enumerate(containers) if c['name']==limits.container_name]
    if len(matches)!=1:
        raise KubernetesRefusal('registered_container_missing')
    return matches[0]


def _owned(obj, kind, uid):
    return any(o.get('kind')==kind and o.get('uid')==uid and o.get('controller') is True
               for o in obj.get('metadata',{}).get('ownerReferences',[]))


def _template(value):
    import copy
    template=copy.deepcopy(value)
    template.get('metadata',{}).get('labels',{}).pop('pod-template-hash',None)
    return template


def lineage(deployment, replica_sets, pods):
    owned=[r for r in replica_sets if _owned(r,'Deployment',deployment['metadata']['uid'])]
    ids={r['metadata']['uid'] for r in owned}
    return owned,[p for p in pods if any(_owned(p,'ReplicaSet',uid) for uid in ids)]


def rollout_snapshot(profile, deployment, replica_sets, pods, *, prior_replica_set_uids=()):
    expected=identity(profile)
    if deployment['metadata']['uid']!=expected.uid:
        raise KubernetesRefusal('deployment_identity_changed')
    owned,_=lineage(deployment,replica_sets,pods)
    known=set(prior_replica_set_uids)|{r['metadata']['uid'] for r in owned}
    pods=[p for p in pods if any(_owned(p,'ReplicaSet',uid) for uid in known)]
    current={r['metadata']['uid'] for r in owned
             if _template(r['spec']['template'])==_template(deployment['spec']['template'])}
    desired=deployment['spec'].get('replicas',1); status=deployment.get('status',{})
    current_pods=[p for p in pods if any(_owned(p,'ReplicaSet',uid) for uid in current)]
    ready=lambda p: not p['metadata'].get('deletionTimestamp') and any(c.get('type')=='Ready' and c.get('status')=='True' for c in p.get('status',{}).get('conditions',[]))
    reasons=[]; restarts=0
    for p in pods:
        for c in p.get('status',{}).get('containerStatuses',[]):
            restarts+=c.get('restartCount',0)
            reason=c.get('state',{}).get('waiting',{}).get('reason')
            if reason in ('CrashLoopBackOff','ImagePullBackOff','ErrImagePull','CreateContainerConfigError','ErrImageNeverPull'):
                reasons.append(reason)
    complete=(status.get('observedGeneration',0)>=deployment['metadata']['generation']
        and status.get('updatedReplicas',0)==desired and status.get('availableReplicas',0)>=desired
        and len(pods)==len(current_pods)==desired and all(ready(p) for p in current_pods) and not reasons)
    container=next(c for c in deployment['spec']['template']['spec']['containers'] if c['name']==profile.constraints.container_name)
    return DeploymentSnapshot(identity=expected,generation=deployment['metadata']['generation'],
        observed_generation=status.get('observedGeneration',0),replicas=desired,updated=status.get('updatedReplicas',0),
        available=status.get('availableReplicas',0),complete=complete,pod_uids=tuple(sorted(p['metadata']['uid'] for p in pods)),
        restart_count=restarts,image=container['image'],reasons=tuple(sorted(set(reasons))))


def check_capacity(profile, deployment, pods, quotas):
    replicas=deployment['spec'].get('replicas',1)
    surge=_count(deployment['spec']['strategy'].get('rollingUpdate',{}).get('maxSurge','25%'),replicas,surge=True)
    for pod in pods:
        if any(c.get('type')=='PodScheduled' and c.get('status')=='False' and c.get('reason')=='Unschedulable'
               for c in pod.get('status',{}).get('conditions',[])):
            raise KubernetesRefusal('deployment_capacity_unschedulable')
    for quota in quotas:
        status=quota.get('status',{}); hard=status.get('hard',{}); used=status.get('used',{})
        if not hard or set(hard)-{'pods','count/pods','count/replicasets.apps','count/deployments.apps'}:
            raise KubernetesRefusal('deployment_unsupported_quota')
        for key,limit in hard.items():
            if not str(limit).isdigit() or not str(used.get(key,'')).isdigit():
                raise KubernetesRefusal('deployment_unsupported_quota')
            extra=surge if key in ('pods','count/pods') else (1 if key=='count/replicasets.apps' else 0)
            if int(used[key])+extra>int(limit):
                raise KubernetesRefusal('deployment_capacity_quota')


from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class KubernetesCredentials(BaseModel):
    model_config=ConfigDict(extra='forbid',frozen=True)
    endpoint: str
    ca_pem: str = Field(min_length=1,max_length=65536,repr=False)
    token: SecretStr

    @field_validator('endpoint')
    @classmethod
    def check_endpoint(cls,value):
        from a4diag.repair_profiles import kubernetes_endpoint
        return kubernetes_endpoint(value)

    @field_validator('token')
    @classmethod
    def check_token(cls,value):
        if not re.fullmatch(r'[A-Za-z0-9._~-]{1,16384}',value.get_secret_value()):
            raise ValueError('invalid_kubernetes_token')
        return value


class KubernetesAPIError(ValueError):
    def __init__(self,status):
        self.status=status
        super().__init__('kubernetes_conflict' if status in (409,422) else f'kubernetes_http_{status}')


class KubernetesCompensationConflict(ValueError):
    pass


class KubernetesPatchRejected(ValueError):
    """An authenticated API explicitly rejected an atomic patch before change."""


class KubernetesAdapter:
    """All endpoints derive from one installed profile. No redirect/proxy/kubeconfig."""
    def __init__(self,profile):
        import ssl
        from pathlib import Path
        from a4diag_target.repair_install import protected_json
        self.profile=profile; self.identity=identity(profile)
        path=Path('/etc/a4diag-target/kubernetes')/(profile.constraints.credential_id+'.json')
        # protected_json checks each ancestor; credentials additionally require 0600.
        if path.lstat().st_mode & 0o077:
            raise ValueError('unprotected_kubernetes_credentials')
        try:
            self.credentials=KubernetesCredentials.model_validate(protected_json(path))
        except ValueError:
            raise ValueError('invalid_kubernetes_credentials') from None
        if self.credentials.endpoint!=profile.constraints.endpoint:
            raise ValueError('kubernetes_endpoint_mismatch')
        self.context=ssl.create_default_context(cadata=self.credentials.ca_pem)
        self.timeout_seconds=5

    def _request(self,kind,*,patch=None,pod=None):
        import http.client
        import json
        import socket
        import time
        from urllib.parse import urlsplit,quote
        from a4diag_target.repair_docker import _DeadlineReader
        base=f'/apis/apps/v1/namespaces/{self.identity.namespace}'
        core=f'/api/v1/namespaces/{self.identity.namespace}'
        paths={'deployment':base+'/deployments/'+self.identity.name,
            'replicasets':base+'/replicasets?limit=200','pods':core+'/pods?limit=200',
            'resourcequotas':core+'/resourcequotas?limit=100',
            'events':core+'/events?limit=100&fieldSelector='+quote('involvedObject.uid='+self.identity.uid,safe='')}
        if kind=='logs' and isinstance(pod,str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}',pod):
            path=core+'/pods/'+pod+'/log?follow=false&tailLines=100&limitBytes=16384&container='+self.profile.constraints.container_name
        elif kind in paths:
            path=paths[kind]
        else:
            raise ValueError('kubernetes_endpoint_denied')
        if patch is not None and kind!='deployment':
            raise ValueError('kubernetes_write_denied')
        deadline=time.monotonic()+self.timeout_seconds
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise TimeoutError('kubernetes_api_timeout')
            return value
        url=urlsplit(self.credentials.endpoint)
        body=b'' if patch is None else json.dumps(patch,separators=(',',':')).encode()
        method='GET' if patch is None else 'PATCH'
        wire=(f'{method} {path} HTTP/1.1\r\nHost: {url.netloc}\r\nAuthorization: Bearer {self.credentials.token.get_secret_value()}\r\nContent-Type: application/json-patch+json\r\nAccept: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()+body
        with socket.create_connection((url.hostname,url.port),timeout=remaining()) as raw:
            raw.settimeout(remaining())
            with self.context.wrap_socket(raw,server_hostname=url.hostname) as channel:
                channel.settimeout(remaining());channel.sendall(wire)
                response=http.client.HTTPResponse(_DeadlineReader(channel,deadline));response.begin()
                limit=16384 if kind=='logs' else 1048576
                content=response.read(limit+1);remaining()
                if response.status!=200:
                    # Server messages and response bodies may contain secrets. Never relay them.
                    raise KubernetesAPIError(response.status)
                if len(content)>limit:raise ValueError('kubernetes_response_too_large')
                if kind=='logs':return content.decode('utf-8','replace')
                value=json.loads(content)
                if type(value) is not dict:raise ValueError('invalid_kubernetes_response')
                if value.get('metadata',{}).get('continue'):raise ValueError('kubernetes_list_too_large')
                return value

    def deployment(self):
        value=self._request('deployment')
        if value.get('metadata',{}).get('uid')!=self.identity.uid:raise KubernetesRefusal('deployment_identity_changed')
        return value

    def inspect(self,*,capacity=False):
        import time
        deadline=time.monotonic()+self.timeout_seconds
        def read(kind):
            self.timeout_seconds=deadline-time.monotonic()
            if self.timeout_seconds<=0:raise TimeoutError('kubernetes_api_timeout')
            return self._request(kind)
        deployment=read('deployment')
        if deployment.get('metadata',{}).get('uid')!=self.identity.uid:raise KubernetesRefusal('deployment_identity_changed')
        sets=read('replicasets')['items'];pods=read('pods')['items']
        if capacity:
            prepare_deployment(self.profile,deployment)
            _,owned=lineage(deployment,sets,pods)
            check_capacity(self.profile,deployment,owned,read('resourcequotas')['items'])
            # Events are bounded diagnostic input, never patch or health authority.
            read('events')
        owned,_=lineage(deployment,sets,pods)
        # A background-deleted old ReplicaSet can leave terminating Pods. Retain
        # only UIDs whose Deployment controller ownership was actually verified.
        known=getattr(self,'_lineage_uids',set())|{r['metadata']['uid'] for r in owned}
        if len(known)>512:raise ValueError('kubernetes_lineage_too_large')
        self._lineage_uids=known
        return deployment,rollout_snapshot(self.profile,deployment,sets,pods,prior_replica_set_uids=known)

    def change(self,deployment,action,transaction):
        index=prepare_deployment(self.profile,deployment)
        if action=='restore-image':
            patch=deployment_patch(uid=self.identity.uid,resource_version=deployment['metadata']['resourceVersion'],
                container_index=index,prior_image=deployment['spec']['template']['spec']['containers'][index]['image'],
                desired_image=self.profile.constraints.known_image)
        elif action=='restart':patch=restart_patch(deployment,transaction)
        else:raise ValueError('kubernetes_action_denied')
        return self._request('deployment',patch=patch)

    def compensate(self,current,record):
        index=record['index'];path=f'/spec/template/spec/containers/{index}/image'
        if (current['metadata']['uid']!=self.identity.uid
                or current['spec']['template']['spec']['containers'][index]['name']!=self.profile.constraints.container_name
                or current['spec']['template']['spec']['containers'][index]['image']!=record['written']):
            raise KubernetesCompensationConflict('kubernetes_compensation_conflict')
        patch=[*_tests(self.identity.uid,current['metadata']['resourceVersion']),
            {'op':'test','path':path,'value':record['written']},{'op':'replace','path':path,'value':record['prior']}]
        return self._request('deployment',patch=patch)

    def evidence(self):
        import time
        from a4diag.redaction import redact
        deadline=time.monotonic()+self.timeout_seconds
        def read(kind,**kwargs):
            self.timeout_seconds=deadline-time.monotonic()
            if self.timeout_seconds<=0:raise TimeoutError('kubernetes_api_timeout')
            return self._request(kind,**kwargs)
        deployment=read('deployment');sets=read('replicasets')['items'];pods=read('pods')['items']
        if deployment['metadata']['uid']!=self.identity.uid:raise KubernetesRefusal('deployment_identity_changed')
        _,owned=lineage(deployment,sets,pods)
        events=read('events')['items']
        evidence={'untrusted':True,'events':[{'reason':str(e.get('reason',''))[:128],
            'message':str(e.get('message',''))[:1024]} for e in events[:20]],'logs':[],'truncated':len(events)>20 or len(owned)>3}
        for pod in sorted(owned,key=lambda p:p['metadata']['uid'])[:3]:
            try:content=read('logs',pod=pod['metadata']['name'])
            except KubernetesAPIError:content='logs_unavailable'
            evidence['logs'].append({'pod_uid':pod['metadata']['uid'],'content':content[:4096]})
            evidence['truncated'] |= len(content)>=4096
        after=read('deployment')
        if (after['metadata']['uid'],after['metadata']['generation'])!=(deployment['metadata']['uid'],deployment['metadata']['generation']):
            raise ValueError('deployment_evidence_changed')
        return redact(evidence)


class KubernetesPlugin:
    """One durable patch intent, then bounded observation with no further mutation."""
    def __init__(self,profile,*,adapter=None,state=None):
        from a4diag_target.repair_install import STATE_ROOT
        self.profile=profile;self.adapter=adapter or KubernetesAdapter(profile)
        self.state=state or STATE_ROOT/profile.id

    def _record(self,request):
        import hashlib
        from a4diag.domain import canonical_json_bytes
        from a4diag.repair_profiles import profile_digest
        bound={'transaction':request.transaction_id,'step':request.step_id,
               'operation':request.operation.model_dump(mode='json'),'profile':profile_digest(self.profile)}
        return self.state/('kubernetes-'+hashlib.sha256(canonical_json_bytes(bound)).hexdigest()+'.json'),bound

    def _read(self,deadline,*,capacity=False):
        import time
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('kubernetes_operation_budget_exhausted')
        self.adapter.timeout_seconds=min(5,remaining)
        result=self.adapter.inspect(capacity=capacity)
        if time.monotonic()>=deadline:raise TimeoutError('kubernetes_operation_budget_exhausted')
        return result

    def _match(self,deployment,marker):
        if (deployment['metadata']['uid'],deployment['metadata']['resourceVersion'])!=(marker['uid'],marker['resource_version']):
            raise ValueError('deployment_precondition_conflict')
        index=prepare_deployment(self.profile,deployment)
        if index!=marker['index'] or deployment['spec']['template']['spec']['containers'][index]['image']!=marker['prior']:
            raise ValueError('deployment_precondition_conflict')

    def admit_effect(self,request,*,deadline=None):
        import time
        from a4diag_target.repair_admission import EffectAdmissionRejected
        try:
            deadline=deadline if deadline is not None else time.monotonic()+request.operation.timeout_seconds
            deployment,_=self._read(deadline,capacity=request.lifecycle=='apply')
            if request.lifecycle=='apply':self._match(deployment,request.marker)
        except (OSError,ValueError,KeyError,TypeError) as error:
            raise EffectAdmissionRejected(str(error)[:256]) from error

    async def dispatch(self,request,*,deadline=None):
        import asyncio
        import secrets
        import time
        from a4diag.domain import canonical_json_bytes
        from a4diag_target.repair_install import protected_json,_atomic_file
        from a4diag_builtin_plugins.capability_common import PrepareResult,EffectResult,VerifyResult,ReconcileResult
        deadline=deadline if deadline is not None else time.monotonic()+request.operation.timeout_seconds
        path,bound=self._record(request)
        if request.lifecycle=='prepare':
            deployment,snapshot=self._read(deadline,capacity=True)
            index=prepare_deployment(self.profile,deployment)
            marker={'uid':identity(self.profile).uid,'resource_version':deployment['metadata']['resourceVersion'],
                'generation':deployment['metadata']['generation'],'index':index,
                'prior':deployment['spec']['template']['spec']['containers'][index]['image'],'nonce':secrets.token_hex(16)}
            if path.exists():
                record=protected_json(path)
                if record['bound']!=bound:raise ValueError('kubernetes_record_mismatch')
                marker=record['marker']
            else:
                _atomic_file(path,canonical_json_bytes({'bound':bound,'marker':marker,'stage':'prepared'}),0o600)
            return PrepareResult(marker=marker)
        record=protected_json(path)
        if record['bound']!=bound or record['marker']!=request.marker:raise ValueError('kubernetes_marker_mismatch')
        def save():_atomic_file(path,canonical_json_bytes(record),0o600)
        if request.lifecycle=='apply':
            if record['stage']=='completed':return EffectResult(**record['result'])
            if record['stage']!='prepared':raise ValueError('kubernetes_operation_uncertain')
            deployment,_=self._read(deadline,capacity=True);self._match(deployment,record['marker'])
            record['stage']='intent';save()
            self.adapter.timeout_seconds=deadline-time.monotonic()
            if self.adapter.timeout_seconds<=0:raise TimeoutError('kubernetes_operation_budget_exhausted')
            try:updated=self.adapter.change(deployment,request.operation.action,record['marker']['nonce'])
            except KubernetesAPIError as error:
                # Only definitive rejections prove no change. Other HTTP errors retain
                # the persisted intent because the patch outcome can be unknown.
                if error.status in (403,409,422):
                    record.update(stage='rejected',reason=str(error));save()
                    raise KubernetesPatchRejected(str(error)) from error
                raise
            generation=updated['metadata']['generation']
            record.update(stage='observing',generation=generation,
                written=self.profile.constraints.known_image if request.operation.action=='restore-image' else record['marker']['nonce'],
                rollout_deadline=int(time.time())+self.profile.constraints.rollout_timeout_seconds)
            save()
            rollout_deadline=time.monotonic()+self.profile.constraints.rollout_timeout_seconds
            reason='kubernetes_rollout_deadline';snapshot=None;ok=False
            while time.monotonic()<rollout_deadline:
                try:
                    _,snapshot=self._read(rollout_deadline)
                    if snapshot.generation!=generation:
                        reason='kubernetes_rollout_conflict';break
                    if snapshot.complete:
                        ok=True;reason=None;break
                except (ValueError,OSError):
                    reason='kubernetes_rollout_unavailable';break
                await asyncio.sleep(min(1,max(0,rollout_deadline-time.monotonic())))
            result=EffectResult(ok=ok,changed=True,reason=reason,data={'generation':generation,
                'snapshot':snapshot.model_dump(mode='json') if snapshot else None})
            record.update(stage='completed',result=result.model_dump(mode='json'));save()
            return result
        if request.lifecycle=='undo':
            if request.operation.action=='restart':
                return EffectResult(ok=False,changed=False,reason='restart_old_pods_not_restorable')
            if record['stage']=='compensated':
                return EffectResult(ok=True,changed=False,reason='image_field_already_restored')
            if record['stage'] != 'completed':
                return EffectResult(ok=False,changed=False,reason='kubernetes_compensation_unavailable')
            current,_=self._read(deadline)
            compensation={'index':record['marker']['index'],'prior':record['marker']['prior'],'written':record['written']}
            self.adapter.timeout_seconds=deadline-time.monotonic()
            if self.adapter.timeout_seconds<=0:raise TimeoutError('kubernetes_operation_budget_exhausted')
            record['stage']='compensation_intent';save()
            try:self.adapter.compensate(current,compensation)
            except (KubernetesCompensationConflict,KubernetesAPIError) as error:
                if isinstance(error,KubernetesAPIError) and error.status not in (403,409,422):raise
                record['stage']='compensation_conflict';save()
                return EffectResult(ok=False,changed=False,reason='kubernetes_compensation_conflict')
            record['stage']='compensated';save()
            return EffectResult(ok=True,changed=True,reason='image_field_restored_business_health_unproven')
        _,snapshot=self._read(deadline)
        data={'snapshot':snapshot.model_dump(mode='json'),'operation_stage':record['stage']}
        if request.lifecycle=='verify':
            return VerifyResult(ok=record['stage']=='completed' and snapshot.generation==record['generation'] and snapshot.complete,data=data)
        state={'prepared':'not_applied','rejected':'not_applied','intent':'unknown','observing':'applied',
               'completed':'applied','compensated':'not_applied','compensation_intent':'unknown','compensation_conflict':'unknown'}[record['stage']]
        return ReconcileResult(state=state,data=data)

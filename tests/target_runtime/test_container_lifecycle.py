import asyncio
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace

import pytest

from tests.target_runtime.test_repair_docker import CID, IMAGE


@pytest.fixture
def protected_state():
    path = Path(tempfile.mkdtemp(prefix='a4diag-container-test-', dir='/var/lib'))
    try:
        yield path
    finally:
        shutil.rmtree(path)


def profile(**changes):
    from a4diag.repair_profiles import RepairProfile
    return RepairProfile.model_validate({'id':'container-demo', 'target_id':'demo',
        'capability':'containers', 'resource':'docker/0/'+CID, 'actions':['start','restart'],
        'constraints':{'image_digest':IMAGE}, 'recovery_check_ids':['web'],
        'expires_at':253402300799, **changes})


def test_container_profile_binds_uid_and_forbids_model_parameters():
    from a4diag.domain import Operation
    from a4diag.repair_profiles import authorize_profile, profile_digest
    selected = profile(resource='podman/1001/'+CID)
    operation = Operation(capability='containers', action='restart', resource=selected.resource,
        parameters={}, verify={'recovery_check_ids':['web']}, model_risk='high', undo=None)
    assert authorize_profile(selected, operation, now=1, presented_digest=profile_digest(selected)).profile_id == selected.id
    for parameters in ({'uid':0}, {'socket':'/run/docker.sock'}, {'container_id':CID}):
        with pytest.raises(ValueError):
            authorize_profile(selected, operation.model_copy(update={'parameters':parameters}), now=1,
                              presented_digest=profile_digest(selected))
    for resource in ('docker/1/'+CID, 'podman/01001/'+CID, 'docker/0/name'):
        with pytest.raises(ValueError):
            profile(resource=resource)


class Runtime:
    def __init__(self):
        from a4diag_target.repair_containers import ContainerSnapshot
        self.snapshot = ContainerSnapshot(identity={'runtime':'docker','container_id':CID,
            'image_digest':IMAGE,'owner_uid':0}, running=True, health='unknown',
            exit_code=0, oom_killed=False, restart_count=0, started_at='before')
        self.effects = 0

    def inspect(self, identifier):
        assert identifier == CID
        return self.snapshot

    def restart(self, identifier, timeout_seconds):
        self.effects += 1
        self.snapshot = self.snapshot.model_copy(update={'started_at':'after'})


def request(lifecycle, marker=None):
    from a4diag.domain import Operation
    return SimpleNamespace(lifecycle=lifecycle, marker=marker, transaction_id='tx1', step_id='0',
        operation=Operation(capability='containers',action='restart',resource='docker/0/'+CID,
            parameters={},verify={'recovery_check_ids':['web']},model_risk='high',undo=None))


def test_running_alone_never_reconciles_a_restart_and_replay_never_restarts(protected_state):
    from a4diag_target.repair_containers import ContainerPlugin
    runtime = Runtime()
    plugin = ContainerPlugin(profile(), adapter=runtime, state=protected_state)
    marker = asyncio.run(plugin.dispatch(request('prepare'))).marker
    assert asyncio.run(plugin.dispatch(request('reconcile',marker))).state == 'not_applied'
    effect = asyncio.run(plugin.dispatch(request('apply',marker)))
    assert effect.ok and effect.changed
    assert asyncio.run(plugin.dispatch(request('reconcile',marker))).state == 'applied'
    assert asyncio.run(plugin.dispatch(request('apply',marker))).ok
    assert runtime.effects == 1


def test_apply_identity_change_and_unknown_timeout_never_retry(protected_state):
    from a4diag_target.repair_containers import ContainerPlugin
    runtime = Runtime()
    plugin = ContainerPlugin(profile(), adapter=runtime, state=protected_state)
    marker = asyncio.run(plugin.dispatch(request('prepare'))).marker
    runtime.snapshot = runtime.snapshot.model_copy(update={'identity':runtime.snapshot.identity.model_copy(update={'image_digest':'sha256:'+'d'*64})})
    with pytest.raises(ValueError):
        asyncio.run(plugin.dispatch(request('apply', marker)))
    assert runtime.effects == 0
    runtime.snapshot = Runtime().snapshot
    def timeout(*args, **kwargs):
        runtime.effects += 1
        raise TimeoutError()
    runtime.restart = timeout
    with pytest.raises(TimeoutError):
        asyncio.run(plugin.dispatch(request('apply', marker)))
    assert asyncio.run(plugin.dispatch(request('reconcile', marker))).state == 'unknown'
    with pytest.raises(ValueError):
        asyncio.run(plugin.dispatch(request('apply', marker)))
    assert runtime.effects == 1


def test_installer_registers_exact_podman_uid_without_writable_trust_state():
    from a4diag_target.repair_install import plan_helpers, sandbox_properties
    selected = profile(resource='podman/22001/'+CID)
    binding, = plan_helpers([selected], [{'profile_id':selected.id,'adapter':'podman'}], peer_uid=1000)
    properties = sandbox_properties(binding)
    assert 'BindReadOnlyPaths=/run/user/22001/podman/podman.sock:/run/a4diag-podman-22001.sock' in properties
    assert not any('/run/user/0/' in p or '/run/systemd' in p or '/run/dbus' in p for p in properties)
    assert 'User=0' in properties


def test_managed_container_routes_before_ticket_only_to_separate_current_profile():
    from a4diag.repair_workflow import route_container_plan
    from a4diag.domain import Plan
    from tests.target_runtime.test_repair_protocol import _profile
    selected=profile(constraints={'image_digest':IMAGE,'service_unit':'demo.service','service_profile_id':'service-demo'})
    service=_profile(id='service-demo',actions=('restart',),recovery_check_ids=('business',))
    target=SimpleNamespace(repair_profiles=(selected,service))
    original=Plan(target_id='demo',target_fingerprint='test',operations=(request('prepare').operation,))
    routed=route_container_plan(target,original,now=100)
    assert routed.operations[0].capability=='services'
    assert routed.operations[0].parameters=={'unit':'demo.service'}
    assert routed.operations[0].verify=={'recovery_check_ids':['business']}
    assert routed.operations[0].model_risk.value=='high'
    for profiles in ((selected,), (selected,service.model_copy(update={'expires_at':99}))):
        with pytest.raises(ValueError):route_container_plan(SimpleNamespace(repair_profiles=profiles),original,now=100)


def test_identity_read_time_is_inside_apply_budget(protected_state):
    import time
    from a4diag_target.repair_containers import ContainerPlugin
    runtime=Runtime();plugin=ContainerPlugin(profile(),adapter=runtime,state=protected_state)
    prepare=request('prepare')
    prepare.operation=prepare.operation.model_copy(update={'timeout_seconds':1})
    marker=asyncio.run(plugin.dispatch(prepare)).marker
    original=runtime.inspect
    def slow(identifier):
        time.sleep(1.1)
        return original(identifier)
    runtime.inspect=slow
    apply=request('apply',marker)
    apply.operation=apply.operation.model_copy(update={'timeout_seconds':1})
    with pytest.raises(TimeoutError):asyncio.run(plugin.dispatch(apply))
    assert runtime.effects==0


def container_worker_case(state, runtime, *, selected=None, timeout=1):
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11 as L
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag.repair_profiles import profile_digest
    from a4diag.repair_store import RepairStore
    from a4diag_target.policy import TargetPolicy
    from a4diag_target.repair_containers import ContainerPlugin
    from a4diag_target.repair_jobs import JobStore
    from tests.target_runtime.test_repair_protocol import _request,FINGERPRINT
    selected=selected or profile(standing_authorization=True)
    operation=request('prepare').operation.model_copy(update={'resource':selected.resource,'timeout_seconds':timeout})
    plugin=ContainerPlugin(selected,adapter=runtime,state=state)
    prepare=_request(selected,L.PREPARE,'container-worker-prepare',operation=operation,authorization_id=selected.id)
    marker=asyncio.run(plugin.dispatch(prepare)).marker
    apply=_request(selected,L.APPLY,'container-worker-apply',operation=operation,marker=marker,authorization_id=selected.id)
    key='sha256:'+'e'*64
    policy=TargetPolicy(target_id='demo',target_fingerprint=FINGERPRINT,controller_key_fingerprint=key,repair_profiles=(selected,))
    jobs=JobStore(state/'jobs.db');limits=RepairStore(jobs.path)
    job=jobs.ensure(apply.transaction_id,apply.step_id,canonical_operation_digest(operation),profile_digest=profile_digest(selected))
    jobs.bind_request(job.id,apply,controller_key_fingerprint=key)
    reservation=limits.reserve('demo',selected.resource,apply.transaction_id,151,600,2)
    limits.bind_job(reservation,job.id);limits.mark_started(reservation,151);jobs.start(job.id,now=151)
    return SimpleNamespace(plugin=plugin,jobs=jobs,limits=limits,job=job,policy=policy,request=apply,profile=selected)


def run_container_worker(case):
    from a4diag_target.repair_jobs import run_job
    from tests.target_runtime.test_repair_protocol import FINGERPRINT
    asyncio.run(run_job(case.jobs,case.job.id,policy=lambda:case.policy,identity_probe=lambda:FINGERPRINT,
                         adapter=None,plugins={'containers':case.plugin},clock=lambda:151))
    return case.jobs.get(case.job.id)


@pytest.mark.parametrize('delay_at',[1,2])
def test_worker_admission_and_dispatch_share_one_deadline(protected_state,delay_at):
    import time
    runtime=Runtime();case=container_worker_case(protected_state,runtime)
    original=runtime.inspect;reads=[]
    def slow(identifier):
        reads.append(runtime.timeout_seconds)
        time.sleep((1.1 if len(reads)==1 else 0) if delay_at==1 else .6)
        return original(identifier)
    runtime.inspect=slow
    job=run_container_worker(case)
    assert runtime.effects==0
    assert reads[0]<=1
    if delay_at==1:
        assert job.state=='failed' and job.changed is False and job.result['change_verified'] is True
        assert len(reads)==1
        case.limits.reserve('demo',case.profile.resource,'after-timeout',9999,600,2)
    else:
        assert len(reads)==2 and reads[1]<.5
        assert job.state=='unknown' and job.changed is None


@pytest.mark.parametrize('timeout_at',['admission','effect'])
def test_owner_child_timeout_worker_classifies_effect_boundary(protected_state,monkeypatch,timeout_at):
    import json,subprocess
    from tests.target_runtime.test_repair_podman import owner_runtime
    selected,runtime,reply=owner_runtime(monkeypatch)
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:reply)
    case=container_worker_case(protected_state,runtime,selected=selected)
    mutations=[]
    def child(*args,**kwargs):
        action=json.loads(kwargs['input'])['action']
        if action in ('start','restart'):mutations.append(action)
        if timeout_at=='admission' or action=='restart':
            raise subprocess.TimeoutExpired(args[0],kwargs['timeout'])
        return reply
    monkeypatch.setattr(subprocess,'run',child)
    job=run_container_worker(case)
    if timeout_at=='admission':
        assert mutations==[]
        assert job.state=='failed' and job.changed is False and job.result['change_verified'] is True
        case.limits.reserve('demo',selected.resource,'after-timeout',9999,600,2)
    else:
        from a4diag.repair_store import RepairLimitError
        assert mutations==['restart'] and job.state=='unknown' and job.changed is None
        with pytest.raises(RepairLimitError,match='resource_busy'):
            case.limits.reserve('demo',selected.resource,'after-timeout',9999,600,2)
        assert asyncio.run(case.plugin.dispatch(case.request.model_copy(update={'lifecycle':'reconcile'}))).state=='unknown'

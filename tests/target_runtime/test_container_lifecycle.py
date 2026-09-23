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

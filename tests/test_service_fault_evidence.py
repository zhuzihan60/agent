import asyncio
import pytest

RAW = ('ActiveState=active\nSubState=running\nInvocationID=abc\n'
       'MainPID=42\nExecMainStatus=0\nResult=success\nNRestarts=3\n')


def test_active_is_not_equivalent_to_business_healthy():
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    state = parse_service_fault_snapshot(RAW, observed_at=100)
    assert state.n_restarts == 3
    assert not hasattr(state, 'business_recovered')


@pytest.mark.parametrize('raw', [RAW.replace('MainPID=42\n',''), RAW+'NRestarts=4\n',
    RAW.replace('NRestarts=3','NRestarts=unknown'), RAW.replace('Result=success','Result='),
    RAW+'Other=x\n', RAW.replace('ActiveState=active','ActiveState=unknown'),
    RAW.replace('InvocationID=abc','InvocationID=')])
def test_fault_snapshot_rejects_missing_unknown_or_ambiguous(raw):
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    with pytest.raises(ValueError):
        parse_service_fault_snapshot(raw, observed_at=100)


@pytest.mark.parametrize('state', ['inactive', 'failed'])
def test_no_historical_invocation_is_valid_for_stopped_service(state):
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    raw=RAW.replace('ActiveState=active',f'ActiveState={state}').replace('InvocationID=abc','InvocationID=').replace('MainPID=42','MainPID=0')
    assert parse_service_fault_snapshot(raw,observed_at=100).invocation_id == ''


def test_compound_action_requires_every_constituent():
    from test_repair_authorization import _profile, _operation
    from a4diag.repair_profiles import RepairProfile, authorize_profile, profile_digest
    data=_profile().model_dump();data['actions']=['reset-failed-restart']
    profile=RepairProfile.model_validate(data)
    op=_operation(action='reset-failed-restart')
    with pytest.raises(ValueError,match='constituent'):
        authorize_profile(profile,op,now=100,presented_digest=profile_digest(profile))
    data['actions']+=['reset-failed','restart']
    profile=RepairProfile.model_validate(data)
    assert authorize_profile(profile,op,now=100,presented_digest=profile_digest(profile))


def test_compound_apply_is_fixed_sequence_with_truthful_partial_change():
    from a4diag_builtin_plugins.capability_services import ServicesPlugin, ServiceMarker
    from a4diag_builtin_plugins.capability_common import CapabilityApplyParams, CommandOutcome
    from contract.test_capability_plugins import service_state, operation as op, apply_params
    class Adapter:
        calls=[]
        async def run_command(self,argv,**kwargs):
            self.calls.append(argv)
            return CommandOutcome(returncode=1 if argv[1]=='restart' else 0,stdout='',stderr='')
    adapter=Adapter();plugin=ServicesPlugin(transport=adapter)
    operation=op(capability='services',action='reset-failed-restart',resource='example.service',parameters={'unit':'example.service'})
    marker=ServiceMarker(action=operation.action,unit=operation.resource,prior=service_state())
    result=asyncio.run(plugin.apply(apply_params(operation,marker.model_dump(mode='json'))))
    assert not result.ok and result.changed
    assert adapter.calls==[['/usr/bin/systemctl','reset-failed','example.service'],['/usr/bin/systemctl','restart','example.service']]


def test_marker_resource_cannot_redirect_reset():
    from a4diag_builtin_plugins.capability_services import ServicesPlugin, ServiceMarker
    from a4diag_builtin_plugins.capability_common import CapabilityApplyParams, CapabilityError
    from contract.test_capability_plugins import service_state, operation as op, apply_params, FakeTarget
    operation=op(capability='services',action='reset-failed',resource='example.service',parameters={'unit':'example.service'})
    marker=ServiceMarker(action='reset-failed',unit='other.service',prior=service_state())
    with pytest.raises(CapabilityError,match='marker_resource_mismatch'):
        asyncio.run(ServicesPlugin(transport=FakeTarget()).apply(apply_params(operation,marker.model_dump(mode='json'))))


@pytest.mark.parametrize('raw', [RAW.replace('NRestarts=3\n',''),RAW+'NRestarts=4\n',RAW+'Mystery=1\n'])
def test_diagnostic_fault_evidence_rejects_incomplete_or_duplicate_properties(tmp_path,monkeypatch,raw):
    from a4diag_target import diagnostics
    from a4diag_builtin_plugins.transport_common import RunOutcome
    from target_runtime.test_diagnostic_reads import policy
    class Runner:
        async def run(self,*args,**kwargs):
            return RunOutcome(started=True,timed_out=False,returncode=0,stdout=raw+'LoadState=loaded\nUnitFileState=static\n')
    monkeypatch.setattr(diagnostics,'SubprocessRunner',Runner)
    response=asyncio.run(diagnostics.read_diagnostic(tmp_path,{'method':'read','kind':'service_state','unit':'demo.service','limit':8192},policy()))
    assert response=={'ok':False,'reason':'read_failed'}


@pytest.mark.parametrize('payload',[b'',b'signed request'])
def test_fast_child_stdin_close_only_makes_nonempty_dispatch_uncertain(monkeypatch,payload):
    from a4diag_builtin_plugins import transport_common as transport
    killed=[]
    class Input:
        def write(self,data):pass
        async def drain(self):raise BrokenPipeError()
        def close(self):pass
    async def run():
        class Process:
            stdin=Input();returncode=0
            stdout=asyncio.StreamReader();stderr=asyncio.StreamReader()
            stdout.feed_data(b'actual bounded result');stdout.feed_eof();stderr.feed_eof()
            async def wait(self):return 0
        async def spawn(*args,**kwargs):return Process()
        monkeypatch.setattr(asyncio,'create_subprocess_exec',spawn)
        monkeypatch.setattr(transport,'_kill_process_group',lambda p:killed.append(p))
        return await transport.SubprocessRunner().run(['/usr/bin/true'],payload=payload,output_limit_bytes=1024)
    result=asyncio.run(run())
    assert result.stdout=='actual bounded result'
    assert result.timed_out is bool(payload)
    assert result.returncode==(None if payload else 0)
    assert bool(killed) is bool(payload)


def test_reset_does_not_claim_verified_zero_counters_or_restored_history():
    from a4diag_builtin_plugins.capability_services import ServicesPlugin,ServiceMarker
    from a4diag_builtin_plugins.capability_common import CommandOutcome
    from contract.test_capability_plugins import FakeTarget,service_state,operation,verify_params
    class Target(FakeTarget):
        async def run_command(self,argv,**kwargs):
            if any('NRestarts' in part for part in argv):return CommandOutcome(returncode=0,stdout=RAW)
            return await super().run_command(argv,**kwargs)
    target=Target();target.service_state['example.service']=service_state(active='active',sub='running')
    op=operation(capability='services',action='reset-failed',resource='example.service',parameters={'unit':'example.service'})
    marker=ServiceMarker(action=op.action,unit=op.resource,prior=target.service_state[op.resource]).model_dump(mode='json')
    plugin=ServicesPlugin(transport=target);params=verify_params(op,marker)
    assert not asyncio.run(plugin.verify(params)).ok
    assert not asyncio.run(plugin.verify_restored(params)).ok

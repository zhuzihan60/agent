import threading
from dataclasses import replace

from a4diag.audit import AuditWriter
from a4diag.runtime import Runtime
from a4diag.poller import RuntimePoller
from a4diag.cli import run_serve_loop
from test_workflow_v3 import deps_factory
from test_repair_workflow import repair_deps, event
from test_repair_workflow_transport import wire


def _hold_workflow(path, acquired, release):
    from a4diag.transaction_store import TransactionStore
    with TransactionStore(path).workflow_guard('repair-1'):
        acquired.set()
        release.wait(20)


def runtime_for(deps, tmp_path):
    return Runtime(settings=deps.settings, registry=deps.registry, policy=deps.policy,
        approvals=deps.approvals, transactions=deps.transactions, tickets=deps.tickets,
        checkpointer=deps.checkpointer, plugins=deps.plugins,
        audit=AuditWriter(tmp_path/'audit.jsonl'), clock=deps.clock, settings_loader=deps.settings_loader)


def test_actual_daemon_heartbeat_completes_existing_job_without_model_calls(deps_factory, tmp_path):
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    runtime = runtime_for(deps, tmp_path)
    assert runtime.handle(event()).status == 'execution_unknown'
    model_calls = list(deps.plugins.model.calls)
    class Stop:
        stopped = False
        waits = []
        def is_set(self):
            return self.stopped
        def set(self):
            self.stopped = True
        def wait(self, seconds):
            self.waits.append(seconds)
            deps.clock.value += 5
            if len(self.waits) == 1:
                jobs.complete(launches[0], state='succeeded', changed=True, result={'ok': True}, now=deps.clock())
            if len(self.waits) == 2:
                self.stopped = True
            return self.stopped
    stop = Stop()
    poller = RuntimePoller(runtime, state_path=tmp_path/'poller.db', report_root=tmp_path/'reports')
    run_serve_loop(runtime, stop, poller=poller)
    assert deps.transactions.get('repair-1').status.value == 'succeeded'
    assert deps.plugins.model.calls == model_calls
    assert len(launches) == 1
    assert stop.waits == [5, 5]
    assert list((tmp_path/'reports').rglob('*.yaml'))


def test_cancelled_plan_keeps_observing_without_new_writes(deps_factory, tmp_path):
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    runtime = runtime_for(deps, tmp_path)
    runtime.handle(event())
    runtime.cancel_repair('repair-1')
    jobs.complete(launches[0], state='partial', changed=True, result={'ok': False}, now=100)
    results = runtime.poll_repair_jobs()
    assert results[0].status == 'execution_unknown'
    assert requests[-1]['lifecycle'] == 'query_job'
    assert not any(r['lifecycle'] == 'undo' for r in requests)
    assert deps.transactions.repair_cancelled('repair-1')
    assert runtime.poll_repair_jobs() == ()


def test_heartbeat_runs_while_alert_fetch_is_blocked(deps_factory, tmp_path):
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    runtime = runtime_for(deps, tmp_path)
    runtime.handle(event())
    entered, release = threading.Event(), threading.Event()
    class Source:
        calls = 0
        def active_alerts(self):
            self.calls += 1
            entered.set()
            assert release.wait(10)
            return []
    source = Source()
    class Stop:
        stopped = False
        def is_set(self): return self.stopped
        def set(self): self.stopped = True
        def wait(self, seconds):
            if threading.current_thread().name == 'a4diag-runtime-poller':
                release.wait(10)
            else:
                assert entered.wait(10)
                self.stopped = True
                release.set()
            return self.stopped
    poller = RuntimePoller(runtime, alert_source=source, state_path=tmp_path/'poller.db', report_root=tmp_path/'reports')
    run_serve_loop(runtime, Stop(), poller=poller)
    assert requests[-1]['lifecycle'] == 'query_job'
    assert source.calls == 1


def test_poll_candidate_rotation_is_bounded_and_skips_finished_transactions(deps_factory, tmp_path):
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    runtime = runtime_for(deps, tmp_path)
    runtime.handle(event())
    assert deps.transactions.repair_poll_candidates(after='', limit=1) == ('repair-1',)
    assert deps.transactions.repair_poll_candidates(after='repair-1', limit=1) == ()
    jobs.complete(launches[0], state='succeeded', changed=True, result={'ok': True}, now=100)
    assert runtime.poll_repair_jobs(limit=1)[0].status == 'succeeded'
    assert deps.transactions.repair_poll_candidates(after='', limit=1) == ()


def test_process_guard_coordinates_daemon_and_separate_runtime_resume(deps_factory, tmp_path):
    import multiprocessing
    deps, jobs, launches, requests, policy, host = wire(repair_deps(deps_factory, tmp_path), tmp_path)
    runtime = runtime_for(deps, tmp_path)
    runtime.handle(event())
    other_runtime = runtime_for(deps, tmp_path)
    ctx = multiprocessing.get_context('spawn')
    acquired, release = ctx.Event(), ctx.Event()
    holder = ctx.Process(target=_hold_workflow, args=(deps.transactions.path, acquired, release))
    holder.start()
    started, completed = threading.Event(), threading.Event()
    result = []
    def resume():
        started.set()
        result.append(other_runtime.resume('repair-1'))
        completed.set()
    thread = threading.Thread(target=resume)
    try:
        assert acquired.wait(10)
        assert runtime.poll_repair_jobs() == ()
        thread.start()
        assert started.wait(10)
        assert not completed.wait(0.1)
        assert [r['lifecycle'] for r in requests] == ['prepare', 'apply']
        release.set()
        holder.join(10)
        assert completed.wait(10)
        thread.join(10)
        assert result[0].status == 'execution_unknown'
        assert requests[-1]['lifecycle'] == 'query_job'
        assert len(launches) == 1
    finally:
        release.set()
        if holder.is_alive():
            holder.terminate()
        holder.join(10)
        if thread.ident is not None:
            thread.join(10)


def test_terminal_known_job_advances_only_next_frozen_step(deps_factory, tmp_path):
    from a4diag.policy_engine import PolicyEngine
    from a4diag.recovery import RecoveryCheck
    from test_workflow_v3 import POLICY_KEY
    from test_repair_authorization import _operation
    deps = repair_deps(deps_factory, tmp_path)
    target = deps.settings.targets[0]
    target = target.model_copy(update={
        'repair_profiles': (*target.repair_profiles, target.repair_profiles[0].model_copy(update={
            'id': 'second', 'resource': 'second.service', 'recovery_check_ids': ('second-health',)})),
        'recovery_checks': (*target.recovery_checks, RecoveryCheck(id='second-health', kind='service_active', resource='second.service')),
        'capabilities': (target.capabilities[0].model_copy(update={'resources': ('demo.service', 'second.service')}),)})
    settings = deps.settings.model_copy(update={'targets': (target,)})
    deps = replace(deps, settings=settings, policy=PolicyEngine(settings, deps.registry, authorization_key=POLICY_KEY))
    deps.plugins.model.plan_result = deps.plugins.model.plan_result.model_copy(update={'operations': (
        _operation(), _operation(resource='second.service', parameters={'unit': 'second.service'},
                                 verify={'recovery_check_ids': ['second-health']}))})
    deps, jobs, launches, requests, policy, host = wire(deps, tmp_path)
    runtime = runtime_for(deps, tmp_path)
    runtime.handle(event())
    jobs.complete(launches[0], state='succeeded', changed=True, result={'ok': True}, now=100)
    assert runtime.poll_repair_jobs()[0].status == 'execution_unknown'
    assert len(launches) == 2
    assert [r['step_id'] for r in requests if r['lifecycle'] == 'apply'] == ['0', '1']
    jobs.complete(launches[1], state='succeeded', changed=True, result={'ok': True}, now=100)
    assert runtime.poll_repair_jobs()[0].status == 'succeeded'


def test_fair_poll_rotates_past_unknown_and_busy_transactions(deps_factory, tmp_path):
    from a4diag.transaction_store import PreparedStep, TransactionStatus
    from a4diag.repair_jobs import RepairJob
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag.domain import canonical_json_bytes
    from test_repair_authorization import _operation
    deps = repair_deps(deps_factory, tmp_path)
    runtime = runtime_for(deps, tmp_path)
    operation = _operation()
    for index in (1, 2):
        tx = f'repair-{index}'
        deps.transactions.begin(tx, f'target-{index}', 'd' * 64, now=100)
        deps.transactions.record_prepared(tx, [PreparedStep('0',
            canonical_json_bytes(operation.model_dump(mode='json')).decode(), '{}', '{}')], now=100)
        deps.transactions.transition(tx, TransactionStatus.EXECUTING, now=100)
        deps.transactions.record_repair_job(RepairJob(id=f'job-{index}', transaction_id=tx,
            step_id='0', profile_digest='b' * 64, operation_digest=canonical_operation_digest(operation),
            state='running', started_at=100), target_id=f'target-{index}', profile_digest='b' * 64, now=100)
    with deps.transactions.workflow_guard('repair-1'):
        assert runtime.poll_repair_jobs(limit=1) == ()
        assert tuple(r.transaction_id for r in runtime.poll_repair_jobs(limit=1)) == ('repair-2',)
    # Missing checkpoints remain unknown, but cannot monopolize the next tick.
    assert tuple(r.transaction_id for r in runtime.poll_repair_jobs(limit=1)) == ('repair-1',)
    assert tuple(r.transaction_id for r in runtime.poll_repair_jobs(limit=1)) == ('repair-2',)

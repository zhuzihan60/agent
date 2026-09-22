"""The single compiled stop -> bounded cleanup -> restore writer workflow.

The journal is core-owned, never populated from model/event dependency fields.
Every uncertain mutation is observed; no APPLY or UNDO is redispatched.
"""
import json
from contextlib import contextmanager

from a4diag.domain import Plan, StepResult, canonical_json_bytes, plan_digest
from a4diag.policy_engine import canonical_operation_digest
from a4diag.preparation import PreparationDependency
from a4diag.plugin_api.ticket import OperationPhase
from a4diag.transaction_store import PreparedStep, TransactionStatus, DispatchStatus


def is_disk_plan(state):
    return any(op.get('capability') == 'disk' for op in state.get('plan', {}).get('operations', []))


def staged_transaction(db, transaction_id):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='disk_workflows'").fetchone():
        return False
    return db.execute('SELECT 1 FROM disk_workflows WHERE transaction_id=?', (transaction_id,)).fetchone() is not None


class DiskJournal:
    def __init__(self, store, state, target):
        self.store, self.tx = store, state['transaction_id']
        plan = Plan.model_validate(state['plan'])
        if len(plan.operations) != 2:
            raise ValueError('disk_requires_exact_stop_cleanup_plan')
        stop, disk = plan.operations
        profiles = {p.id:p for p in target.repair_profiles}
        bindings = state['repair_bindings']
        with self.db() as db:
            existing=staged_transaction(db,self.tx)
        if (set(bindings) != {'0','1'} or (stop.capability,stop.action,disk.capability,disk.action)
                != ('services','stop','disk','cleanup')
                or (not existing and profiles[bindings['1']['profile_id']].constraints.writer_unit != stop.resource)
                or plan_digest(plan) != state['digest']):
            raise ValueError('disk_requires_exact_stop_cleanup_plan')
        dep = PreparationDependency(stop_step_id='0', stop_profile_id=bindings['0']['profile_id'],
            stop_profile_digest=bindings['0']['profile_digest'], stop_operation_digest=canonical_operation_digest(stop),
            dependent_step_id='1', dependent_profile_id=bindings['1']['profile_id'],
            dependent_profile_digest=bindings['1']['profile_digest'], dependent_operation_digest=canonical_operation_digest(disk))
        self.dependency = dep
        encoded = canonical_json_bytes({'plan':state['digest'], 'dependency':dep.identity()}).decode()
        with self.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS disk_workflows
                (transaction_id TEXT PRIMARY KEY, identity TEXT NOT NULL, failure TEXT,
                 finally_required INTEGER NOT NULL DEFAULT 1, restored INTEGER NOT NULL DEFAULT 0)''')
            db.execute('INSERT OR IGNORE INTO disk_workflows(transaction_id,identity) VALUES (?,?)', (self.tx,encoded))
            if db.execute('SELECT identity FROM disk_workflows WHERE transaction_id=?',(self.tx,)).fetchone()[0] != encoded:
                raise ValueError('disk_workflow_identity_changed')

    @contextmanager
    def db(self):
        db = self.store._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def row(self):
        with self.db() as db:
            return dict(db.execute('SELECT * FROM disk_workflows WHERE transaction_id=?',(self.tx,)).fetchone())

    def failure(self, reason):
        with self.db() as db:
            db.execute('UPDATE disk_workflows SET failure=COALESCE(failure,?) WHERE transaction_id=?',(reason,self.tx))

    def restored(self):
        with self.db() as db:
            db.execute('UPDATE disk_workflows SET restored=1 WHERE transaction_id=?',(self.tx,))


def run_disk_workflow(deps, state, *, target_for, ready):
    from a4diag.repair_workflow import (issue_repair_ticket, reserve_attempt, record_job,
        job_result, observe_job, record_effect, plan_authorization)
    from a4diag.writer_holds import controller_mutation_guard, record_controller_restoration
    from a4diag.workflow import PreparedEffect
    from a4diag.repair_jobs import RepairJobResponse
    from a4diag.transaction_store import UnknownTransactionError
    store, tx, clock = deps.transactions, state['transaction_id'], deps.clock
    plan = Plan.model_validate(state['plan'])
    journal = None

    def gate():
        target = target_for(state)
        if store.repair_cancelled(tx):
            raise PermissionError('repair_cancelled_manual_writer_recovery')
        if deps.plugins.collector.verify_identity(target) != plan.target_fingerprint:
            raise PermissionError('target_identity_changed')
        plan_authorization(deps,state,target,plan,now=clock())
        return target

    def dependency(step, phase):
        dep = journal.dependency
        if step == '1' or phase not in ('prepare','apply'):
            jobs = [j for j in store.repair_jobs(tx) if j.step_id=='0']
            if len(jobs) != 1 or jobs[0].state != 'succeeded':
                raise ValueError('stop_job_unproven')
            dep = dep.model_copy(update={'stop_job_id':jobs[0].id})
        return dep

    def ticket(step, phase, fields):
        target = gate()
        if phase in ('prepare','apply'):
            checked = ready(state)
            if not checked.ok:
                raise PermissionError(checked.status)
        return target, issue_repair_ticket(deps,state,target,plan.operations[int(step)],step,
            OperationPhase(phase),fields,now=clock(),preparation_dependency=dependency(step,phase))

    def dispatch(step, phase):
        return next((d for d in store.get_dispatches(tx) if d.step_id==step and d.phase.value==phase),None)

    def prepared(step):
        return next((s for s in store.get_steps(tx) if s.step_id==step),None)

    def prepare(step):
        if prepared(step) is not None:
            return
        prior = dispatch(step,'prepare')
        if prior is not None:
            # PREPARE has no effect. A lost candidate snapshot is abandoned;
            # a previously stopped writer still has its finally obligation.
            if prior.status is DispatchStatus.DISPATCHED:
                store.complete_dispatch(prior.dispatch_id,now=clock())
            raise ValueError('disk_prepare_snapshot_lost')
        target, token = ticket(step,'prepare',{})
        d = store.begin_dispatch(tx,step,phase='prepare',dispatch_id=f'{tx}:prepare:{step}',ticket=token,now=clock())
        try:
            value = PreparedEffect.model_validate(deps.plugins.executor.prepare(target,step,plan.operations[int(step)],token))
            store.complete_prepare_dispatch(d.dispatch_id,PreparedStep(step_id=step,
                operation_json=canonical_json_bytes(plan.operations[int(step)].model_dump(mode='json')).decode(),
                pre_state_json=canonical_json_bytes(value.pre_state).decode(),
                plugin_marker_json=canonical_json_bytes(value.marker).decode()),now=clock())
        except Exception:
            if store.pending_dispatch(tx) is not None:
                store.complete_dispatch(d.dispatch_id,now=clock())
            raise

    def apply(step):
        operation = plan.operations[int(step)]
        marker = json.loads(prepared(step).plugin_marker_json)
        prior = dispatch(step,'apply')
        if prior is not None:
            known = next((r for r in store.get_results(tx) if r.step_id==step and r.phase=='apply' and r.status!='unknown'),None)
            if prior.status is DispatchStatus.COMPLETED and known is not None:
                observe_job(deps,state,target_for(state),step,now=clock())
                return StepResult.model_validate_json(known.payload_json)
            observed=observe_job(deps,state,target_for(state),step,now=clock())
            result = job_result(observed)
            if step=='1' and observed.state=='partial' and observed.result.get('worker_exited') is True:
                result=StepResult(ok=False,status='partial',data={'job_id':observed.id,
                    'changed':observed.changed,'result':observed.result})
        else:
            target, token = ticket(step,'apply',{'marker':marker})
            reserve_attempt(deps,state,target,operation,step,now=clock())
            prior = store.begin_dispatch(tx,step,phase='apply',dispatch_id=f'{tx}:apply:{step}',ticket=token,now=clock())
            record_effect(deps,state,step,None)
            with controller_mutation_guard(deps,state,target,operation,step,marker,token):
                response = deps.plugins.executor.apply(target,step,operation,marker,token)
            if not isinstance(response,RepairJobResponse):
                raise ValueError('disk_requires_durable_job')
            result = job_result(record_job(deps,state,response,now=clock()))
        if result.status=='unknown':
            raise RuntimeError('disk_job_pending_observe_only')
        store.complete_result_dispatch(prior.dispatch_id,phase='apply',status='succeeded' if result.ok else 'failed',
            payload=result.model_dump(mode='json'),now=clock())
        gate()
        return result

    def restore():
        if journal.row()['restored']:
            return
        step='0'
        operation=plan.operations[0]
        value=prepared(step)
        marker=json.loads(value.plugin_marker_json)
        target=gate()
        prior=dispatch(step,'undo')
        if prior is None:
            target, token=ticket(step,'undo',{'marker':marker,'undo':operation.undo})
            prior=store.begin_dispatch(tx,step,phase='undo',dispatch_id=f'{tx}:undo:0',ticket=token,now=clock())
            with controller_mutation_guard(deps,state,target,operation,step,marker,token):
                result=StepResult.model_validate(deps.plugins.executor.undo(target,step,operation,marker,operation.undo,token))
            if not result.ok:
                raise RuntimeError('writer_undo_unresolved_manual_recovery')
            record_controller_restoration(deps,state,step,phase='undo',result=result)
            store.complete_result_dispatch(prior.dispatch_id,phase='undo',status='succeeded',payload=result.model_dump(mode='json'),now=clock())
            prior=store.dispatch(prior.dispatch_id)
        else:
            # Rebuild signed read context without replaying a lost UNDO.
            observe_job(deps,state,target,step,now=clock())
        gate()
        restored=StepResult.model_validate(deps.plugins.executor.verify_restored(target,step,operation,marker,json.loads(value.pre_state_json)))
        if not restored.ok:
            raise RuntimeError('writer_restoration_unresolved_manual_recovery')
        # Target verify_restored itself requires actual successful UNDO evidence.
        # This recovers a crash between its signed reply and controller commit.
        if prior.status is DispatchStatus.DISPATCHED:
            record_controller_restoration(deps,state,step,phase='undo',result=restored)
            store.complete_result_dispatch(prior.dispatch_id,phase='undo',status='succeeded',payload=restored.model_dump(mode='json'),now=clock())
        record_controller_restoration(deps,state,step,phase='verify_restored',result=restored)
        stopped=next(j for j in store.repair_jobs(tx) if j.step_id=='0')
        record_effect(deps,state,step,stopped.changed,restored=True)
        journal.restored()

    try:
        target=target_for(state)
        try:
            transaction=store.get(tx)
        except UnknownTransactionError:
            gate()
            transaction=store.begin(tx,target.id,state['digest'],expected_operations=tuple(
                canonical_json_bytes(o.model_dump(mode='json')).decode() for o in plan.operations),now=clock())
        if transaction.status in {TransactionStatus.SUCCEEDED,TransactionStatus.ROLLBACK_PARTIAL,TransactionStatus.FAILED}:
            return {'status':transaction.status.value}
        journal=DiskJournal(store,state,target)
        try:
            gate()
        except Exception:
            # Current denial forbids continuation/finally, but signed owned
            # job observation must survive cancellation, expiry and revocation.
            for job in store.repair_jobs(tx):
                try:
                    observe_job(deps,state,target,job.step_id,now=clock())
                except Exception:
                    pass
            raise
        if transaction.status is TransactionStatus.CREATED:
            store.transition(tx,TransactionStatus.PREPARING,now=clock())
        if not journal.row()['failure'] and not journal.row()['restored']:
            prepare('0')
            if store.get(tx).status is TransactionStatus.PREPARING:
                store.finish_prepared(tx,expected_steps=1,now=clock())
            if store.get(tx).status is TransactionStatus.PREPARED:
                store.transition(tx,TransactionStatus.EXECUTING,now=clock())
            if not apply('0').ok:
                raise RuntimeError('stop_failed_manual_recovery')
            gate()
            stop=prepared('0')
            try:
                verified=deps.plugins.executor.verify(target_for(state),'0',plan.operations[0],json.loads(stop.plugin_marker_json))
            except Exception:
                verified=StepResult(ok=False,status='writer_stop_verification_unavailable')
            if not verified.ok:
                journal.failure('writer_stop_verification_failed')
            else:
                try:
                    prepare('1')
                except PermissionError:
                    raise
                except Exception as error:
                    journal.failure('cleanup_prepare_failed:'+type(error).__name__)
                if not journal.row()['failure']:
                    result=apply('1')
                    if not result.ok:
                        journal.failure('cleanup_failed')
                    else:
                        value=prepared('1')
                        try:
                            checked=deps.plugins.executor.verify(target_for(state),'1',plan.operations[1],json.loads(value.plugin_marker_json))
                        except Exception:
                            checked=StepResult(ok=False,status='capacity_verification_unavailable')
                        if not checked.ok:
                            journal.failure('capacity_verification_failed')
        restore()
        gate()
        view=deps.plugins.collector.acquire_read_view(target_for(state),plan.target_fingerprint)
        evidence=deps.plugins.collector.collect(target_for(state),view)
        business=StepResult.model_validate(deps.plugins.collector.final_verify(target_for(state),view,evidence))
        if not business.ok:
            journal.failure('business_verification_failed')
        failure=journal.row()['failure']
        if failure:
            store.transition(tx,TransactionStatus.ROLLBACK_RUNNING,now=clock())
            store.transition(tx,TransactionStatus.ROLLBACK_PARTIAL,now=clock())
        else:
            store.transition(tx,TransactionStatus.VERIFYING,now=clock())
            store.transition(tx,TransactionStatus.SUCCEEDED,now=clock())
        return {'status':'rollback_partial' if failure else 'succeeded', 'error':failure or '',
                'recovery_result':business.model_dump(mode='json'), 'reconcile_attempted':True}
    except Exception as error:
        return {'status':'execution_unknown','error':str(error), 'reconcile_attempted':True}

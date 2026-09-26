"""Finite, measured service observations; never infer business health from PID."""
from collections.abc import Sequence
from pydantic import BaseModel, ConfigDict, Field, StrictBool
import json
import os
import sqlite3
import uuid
from time import monotonic, time as wall_time

_PROCESS = uuid.uuid4().hex
RECOVERY_ACTIONS = frozenset({'start', 'restart', 'reset-failed', 'reset-failed-start', 'reset-failed-restart', 'restore-image'})
OBSERVATION_SCHEMA = '''CREATE TABLE IF NOT EXISTS service_observations (
    transaction_id TEXT PRIMARY KEY, phase TEXT NOT NULL, snapshot TEXT NOT NULL)'''


class HealthSample(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    resource_identity: str = Field(min_length=1)
    healthy: StrictBool
    restart_count: int = Field(ge=0, strict=True)


def observation_passed(samples: Sequence[HealthSample], *, min_duration_seconds: int = 60,
                       max_gap_seconds: int = 5) -> bool:
    if min_duration_seconds < 60 or not 0 < max_gap_seconds <= 5 or len(samples) < 2:
        return False
    first = samples[0]
    return (samples[-1].elapsed_seconds-first.elapsed_seconds >= min_duration_seconds
        and all(s.healthy and s.resource_identity == first.resource_identity
                and s.restart_count == first.restart_count for s in samples)
        and all(0 < b.elapsed_seconds-a.elapsed_seconds <= max_gap_seconds
                for a,b in zip(samples,samples[1:])))


class ServiceObservations:
    """Controller-owned state; process continuity and durable wall deadline differ."""
    def __init__(self, path, *, monotonic=None, wall=None, process=None):
        self.path = path
        self.monotonic = monotonic or globals()['monotonic']
        self.wall = wall or wall_time
        self.process = process or f'{os.getpid()}:{_PROCESS}'
        with sqlite3.connect(path) as db:
            db.execute(OBSERVATION_SCHEMA)

    def load(self, transaction_id, *, budget_seconds=300):
        with sqlite3.connect(self.path) as db:
            row = db.execute('SELECT snapshot FROM service_observations WHERE transaction_id=?', (transaction_id,)).fetchone()
        if row is None:
            data = {'phase':'preflight', 'deadline':self.wall()+budget_seconds,
                    'last_wall':self.wall(), 'started':self.monotonic(),
                    'monotonic_deadline':self.monotonic()+budget_seconds, 'remaining_budget':budget_seconds,
                    'process':self.process, 'samples':{}, 'last':{}, 'clock_invalid':False}
            self.save(transaction_id, data)
            return data
        data = json.loads(row[0])
        if self.wall() < data['last_wall']:
            data['clock_invalid'] = True
        if data['process'] != self.process:
            # Never splice observations across controller restart. Preserve the
            # original deadline and fault baseline to detect a later crash.
            data.update(process=self.process, started=self.monotonic(), samples={})
            data['monotonic_deadline']=self.monotonic()+min(data['remaining_budget'],max(0,data['deadline']-self.wall()))
        elif self.monotonic() < data['started']:
            data['clock_invalid'] = True
        return data

    def expired(self, data):
        return (data['clock_invalid'] or self.wall() < data['last_wall']
                or self.wall() >= data['deadline']
                or self.monotonic() >= data['monotonic_deadline']
                or self.monotonic() < data['started'])

    def remaining(self, data):
        return max(0, data['deadline']-self.wall()) if not self.expired(data) else 0

    def save(self, transaction_id, data):
        data['remaining_budget']=min(data['remaining_budget'],max(0,data['monotonic_deadline']-self.monotonic()))
        data['last_wall'] = max(data['last_wall'], self.wall())
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO service_observations VALUES(?,?,?) ON CONFLICT(transaction_id) DO UPDATE SET phase=excluded.phase,snapshot=excluded.snapshot',
                       (transaction_id, data['phase'], json.dumps(data,allow_nan=False)))


def service_operations(state):
    from a4diag.domain import Plan
    if not state.get('repair_bindings'):
        return []
    return [(str(i), op) for i,op in enumerate(Plan.model_validate(state['plan']).operations)
            if str(i) in state['repair_bindings'] and op.capability in ('services','containers','kubernetes') and op.action in RECOVERY_ACTIONS]


def observe_services(deps, state, target, phase):
    """One bounded read pass. Return ready/pending/failed with retained evidence."""
    operations = service_operations(state)
    if not operations:
        return 'ready', {}
    from a4diag.repair_profiles import RepairProfile, profile_digest
    from a4diag.domain import TargetConfig
    store = ServiceObservations(deps.transactions.path)
    bound_profiles = {}
    if phase == 'preflight':
        for step, _ in operations:
            binding = state['repair_bindings'][step]
            profile = next(p for p in target.repair_profiles if p.id == binding['profile_id'])
            if profile_digest(profile) != binding['profile_digest']:
                raise ValueError('frozen_observation_profile_mismatch')
            bound_profiles[step] = profile
    # Only the selected profiles can set a new budget. Post-observation loads
    # the already frozen deadline, even when current grants have been removed.
    budget = max([300]+[p.constraints.verification_window_seconds+120+(p.constraints.rollout_timeout_seconds if p.capability=='kubernetes' else 0) for p in bound_profiles.values()])
    data = store.load(state['transaction_id'],budget_seconds=budget)
    if data['phase'] == 'done':
        return data['outcome'], data
    if store.expired(data):
        data.update(phase='done', outcome='failed', reason='service_observation_budget_exhausted')
        store.save(state['transaction_id'],data)
        return 'failed', data
    if phase == 'post' and data['phase'] != 'post':
        data['preflight']={'samples':data['samples'],'evidence':data.get('evidence',{})}
        data.update(phase='post', samples={}, last={}, evidence={})
    if phase == 'preflight' and 'profiles' not in data:
        data['profiles']={step:p.model_dump(mode='json') for step,p in bound_profiles.items()}
        data['read_catalog']=target.model_dump(mode='json',include={'recovery_checks','diagnostic_probes'})
    # This view is passed only to service_health. Keep current connection,
    # identity and capability policy, with a consistent original check catalog.
    # General evidence sources are unused here and may reference replaced probes.
    read_target=TargetConfig.model_validate({**target.model_dump(mode='json'),**data['read_catalog'],
        'repair_profiles':tuple({p['id']:p for p in data['profiles'].values()}.values()),
        'evidence_sources':()})
    ready = True
    reason = None
    unavailable = False
    for step_id, op in operations:
        profile = RepairProfile.model_validate(data['profiles'][step_id])
        if profile_digest(profile) != state['repair_bindings'][step_id]['profile_digest']:
            raise ValueError('frozen_observation_profile_mismatch')
        if phase == 'preflight' and data['phase'] == 'ready':
            continue
        before = store.monotonic()
        previous = data['samples'].get(step_id, [])
        if previous and before-previous[-1]['elapsed_seconds'] < min(1,profile.constraints.sample_interval_seconds):
            ready = False
            continue
        try:
            collector = getattr(deps.plugins.collector, {'containers':'container_health','kubernetes':'kubernetes_health'}.get(op.capability,'service_health'))
            snapshot, healthy, detail = collector(read_target,op,profile,
                timeout_seconds=min(4.,store.remaining(data)))
            stamp = store.monotonic()  # Includes the complete HTTP/RPC duration.
            data.setdefault('evidence',{})[step_id] = {'fault':snapshot.model_dump(mode='json'), 'health':detail}
        except Exception as error:
            reason = 'service_evidence_unavailable:' + type(error).__name__
            unavailable = phase == 'post'
            break
        if store.expired(data):
            reason = 'service_observation_budget_exhausted'
            break
        if phase == 'post' and op.capability == 'kubernetes':
            accepted=[job.result.get('data',{}).get('generation') for job in deps.transactions.repair_jobs(state['transaction_id']) if job.step_id==step_id]
            if len(accepted)!=1 or snapshot.generation!=accepted[0]:
                reason='kubernetes_rollout_conflict'
                break
        if phase == 'preflight':
            kubernetes = op.capability == 'kubernetes'
            container = op.capability == 'containers'
            if healthy or (not (container or kubernetes) and snapshot.active_state not in ('active','failed','inactive')):
                reason = 'service_not_eligible'
                break
            if previous and stamp-previous[-1]['elapsed_seconds'] > 5:
                previous = []
            previous.append({'elapsed_seconds':stamp,'healthy':False,
                             'invocation_id':str(snapshot.generation) if kubernetes else (snapshot.started_at if container else snapshot.invocation_id),
                             'restart_count':snapshot.restart_count if container or kubernetes else snapshot.n_restarts})
            data['samples'][step_id] = previous[-301:]
            ready &= len(previous) >= 3 and stamp-previous[0]['elapsed_seconds'] >= 10
        else:
            kubernetes = op.capability == 'kubernetes'
            container = op.capability == 'containers'
            identity = (f'{target.id}:{op.resource}:{snapshot.identity.image_digest}:{snapshot.started_at}' if container
                        else ('' if kubernetes else f'{target.id}:{op.resource}:{snapshot.invocation_id}:{snapshot.main_pid}'))
            if kubernetes:
                identity=f'{target.id}:{op.resource}:{snapshot.generation}:{snapshot.image}:{snapshot.pod_uids}'
            sample = HealthSample(elapsed_seconds=stamp,resource_identity=identity,
                healthy=healthy and (snapshot.complete if kubernetes else (snapshot.running and not snapshot.oom_killed if container else snapshot.active_state=='active' and bool(snapshot.invocation_id))),
                restart_count=snapshot.restart_count if container or kubernetes else snapshot.n_restarts)
            last = data['last'].get(step_id)
            if last and (last['resource_identity'] != identity or last['restart_count'] != sample.restart_count):
                reason = 'service_failed_during_observation'
                break
            if container and not previous and (not last or not last['healthy']) and detail.get('identity_stable') is not False and snapshot.health=='starting' and snapshot.running and not snapshot.oom_killed:
                # Known startup is bounded by the original deadline. Establish
                # identity/restart baseline now, but accrue no healthy duration.
                data['last'][step_id] = sample.model_dump(mode='json')
                ready = False
                continue
            if not sample.healthy:
                reason = 'service_failed_during_observation'
                break
            data['last'][step_id] = sample.model_dump(mode='json')
            if previous and stamp-previous[-1]['elapsed_seconds'] > profile.constraints.sample_interval_seconds:
                previous = []
            previous.append(sample.model_dump(mode='json'))
            data['samples'][step_id] = previous[-601:]
            ready &= observation_passed([HealthSample.model_validate(s) for s in previous],
                min_duration_seconds=profile.constraints.verification_window_seconds,
                max_gap_seconds=profile.constraints.sample_interval_seconds)
    outcome = 'unknown' if unavailable else ('failed' if reason else ('ready' if ready else 'pending'))
    if reason or (ready and phase=='post'):
        data.update(phase='done',outcome=outcome,reason=reason or 'observation_period_recovered_root_cause_unproven')
    elif ready:
        data['phase'] = 'ready'
    store.save(state['transaction_id'], data)
    return outcome,data

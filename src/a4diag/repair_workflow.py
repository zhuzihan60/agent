"""Trusted controller repair selection and authorization orchestration.

Profiles supplement existing capability grants. A candidate ID is advisory;
only current registered configuration and the approval store grant authority.
"""
from a4diag.domain import Operation, Plan, Risk, TargetConfig, plan_digest
from a4diag.repair_profiles import RepairAuthorizationError, authorize_profile, profile_digest

TARGET_REGISTRATION_FIELDS = ('id', 'mode', 'identity_ref', 'identity_fingerprint', 'transport',
    'host', 'port', 'user', 'identity_file_ref', 'known_hosts_ref', 'operation_signing_key_ref', 'host_key_sha256')


def target_registration(target):
    return target.model_dump(mode='json', include=set(TARGET_REGISTRATION_FIELDS))


def check_target_registration(state, target):
    frozen = state.get('target_registration')
    if frozen is not None and frozen != target_registration(target):
        raise PermissionError('target_registration_changed')


def resolve_repair_profile(target: TargetConfig, operation: Operation, *, now: int,
                           candidate_id: str | None = None):
    scope = [p for p in target.repair_profiles
             if p.capability == operation.capability and p.resource == operation.resource]
    if candidate_id is not None:
        scope = [p for p in scope if p.id == candidate_id]
        if not scope:
            raise RepairAuthorizationError('profile_not_registered')
    if not scope:
        return None
    if len(scope) != 1:
        raise RepairAuthorizationError('profile_ambiguous')
    profile = scope[0]
    authorize_profile(profile, operation, now=now, presented_digest=profile_digest(profile))
    return profile


def resolve_plan(target, plan, *, now):
    bindings = {}
    for index, operation in enumerate(plan.operations):
        profile = resolve_repair_profile(target, operation, now=now)
        if profile is not None:
            bindings[str(index)] = {'profile_id': profile.id, 'profile_digest': profile_digest(profile)}
    return bindings


def current_profiles(target, plan, bindings, *, now):
    profiles = {}
    for step_id, binding in bindings.items():
        profile = resolve_repair_profile(target, plan.operations[int(step_id)], now=now,
                                         candidate_id=binding['profile_id'])
        if profile_digest(profile) != binding['profile_digest']:
            raise RepairAuthorizationError('profile_digest_mismatch')
        profiles[step_id] = profile
    return profiles


def plan_authorization(deps, state, target, plan, *, now, require_approval=True):
    """Check current config, common policy and authenticated approval evidence."""
    settings = deps.settings_loader() if deps.settings_loader is not None else deps.settings
    check_target_registration(state, target)
    current = next((t for t in settings.targets if t.id == target.id), None)
    if current is None or current != target:
        raise PermissionError('target_configuration_changed')
    profiles = current_profiles(target, plan, state.get('repair_bindings', {}), now=now)
    standing = len(profiles) == len(plan.operations) and all(p.standing_authorization for p in profiles.values())
    approval = deps.approvals.valid_approval(state['transaction_id'], expected_digest=plan_digest(plan),
                                           expected_target=target.id, now=now)
    # evaluate's legacy approval fields are supplied exclusively from actual
    # approval evidence or a completely checked all-standing registered plan.
    approval_id = approval.id if approval is not None else (next(iter(profiles.values())).id if standing else None)
    decision = deps.policy.with_settings(settings).evaluate(target, plan,
        critic_risk=Risk(state['critic_risk']),
        approval_digest=plan_digest(plan) if approval_id is not None else None, approval_id=approval_id)
    if require_approval and not decision.allowed:
        raise PermissionError(decision.reason)
    return decision, profiles, approval, standing


def issue_repair_ticket(deps, state, target, operation, step_id, phase, fields, *, now,
                        preparation_dependency=None):
    from a4diag.plugin_api.ticket import OperationTicketRequestV11, effect_payload_digest
    if deps.transactions.repair_cancelled(state['transaction_id']):
        raise PermissionError('repair_cancelled')
    plan = Plan.model_validate(state['plan'])
    if plan_digest(plan) != state['digest'] or plan.operations[int(step_id)] != operation:
        raise PermissionError('frozen_plan_changed')
    decision, profiles, approval, _ = plan_authorization(deps, state, target, plan, now=now)
    profile = profiles[step_id]
    kind = 'one_shot' if approval is not None else 'standing'
    authorization = deps.policy.authorize_repair(profile, operation,
        target_fingerprint=plan.target_fingerprint, digest=state['digest'],
        authorization_kind=kind, authorization_id=approval.id if approval is not None else profile.id,
        now=now, marker=fields.get('marker'))
    request = OperationTicketRequestV11(transaction_id=state['transaction_id'], step_id=step_id,
        target_id=target.id, target_fingerprint=plan.target_fingerprint, operation=operation,
        phase=phase, plan_digest=state['digest'], binding=authorization.binding,
        authorization_kind=authorization.authorization_kind, authorization_id=authorization.authorization_id,
        preparation_dependency=preparation_dependency,
        effect_payload_digest=effect_payload_digest(fields), ttl_seconds=deps.ticket_ttl_seconds)
    return deps.tickets.issue(request, authorization)


def record_job(deps, state, response, *, now):
    from a4diag.repair_jobs import RepairJobResponse
    job = RepairJobResponse.model_validate(response).job
    if job.transaction_id != state['transaction_id']:
        raise PermissionError('job_transaction_mismatch')
    binding = state['repair_bindings'][job.step_id]
    deps.transactions.record_repair_job(job, target_id=state['target_id'],
        profile_digest=binding['profile_digest'], now=now)
    from a4diag.repair_store import RepairStore
    from a4diag.repair_jobs import TERMINAL_JOB_STATES
    store = RepairStore(deps.transactions.path)
    operation = Plan.model_validate(state['plan']).operations[int(job.step_id)]
    reservation = store.reservation_for(state['target_id'], operation.resource, state['transaction_id'])
    store.bind_job(reservation, job.id)
    from a4diag.writer_holds import bind_controller_stop_job
    bind_controller_stop_job(deps, state, job)
    if job.state in TERMINAL_JOB_STATES and job.changed is not None:
        store.finish(reservation, job.state)
    record_effect(deps, state, job.step_id, job.changed)
    return job


def reserve_attempt(deps, state, target, operation, step_id, *, now):
    from a4diag.repair_store import RepairStore
    _, profiles, _, _ = plan_authorization(deps, state, target, Plan.model_validate(state['plan']), now=now)
    profile = profiles[step_id]
    store = RepairStore(deps.transactions.path)
    reservation = store.reserve(target.id, operation.resource, state['transaction_id'],
                                now, profile.cooldown_seconds, profile.hourly_limit)
    # Conservatively claim before effect dispatch; failure cannot auto-release.
    store.mark_started(reservation, now)


def record_effect(deps, state, step_id, changed, *, restored=None):
    from a4diag.repair_effects import RepairEffect
    kind = state.get('effect_kinds', {}).get(step_id)
    if kind is not None:
        previous = deps.transactions.repair_effects(state['transaction_id']).get(step_id)
        if restored is None:
            restored = previous.restoration_verified if previous is not None and previous.changed == changed else False
        deps.transactions.record_effect(state['transaction_id'], step_id,
            RepairEffect(kind=kind, changed=changed, restoration_verified=restored))


def job_origin(deps, state, step_id):
    """Authenticate historical APPLY proof; never authorize a new mutation."""
    from a4diag.plugin_api.ticket import OperationPhase, OperationTicketV11, effect_payload_digest
    from a4diag.policy_engine import canonical_operation_digest
    import json
    transaction = deps.transactions.get(state['transaction_id'])
    plan = Plan.model_validate(state['plan'])
    operation = plan.operations[int(step_id)]
    job = next(j for j in deps.transactions.repair_jobs(transaction.transaction_id) if j.step_id == step_id)
    dispatch = next(d for d in deps.transactions.get_dispatches(transaction.transaction_id)
                    if d.step_id == step_id and d.phase.value == 'apply')
    claim = deps.tickets.inspect_for_recovery(dispatch.ticket)
    prepared = next(s for s in deps.transactions.get_steps(transaction.transaction_id) if s.step_id == step_id)
    if (not isinstance(claim, OperationTicketV11) or claim.phase is not OperationPhase.APPLY
        or claim.transaction_id != transaction.transaction_id or claim.step_id != step_id
        or claim.target_id != transaction.target_id or claim.target_id != state['target_id']
        or claim.target_fingerprint != state['target_fingerprint']
        or claim.target_fingerprint != plan.target_fingerprint
        or claim.plan_digest != transaction.plan_digest or claim.plan_digest != plan_digest(plan)
        or claim.plan_digest != state['digest']
        or claim.operation_digest != canonical_operation_digest(operation)
        or claim.operation_digest != job.operation_digest
        or claim.binding.profile_digest != job.profile_digest
        or {'profile_id': claim.binding.profile_id, 'profile_digest': claim.binding.profile_digest}
            != state['repair_bindings'][step_id]
        or claim.effect_payload_digest != effect_payload_digest({'marker': json.loads(prepared.plugin_marker_json)})):
        raise PermissionError('job_origin_mismatch')
    return job, operation, claim


def observe_job(deps, state, target, step_id, *, now):
    check_target_registration(state, target)
    job, operation, claim = job_origin(deps, state, step_id)
    if target.id != claim.target_id:
        raise PermissionError('job_target_mismatch')
    response = deps.plugins.executor.query_job(target, step_id, operation, job.id, claim)
    if response.job.id != job.id:
        raise PermissionError('job_id_mismatch')
    return record_job(deps, state, response, now=now)


def job_result(job):
    from a4diag.domain import StepResult
    from a4diag.repair_jobs import TERMINAL_JOB_STATES
    unknown = job.state not in TERMINAL_JOB_STATES or job.changed is None
    return StepResult(ok=job.state == 'succeeded' and not unknown,
        status='unknown' if unknown else job.state,
        data={'job_id': job.id, 'job_state': job.state, 'changed': job.changed, 'result': job.result})


def completed_repair_dispatch(deps, state):
    """Recognize a terminal APPLY whose advancement checkpoint was interrupted.

    Re-enter normal observation and live authorization; this proof itself
    authorizes neither continuation nor compensation.
    """
    import json
    from a4diag.transaction_store import DispatchStatus, EffectPhase, TransactionStatus
    tx = state['transaction_id']
    transaction_status = deps.transactions.get(tx).status
    if transaction_status not in {TransactionStatus.EXECUTION_UNKNOWN,
                                  TransactionStatus.EXECUTING, TransactionStatus.ROLLBACK_RUNNING}:
        return None
    dispatches = deps.transactions.get_dispatches(tx)
    if any(d.status is not DispatchStatus.COMPLETED or d.phase is EffectPhase.UNDO for d in dispatches):
        return None
    applies = [d for d in dispatches if d.phase is EffectPhase.APPLY]
    if not applies:
        return None
    latest = max(applies, key=lambda d: int(d.step_id))
    if latest.step_id not in state.get('repair_bindings', {}):
        return None
    results = {r.step_id: r for r in deps.transactions.get_results(tx) if r.phase == 'apply'}
    if any(d.step_id not in results or
           (d is not latest and results[d.step_id].status != 'succeeded') for d in applies):
        return None
    job, _, _ = job_origin(deps, state, latest.step_id)
    expected = job_result(job)
    result = results[latest.step_id]
    if (expected.status == 'unknown'
        or transaction_status not in {TransactionStatus.EXECUTION_UNKNOWN,
            TransactionStatus.EXECUTING if expected.ok else TransactionStatus.ROLLBACK_RUNNING}
        or result.status != ('succeeded' if expected.ok else 'failed')
        or json.loads(result.payload_json) != expected.model_dump(mode='json')):
        return None
    return latest


def confirm_job(deps, state, target, step_id, *, now):
    """Acknowledge a durable terminal job; never assert network/business recovery."""
    from a4diag.plugin_api.ticket import OperationPhase
    from a4diag.repair_jobs import TERMINAL_JOB_STATES
    job, operation, original = job_origin(deps, state, step_id)
    if job.state not in TERMINAL_JOB_STATES:
        raise PermissionError('job_not_terminal')
    if deps.plugins.collector.verify_identity(target) != original.target_fingerprint:
        raise PermissionError('target_identity_changed')
    token = issue_repair_ticket(deps, state, target, operation, step_id,
                               OperationPhase.CONFIRM_JOB, {'job_id': job.id}, now=now)
    response = deps.plugins.executor.confirm_job(target, step_id, operation, job.id, token)
    if response.job != job:
        raise PermissionError('job_confirmation_changed_result')
    return record_job(deps, state, response, now=now)

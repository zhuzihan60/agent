"""Exact container identities shared by the closed Docker and Podman adapters."""
from a4diag_builtin_plugins.capability_containers import ContainerIdentity, ContainerSnapshot


class ContainerIdentityError(ValueError):
    pass


def require_same_container(expected, observed):
    if expected != observed:
        raise ContainerIdentityError('container_identity_changed')


def profile_identity(profile):
    from a4diag.repair_profiles import container_scope
    runtime, uid, identifier = container_scope(profile.resource)
    return ContainerIdentity(runtime=runtime, owner_uid=uid, container_id=identifier,
                             image_digest=profile.constraints.image_digest)


def runtime_socket(profile):
    identity = profile_identity(profile)
    if identity.runtime == 'docker':
        return '/run/docker.sock'
    return '/run/podman/podman.sock' if identity.owner_uid == 0 else f'/run/user/{identity.owner_uid}/podman/podman.sock'


def profile_adapter(profile):
    identity = profile_identity(profile)
    if identity.runtime == 'docker':
        from a4diag_target.repair_docker import DockerAdapter
        return DockerAdapter()
    from a4diag_target.repair_podman import OwnerBoundPodman
    return OwnerBoundPodman(profile)


class ContainerPlugin:
    """Persistent operation intent prevents guessing that a running restart completed."""
    def __init__(self, profile, *, adapter=None, state=None):
        from a4diag_target.repair_install import STATE_ROOT
        self.profile = profile
        self.identity = profile_identity(profile)
        self.adapter = adapter or profile_adapter(profile)
        self.state = state or STATE_ROOT / profile.id

    def _snapshot(self):
        if self.profile.constraints.service_unit is not None:
            raise ContainerIdentityError('service_route_required:'+self.profile.constraints.service_profile_id)
        snapshot = self.adapter.inspect(self.identity.container_id)
        require_same_container(self.identity, snapshot.identity)
        return snapshot

    def admit_effect(self, request, *, deadline=None):
        import time
        from a4diag_target.repair_admission import EffectAdmissionRejected
        if deadline is None:
            deadline = time.monotonic() + request.operation.timeout_seconds
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('container_operation_budget_exhausted')
            self.adapter.timeout_seconds = min(5, remaining)
            self._snapshot()
            if time.monotonic() >= deadline:
                raise TimeoutError('container_operation_budget_exhausted')
        except (ValueError, OSError) as error:
            raise EffectAdmissionRejected(str(error)) from error

    async def dispatch(self, request, *, deadline=None):
        import hashlib
        import json
        import os
        import secrets
        import time
        from a4diag.domain import canonical_json_bytes
        from a4diag_target.repair_install import _atomic_file, protected_json
        from a4diag_builtin_plugins.capability_common import PrepareResult, EffectResult, VerifyResult, ReconcileResult
        from a4diag.repair_profiles import profile_digest
        # The worker supplies the deadline it established before admission.
        # Standalone prepare/observation calls get their own bounded read budget.
        if deadline is None:
            deadline = time.monotonic() + request.operation.timeout_seconds
        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError('container_operation_budget_exhausted')
            return value
        self.adapter.timeout_seconds = min(5, remaining())
        bound = {'transaction':request.transaction_id, 'step':request.step_id,
                 'operation':request.operation.model_dump(mode='json'), 'profile':profile_digest(self.profile)}
        key = hashlib.sha256(canonical_json_bytes(bound)).hexdigest()
        path = self.state / f'container-{key}.json'
        if request.lifecycle == 'prepare':
            snapshot = self._snapshot()
            if path.exists():
                record = protected_json(path)
                if record['bound'] != bound:
                    raise ValueError('container_record_mismatch')
            else:
                record = {'bound':bound,'marker':{'identity':self.identity.model_dump(),
                    'before':snapshot.model_dump(mode='json'), 'nonce':secrets.token_hex(16)}, 'stage':'prepared'}
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(canonical_json_bytes(record)); stream.flush(); os.fsync(stream.fileno())
            return PrepareResult(marker=record['marker'])
        record = protected_json(path)
        if record['bound'] != bound or record['marker'] != request.marker:
            raise ValueError('container_marker_mismatch')
        snapshot = self._snapshot()
        remaining()
        if request.lifecycle == 'undo':
            return EffectResult(ok=False, changed=False, reason='container_process_state_not_restorable')
        if request.lifecycle == 'apply':
            if record['stage'] == 'completed':
                return EffectResult(**record['result'])
            if record['stage'] != 'prepared':
                raise ValueError('container_operation_uncertain')
            before = ContainerSnapshot.model_validate(record['marker']['before'])
            if snapshot != before:
                raise ContainerIdentityError('container_state_changed_since_prepare')
            if request.operation.action == 'start' and snapshot.running:
                result = EffectResult(ok=True, changed=False, data={'snapshot':snapshot.model_dump(mode='json')})
            else:
                record['stage'] = 'intent'
                _atomic_file(path, canonical_json_bytes(record), 0o600)
                self.adapter.timeout_seconds = remaining()
                if request.operation.action == 'start':
                    self.adapter.start(self.identity.container_id)
                elif request.operation.action == 'restart':
                    self.adapter.restart(self.identity.container_id, remaining())
                else:
                    raise ValueError('container_action_denied')
                self.adapter.timeout_seconds = min(5, remaining())
                after = self._snapshot()
                remaining()
                ok = after.running and after.started_at != before.started_at and not after.oom_killed
                result = EffectResult(ok=ok, changed=True,
                    reason=None if ok else 'container_failed_after_operation', data={'snapshot':after.model_dump(mode='json'),
                    'execution':getattr(self.adapter,'last_execution',{})})
            record.update(stage='completed',result=result.model_dump(mode='json'))
            _atomic_file(path, canonical_json_bytes(record), 0o600)
            return result
        data = {'snapshot':snapshot.model_dump(mode='json'), 'operation_stage':record['stage']}
        # This is only effect acknowledgement. The mandatory controller window
        # waits out known Health.starting and requires independent business checks.
        healthy = snapshot.running and not snapshot.oom_killed and snapshot.health != 'unhealthy'
        if request.lifecycle == 'verify':
            return VerifyResult(ok=record['stage']=='completed' and record['result']['ok'] and healthy, data=data)
        return ReconcileResult(state={'prepared':'not_applied','intent':'unknown','completed':'applied'}[record['stage']],data=data)

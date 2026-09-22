"""Typed target-side executor with no generic command dispatch surface."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

from a4diag.plugin_api.target_protocol import (
    SignedTargetRequest,
    TargetLifecycle,
    TargetLifecycleV11,
    TargetProtocolError,
    TargetRequest,
    TargetRequestType,
    TargetRequestV11,
    TargetVerifier,
)
from a4diag.plugin_api.ticket import effect_payload_digest
from a4diag.domain import canonical_json_bytes
from a4diag.policy_engine import canonical_operation_digest
from a4diag.repair_jobs import RepairJobResponse, TERMINAL_JOB_STATES
from a4diag.repair_store import RepairStore, RepairLimitError
from a4diag_target.repair_jobs import JobStore, RepairJobError
from a4diag_builtin_plugins.capability_common import (
    CapabilityApplyParams,
    CapabilityPrepareParams,
    CapabilityReconcileParams,
    CapabilityUndoParams,
    CapabilityVerifyParams,
    TransportAdapter,
)
from a4diag_builtin_plugins.capability_files import FilesPlugin
from a4diag_builtin_plugins.capability_packages import PackagesPlugin
from a4diag_builtin_plugins.capability_services import ServicesPlugin

from a4diag_target.policy import PolicyDenied, TargetPolicy


class ExecutorError(RuntimeError):
    pass


class TargetExecutor:
    def __init__(
        self,
        *,
        verifier: TargetVerifier,
        policy: TargetPolicy | Callable[[], TargetPolicy],
        identity_probe: Callable[[], str],
        adapter: TransportAdapter,
    ) -> None:
        self._verifier = verifier
        if not isinstance(policy, TargetPolicy) and not callable(policy):
            raise TypeError("policy must be TargetPolicy or a policy provider")
        self._policy_source = policy
        self._identity_probe = identity_probe
        self._jobs = None
        self._limits = None
        self._launch = None
        self._plugins = {
            "files": FilesPlugin(transport=adapter),
            "services": ServicesPlugin(transport=adapter),
            "packages": PackagesPlugin(transport=adapter),
        }

    def configure_jobs(self, jobs: JobStore, limits: RepairStore,
                       launch: Callable[[str], None]) -> None:
        if jobs.path.resolve() != limits.path.resolve():
            raise ValueError('jobs and reservations must share a database')
        self._jobs, self._limits, self._launch = jobs, limits, launch

    async def execute(self, envelope: SignedTargetRequest) -> dict[str, Any]:
        policy = self._current_policy()
        if envelope.key_fingerprint != policy.controller_key_fingerprint:
            raise ExecutorError("controller_key_mismatch")
        try:
            request = self._verifier.verify(
                envelope, expected_target=policy.target_id
            )
        except TargetProtocolError as exc:
            raise ExecutorError(exc.code) from exc
        if request.target_fingerprint != policy.target_fingerprint:
            raise ExecutorError("request_identity_mismatch")
        try:
            current_identity = self._identity_probe()
        except Exception as exc:
            raise ExecutorError("target_identity_unavailable") from exc
        if current_identity != policy.target_fingerprint:
            raise ExecutorError("target_identity_mismatch")
        job_query = isinstance(request, TargetRequestV11) and request.lifecycle is TargetLifecycleV11.QUERY_JOB
        if job_query:
            # Signature, target identity and persisted ownership are all required.
            # Only observation of this exact job survives grant revocation.
            self._lookup_job(request)
        elif isinstance(request, TargetRequestV11):
            self._authorize_repair(policy, request)
        else:
            try:
                policy.authorize(request.operation)
            except PolicyDenied as exc:
                raise ExecutorError(str(exc)) from exc
        self._verify_effect_digest(request)
        plugin = self._plugins.get(request.operation.capability)
        if plugin is None:
            raise ExecutorError("capability_not_wired")
        try:
            if isinstance(request, TargetRequestV11) and request.lifecycle in {
                TargetLifecycleV11.APPLY, TargetLifecycleV11.QUERY_JOB, TargetLifecycleV11.CONFIRM_JOB,
            }:
                result = await self._dispatch_job(policy, request)
            else:
                result = await self._dispatch(plugin, request)
        except ExecutorError:
            raise
        except (RepairJobError, RepairLimitError) as exc:
            raise ExecutorError(exc.code) from exc
        except Exception as exc:
            raise ExecutorError("capability_failed") from exc
        payload = result.model_dump(mode="json")
        try:
            canonical_json_bytes(payload, max_bytes=request.operation.output_limit_bytes)
        except ValueError as exc:
            raise ExecutorError('result_too_large') from exc
        try:
            self._verifier.record_result(request.nonce, payload)
        except Exception as exc:
            raise ExecutorError("result_record_failed") from exc
        return payload

    def _lookup_job(self, request):
        if self._jobs is None:
            raise ExecutorError('lifecycle_not_wired')
        try:
            return self._jobs.lookup(request)
        except RepairJobError as exc:
            raise ExecutorError(exc.code) from exc

    async def _dispatch_job(self, policy, request):
        if self._jobs is None or self._limits is None or self._launch is None:
            raise ExecutorError('job_store_required' if request.lifecycle is TargetLifecycleV11.APPLY else 'lifecycle_not_wired')
        if request.lifecycle is not TargetLifecycleV11.APPLY:
            job = self._lookup_job(request)
            if request.lifecycle is TargetLifecycleV11.CONFIRM_JOB:
                if job.state not in TERMINAL_JOB_STATES:
                    raise ExecutorError('job_not_terminal')
                # Recover a crash between terminal persistence and release.
                # finish_job rechecks the exact persisted reservation binding.
                self._limits.finish_job(job.id, job.state)
            else:
                job = self._reconcile_job(job.id)
                if job.state == 'unknown':
                    original = self._jobs.request(job.id)
                    try:
                        observation = await self._dispatch(self._plugins[original.operation.capability],
                            original.model_copy(update={'lifecycle': TargetLifecycleV11.RECONCILE}))
                        detail = observation.model_dump(mode='json')
                    except Exception:
                        detail = {'state': 'unknown', 'reason': 'target_observation_unavailable'}
                    # Observed service state is evidence, not proof that an
                    # unobserved worker completed. Never release or retry it.
                    job = self._jobs.complete(job.id, state='unknown', changed=None,
                        result={**job.result, 'target_observation': detail}, now=self._verifier.now())
            return RepairJobResponse(job=job)
        profile = policy.require_repair_profile(request.binding.profile_id, request.binding.profile_digest)
        job = self._jobs.ensure(request.transaction_id, request.step_id,
            canonical_operation_digest(request.operation), profile_digest=request.binding.profile_digest)
        self._jobs.bind_request(job.id, request, controller_key_fingerprint=policy.controller_key_fingerprint)
        self._verifier.record_job(request, job.id)
        if job.state != 'prepared':
            return RepairJobResponse(job=job)
        now = self._verifier.now()
        reservation = self._limits.reserve(request.target_id, profile.resource,
            request.transaction_id, now, profile.cooldown_seconds, profile.hourly_limit)
        self._limits.bind_job(reservation, job.id)
        self._limits.mark_started(reservation, now)
        launch_failed = False
        with self._jobs.launching(job.id):
            if self._jobs.start(job.id, now=now):
                try:
                    self._launch(job.id)
                except Exception:
                    launch_failed = True
        if launch_failed:
            # The manager might have accepted the unit despite a lost reply.
            self._reconcile_job(job.id)
        return RepairJobResponse(job=self._jobs.get(job.id))

    def _reconcile_job(self, job_id):
        probe = getattr(self._launch, 'worker_identity', None)
        return self._jobs.reconcile(job_id,
            startup_probe=(lambda: probe(job_id)) if callable(probe) else None)

    def _current_policy(self) -> TargetPolicy:
        policy = (
            self._policy_source()
            if callable(self._policy_source)
            else self._policy_source
        )
        if not isinstance(policy, TargetPolicy):
            raise ExecutorError("target_policy_unavailable")
        return policy

    def _authorize_repair(
        self, policy: TargetPolicy, request: TargetRequestV11
    ) -> None:
        try:
            policy.authorize_repair(
                request.binding,
                request.operation,
                authorization_kind=request.authorization_kind,
                authorization_id=request.authorization_id,
                now=self._verifier.now(),
            )
        except PolicyDenied as exc:
            code = str(exc)
            if code == "profile_not_granted":
                code = "profile_revoked"
            raise ExecutorError(code) from exc
        if request.lifecycle is TargetLifecycleV11.PREPARE:
            if request.binding.preconditions_digest is not None:
                raise ExecutorError("preconditions_digest_unexpected")
            return
        if request.lifecycle in {
            TargetLifecycleV11.QUERY_JOB,
            TargetLifecycleV11.CONFIRM_JOB,
        }:
            return
        if request.marker is None or request.binding.preconditions_digest is None:
            raise ExecutorError("preconditions_digest_required")
        actual = hashlib.sha256(canonical_json_bytes(request.marker)).hexdigest()
        if not hmac.compare_digest(actual, request.binding.preconditions_digest):
            raise ExecutorError("preconditions_digest_mismatch")

    def _base(self, request: TargetRequestType) -> dict[str, Any]:
        return {
            "transaction_id": request.transaction_id,
            "step_id": request.step_id,
            "target_id": request.target_id,
            "target_fingerprint": request.target_fingerprint,
            "operation": request.operation,
            "plan_digest": request.plan_digest,
            "risk": request.risk,
            "approval_id": (
                request.approval_id
                if isinstance(request, TargetRequest)
                else request.authorization_id
            ),
        }

    async def _dispatch(self, plugin: object, request: TargetRequestType) -> Any:
        base = self._base(request)
        if request.lifecycle in {TargetLifecycle.PREPARE, TargetLifecycleV11.PREPARE}:
            return await plugin.prepare(CapabilityPrepareParams(**base))
        if request.lifecycle in {
            TargetLifecycleV11.QUERY_JOB,
            TargetLifecycleV11.CONFIRM_JOB,
        }:
            raise ExecutorError("lifecycle_not_wired")
        if request.marker is None:
            raise ExecutorError("marker_required")
        if request.lifecycle in {TargetLifecycle.APPLY, TargetLifecycleV11.APPLY}:
            return await plugin.apply(CapabilityApplyParams(**base, marker=request.marker))
        if request.lifecycle in {TargetLifecycle.UNDO, TargetLifecycleV11.UNDO}:
            return await plugin.undo(
                CapabilityUndoParams(**base, marker=request.marker, undo=request.undo)
            )
        read_base = {
            "transaction_id": request.transaction_id,
            "step_id": request.step_id,
            "operation": request.operation,
            "marker": request.marker,
        }
        if request.lifecycle in {TargetLifecycle.VERIFY, TargetLifecycleV11.VERIFY}:
            if request.verify_restored:
                return await plugin.verify_restored(CapabilityVerifyParams(**read_base))
            return await plugin.verify(CapabilityVerifyParams(**read_base))
        if request.lifecycle in {TargetLifecycle.RECONCILE, TargetLifecycleV11.RECONCILE}:
            return await plugin.reconcile(CapabilityReconcileParams(**read_base))
        raise ExecutorError("lifecycle_not_wired")

    @staticmethod
    def _verify_effect_digest(request: TargetRequestType) -> None:
        payload: dict[str, Any]
        if request.lifecycle in {TargetLifecycle.PREPARE, TargetLifecycleV11.PREPARE}:
            payload = {}
        elif request.lifecycle in {TargetLifecycle.UNDO, TargetLifecycleV11.UNDO}:
            payload = {"marker": request.marker, "undo": request.undo}
        elif request.lifecycle in {
            TargetLifecycleV11.QUERY_JOB,
            TargetLifecycleV11.CONFIRM_JOB,
        }:
            payload = {}
        else:
            payload = {"marker": request.marker}
        if effect_payload_digest(payload) != request.effect_payload_digest:
            raise ExecutorError("effect_payload_digest_mismatch")


def main() -> int:
    from a4diag_target.server import main as server_main

    return server_main()


__all__ = ["ExecutorError", "TargetExecutor", "main"]

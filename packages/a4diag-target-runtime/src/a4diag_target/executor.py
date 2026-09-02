"""Typed target-side executor with no generic command dispatch surface."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from a4diag.plugin_api.target_protocol import (
    SignedTargetRequest,
    TargetLifecycle,
    TargetProtocolError,
    TargetRequest,
    TargetVerifier,
)
from a4diag.plugin_api.ticket import effect_payload_digest
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
        policy: TargetPolicy,
        identity_probe: Callable[[], str],
        adapter: TransportAdapter,
    ) -> None:
        self._verifier = verifier
        self._policy = policy
        self._identity_probe = identity_probe
        self._plugins = {
            "files": FilesPlugin(transport=adapter),
            "services": ServicesPlugin(transport=adapter),
            "packages": PackagesPlugin(transport=adapter),
        }

    async def execute(self, envelope: SignedTargetRequest) -> dict[str, Any]:
        if envelope.key_fingerprint != self._policy.controller_key_fingerprint:
            raise ExecutorError("controller_key_mismatch")
        try:
            request = self._verifier.verify(
                envelope, expected_target=self._policy.target_id
            )
        except TargetProtocolError as exc:
            raise ExecutorError(exc.code) from exc
        if request.target_fingerprint != self._policy.target_fingerprint:
            raise ExecutorError("request_identity_mismatch")
        try:
            current_identity = self._identity_probe()
        except Exception as exc:
            raise ExecutorError("target_identity_unavailable") from exc
        if current_identity != self._policy.target_fingerprint:
            raise ExecutorError("target_identity_mismatch")
        try:
            self._policy.authorize(request.operation)
        except PolicyDenied as exc:
            raise ExecutorError(str(exc)) from exc
        self._verify_effect_digest(request)
        plugin = self._plugins.get(request.operation.capability)
        if plugin is None:
            raise ExecutorError("capability_not_wired")
        try:
            result = await self._dispatch(plugin, request)
        except ExecutorError:
            raise
        except Exception as exc:
            raise ExecutorError("capability_failed") from exc
        payload = result.model_dump(mode="json")
        try:
            self._verifier.record_result(request.nonce, payload)
        except Exception as exc:
            raise ExecutorError("result_record_failed") from exc
        return payload

    def _base(self, request: TargetRequest) -> dict[str, Any]:
        return {
            "transaction_id": request.transaction_id,
            "step_id": request.step_id,
            "target_id": request.target_id,
            "target_fingerprint": request.target_fingerprint,
            "operation": request.operation,
            "plan_digest": request.plan_digest,
            "risk": request.risk,
            "approval_id": request.approval_id,
        }

    async def _dispatch(self, plugin: object, request: TargetRequest) -> Any:
        base = self._base(request)
        if request.lifecycle is TargetLifecycle.PREPARE:
            return await plugin.prepare(CapabilityPrepareParams(**base))
        if request.marker is None:
            raise ExecutorError("marker_required")
        if request.lifecycle is TargetLifecycle.APPLY:
            return await plugin.apply(CapabilityApplyParams(**base, marker=request.marker))
        if request.lifecycle is TargetLifecycle.UNDO:
            return await plugin.undo(
                CapabilityUndoParams(**base, marker=request.marker, undo=request.undo)
            )
        read_base = {
            "transaction_id": request.transaction_id,
            "step_id": request.step_id,
            "operation": request.operation,
            "marker": request.marker,
        }
        if request.lifecycle is TargetLifecycle.VERIFY:
            return await plugin.verify(CapabilityVerifyParams(**read_base))
        if request.lifecycle is TargetLifecycle.RECONCILE:
            return await plugin.reconcile(CapabilityReconcileParams(**read_base))
        raise ExecutorError("lifecycle_not_wired")

    @staticmethod
    def _verify_effect_digest(request: TargetRequest) -> None:
        payload: dict[str, Any]
        if request.lifecycle is TargetLifecycle.PREPARE:
            payload = {}
        elif request.lifecycle is TargetLifecycle.UNDO:
            payload = {"marker": request.marker, "undo": request.undo}
        else:
            payload = {"marker": request.marker}
        if effect_payload_digest(payload) != request.effect_payload_digest:
            raise ExecutorError("effect_payload_digest_mismatch")


def main() -> int:
    from a4diag_target.server import main as server_main

    return server_main()


__all__ = ["ExecutorError", "TargetExecutor", "main"]

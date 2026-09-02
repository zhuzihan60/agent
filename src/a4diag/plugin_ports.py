"""Production plugin ports composed over the AF_UNIX RPC clients.

Each registered plugin instance is reached through its AF_UNIX socket via
:class:`a4diag.plugin_client.PluginClient`.  Every adapter validates the
untrusted RPC result before returning a core domain object.  Missing plugins,
unregistered transport types, malformed results and identity drift all fail
closed.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from pydantic import JsonValue
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import Operation, Plan, Risk, StepResult, TargetConfig, canonical_json_bytes
from a4diag.plugin_api.manifest import PluginType
from a4diag.plugin_client import PluginClient
from a4diag.plugin_api.target_protocol import TargetLifecycle, TargetRequest, TargetSigner
from a4diag.plugin_api.ticket import OperationPhase, OperationTicket, effect_payload_digest
from a4diag.plugin_registry import PluginRegistry
from a4diag.policy_engine import canonical_operation_digest
from a4diag.runtime import RuntimeFailure
from a4diag.settings import AgentSettings
from a4diag.workflow import (
    PluginPorts,
    PreparedEffect,
    ReconcileEffect,
)

_SAFE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ClientFactory = Callable[[str], PluginClient]


def _run(coroutine_factory):
    try:
        return asyncio.run(coroutine_factory())
    except Exception as error:
        raise RuntimeFailure(
            "plugin_rpc_failed", f"{type(error).__name__}: {error}"
        ) from error


@dataclass(frozen=True)
class _RpcExecutorPort:
    """Signs complete lifecycle calls and sends them only to a target transport."""

    clients: dict[str, PluginClient]
    signer_resolver: Callable[[TargetConfig], TargetSigner]
    clock: Callable[[], int] = lambda: int(time.time())
    nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24)
    _contexts: dict[tuple[str, str], OperationTicket] = field(default_factory=dict)
    _transaction: ContextVar[str | None] = ContextVar(
        "a4diag_rpc_transaction", default=None
    )

    def bind_transaction(self, transaction_id: str) -> None:
        if not isinstance(transaction_id, str) or not transaction_id:
            raise RuntimeFailure("invalid_transaction_id")
        self._transaction.set(transaction_id)

    def _transaction_id(self) -> str:
        transaction_id = self._transaction.get()
        if transaction_id is None:
            raise RuntimeFailure("transaction_context_missing")
        return transaction_id

    def _client(self, target: TargetConfig) -> PluginClient:
        client = self.clients.get(target.id)
        if client is None:
            raise RuntimeFailure(
                "target_transport_unavailable", target.id
            )
        return client

    @staticmethod
    def _claims(ticket: str) -> OperationTicket:
        try:
            if not isinstance(ticket, str) or ticket.count(".") != 1:
                raise ValueError("malformed ticket")
            payload_segment = ticket.split(".", 1)[0]
            padded = payload_segment + "=" * ((4 - len(payload_segment) % 4) % 4)
            payload = base64.b64decode(padded, altchars=b"-_", validate=True)
            claims = OperationTicket.model_validate_json(payload)
            if canonical_json_bytes(claims.model_dump(mode="json")) != payload:
                raise ValueError("noncanonical ticket")
            return claims
        except Exception as error:
            raise RuntimeFailure("ticket_context_invalid") from error

    def _validate_claims(
        self, claims: OperationTicket, target: TargetConfig, step_id: str,
        operation: Operation, phase: OperationPhase,
    ) -> None:
        if claims.target_id != target.id:
            raise RuntimeFailure("target_ticket_mismatch")
        if (
            claims.transaction_id != self._transaction_id()
            or claims.step_id != step_id
            or claims.operation_digest != canonical_operation_digest(operation)
            or claims.phase is not phase
        ):
            raise RuntimeFailure("ticket_context_mismatch")

    @staticmethod
    def _ticket_base(claims: OperationTicket, operation: Operation) -> dict[str, object]:
        return {
            "transaction_id": claims.transaction_id,
            "step_id": claims.step_id,
            "target_id": claims.target_id,
            "target_fingerprint": claims.target_fingerprint,
            "operation": operation.model_dump(mode="json"),
            "plan_digest": claims.plan_digest,
            "risk": claims.risk.value,
            "approval_id": claims.approval_id,
        }

    def _envelope(
        self, *, target: TargetConfig, operation: Operation,
        lifecycle: TargetLifecycle, marker: dict[str, object] | None,
        undo: dict[str, object] | None, claims: OperationTicket,
        effect_digest: str,
    ) -> dict[str, object]:
        issued = int(self.clock())
        request = TargetRequest(
            controller_id="a4diag-core", target_id=target.id,
            target_fingerprint=claims.target_fingerprint,
            transaction_id=self._transaction_id(), step_id=claims.step_id,
            lifecycle=lifecycle, operation=operation, marker=marker, undo=undo,
            plan_digest=claims.plan_digest, effect_payload_digest=effect_digest,
            risk=claims.risk, approval_id=claims.approval_id,
            issued_at=issued, expires_at=issued + 30, nonce=self.nonce_factory(),
        )
        return self.signer_resolver(target).sign(request).model_dump(mode="json")

    @staticmethod
    def _target_result(result: object, method: str) -> dict[str, object]:
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise RuntimeFailure("target_transport_failed", method)
        data = result.get("data")
        value = data.get("result") if isinstance(data, dict) else None
        if not isinstance(value, dict):
            raise RuntimeFailure("plugin_result_invalid", method)
        return value

    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        ticket: str,
    ) -> PreparedEffect:
        claims = self._claims(ticket)
        self._validate_claims(claims, target, step_id, operation, OperationPhase.PREPARE)
        self._contexts[(claims.transaction_id, step_id)] = claims
        params = self._ticket_base(claims, operation)
        params["envelope"] = self._envelope(
            target=target, operation=operation, lifecycle=TargetLifecycle.PREPARE,
            marker=None, undo=None, claims=claims, effect_digest=claims.effect_payload_digest,
        )
        result = self._target_result(
            _run(lambda: self._client(target).call("prepare_typed", params, ticket=ticket)),
            "prepare_typed",
        )
        if not isinstance(result.get("marker"), dict):
            raise RuntimeFailure("plugin_result_invalid", "prepare")
        marker = result["marker"]
        return PreparedEffect(pre_state=marker, marker=marker)

    @staticmethod
    def _step_result(result: object, success_status: str) -> StepResult:
        if not isinstance(result, dict) or type(result.get("ok")) is not bool:
            raise RuntimeFailure("plugin_result_invalid", success_status)
        reason = result.get("reason")
        data = result.get("data", {})
        if reason is not None and not isinstance(reason, str):
            raise RuntimeFailure("plugin_result_invalid", success_status)
        if not isinstance(data, dict):
            raise RuntimeFailure("plugin_result_invalid", success_status)
        return StepResult(
            ok=result["ok"],
            status=success_status if result["ok"] else (reason or "failed"),
            data=data,
        )

    def apply(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        ticket: str,
    ) -> StepResult:
        claims = self._claims(ticket)
        self._validate_claims(claims, target, step_id, operation, OperationPhase.APPLY)
        self._contexts[(claims.transaction_id, step_id)] = claims
        params = {**self._ticket_base(claims, operation), "marker": marker}
        params["envelope"] = self._envelope(
            target=target, operation=operation, lifecycle=TargetLifecycle.APPLY,
            marker=marker, undo=None, claims=claims, effect_digest=claims.effect_payload_digest,
        )
        result = self._target_result(
            _run(lambda: self._client(target).call("apply_typed", params, ticket=ticket)),
            "apply_typed",
        )
        return self._step_result(result, "applied")

    def verify(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
    ) -> StepResult:
        claims = self._context(step_id)
        envelope = self._envelope(
            target=target, operation=operation, lifecycle=TargetLifecycle.VERIFY,
            marker=marker, undo=None, claims=claims,
            effect_digest=effect_payload_digest({"marker": marker}),
        )
        result = self._target_result(
            _run(lambda: self._client(target).call("verify_typed", {
                "transaction_id": self._transaction_id(), "step_id": step_id,
                "operation": operation.model_dump(mode="json"), "marker": marker,
                "envelope": envelope,
            })), "verify_typed",
        )
        return self._step_result(result, "verified")

    def undo(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        undo: dict[str, object] | None,
        ticket: str,
    ) -> StepResult:
        claims = self._claims(ticket)
        self._validate_claims(claims, target, step_id, operation, OperationPhase.UNDO)
        self._contexts[(claims.transaction_id, step_id)] = claims
        params = {**self._ticket_base(claims, operation), "marker": marker, "undo": undo}
        params["envelope"] = self._envelope(
            target=target, operation=operation, lifecycle=TargetLifecycle.UNDO,
            marker=marker, undo=undo, claims=claims, effect_digest=claims.effect_payload_digest,
        )
        result = self._target_result(
            _run(lambda: self._client(target).call("undo_typed", params, ticket=ticket)),
            "undo_typed",
        )
        return self._step_result(result, "undone")

    def reconcile(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        phase: object,
        dispatch_id: str,
        marker: dict[str, object] | None,
    ) -> ReconcileEffect:
        del phase, dispatch_id
        claims = self._context(step_id)
        envelope = self._envelope(
            target=target, operation=operation, lifecycle=TargetLifecycle.RECONCILE,
            marker=marker, undo=None, claims=claims,
            effect_digest=effect_payload_digest({"marker": marker}),
        )
        result = self._target_result(
            _run(lambda: self._client(target).call("reconcile_typed", {
                "transaction_id": self._transaction_id(), "step_id": step_id,
                "operation": operation.model_dump(mode="json"), "marker": marker,
                "envelope": envelope,
            })), "reconcile_typed",
        )
        if not isinstance(result, dict):
            raise RuntimeFailure("plugin_result_invalid", "reconcile")
        outcome = result.get("state", result.get("outcome"))
        try:
            return ReconcileEffect(outcome=outcome, prepared=None)
        except ValueError as error:
            raise RuntimeFailure("plugin_result_invalid", "reconcile") from error

    def _context(self, step_id: str) -> OperationTicket:
        claims = self._contexts.get((self._transaction_id(), step_id))
        if claims is None:
            raise RuntimeFailure("target_request_context_missing", step_id)
        return claims

    def verify_restored(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        pre_state: dict[str, object],
    ) -> StepResult:
        # Capability plugins prove restoration inside undo/verify; there is no
        # separate RPC method, so a caller asking for it fails closed.
        raise RuntimeFailure("method_not_supported", "verify_restored")


def _socket_client(instance: str) -> PluginClient:
    if not _SAFE_INSTANCE.fullmatch(instance):
        raise RuntimeFailure("plugin_instance_invalid", instance)
    return PluginClient(f"/run/a4diag/{instance}.sock")


def _target_signer(target: TargetConfig) -> TargetSigner:
    from a4diag.secrets import SecretError, SecretResolver

    try:
        pem = SecretResolver().resolve(
            f"file:targets/{target.id}/operation-ed25519.pem"
        ).value.encode("utf-8")
        key = serialization.load_pem_private_key(pem, password=None)
    except (SecretError, ValueError, TypeError) as error:
        raise RuntimeFailure("target_signing_key_unavailable", target.id) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeFailure("target_signing_key_invalid", target.id)
    return TargetSigner(key)


@dataclass(frozen=True, slots=True)
class _RpcCollectorPort:
    registry: PluginRegistry
    client_factory: ClientFactory

    def _client(self, target: TargetConfig) -> PluginClient:
        manifest_name = f"transport-{target.mode.value}"
        self.registry.require(manifest_name, PluginType.TRANSPORT)
        instance = target.transport or manifest_name
        if not _SAFE_INSTANCE.fullmatch(instance):
            raise RuntimeFailure("plugin_instance_invalid", instance)
        return self.client_factory(instance)

    def verify_identity(self, target: TargetConfig) -> str:
        result = _run(lambda: self._client(target).call("verify_identity", {}))
        data = result.get("data") if isinstance(result, dict) else None
        fingerprint = data.get("fingerprint") if isinstance(data, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("ok") is not True
            or not isinstance(fingerprint, str)
            or not fingerprint
        ):
            raise RuntimeFailure("target_identity_unavailable", target.id)
        return fingerprint

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str:
        if self.verify_identity(target) != fingerprint:
            raise RuntimeFailure("target_identity_mismatch", target.id)
        return fingerprint

    def collect(
        self, target: TargetConfig, read_view: str
    ) -> list[dict[str, JsonValue]]:
        if self.verify_identity(target) != read_view:
            raise RuntimeFailure("target_identity_mismatch", target.id)
        evidence: list[dict[str, JsonValue]] = [
            {"kind": "target_fingerprint", "content": read_view, "truncated": False}
        ]
        for kind in ("machine_id", "os_release", "systemd_version"):
            result = _run(
                lambda kind=kind: self._client(target).call(
                    "read", {"kind": kind, "output_limit_bytes": 65_536}
                )
            )
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise RuntimeFailure("collection_failed", kind)
            stdout = result.get("stdout")
            data = result.get("data")
            if not isinstance(stdout, str) or not isinstance(data, dict):
                raise RuntimeFailure("collection_result_invalid", kind)
            evidence.append(
                {
                    "kind": kind,
                    "content": stdout,
                    "truncated": bool(data.get("truncated", False)),
                }
            )
        return evidence

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, JsonValue]],
    ) -> StepResult:
        del evidence
        current = self.verify_identity(target)
        return StepResult(
            ok=current == read_view,
            status="identity_verified" if current == read_view else "identity_mismatch",
            data={"fingerprint": current},
        )


@dataclass(frozen=True, slots=True)
class _RpcModelPort:
    client: PluginClient

    @staticmethod
    def _evidence(
        target: TargetConfig,
        evidence: list[dict[str, JsonValue]],
        **extra: JsonValue,
    ) -> dict[str, JsonValue]:
        return {
            "target_id": target.id,
            "target_fingerprint": target.identity_ref,
            "observations": evidence,
            **extra,
        }

    def diagnose(
        self, target: TargetConfig, evidence: list[dict[str, JsonValue]]
    ) -> dict[str, JsonValue]:
        result = _run(
            lambda: self.client.call(
                "diagnose", {"evidence": self._evidence(target, evidence)}
            )
        )
        if not isinstance(result, dict):
            raise RuntimeFailure("model_result_invalid", "diagnose")
        return result

    def plan(
        self,
        target: TargetConfig,
        evidence: list[dict[str, JsonValue]],
        diagnosis: dict[str, JsonValue],
    ) -> Plan:
        fingerprint = next(
            (
                str(item.get("content"))
                for item in evidence
                if item.get("kind") == "target_fingerprint"
            ),
            "",
        )
        result = _run(
            lambda: self.client.call(
                "plan",
                {
                    "evidence": self._evidence(
                        target, evidence, diagnosis=diagnosis
                    )
                },
            )
        )
        operations_value = result.get("operations") if isinstance(result, dict) else None
        if not isinstance(operations_value, list):
            raise RuntimeFailure("model_result_invalid", "plan")
        operations: list[Operation] = []
        for value in operations_value:
            if not isinstance(value, dict):
                raise RuntimeFailure("model_result_invalid", "operation")
            operations.append(
                Operation(
                    capability=value.get("capability"),
                    action=value.get("action"),
                    resource=value.get("resource"),
                    parameters=value.get("parameters", {}),
                    model_risk=value.get("model_risk", Risk.HIGH.value),
                    verify=value.get("verify", {}),
                    undo=value.get("undo"),
                    timeout_seconds=value.get("timeout_seconds", 20),
                    output_limit_bytes=value.get("output_limit_bytes", 262_144),
                )
            )
        return Plan(
            target_id=target.id,
            target_fingerprint=fingerprint,
            operations=tuple(operations),
        )

    def critic(
        self,
        target: TargetConfig,
        evidence: list[dict[str, JsonValue]],
        plan: Plan,
    ) -> Risk:
        result = _run(
            lambda: self.client.call(
                "critic",
                {
                    "plan": plan.model_dump(mode="json"),
                    "evidence": self._evidence(target, evidence),
                },
            )
        )
        if not isinstance(result, dict):
            raise RuntimeFailure("model_result_invalid", "critic")
        try:
            return Risk(result.get("risk"))
        except ValueError as error:
            raise RuntimeFailure("model_result_invalid", "critic risk") from error


@dataclass(frozen=True, slots=True)
class _RpcNotificationPort:
    clients: tuple[PluginClient, ...]

    def send_approval(
        self,
        target: TargetConfig,
        transaction_id: str,
        digest: str,
        plan: Plan,
        risk: Risk,
    ) -> bool:
        if not self.clients:
            return False
        operations = tuple(
            operation.model_dump(mode="json") for operation in plan.operations
        )
        event = {
            "target_id": target.id,
            "plan_digest": digest,
            "risk": risk.value,
            "status": "pending_approval",
            "message": f"Transaction {transaction_id} requires approval",
            "operations": operations,
            "equivalent_commands": tuple(
                f"{operation.capability} {operation.action} {operation.resource}"
                for operation in plan.operations
            ),
            "verify": tuple(
                f"verify {operation.capability} {operation.action} {operation.resource}"
                for operation in plan.operations
            ),
            "undo": tuple(
                f"undo {operation.capability} {operation.action} {operation.resource}"
                for operation in plan.operations
            ),
            "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for client in self.clients:
            result = _run(lambda client=client: client.call("send", {"event": event}))
            if not isinstance(result, dict) or not result.get("external_id"):
                return False
        return True


def build_rpc_plugin_ports(
    settings: AgentSettings,
    registry: PluginRegistry,
    *,
    client_factory: ClientFactory = _socket_client,
) -> PluginPorts:
    """Compose production ports from the registered plugin instances.

    Capability plugins back the executor.  Target transports, the selected
    model provider and configured notification channels are independently
    resolved from the verified registry and addressed by safe instance names.
    """
    if not isinstance(settings, AgentSettings):
        raise TypeError("settings must be AgentSettings")
    if not isinstance(registry, PluginRegistry):
        raise TypeError("registry must be PluginRegistry")

    transport_clients: dict[str, PluginClient] = {}
    for target in settings.targets:
        manifest_name = f"transport-{target.mode.value}"
        registry.require(manifest_name, PluginType.TRANSPORT)
        instance = target.transport or manifest_name
        if not _SAFE_INSTANCE.fullmatch(instance):
            raise RuntimeFailure("plugin_instance_invalid", instance)
        transport_clients[target.id] = client_factory(instance)

    executor = _RpcExecutorPort(transport_clients, signer_resolver=_target_signer)
    collector = _RpcCollectorPort(registry, client_factory)
    if settings.model is None:
        model = _UnavailableModelPort()
    else:
        registry.require(settings.model.plugin, PluginType.MODEL)
        model = _RpcModelPort(client_factory(settings.model.plugin))
    notification_clients: list[PluginClient] = []
    for notification in settings.notifications:
        plugin_name = (
            notification.channel
            if notification.channel.startswith("notification-")
            else f"notification-{notification.channel}"
        )
        registry.require(plugin_name, PluginType.NOTIFICATION)
        notification_clients.append(client_factory(plugin_name))
    notifier = _RpcNotificationPort(tuple(notification_clients))
    return PluginPorts(
        model=model,
        collector=collector,
        executor=executor,
        notifier=notifier,
    )


class _UnavailableModelPort:
    def _raise(self) -> None:
        raise RuntimeFailure("model_unavailable")

    def diagnose(self, *_args: object) -> dict[str, JsonValue]:
        self._raise()

    def plan(self, *_args: object) -> Plan:
        self._raise()

    def critic(self, *_args: object) -> Risk:
        self._raise()


__all__ = ["build_rpc_plugin_ports"]

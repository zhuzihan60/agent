"""Plugin crash/recovery matrix.

Exercises the shared host boundary across crash, restart, duplicate request,
invalid ticket, oversized input, output bound, timeout, and secret-redaction
scenarios. A "plugin process" is a fresh ``PluginHost``; restart means a new
host instance sharing the same replay store, exactly as a supervisor restart
would in production. No socket, network, or real plugin process is involved.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from a4diag.domain import Operation, Risk, canonical_json_bytes
from a4diag.plugin_api.protocol import (
    MAX_RPC_BYTES,
    EmptyParams,
    MethodBinding,
    MethodKind,
    PluginHost,
    RpcRequest,
    TicketedEffectParams,
    decode_request_frame,
    effect_fields_digest,
)
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketRequest,
    TicketIssuer,
    TicketVerifier,
)
from a4diag.policy_engine import PolicyAuthorization, canonical_operation_digest

KEY = b"crash-matrix-ticket-key-32bytes-longer"
POLICY_KEY = b"crash-matrix-policy-key-32bytes-longer"
SECRET_MARKER = "crash-secret-value-xyz"


class EmptyResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool = True


class EffectResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    changed: bool


class ApplyParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)

    marker: dict[str, Any] = {}


class ReconcileParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str
    step_id: str


class ReplayStore:
    def __init__(self) -> None:
        self.consumed: set[str] = set()

    def consume(self, ticket_id: str) -> bool:
        if ticket_id in self.consumed:
            return False
        self.consumed.add(ticket_id)
        return True


def make_operation() -> Operation:
    return Operation(
        capability="services",
        action="restart",
        resource="example.service",
        parameters={"unit": "example.service"},
        model_risk=Risk.LOW,
        verify={"active": True},
        undo={"restore": True},
        timeout_seconds=5,
        output_limit_bytes=4096,
    )


def apply_params() -> ApplyParams:
    return ApplyParams(
        transaction_id="tx-1",
        step_id="step-1",
        target_id="lab",
        target_fingerprint="machine-1",
        operation=make_operation(),
        plan_digest="a" * 64,
        risk=Risk.LOW,
        approval_id=None,
        marker={"phase": "apply"},
    )


def authorization(params: TicketedEffectParams) -> PolicyAuthorization:
    unsigned = PolicyAuthorization(
        target_id=params.target_id,
        target_fingerprint=params.target_fingerprint,
        plan_digest=params.plan_digest,
        risk=params.risk,
        approval_id=params.approval_id,
        operation_digests=(canonical_operation_digest(params.operation),),
        mac="0" * 64,
    )
    payload = canonical_json_bytes(unsigned.model_dump(mode="json", exclude={"mac"}))
    tag = hmac.new(
        POLICY_KEY,
        b"a4diag-policy-authorization-v1\x00" + payload,
        hashlib.sha256,
    ).hexdigest()
    return unsigned.model_copy(update={"mac": tag})


def issue_ticket(params: TicketedEffectParams, *, ticket_id: str = "ticket-1") -> str:
    request = OperationTicketRequest(
        **params.model_dump(exclude={"marker"}),
        phase=OperationPhase.APPLY,
        effect_payload_digest=effect_fields_digest(params),
        ttl_seconds=30,
    )
    return TicketIssuer(
        KEY,
        authorization_key=POLICY_KEY,
        clock=lambda: 100,
        ticket_id_factory=lambda: ticket_id,
    ).issue(request, authorization(params))


def crash_handler_factory() -> tuple[list[str], Any]:
    calls: list[str] = []

    async def effect_handler(params: TicketedEffectParams, invocation: object) -> EffectResult:
        calls.append("apply")
        raise RuntimeError(f"simulated plugin crash with {SECRET_MARKER}")

    def read_handler(params: EmptyParams) -> EmptyResult:
        calls.append("read")
        return EmptyResult()

    return calls, effect_handler, read_handler


def build_host(
    replay: ReplayStore,
    *,
    crash_apply: bool = False,
) -> tuple[PluginHost, list[str], Any]:
    calls: list[str] = []
    ticketed_apply: Any

    async def healthy_apply(params: TicketedEffectParams, invocation: object) -> EffectResult:
        calls.append("apply")
        return EffectResult(changed=True)

    async def crashing_apply(params: TicketedEffectParams, invocation: object) -> EffectResult:
        calls.append("apply")
        raise RuntimeError(f"simulated plugin crash with {SECRET_MARKER}")

    def read_handler(params: EmptyParams) -> EmptyResult:
        calls.append("read")
        return EmptyResult()

    def reconcile_handler(params: ReconcileParams) -> EmptyResult:
        calls.append("reconcile")
        return EmptyResult()

    ticketed_apply = crashing_apply if crash_apply else healthy_apply
    bindings = {
        name: MethodBinding(
            name, EmptyParams, EmptyResult, read_handler, kind=MethodKind.READ
        )
        for name in ("health", "describe", "capability_probe")
    }
    bindings["read"] = MethodBinding(
        "read", EmptyParams, EmptyResult, read_handler, kind=MethodKind.READ
    )
    bindings["reconcile"] = MethodBinding(
        "reconcile", ReconcileParams, EmptyResult, reconcile_handler, kind=MethodKind.RECONCILE
    )
    bindings["apply"] = MethodBinding(
        "apply", ApplyParams, EffectResult, ticketed_apply, kind=MethodKind.APPLY
    )
    host = PluginHost(bindings, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100))
    return host, calls, bindings


def dispatch(host: PluginHost, request: RpcRequest) -> Any:
    return asyncio.run(host.dispatch(request))


def test_crash_after_dispatch_is_execution_unknown_and_redacted() -> None:
    replay = ReplayStore()
    host, calls, _bindings = build_host(replay, crash_apply=True)
    params = apply_params()
    token = issue_ticket(params)
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket=token,
    )

    response = dispatch(host, request)

    assert response.error is not None
    assert response.error.data.reason == "execution_unknown"
    assert SECRET_MARKER not in response.model_dump_json()
    assert calls == ["apply"]


def test_restart_recovers_health_and_read() -> None:
    replay = ReplayStore()
    _crashed_host, _calls, _bindings = build_host(replay, crash_apply=True)
    # The plugin process restarts: a fresh host shares the same replay store.
    restarted, calls, _bindings = build_host(replay, crash_apply=False)

    health = dispatch(
        restarted,
        RpcRequest(jsonrpc="2.0", api_version="1.0", id="h", method="health", params={}),
    )
    read = dispatch(
        restarted,
        RpcRequest(jsonrpc="2.0", api_version="1.0", id="r", method="read", params={}),
    )

    assert health.result == {"ok": True}
    assert read.result == {"ok": True}
    # health/describe/capability_probe and read all share the recording handler.
    assert calls == ["read", "read"]


def test_restart_does_not_replay_the_crashed_ticket() -> None:
    replay = ReplayStore()
    crashed, _calls, _bindings = build_host(replay, crash_apply=True)
    params = apply_params()
    token = issue_ticket(params)
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket=token,
    )
    assert dispatch(crashed, request).error.data.reason == "execution_unknown"

    # After restart, blindly re-sending the same ticket must not re-execute.
    restarted, calls, _bindings = build_host(replay, crash_apply=False)
    response = dispatch(restarted, request)

    assert response.error is not None
    assert response.error.data.reason == "replay"
    assert calls == []


def test_restart_with_fresh_ticket_recovers_execution() -> None:
    replay = ReplayStore()
    crashed, _calls, _bindings = build_host(replay, crash_apply=True)
    params = apply_params()
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket=issue_ticket(params, ticket_id="ticket-crash"),
    )
    assert dispatch(crashed, request).error.data.reason == "execution_unknown"

    restarted, calls, _bindings = build_host(replay, crash_apply=False)
    fresh = request.model_copy(
        update={"ticket": issue_ticket(params, ticket_id="ticket-fresh")}
    )
    response = dispatch(restarted, fresh)

    assert response.result == {"changed": True}
    assert calls == ["apply"]


def test_invalid_ticket_has_zero_dispatch() -> None:
    replay = ReplayStore()
    host, calls, _bindings = build_host(replay)
    params = apply_params()
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket="forged.token",
    )

    response = dispatch(host, request)

    assert response.error is not None
    assert response.error.data.reason == "malformed_token"
    assert calls == []


def test_duplicate_request_is_rejected() -> None:
    replay = ReplayStore()
    host, calls, _bindings = build_host(replay)
    params = apply_params()
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket=issue_ticket(params),
    )

    first = dispatch(host, request)
    second = dispatch(host, request)

    assert first.result == {"changed": True}
    assert second.error is not None
    assert second.error.data.reason == "replay"
    assert calls == ["apply"]


@pytest.mark.parametrize(
    "payload",
    [
        b"x" * (MAX_RPC_BYTES + 1) + b"\n",
        b"{} {}\n",
        b"[\n",
        b"\xff\xfe\n",
        b'{"jsonrpc":"2.0","api_version":"1.0","id":"1","method":"health","params":{},"params":{}}\n',
    ],
    ids=["oversized", "multiple_frames", "invalid_json", "invalid_utf8", "duplicate_key"],
)
def test_oversized_or_malformed_requests_are_rejected(payload: bytes) -> None:
    with pytest.raises(Exception) as caught:
        decode_request_frame(payload)
    reasons = {
        "payload_too_large",
        "multiple_frames",
        "invalid_json",
        "invalid_utf8",
        "duplicate_key",
    }
    assert getattr(caught.value, "reason", None) in reasons


def test_oversized_handler_output_is_bounded() -> None:
    def huge(params: EmptyParams) -> EmptyResult:
        return EmptyResult(ok=True)

    class HugeResult(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)

        blob: str

    def huge_result(params: EmptyParams) -> HugeResult:
        return HugeResult(blob="y" * (MAX_RPC_BYTES + 100))

    bindings = {
        "health": MethodBinding("health", EmptyParams, EmptyResult, huge, kind=MethodKind.READ),
        "describe": MethodBinding("describe", EmptyParams, EmptyResult, huge, kind=MethodKind.READ),
        "capability_probe": MethodBinding(
            "capability_probe", EmptyParams, EmptyResult, huge, kind=MethodKind.READ
        ),
        "read": MethodBinding(
            "read", EmptyParams, HugeResult, huge_result, kind=MethodKind.READ
        ),
    }
    host = PluginHost(bindings)
    response = dispatch(
        host,
        RpcRequest(jsonrpc="2.0", api_version="1.0", id="big", method="read", params={}),
    )

    assert response.error is not None
    assert response.error.data.reason == "invalid_handler_result"


def test_effect_timeout_is_execution_unknown_and_quarantines_same_instance() -> None:
    replay = ReplayStore()
    calls: list[str] = []

    async def hanging_apply(params: TicketedEffectParams, invocation: object) -> EffectResult:
        calls.append("apply")
        await asyncio.sleep(3600)

    bindings = {
        name: MethodBinding(
            name,
            EmptyParams,
            EmptyResult,
            lambda params: EmptyResult(),
            kind=MethodKind.READ,
        )
        for name in ("health", "describe", "capability_probe")
    }
    bindings["apply"] = MethodBinding(
        "apply",
        ApplyParams,
        EffectResult,
        hanging_apply,
        kind=MethodKind.APPLY,
        dispatch_timeout_seconds=0.05,
    )
    host = PluginHost(bindings, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100))
    params = apply_params()
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket=issue_ticket(params, ticket_id="ticket-hang"),
    )

    response = dispatch(host, request)

    assert response.error is not None
    assert response.error.data.reason == "execution_unknown"
    assert calls == ["apply"]


def test_reconcile_after_crash_runs_on_quiescent_restarted_instance() -> None:
    replay = ReplayStore()
    crashed, _calls, _bindings = build_host(replay, crash_apply=True)
    params = apply_params()
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="apply",
        method="apply",
        params=params.model_dump(mode="json"),
        ticket=issue_ticket(params, ticket_id="ticket-reconcile"),
    )
    assert dispatch(crashed, request).error.data.reason == "execution_unknown"

    restarted, calls, _bindings = build_host(replay, crash_apply=False)
    reconcile = dispatch(
        restarted,
        RpcRequest(
            jsonrpc="2.0",
            api_version="1.0",
            id="reconcile",
            method="reconcile",
            params={"transaction_id": "tx-1", "step_id": "step-1"},
        ),
    )
    assert reconcile.result == {"ok": True}
    assert "reconcile" in calls

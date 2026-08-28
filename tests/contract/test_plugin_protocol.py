from __future__ import annotations

import asyncio
import errno
import hashlib
import hmac
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from a4diag.domain import Operation, Risk, canonical_json_bytes
from a4diag.plugin_api.protocol import (
    MAX_RPC_BYTES,
    EmptyParams,
    MethodBinding,
    MethodKind,
    PluginHost,
    RpcClientError,
    RpcRequest,
    TicketedEffectParams,
    decode_request_frame,
    decode_response_frame,
    effect_fields_digest,
    read_bounded_frame,
)
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketRequest,
    TicketIssuer,
    TicketVerifier,
)
from a4diag.policy_engine import PolicyAuthorization, canonical_operation_digest
from tests.contract.plugin_harness import running_harness
from tests.contract.plugin_harness import is_af_unix_unavailable


KEY = b"plugin-protocol-ticket-key-32bytes"
POLICY_KEY = b"plugin-protocol-policy-key-32bytes"


class EmptyResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    ok: bool = True


class EffectResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    changed: bool


class ApplyEffectParams(TicketedEffectParams):
    marker: dict[str, JsonValue]
    pre_state: dict[str, JsonValue] = Field(
        default_factory=lambda: {"content": "before"}
    )
    custom_effect_field: str = "bound"


class ReconcileCallParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str
    step_id: str


class ReplayStore:
    def __init__(self) -> None:
        self.values: set[str] = set()
        self.calls = 0

    def consume(self, ticket_id: str) -> bool:
        self.calls += 1
        if ticket_id in self.values:
            return False
        self.values.add(ticket_id)
        return True


def operation() -> Operation:
    return Operation(
        capability="services",
        action="restart",
        resource="example.service",
        parameters={"unit": "example.service"},
        model_risk=Risk.LOW,
        verify={"active": True},
        undo={"restore": True},
    )


def effect_params(**updates: object) -> TicketedEffectParams:
    data: dict[str, object] = {
        "transaction_id": "tx-1",
        "step_id": "step-1",
        "target_id": "lab",
        "target_fingerprint": "machine-1",
        "operation": operation(),
        "plan_digest": "a" * 64,
        "risk": Risk.LOW,
        "approval_id": None,
    }
    data.update(updates)
    return TicketedEffectParams.model_validate(data)


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
    payload = canonical_json_bytes(
        unsigned.model_dump(mode="json", exclude={"mac"})
    )
    tag = hmac.new(
        POLICY_KEY, b"a4diag-policy-authorization-v1\x00" + payload, hashlib.sha256
    ).hexdigest()
    return unsigned.model_copy(update={"mac": tag})


def issue_ticket(
    params: TicketedEffectParams, phase: OperationPhase, *, now: int = 100
) -> str:
    request = OperationTicketRequest(
        **params.model_dump(
            exclude={"marker", "pre_state", "custom_effect_field"}
        ),
        phase=phase,
        effect_payload_digest=effect_fields_digest(params),
        ttl_seconds=30,
    )
    return TicketIssuer(
        KEY,
        authorization_key=POLICY_KEY,
        clock=lambda: now,
        ticket_id_factory=lambda: f"ticket-{phase.value}",
    ).issue(request, authorization(params))


def bindings(calls: list[str]) -> dict[str, MethodBinding[Any, Any]]:
    def read_handler(params: EmptyParams) -> EmptyResult:
        calls.append("read")
        return EmptyResult()

    async def effect_handler(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        assert not hasattr(invocation, "raw_token")
        calls.append("apply")
        return EffectResult(changed=True)

    required = {
        name: MethodBinding(
            name, EmptyParams, EmptyResult, read_handler, kind=MethodKind.READ
        )
        for name in ("health", "describe", "capability_probe")
    }
    required["apply"] = MethodBinding(
        "apply",
        TicketedEffectParams,
        EffectResult,
        effect_handler,
        kind=MethodKind.APPLY,
    )
    return required


def test_unknown_fields_and_methods_are_rejected(tmp_path: Path) -> None:
    async def scenario() -> None:
        calls: list[str] = []
        verifier = TicketVerifier(KEY, ReplayStore(), clock=lambda: 100)
        async with running_harness(tmp_path, bindings(calls), ticket_verifier=verifier) as h:
            response = await h.raw(
                {
                    "jsonrpc": "2.0",
                    "api_version": "1.0",
                    "id": "1",
                    "method": "unknown",
                    "params": {},
                    "extra": 1,
                }
            )
            assert response["error"]["code"] == -32600
            assert response["error"]["data"]["reason"] == "invalid_request"
            response = await h.call("unknown", {})
            assert response["error"]["code"] == -32601
        assert calls == []

    asyncio.run(scenario())


def test_write_method_requires_valid_bound_single_use_ticket(tmp_path: Path) -> None:
    async def scenario() -> None:
        calls: list[str] = []
        replay = ReplayStore()
        params = effect_params()
        verifier = TicketVerifier(KEY, replay, clock=lambda: 100)
        async with running_harness(tmp_path, bindings(calls), ticket_verifier=verifier) as h:
            missing = await h.call("apply", params.model_dump(mode="json"))
            assert missing["error"]["data"]["reason"] == "ticket_required"
            assert replay.calls == 0
            wrong = issue_ticket(params, OperationPhase.UNDO)
            rejected = await h.call("apply", params.model_dump(mode="json"), wrong)
            assert rejected["error"]["data"]["reason"] == "phase_mismatch"
            assert replay.calls == 0
            token = issue_ticket(params, OperationPhase.APPLY)
            accepted = await h.call("apply", params.model_dump(mode="json"), token)
            assert accepted["result"] == {"changed": True}
            replayed = await h.call("apply", params.model_dump(mode="json"), token)
            assert replayed["error"]["data"]["reason"] == "replay"
        assert calls == ["apply"]

    asyncio.run(scenario())


def test_ticket_checks_precede_dispatch_and_replay_consumption() -> None:
    calls: list[str] = []
    replay = ReplayStore()
    params = effect_params()
    host = PluginHost(
        bindings(calls),
        ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100),
    )

    def request(ticket: str | None, body: TicketedEffectParams = params) -> RpcRequest:
        return RpcRequest(
            jsonrpc="2.0",
            api_version="1.0",
            id="direct",
            method="apply",
            params=body.model_dump(mode="json"),
            ticket=ticket,
        )

    missing = asyncio.run(host.dispatch(request(None)))
    assert missing.error is not None and missing.error.data.reason == "ticket_required"
    invalid = asyncio.run(host.dispatch(request("not-a-ticket")))
    assert invalid.error is not None and invalid.error.data.reason == "malformed_token"
    expired_token = issue_ticket(params, OperationPhase.APPLY, now=50)
    expired = asyncio.run(host.dispatch(request(expired_token)))
    assert expired.error is not None and expired.error.data.reason == "expired"
    wrong_phase_token = issue_ticket(params, OperationPhase.UNDO)
    wrong_phase = asyncio.run(host.dispatch(request(wrong_phase_token)))
    assert wrong_phase.error is not None and wrong_phase.error.data.reason == "phase_mismatch"
    assert replay.calls == 0

    token = issue_ticket(params, OperationPhase.APPLY)
    wrong_target = asyncio.run(
        host.dispatch(request(token, effect_params(target_id="other")))
    )
    assert wrong_target.error is not None and wrong_target.error.data.reason == "target_mismatch"
    assert replay.calls == 0
    accepted = asyncio.run(host.dispatch(request(token)))
    assert accepted.error is None and accepted.result == {"changed": True}
    assert replay.calls == 1
    replayed = asyncio.run(host.dispatch(request(token)))
    assert replayed.error is not None and replayed.error.data.reason == "replay"
    assert replay.calls == 2
    assert calls == ["apply"]


def test_host_binds_every_operation_field_before_handler_dispatch() -> None:
    original = operation()
    mutations: tuple[dict[str, object], ...] = (
        {"capability": "files"},
        {"action": "start"},
        {"resource": "other.service"},
        {"parameters": {"unit": "other.service"}},
        {"model_risk": Risk.HIGH},
        {"verify": {"active": False}},
        {"undo": {"restore": False}},
        {"timeout_seconds": 21},
        {"output_limit_bytes": 1024},
    )
    for update in mutations:
        calls: list[str] = []
        replay = ReplayStore()
        params = effect_params()
        token = issue_ticket(params, OperationPhase.APPLY)
        host = PluginHost(
            bindings(calls),
            ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100),
        )
        tampered_operation = original.model_copy(update=update)
        tampered = params.model_copy(
            update={
                "operation": tampered_operation,
                "approval_id": "approval-1"
                if tampered_operation.model_risk is Risk.HIGH
                else None,
            }
        )
        rejected = asyncio.run(
            host.dispatch(
                RpcRequest(
                    jsonrpc="2.0",
                    api_version="1.0",
                    id="tampered",
                    method="apply",
                    params=tampered.model_dump(mode="json"),
                    ticket=token,
                )
            )
        )
        assert rejected.error is not None
        assert rejected.error.data.reason == "operation_mismatch"
        assert replay.calls == 0
        accepted = asyncio.run(
            host.dispatch(
                RpcRequest(
                    jsonrpc="2.0",
                    api_version="1.0",
                    id="original",
                    method="apply",
                    params=params.model_dump(mode="json"),
                    ticket=token,
                )
            )
        )
        assert accepted.result == {"changed": True}
        assert calls == ["apply"]


@pytest.mark.parametrize(
    "update",
    [
        {"marker": {"id": "tampered"}},
        {"pre_state": {"content": "tampered"}},
        {"custom_effect_field": "tampered"},
    ],
)
def test_phase_specific_effect_fields_are_digest_bound_without_burning_ticket(
    update: dict[str, object],
) -> None:
    calls: list[str] = []
    replay = ReplayStore()
    params = ApplyEffectParams(
        **effect_params().model_dump(), marker={"id": "original"}
    )

    async def handler(params: ApplyEffectParams, invocation: object) -> EffectResult:
        calls.append("apply")
        return EffectResult(changed=True)

    methods = bindings([])
    methods["apply"] = MethodBinding(
        "apply", ApplyEffectParams, EffectResult, handler, kind=MethodKind.APPLY
    )
    host = PluginHost(
        methods, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100)
    )
    token = issue_ticket(params, OperationPhase.APPLY)
    tampered = params.model_copy(update=update)
    rejected = asyncio.run(
        host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="tampered-effect",
                method="apply",
                params=tampered.model_dump(mode="json"),
                ticket=token,
            )
        )
    )
    assert rejected.error is not None
    assert rejected.error.data.reason == "effect_payload_mismatch"
    assert replay.calls == 0
    accepted = asyncio.run(
        host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="original-effect",
                method="apply",
                params=params.model_dump(mode="json"),
                ticket=token,
            )
        )
    )
    assert accepted.result == {"changed": True}
    assert calls == ["apply"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("transaction_id", "contains space"),
        ("transaction_id", "x" * 129),
        ("step_id", "step\n1"),
        ("target_id", "_unsafe"),
        ("target_fingerprint", "x" * 513),
        ("target_fingerprint", "machine\x00one"),
        ("plan_digest", "A" * 64),
        ("approval_id", "not safe"),
    ],
)
def test_effect_envelope_reuses_strict_ticket_validation(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        effect_params(**{field: value})


def test_handler_failures_are_redacted() -> None:
    def explode(params: EmptyParams) -> EmptyResult:
        raise RuntimeError("secret-token-value")

    methods = {
        name: MethodBinding(
            name, EmptyParams, EmptyResult, explode, kind=MethodKind.READ
        )
        for name in ("health", "describe", "capability_probe")
    }
    host = PluginHost(methods)
    response = asyncio.run(
        host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="redact",
                method="health",
                params={},
            )
        )
    )
    encoded = response.model_dump_json()
    assert response.error is not None
    assert response.error.data.reason == "internal_error"
    assert "secret-token-value" not in encoded


def test_host_refuses_preexisting_non_socket_without_deleting_it(tmp_path: Path) -> None:
    path = tmp_path / "occupied"
    path.write_text("keep", encoding="utf-8")
    host = PluginHost(bindings([]), ticket_verifier=TicketVerifier(KEY, ReplayStore()))
    with pytest.raises(FileExistsError):
        asyncio.run(host.start(path))
    assert path.read_text(encoding="utf-8") == "keep"


def test_host_refuses_preexisting_unix_socket(tmp_path: Path) -> None:
    path = tmp_path / "occupied.sock"
    occupied: socket.socket | None = None
    try:
        occupied = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        occupied.bind(str(path))
    except (AttributeError, OSError) as error:
        if occupied is not None:
            occupied.close()
        if is_af_unix_unavailable(error, api="socket.AF_UNIX"):
            pytest.skip(
                f"runtime AF_UNIX bind unsupported; mandatory Linux Phase 4 gate: {type(error).__name__}"
            )
        raise
    try:
        host = PluginHost(
            bindings([]), ticket_verifier=TicketVerifier(KEY, ReplayStore())
        )
        with pytest.raises(FileExistsError):
            asyncio.run(host.start(path))
        assert path.exists()
    finally:
        occupied.close()
        path.unlink(missing_ok=True)


def test_socket_cleanup_preserves_replacement_inode(tmp_path: Path) -> None:
    async def scenario() -> None:
        path = tmp_path / "owned.sock"
        host = PluginHost(
            bindings([]), ticket_verifier=TicketVerifier(KEY, ReplayStore())
        )
        try:
            server = await host.start(path)
        except (AttributeError, NotImplementedError, OSError) as error:
            if is_af_unix_unavailable(error, api="asyncio.start_unix_server"):
                pytest.skip(
                    f"runtime AF_UNIX asyncio setup unsupported; mandatory Linux Phase 4 gate: {type(error).__name__}"
                )
            raise
        server.close()
        await server.wait_closed()
        path.unlink()
        path.write_text("replacement", encoding="utf-8")
        host.cleanup_socket()
        assert path.read_text(encoding="utf-8") == "replacement"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"\xff\n", "invalid_utf8"),
        (b'{"jsonrpc":"2.0",}\n', "invalid_json"),
        (b'{"jsonrpc":"2.0","jsonrpc":"2.0"}\n', "duplicate_key"),
        (b"[]\n", "batch_not_allowed"),
        (b"{}\n{}\n", "multiple_frames"),
        (b'{"x":NaN}\n', "invalid_json"),
    ],
)
def test_malformed_frames_have_stable_reasons(payload: bytes, reason: str) -> None:
    with pytest.raises(RpcClientError) as caught:
        decode_request_frame(payload)
    assert caught.value.reason == reason


def test_frame_bounds_depth_and_item_bombs() -> None:
    with pytest.raises(RpcClientError, match="payload_too_large"):
        decode_request_frame(b"{" + b" " * MAX_RPC_BYTES + b"}\n")
    deep: object = {"leaf": 0}
    for _ in range(40):
        deep = {"child": deep}
    with pytest.raises(RpcClientError, match="structure_too_complex"):
        decode_request_frame(json.dumps(deep).encode() + b"\n")
    many = {str(index): index for index in range(10_001)}
    with pytest.raises(RpcClientError, match="structure_too_complex"):
        decode_request_frame(json.dumps(many).encode() + b"\n")


def test_incremental_frame_reader_accepts_fragmentation_and_rejects_stream_abuse() -> None:
    class Reader:
        def __init__(self, chunks: list[bytes]) -> None:
            self.chunks = list(chunks)

        async def read(self, limit: int) -> bytes:
            return self.chunks.pop(0) if self.chunks else b""

    valid = asyncio.run(read_bounded_frame(Reader([b'{"a"', b":1}", b"\n"])))  # type: ignore[arg-type]
    assert valid == b'{"a":1}\n'
    with pytest.raises(RpcClientError, match="premature_eof"):
        asyncio.run(read_bounded_frame(Reader([b"{}"])))  # type: ignore[arg-type]
    with pytest.raises(RpcClientError, match="multiple_frames"):
        asyncio.run(read_bounded_frame(Reader([b"{}\n", b"{}\n"])))  # type: ignore[arg-type]
    with pytest.raises(RpcClientError, match="payload_too_large"):
        asyncio.run(
            read_bounded_frame(
                Reader([b"x" * 600_000, b"x" * 448_578])  # type: ignore[arg-type]
            )
        )


@pytest.mark.parametrize(
    ("error", "api", "expected"),
    [
        (OSError(errno.EAFNOSUPPORT, "unsupported"), "socket.AF_UNIX", True),
        (OSError(errno.EPROTONOSUPPORT, "unsupported"), "asyncio.start_unix_server", True),
        (OSError(errno.ENOSYS, "unsupported"), "asyncio.start_unix_server", True),
        (OSError(errno.EACCES, "denied"), "asyncio.start_unix_server", False),
        (OSError(errno.EINVAL, "invalid"), "asyncio.start_unix_server", False),
        (OSError(errno.ENAMETOOLONG, "long"), "asyncio.start_unix_server", False),
    ],
)
def test_af_unix_skip_predicate_is_errno_specific(
    error: BaseException, api: str, expected: bool
) -> None:
    assert is_af_unix_unavailable(error, api=api) is expected


def test_real_host_accepts_fragmented_request_when_async_unix_is_available(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        async with running_harness(
            tmp_path,
            bindings([]),
            ticket_verifier=TicketVerifier(KEY, ReplayStore()),
        ) as harness:
            response = await harness.raw_chunks(
                [
                    b'{"jsonrpc":"2.0","api_version":"1.0",',
                    b'"id":"fragmented","method":"health",',
                    b'"params":{}}\n',
                ]
            )
            assert response["result"] == {"ok": True}

    asyncio.run(scenario())


def test_host_requires_mandatory_methods_and_immutable_registry() -> None:
    with pytest.raises(ValueError, match="mandatory"):
        PluginHost({})
    calls: list[str] = []
    source = bindings(calls)
    host = PluginHost(source, ticket_verifier=TicketVerifier(KEY, ReplayStore()))
    source.clear()
    assert set(host.methods) == {"health", "describe", "capability_probe", "apply"}
    with pytest.raises(TypeError):
        host.methods["other"] = object()  # type: ignore[index]


@pytest.mark.parametrize(
    ("name", "kind", "phase"),
    [
        ("prepare", MethodKind.READ, OperationPhase.PREPARE),
        ("prepare", MethodKind.APPLY, OperationPhase.PREPARE),
        ("apply", MethodKind.UNDO, OperationPhase.APPLY),
        ("undo", MethodKind.PREPARE, OperationPhase.UNDO),
    ],
)
def test_effect_method_names_cannot_be_registered_with_wrong_method_kind(
    name: str, kind: MethodKind, phase: OperationPhase
) -> None:
    def handler(params: TicketedEffectParams, invocation: object) -> EffectResult:
        return EffectResult(changed=True)

    with pytest.raises(ValueError, match="ticket phase"):
        MethodBinding(
            name,
            TicketedEffectParams,
            EffectResult,
            handler,
            kind=kind,
        )


def test_execute_typed_effect_alias_still_requires_fixed_phase_ticket() -> None:
    calls: list[str] = []
    replay = ReplayStore()
    params = effect_params()

    async def handler(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        calls.append("effect")
        return EffectResult(changed=True)

    methods = bindings([])
    methods["execute_typed"] = MethodBinding(
        "execute_typed",
        TicketedEffectParams,
        EffectResult,
        handler,
        kind=MethodKind.APPLY,
    )
    host = PluginHost(methods, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100))
    request = RpcRequest(
        jsonrpc="2.0",
        api_version="1.0",
        id="alias",
        method="execute_typed",
        params=params.model_dump(mode="json"),
    )
    missing = asyncio.run(host.dispatch(request))
    assert missing.error is not None and missing.error.data.reason == "ticket_required"
    token = issue_ticket(params, OperationPhase.APPLY)
    accepted = asyncio.run(host.dispatch(request.model_copy(update={"ticket": token})))
    assert accepted.result == {"changed": True}
    assert calls == ["effect"]


def test_method_binding_rejects_non_strict_parameter_or_result_models() -> None:
    class LooseModel(BaseModel):
        value: str = "ignored"

    def handler(params: BaseModel) -> BaseModel:
        return params

    with pytest.raises(TypeError, match="extra='forbid'"):
        MethodBinding("loose", LooseModel, EmptyResult, handler, kind=MethodKind.READ)
    with pytest.raises(TypeError, match="extra='forbid'"):
        MethodBinding("loose", EmptyParams, LooseModel, handler, kind=MethodKind.READ)


def test_method_binding_rejects_unknown_administration_kind() -> None:
    with pytest.raises(TypeError, match="MethodKind"):
        MethodBinding(
            "administration_alias",
            EmptyParams,
            EmptyResult,
            lambda params: EmptyResult(),
            kind="administration",  # type: ignore[arg-type]
        )


def test_unknown_administration_method_cannot_be_misclassified_as_read() -> None:
    with pytest.raises(ValueError, match="method name"):
        MethodBinding(
            "set_webhook",
            EmptyParams,
            EmptyResult,
            lambda params: EmptyResult(),
            kind=MethodKind.READ,
        )


def test_sync_effect_handler_is_rejected_at_registration() -> None:
    with pytest.raises(TypeError, match="async"):
        MethodBinding(
            "apply",
            TicketedEffectParams,
            EffectResult,
            lambda params, invocation: EffectResult(changed=True),
            kind=MethodKind.APPLY,
        )


@pytest.mark.parametrize("timeout", [0, -1, 121, "30"])
def test_method_binding_dispatch_timeout_is_strictly_bounded(timeout: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        MethodBinding(
            "bounded",
            EmptyParams,
            EmptyResult,
            lambda params: EmptyResult(),
            kind=MethodKind.READ,
            dispatch_timeout_seconds=timeout,  # type: ignore[arg-type]
        )


def test_stalled_sync_handler_does_not_block_independent_health_dispatch() -> None:
    release = threading.Event()

    def slow(params: EmptyParams) -> EmptyResult:
        release.wait(0.2)
        return EmptyResult()

    methods = bindings([])
    methods["read"] = MethodBinding(
        "read",
        EmptyParams,
        EmptyResult,
        slow,
        kind=MethodKind.READ,
        dispatch_timeout_seconds=0.02,
    )
    host = PluginHost(methods)

    async def scenario() -> tuple[object, object, float]:
        slow_request = RpcRequest(
            jsonrpc="2.0", api_version="1.0", id="slow", method="read", params={}
        )
        health_request = RpcRequest(
            jsonrpc="2.0", api_version="1.0", id="health", method="health", params={}
        )
        started = time.monotonic()
        slow_response, health_response = await asyncio.gather(
            host.dispatch(slow_request), host.dispatch(health_request)
        )
        return slow_response, health_response, time.monotonic() - started

    try:
        slow_response, health_response, elapsed = asyncio.run(scenario())
    finally:
        release.set()
    assert slow_response.error is not None
    assert slow_response.error.data.reason == "handler_timeout"
    assert health_response.result == {"ok": True}
    assert elapsed < 0.15


@pytest.mark.parametrize("failure", ["timeout", "crash"])
def test_effect_timeout_or_crash_after_dispatch_is_execution_unknown(
    failure: str,
) -> None:
    params = effect_params()
    replay = ReplayStore()

    async def timeout_handler(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        await asyncio.sleep(0.2)
        return EffectResult(changed=True)

    async def crash_handler(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        raise RuntimeError("private-effect-detail")

    handler = timeout_handler if failure == "timeout" else crash_handler
    methods = bindings([])
    methods["execute_typed"] = MethodBinding(
        "execute_typed",
        TicketedEffectParams,
        EffectResult,
        handler,
        kind=MethodKind.APPLY,
        dispatch_timeout_seconds=0.02,
    )
    host = PluginHost(
        methods, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100)
    )
    response = asyncio.run(
        host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="effect-timeout",
                method="execute_typed",
                params=params.model_dump(mode="json"),
                ticket=issue_ticket(params, OperationPhase.APPLY),
            )
        )
    )
    assert response.error is not None
    assert response.error.data.reason == "execution_unknown"
    assert "private-effect-detail" not in response.model_dump_json()
    assert replay.calls == 1


def test_effect_timeout_waits_for_quiescence_and_blocks_reconcile_while_active() -> None:
    params = effect_params()
    replay = ReplayStore()
    started = asyncio.Event()
    cleanup_done = asyncio.Event()
    late_mutations: list[str] = []

    async def effect_handler(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        started.set()
        try:
            await asyncio.sleep(10)
            late_mutations.append("mutated")
        except asyncio.CancelledError:
            await asyncio.sleep(0.03)
            cleanup_done.set()
            return EffectResult(changed=True)
        return EffectResult(changed=True)

    async def reconcile_handler(params: ReconcileCallParams) -> EmptyResult:
        return EmptyResult()

    methods = bindings([])
    methods["apply"] = MethodBinding(
        "apply",
        TicketedEffectParams,
        EffectResult,
        effect_handler,
        kind=MethodKind.APPLY,
        dispatch_timeout_seconds=0.01,
        cancellation_grace_seconds=0.1,
    )
    methods["reconcile"] = MethodBinding(
        "reconcile",
        ReconcileCallParams,
        EmptyResult,
        reconcile_handler,
        kind=MethodKind.RECONCILE,
    )
    host = PluginHost(
        methods, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100)
    )

    async def scenario() -> None:
        effect_request = RpcRequest(
            jsonrpc="2.0",
            api_version="1.0",
            id="effect-quiescence",
            method="apply",
            params=params.model_dump(mode="json"),
            ticket=issue_ticket(params, OperationPhase.APPLY),
        )
        dispatch = asyncio.create_task(host.dispatch(effect_request))
        await started.wait()
        active_reconcile = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="active-reconcile",
                method="reconcile",
                params={"transaction_id": params.transaction_id, "step_id": params.step_id},
            )
        )
        assert active_reconcile.error is not None
        assert active_reconcile.error.data.reason == "dispatch_not_quiescent"
        health = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="health-during-effect",
                method="health",
                params={},
            )
        )
        assert health.result == {"ok": True}
        response = await dispatch
        assert response.error is not None
        assert response.error.data.reason == "execution_unknown"
        assert cleanup_done.is_set()
        assert late_mutations == []
        quiescent_reconcile = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="quiescent-reconcile",
                method="reconcile",
                params={"transaction_id": params.transaction_id, "step_id": params.step_id},
            )
        )
        assert quiescent_reconcile.result == {"ok": True}

    asyncio.run(scenario())


def test_effect_that_suppresses_cancellation_requires_process_quarantine() -> None:
    params = effect_params()
    replay = ReplayStore()
    started = asyncio.Event()
    release = asyncio.Event()
    completed = asyncio.Event()

    async def non_quiescent_effect(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        started.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            await release.wait()
        completed.set()
        return EffectResult(changed=True)

    async def reconcile_handler(params: ReconcileCallParams) -> EmptyResult:
        return EmptyResult()

    methods = bindings([])
    methods["apply"] = MethodBinding(
        "apply",
        TicketedEffectParams,
        EffectResult,
        non_quiescent_effect,
        kind=MethodKind.APPLY,
        dispatch_timeout_seconds=0.01,
        cancellation_grace_seconds=0.01,
    )
    methods["reconcile"] = MethodBinding(
        "reconcile",
        ReconcileCallParams,
        EmptyResult,
        reconcile_handler,
        kind=MethodKind.RECONCILE,
    )
    host = PluginHost(
        methods, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100)
    )

    async def scenario() -> None:
        dispatch = asyncio.create_task(
            host.dispatch(
                RpcRequest(
                    jsonrpc="2.0",
                    api_version="1.0",
                    id="non-quiescent",
                    method="apply",
                    params=params.model_dump(mode="json"),
                    ticket=issue_ticket(params, OperationPhase.APPLY),
                )
            )
        )
        await started.wait()
        response = await dispatch
        assert response.error is not None
        assert response.error.data.reason == "quarantine_required"
        blocked = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="quarantined-reconcile",
                method="reconcile",
                params={"transaction_id": params.transaction_id, "step_id": params.step_id},
            )
        )
        assert blocked.error is not None
        assert blocked.error.data.reason == "quarantine_required"
        release.set()
        await completed.wait()
        await asyncio.sleep(0)
        still_blocked = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="still-quarantined",
                method="reconcile",
                params={"transaction_id": params.transaction_id, "step_id": params.step_id},
            )
        )
        assert still_blocked.error is not None
        assert still_blocked.error.data.reason == "quarantine_required"
        assert host.quarantine_required is True
        health_after_quarantine = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="health-after-quarantine",
                method="health",
                params={},
            )
        )
        assert health_after_quarantine.result == {"ok": True}

    asyncio.run(scenario())


def test_async_callable_objects_are_awaited_and_effects_are_ticketed() -> None:
    params = effect_params()

    class AsyncRead:
        async def __call__(self, params: EmptyParams) -> EmptyResult:
            return EmptyResult()

    class AsyncEffect:
        async def __call__(
            self, params: TicketedEffectParams, invocation: object
        ) -> EffectResult:
            return EffectResult(changed=True)

    methods = bindings([])
    methods["read"] = MethodBinding(
        "read", EmptyParams, EmptyResult, AsyncRead(), kind=MethodKind.READ
    )
    methods["execute_typed"] = MethodBinding(
        "execute_typed",
        TicketedEffectParams,
        EffectResult,
        AsyncEffect(),
        kind=MethodKind.APPLY,
    )
    host = PluginHost(
        methods, ticket_verifier=TicketVerifier(KEY, ReplayStore(), clock=lambda: 100)
    )
    read = asyncio.run(
        host.dispatch(
            RpcRequest(
                jsonrpc="2.0", api_version="1.0", id="read-object", method="read", params={}
            )
        )
    )
    assert read.result == {"ok": True}
    effect = asyncio.run(
        host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="effect-object",
                method="execute_typed",
                params=params.model_dump(mode="json"),
                ticket=issue_ticket(params, OperationPhase.APPLY),
            )
        )
    )
    assert effect.result == {"changed": True}


def test_high_effect_params_require_approval_before_ticket_verification() -> None:
    with pytest.raises(ValueError, match="approval"):
        effect_params(risk=Risk.HIGH, approval_id=None)


def test_client_validates_response_id_and_exclusive_payload(tmp_path: Path) -> None:
    from a4diag.plugin_client import PluginClient

    async def fake_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read()
        writer.write(
            b'{"jsonrpc":"2.0","api_version":"1.0","id":"wrong",'
            b'"result":{},"error":{"code":-1,"message":"x","data":{"reason":"x"}}}\n'
        )
        await writer.drain()
        writer.close()

    async def scenario() -> None:
        path = tmp_path / "c.sock"
        try:
            server = await asyncio.start_unix_server(fake_server, str(path))
        except (AttributeError, NotImplementedError, OSError) as error:
            if is_af_unix_unavailable(error, api="asyncio.start_unix_server"):
                pytest.skip(
                    f"runtime AF_UNIX asyncio setup unsupported; mandatory Linux Phase 4 gate: {type(error).__name__}"
                )
            raise
        try:
            with pytest.raises(RpcClientError) as caught:
                await PluginClient(path, timeout_seconds=1).call("health", {})
            assert caught.value.reason in {"invalid_response", "response_id_mismatch"}
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_response_schema_rejects_wrong_version_and_nonexclusive_payload() -> None:
    wrong_version = (
        b'{"jsonrpc":"2.0","api_version":"2.0","id":"x","result":{}}\n'
    )
    with pytest.raises(RpcClientError, match="invalid_response"):
        decode_response_frame(wrong_version)
    both = (
        b'{"jsonrpc":"2.0","api_version":"1.0","id":"x","result":{},'
        b'"error":{"code":-1,"message":"x","data":{"reason":"x"}}}\n'
    )
    with pytest.raises(RpcClientError, match="invalid_response"):
        decode_response_frame(both)


def test_client_reports_premature_eof_without_exposing_stream_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        def __init__(self) -> None:
            self.sent = False

        async def read(self, limit: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            return b'{"jsonrpc":"2.0"}'

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            PluginClient(
                "/run/a4diag/test.sock",
                request_id_factory=lambda: "request-1",
            ).call("health", {})
        )
    assert caught.value.reason == "premature_eof"


def test_client_accepts_fragmented_bounded_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        def __init__(self) -> None:
            self.chunks = [
                b'{"api_version":"1.0","id":"request-1",',
                b'"jsonrpc":"2.0","result":{"ok":true}}',
                b"\n",
            ]

        async def read(self, limit: int) -> bytes:
            return self.chunks.pop(0) if self.chunks else b""

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    result = asyncio.run(
        PluginClient(
            "/run/a4diag/test.sock",
            request_id_factory=lambda: "request-1",
        ).call("health", {})
    )
    assert result == {"ok": True}


def test_effect_client_deadline_allows_host_cancellation_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        def __init__(self) -> None:
            self.sent = False

        async def read(self, limit: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            await asyncio.sleep(0.03)
            return (
                b'{"api_version":"1.0","id":"request-1",'
                b'"jsonrpc":"2.0","result":{"changed":true}}\n'
            )

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    result = asyncio.run(
        PluginClient(
            "/run/a4diag/test.sock",
            timeout_seconds=0.01,
            request_id_factory=lambda: "request-1",
        ).call(
            "apply",
            {
                **effect_params().model_dump(mode="json"),
                "operation": operation().model_copy(
                    update={"timeout_seconds": 1}
                ).model_dump(mode="json"),
            },
            ticket="signed-ticket",
        )
    )
    assert result == {"changed": True}


def test_effect_client_transport_loss_after_dispatch_requires_quarantine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        async def read(self, limit: int) -> bytes:
            return b""

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            PluginClient(
                "/run/a4diag/test.sock",
                timeout_seconds=0.01,
                request_id_factory=lambda: "request-1",
            ).call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert caught.value.reason == "quarantine_required"


@pytest.mark.parametrize(
    ("payload", "underlying_reason"),
    [
        (b"\xff\n", "invalid_utf8"),
        (b'{"jsonrpc":"2.0",}\n', "invalid_json"),
        (b'{"jsonrpc":"2.0","id":"request-1","jsonrpc":"2.0",'
         b'"result":{}}\n', "duplicate_key"),
        (b'{"jsonrpc":"2.0","api_version":"2.0","id":"request-1",'
         b'"result":{}}\n', "invalid_response"),
        (b'{"jsonrpc":"2.0","api_version":"1.0","id":"request-1",'
         b'"result":{},"error":{"code":-1,"message":"x",'
         b'"data":{"reason":"x"}}}\n', "invalid_response"),
        (b'{"jsonrpc":"2.0","api_version":"1.0","id":"request-1",'
         b'"result":{}}\n{}', "multiple_frames"),
        (b'{"jsonrpc":"2.0","api_version":"1.0","id":"request-1",'
         b'"result":{}}\n', "response_id_mismatch"),
    ],
)
def test_effect_client_quarantines_every_ambiguous_response(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    underlying_reason: str,
) -> None:
    from a4diag.plugin_client import PluginClient

    if underlying_reason == "response_id_mismatch":
        payload = payload.replace(b'"request-1"', b'"wrong"')

    class Reader:
        def __init__(self) -> None:
            self._sent = False

        async def read(self, limit: int) -> bytes:
            if self._sent:
                return b""
            self._sent = True
            return payload

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            PluginClient(
                "/run/a4diag/test.sock",
                timeout_seconds=0.1,
                request_id_factory=lambda: "request-1",
            ).call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert caught.value.reason == "quarantine_required"
    assert caught.value.data == {"underlying_reason": underlying_reason}


def test_effect_client_quarantines_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        async def read(self, limit: int) -> bytes:
            return b"{" + b"x" * (MAX_RPC_BYTES + 1) + b"}\n"

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            PluginClient(
                "/run/a4diag/test.sock",
                timeout_seconds=0.1,
                request_id_factory=lambda: "request-1",
            ).call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert caught.value.reason == "quarantine_required"
    assert caught.value.data == {"underlying_reason": "response_too_large"}


def test_matching_host_error_after_effect_dispatch_remains_ordinary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        def __init__(self) -> None:
            self._sent = False

        async def read(self, limit: int) -> bytes:
            if self._sent:
                return b""
            self._sent = True
            return (
                b'{"jsonrpc":"2.0","api_version":"1.0","id":"request-1",'
                b'"error":{"code":-32001,"message":"Ticket rejected",'
                b'"data":{"reason":"ticket_rejected"}}}\n'
            )

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    client = PluginClient(
        "/run/a4diag/test.sock",
        timeout_seconds=0.1,
        request_id_factory=lambda: "request-1",
    )
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            client.call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert caught.value.reason == "ticket_rejected"
    assert caught.value.code == -32001
    assert caught.value.data == {"reason": "ticket_rejected"}
    assert client.quarantine_required is False


def test_client_latches_host_quarantine_and_preserves_read_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    params = effect_params()
    replay = ReplayStore()
    started = asyncio.Event()
    release = asyncio.Event()
    completed = asyncio.Event()

    async def non_quiescent_effect(
        params: TicketedEffectParams, invocation: object
    ) -> EffectResult:
        started.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            await release.wait()
        completed.set()
        return EffectResult(changed=True)

    async def reconcile_handler(params: ReconcileCallParams) -> EmptyResult:
        return EmptyResult()

    methods = bindings([])
    methods["apply"] = MethodBinding(
        "apply",
        TicketedEffectParams,
        EffectResult,
        non_quiescent_effect,
        kind=MethodKind.APPLY,
        dispatch_timeout_seconds=0.01,
        cancellation_grace_seconds=0.01,
    )
    methods["reconcile"] = MethodBinding(
        "reconcile",
        ReconcileCallParams,
        EmptyResult,
        reconcile_handler,
        kind=MethodKind.RECONCILE,
    )
    host = PluginHost(
        methods,
        ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100),
    )

    async def scenario() -> None:
        connections = 0

        class Reader:
            def __init__(self) -> None:
                self.response: bytes | None = None

            async def read(self, limit: int) -> bytes:
                while self.response is None:
                    await asyncio.sleep(0)
                response, self.response = self.response, b""
                return response

        class Writer:
            def __init__(self, reader: Reader) -> None:
                self.reader = reader
                self.payload = bytearray()

            def write(self, data: bytes) -> None:
                self.payload.extend(data)

            async def drain(self) -> None:
                self.reader.response = await host.handle_frame(bytes(self.payload))

            def can_write_eof(self) -> bool:
                return False

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                pass

        async def counted_connect(path: str) -> tuple[Reader, Writer]:
            nonlocal connections
            connections += 1
            reader = Reader()
            return reader, Writer(reader)

        monkeypatch.setattr(asyncio, "open_unix_connection", counted_connect, raising=False)
        client = PluginClient(
            "/run/a4diag/test.sock",
            timeout_seconds=0.1,
            request_id_factory=lambda: "request-1",
        )
        dispatch = asyncio.create_task(
            client.call(
                "apply",
                params.model_dump(mode="json"),
                ticket=issue_ticket(params, OperationPhase.APPLY),
            )
        )
        await started.wait()
        with pytest.raises(RpcClientError) as caught:
            await dispatch
        assert caught.value.reason == "quarantine_required"
        assert caught.value.code == -32004
        assert caught.value.data == {"reason": "quarantine_required"}
        assert caught.value.quarantine_required is True
        assert client.quarantine_required is True
        assert connections == 1

        with pytest.raises(RpcClientError) as blocked_effect:
            await client.call(
                "apply",
                params.model_dump(mode="json"),
                ticket="must-not-connect",
            )
        assert blocked_effect.value.quarantine_required is True
        with pytest.raises(RpcClientError) as blocked_reconcile:
            await client.call(
                "reconcile",
                {
                    "transaction_id": params.transaction_id,
                    "step_id": params.step_id,
                },
            )
        assert blocked_reconcile.value.data == {
            "underlying_reason": "client_quarantined"
        }
        assert connections == 1

        assert await client.call("health", {}) == {"ok": True}
        assert connections == 2

        release.set()
        await completed.wait()

    asyncio.run(scenario())


def test_effect_client_connect_failure_before_write_is_not_quarantine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    async def connect(path: str) -> tuple[object, object]:
        raise ConnectionRefusedError("not connected")

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            PluginClient(
                "/run/a4diag/test.sock",
                timeout_seconds=0.1,
                request_id_factory=lambda: "request-1",
            ).call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert caught.value.reason == "connection_failed"


def test_effect_client_write_failure_before_dispatch_is_not_quarantine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Writer:
        def write(self, data: bytes) -> None:
            raise ConnectionResetError("write failed before bytes were sent")

        async def drain(self) -> None:
            raise AssertionError("drain must not run after write failure")

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    class Reader:
        async def read(self, limit: int) -> bytes:
            raise AssertionError("read must not run after write failure")

    async def connect(path: str) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    client = PluginClient(
        "/run/a4diag/test.sock",
        timeout_seconds=0.1,
        request_id_factory=lambda: "request-1",
    )
    with pytest.raises(RpcClientError) as caught:
        asyncio.run(
            client.call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert caught.value.reason == "connection_failed"
    assert client.quarantine_required is False


def test_client_quarantine_blocks_same_instance_reconcile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from a4diag.plugin_client import PluginClient

    class Reader:
        def __init__(self) -> None:
            self._sent = False

        async def read(self, limit: int) -> bytes:
            if self._sent:
                return b""
            self._sent = True
            return b'{"jsonrpc":"2.0","api_version":"1.0","id":"wrong",' \
                b'"result":{}}\n'

    class Writer:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def can_write_eof(self) -> bool:
            return False

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    connections = 0

    async def connect(path: str) -> tuple[Reader, Writer]:
        nonlocal connections
        connections += 1
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    client = PluginClient(
        "/run/a4diag/test.sock",
        timeout_seconds=0.1,
        request_id_factory=lambda: "request-1",
    )
    with pytest.raises(RpcClientError) as first:
        asyncio.run(
            client.call(
                "apply",
                effect_params().model_dump(mode="json"),
                ticket="signed-ticket",
            )
        )
    assert first.value.quarantine_required is True
    assert client.quarantine_required is True
    with pytest.raises(RpcClientError) as second:
        asyncio.run(
            client.call(
                "reconcile",
                {
                    "transaction_id": effect_params().transaction_id,
                    "step_id": effect_params().step_id,
                },
            )
        )
    assert second.value.quarantine_required is True
    assert second.value.data == {"underlying_reason": "client_quarantined"}
    assert connections == 1

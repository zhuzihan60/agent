from __future__ import annotations

import asyncio
import inspect
import json
import os
import socket
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Generic, Literal, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    model_validator,
)

from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicket,
    OperationTicketEnvelope,
    OperationTicketExpectation,
    TicketError,
    TicketVerifier,
    effect_payload_digest,
)


API_VERSION = "1.0"
MAX_RPC_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 10_000
DEFAULT_RPC_TIMEOUT_SECONDS = 30.0
DEFAULT_EFFECT_CANCELLATION_GRACE_SECONDS = 1.0
MAX_EFFECT_CANCELLATION_GRACE_SECONDS = 5.0
EFFECT_RESPONSE_TRANSPORT_GRACE_SECONDS = 1.0
_MANDATORY_METHODS = frozenset({"health", "describe", "capability_probe"})


class RpcClientError(RuntimeError):
    """Stable protocol/client error that never contains internal tracebacks."""

    def __init__(
        self,
        reason: str,
        *,
        code: int | None = None,
        data: Mapping[str, JsonValue] | None = None,
    ) -> None:
        self.reason = reason
        self.code = code
        self.data = dict(data or {})
        super().__init__(reason)

    @property
    def quarantine_required(self) -> bool:
        """Whether the caller must replace the plugin instance before retrying."""

        return self.reason == "quarantine_required"


class RpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    jsonrpc: Literal["2.0"]
    id: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    params: dict[str, JsonValue]
    api_version: Literal["1.0"]
    ticket: str | None = Field(default=None, max_length=800_000)


class RpcErrorData(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str = Field(min_length=1, max_length=128)


class RpcError(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: int
    message: str = Field(min_length=1, max_length=256)
    data: RpcErrorData


class RpcResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    jsonrpc: Literal["2.0"] = "2.0"
    api_version: Literal["1.0"] = "1.0"
    id: str | None
    result: JsonValue | None = None
    error: RpcError | None = None

    @model_validator(mode="after")
    def exactly_one_payload(self) -> RpcResponse:
        fields = self.model_fields_set
        if ("result" in fields) == ("error" in fields):
            raise ValueError("response must contain exactly one of result or error")
        if "error" in fields and self.error is None:
            raise ValueError("error must not be null")
        return self


class RpcSuccess(RpcResponse):
    result: JsonValue
    error: None = None


class EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TicketedEffectParams(OperationTicketEnvelope):
    """Core-validated effect identity used to bind a ticket to one RPC call."""

    model_config = ConfigDict(extra="forbid", frozen=True)


_BASE_EFFECT_FIELDS = frozenset(OperationTicketEnvelope.model_fields)


def effect_fields_digest(params: TicketedEffectParams) -> str:
    """Bind every strict phase-specific field added by an effect params subtype."""

    if not isinstance(params, TicketedEffectParams):
        raise TicketError("invalid_effect_payload")
    dumped = params.model_dump(mode="json")
    extras = {key: value for key, value in dumped.items() if key not in _BASE_EFFECT_FIELDS}
    return effect_payload_digest(extras)


class MethodKind(StrEnum):
    READ = "read"
    MODEL = "model"
    VERIFY = "verify"
    RECONCILE = "reconcile"
    NOTIFICATION = "notification"
    PREPARE = "prepare"
    APPLY = "apply"
    UNDO = "undo"

    @property
    def ticket_phase(self) -> OperationPhase | None:
        return {
            MethodKind.PREPARE: OperationPhase.PREPARE,
            MethodKind.APPLY: OperationPhase.APPLY,
            MethodKind.UNDO: OperationPhase.UNDO,
        }.get(self)

    @property
    def is_effect(self) -> bool:
        return self.ticket_phase is not None


_METHOD_KINDS = MappingProxyType(
    {
        "health": MethodKind.READ,
        "describe": MethodKind.READ,
        "capability_probe": MethodKind.READ,
        "collect": MethodKind.READ,
        "verify_identity": MethodKind.READ,
        "read": MethodKind.READ,
        "diagnose": MethodKind.MODEL,
        "plan": MethodKind.MODEL,
        "critic": MethodKind.MODEL,
        "verify": MethodKind.VERIFY,
        "reconcile": MethodKind.RECONCILE,
        "send": MethodKind.NOTIFICATION,
        "prepare": MethodKind.PREPARE,
        "apply": MethodKind.APPLY,
        "undo": MethodKind.UNDO,
        "execute_typed": MethodKind.APPLY,
    }
)
EFFECT_METHOD_NAMES = frozenset(
    name for name, kind in _METHOD_KINDS.items() if kind.is_effect
)


def _is_async_callable(handler: Callable[..., object]) -> bool:
    return inspect.iscoroutinefunction(handler) or inspect.iscoroutinefunction(
        getattr(handler, "__call__", None)
    )


@dataclass(frozen=True, slots=True)
class VerifiedInvocation:
    request_id: str
    method: str
    claims: OperationTicket


ParamsT = TypeVar("ParamsT", bound=BaseModel)
ResultT = TypeVar("ResultT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class MethodBinding(Generic[ParamsT, ResultT]):
    name: str
    params_model: type[ParamsT]
    result_model: type[ResultT]
    handler: Callable[..., ResultT | Any]
    kind: MethodKind
    dispatch_timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS
    cancellation_grace_seconds: float = DEFAULT_EFFECT_CANCELLATION_GRACE_SECONDS

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.params_model, type) or not issubclass(self.params_model, BaseModel):
            raise TypeError("method binding requires a name and Pydantic params model")
        if not isinstance(self.result_model, type) or not issubclass(self.result_model, BaseModel):
            raise TypeError("method binding requires a Pydantic result model")
        if self.params_model.model_config.get("extra") != "forbid":
            raise TypeError("method binding params model must set extra='forbid'")
        if self.result_model.model_config.get("extra") != "forbid":
            raise TypeError("method binding result model must set extra='forbid'")
        if not callable(self.handler):
            raise TypeError("method binding handler must be callable")
        if not isinstance(self.kind, MethodKind):
            raise TypeError("method binding kind must be MethodKind")
        expected_kind = _METHOD_KINDS.get(self.name)
        if expected_kind is None:
            raise ValueError("unsupported method name")
        if self.kind is not expected_kind:
            if expected_kind.is_effect:
                raise ValueError(
                    f"{self.name} requires fixed {expected_kind.value} ticket phase"
                )
            raise ValueError(
                f"{self.name} requires fixed {expected_kind.value} method kind"
            )
        if (
            type(self.dispatch_timeout_seconds) not in {int, float}
            or not 0 < self.dispatch_timeout_seconds <= 120
        ):
            raise ValueError("dispatch_timeout_seconds must be between 0 and 120")
        if (
            type(self.cancellation_grace_seconds) not in {int, float}
            or not 0 < self.cancellation_grace_seconds
            <= MAX_EFFECT_CANCELLATION_GRACE_SECONDS
        ):
            raise ValueError(
                "cancellation_grace_seconds must be between 0 and "
                f"{MAX_EFFECT_CANCELLATION_GRACE_SECONDS:g}"
            )
        if self.kind.is_effect and not issubclass(
            self.params_model, TicketedEffectParams
        ):
            raise TypeError("ticketed binding params must extend TicketedEffectParams")
        if self.kind.is_effect and not _is_async_callable(self.handler):
            raise TypeError(
                "effect handler must be a cancellation-safe async callable"
            )
        if self.kind is MethodKind.RECONCILE and not {
            "transaction_id",
            "step_id",
        }.issubset(self.params_model.model_fields):
            raise TypeError(
                "reconcile params must contain transaction_id and step_id"
            )

    @property
    def ticket_phase(self) -> OperationPhase | None:
        return self.kind.ticket_phase


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(key)
        value[key] = item
    return value


def _reject_number(value: str) -> object:
    raise ValueError(f"unsupported JSON number: {value}")


def _validate_structure(value: object) -> None:
    count = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_ITEMS:
            raise RpcClientError("structure_too_complex")
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)


def _decode_frame(frame: bytes) -> object:
    if not isinstance(frame, bytes):
        raise TypeError("RPC frame must be bytes")
    if len(frame) > MAX_RPC_BYTES + 1:
        raise RpcClientError("payload_too_large")
    if frame.count(b"\n") != 1 or not frame.endswith(b"\n"):
        raise RpcClientError("multiple_frames")
    payload = frame[:-1]
    if len(payload) > MAX_RPC_BYTES:
        raise RpcClientError("payload_too_large")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RpcClientError("invalid_utf8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except _DuplicateKey as error:
        raise RpcClientError("duplicate_key") from error
    except (json.JSONDecodeError, ValueError) as error:
        raise RpcClientError("invalid_json") from error
    if type(value) is list:
        raise RpcClientError("batch_not_allowed")
    if type(value) is not dict:
        raise RpcClientError("invalid_json")
    _validate_structure(value)
    return value


def decode_request_frame(frame: bytes) -> RpcRequest:
    value = _decode_frame(frame)
    try:
        return RpcRequest.model_validate(value)
    except ValidationError as error:
        raise RpcClientError("invalid_request", code=-32600) from error


def decode_response_frame(frame: bytes) -> RpcResponse:
    value = _decode_frame(frame)
    try:
        return RpcResponse.model_validate(value)
    except ValidationError as error:
        raise RpcClientError("invalid_response") from error


def encode_response(response: RpcResponse) -> bytes:
    encoded = json.dumps(
        response.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_RPC_BYTES + 1:
        raise RpcClientError("response_too_large")
    return encoded


async def read_bounded_frame(
    reader: asyncio.StreamReader,
    *,
    eof_reason: str = "premature_eof",
) -> bytes:
    """Incrementally read exactly one newline frame followed by connection EOF."""

    frame = bytearray()
    newline_seen = False
    while True:
        chunk = await reader.read(65_536)
        if not chunk:
            if not newline_seen:
                raise RpcClientError(eof_reason)
            return bytes(frame)
        if newline_seen:
            raise RpcClientError("multiple_frames")
        if len(frame) + len(chunk) > MAX_RPC_BYTES + 1:
            raise RpcClientError("payload_too_large")
        frame.extend(chunk)
        newline_index = frame.find(b"\n")
        if newline_index >= 0:
            if newline_index != len(frame) - 1:
                raise RpcClientError("multiple_frames")
            newline_seen = True


def _error(request_id: str | None, code: int, message: str, reason: str) -> RpcResponse:
    return RpcResponse(
        id=request_id,
        error=RpcError(code=code, message=message, data=RpcErrorData(reason=reason)),
    )


class PluginHost:
    def __init__(
        self,
        bindings: Mapping[str, MethodBinding[Any, Any]],
        *,
        ticket_verifier: TicketVerifier | object | None = None,
        timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS,
    ) -> None:
        copied = dict(bindings)
        if not _MANDATORY_METHODS.issubset(copied):
            missing = sorted(_MANDATORY_METHODS - copied.keys())
            raise ValueError(f"mandatory plugin methods missing: {', '.join(missing)}")
        for name, binding in copied.items():
            if not isinstance(binding, MethodBinding) or name != binding.name:
                raise TypeError("binding registry keys must match MethodBinding names")
            if name in _MANDATORY_METHODS and binding.kind is not MethodKind.READ:
                raise ValueError("mandatory methods must be read-only")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._methods = MappingProxyType(copied)
        self._ticket_verifier = ticket_verifier
        self._timeout_seconds = float(timeout_seconds)
        self._socket_path: Path | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._active_effects: dict[tuple[str, str], asyncio.Task[object]] = {}
        self._quarantine_required = False

    @property
    def methods(self) -> Mapping[str, MethodBinding[Any, Any]]:
        return self._methods

    @property
    def quarantine_required(self) -> bool:
        """Whether this host instance must not dispatch further recovery calls."""

        return self._quarantine_required

    @staticmethod
    def _dispatch_key(params: BaseModel) -> tuple[str, str]:
        transaction_id = getattr(params, "transaction_id", None)
        step_id = getattr(params, "step_id", None)
        if type(transaction_id) is not str or type(step_id) is not str:
            raise ValueError("dispatch identity is invalid")
        return transaction_id, step_id

    def _effect_finished(
        self, key: tuple[str, str], task: asyncio.Task[object]
    ) -> None:
        try:
            task.exception()
        except asyncio.CancelledError:
            pass
        if self._active_effects.get(key) is task:
            del self._active_effects[key]

    async def dispatch(self, request: RpcRequest) -> RpcResponse:
        binding = self._methods.get(request.method)
        if binding is None:
            return _error(request.id, -32601, "Method not found", "method_not_found")
        try:
            params = binding.params_model.model_validate(request.params)
        except ValidationError:
            return _error(request.id, -32602, "Invalid params", "invalid_params")

        dispatch_key: tuple[str, str] | None = None
        if binding.kind.is_effect or binding.kind is MethodKind.RECONCILE:
            try:
                dispatch_key = self._dispatch_key(params)
            except ValueError:
                return _error(request.id, -32602, "Invalid params", "invalid_params")
            if self._quarantine_required:
                return _error(
                    request.id,
                    -32004,
                    "Plugin quarantine required",
                    "quarantine_required",
                )
            if dispatch_key in self._active_effects:
                return _error(
                    request.id,
                    -32003,
                    "Effect dispatch is not quiescent",
                    "dispatch_not_quiescent",
                )

        invocation: VerifiedInvocation | None = None
        if binding.kind.is_effect:
            if request.ticket is None:
                return _error(request.id, -32001, "Ticket rejected", "ticket_required")
            if self._ticket_verifier is None or not isinstance(params, TicketedEffectParams):
                return _error(request.id, -32603, "Internal error", "ticket_verifier_unavailable")
            try:
                expected = OperationTicketExpectation(
                    **params.model_dump(
                        exclude=set(type(params).model_fields) - _BASE_EFFECT_FIELDS
                    ),
                    phase=binding.kind.ticket_phase,
                    effect_payload_digest=effect_fields_digest(params),
                )
                claims = self._ticket_verifier.verify(request.ticket, expected)  # type: ignore[attr-defined]
            except (ValidationError, TicketError) as error:
                if isinstance(error, TicketError):
                    return _error(request.id, -32001, "Ticket rejected", error.code)
                return _error(request.id, -32602, "Invalid params", "invalid_params")
            except Exception:
                return _error(request.id, -32603, "Internal error", "internal_error")
            invocation = VerifiedInvocation(request.id, request.method, claims)

        async def invoke() -> object:
            arguments = (params, invocation) if invocation is not None else (params,)
            if _is_async_callable(binding.handler):
                value = binding.handler(*arguments)
            else:
                value = await asyncio.to_thread(binding.handler, *arguments)
            if inspect.isawaitable(value):
                return await value
            return value

        if binding.kind.is_effect:
            assert dispatch_key is not None
            # Effect handlers own every subprocess they start. On CancelledError
            # they must terminate and await those subprocesses before returning or
            # re-raising. A handler that cannot prove quiescence within the bounded
            # grace quarantines this plugin instance; reconciliation is forbidden.
            task = asyncio.create_task(invoke())
            self._active_effects[dispatch_key] = task
            task.add_done_callback(
                lambda completed, key=dispatch_key: self._effect_finished(
                    key, completed
                )
            )
            effect_timeout = min(
                float(binding.dispatch_timeout_seconds),
                float(params.operation.timeout_seconds),
            )
            completed, _ = await asyncio.wait({task}, timeout=effect_timeout)
            timed_out = not completed
            if timed_out:
                task.cancel()
                completed, _ = await asyncio.wait(
                    {task}, timeout=float(binding.cancellation_grace_seconds)
                )
                if not completed:
                    self._quarantine_required = True
                    return _error(
                        request.id,
                        -32004,
                        "Plugin quarantine required",
                        "quarantine_required",
                    )
                # Cancellation may be suppressed and a success returned. Once the
                # deadline fired, the effect outcome stays unknown even after the
                # task has fully quiesced.
                try:
                    task.result()
                except BaseException:
                    pass
                return _error(
                    request.id, -32002, "Handler timeout", "execution_unknown"
                )
            try:
                value = task.result()
                result = binding.result_model.model_validate(value)
                response = RpcResponse(
                    id=request.id, result=result.model_dump(mode="json")
                )
                encode_response(response)
                return response
            except BaseException:
                return _error(
                    request.id, -32603, "Internal error", "execution_unknown"
                )

        try:
            value = await asyncio.wait_for(
                invoke(), timeout=float(binding.dispatch_timeout_seconds)
            )
            result = binding.result_model.model_validate(value)
            response = RpcResponse(id=request.id, result=result.model_dump(mode="json"))
            encode_response(response)
            return response
        except asyncio.TimeoutError:
            return _error(request.id, -32002, "Handler timeout", "handler_timeout")
        except (ValidationError, RpcClientError):
            return _error(
                request.id, -32603, "Internal error", "invalid_handler_result"
            )
        except Exception:
            return _error(request.id, -32603, "Internal error", "internal_error")

    async def handle_frame(self, frame: bytes) -> bytes:
        try:
            request = decode_request_frame(frame)
        except RpcClientError as error:
            code = error.code if error.code is not None else -32700
            return encode_response(_error(None, code, "Invalid request", error.reason))
        response = await self.dispatch(request)
        try:
            return encode_response(response)
        except RpcClientError:
            return encode_response(_error(request.id, -32603, "Internal error", "response_too_large"))

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            frame = await asyncio.wait_for(
                read_bounded_frame(reader, eof_reason="premature_eof"),
                timeout=self._timeout_seconds,
            )
            response = await self.handle_frame(frame)
            writer.write(response)
            await writer.drain()
        except asyncio.TimeoutError:
            writer.write(encode_response(_error(None, -32000, "Timeout", "request_timeout")))
            await writer.drain()
        except RpcClientError as error:
            writer.write(
                encode_response(_error(None, -32700, "Invalid request", error.reason))
            )
            await writer.drain()
        except Exception:
            try:
                writer.write(encode_response(_error(None, -32603, "Internal error", "internal_error")))
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self, socket_path: str | os.PathLike[str]) -> asyncio.AbstractServer:
        path = Path(socket_path)
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("refusing to replace a pre-existing socket path")
        server = await asyncio.start_unix_server(self._handle_client, str(path))
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            server.close()
            await server.wait_closed()
            raise RuntimeError("created endpoint is not a Unix socket")
        self._socket_path = path
        self._socket_identity = (info.st_dev, info.st_ino)
        return server

    async def start_activated(self, inherited: socket.socket) -> asyncio.AbstractServer:
        """Serve a systemd-owned AF_UNIX stream socket without unlinking it."""
        if not isinstance(inherited, socket.socket):
            raise TypeError("inherited socket must be a socket.socket")
        if inherited.family != socket.AF_UNIX or inherited.type & socket.SOCK_STREAM == 0:
            raise ValueError("inherited socket must be an AF_UNIX stream socket")
        inherited.setblocking(False)
        return await asyncio.start_unix_server(self._handle_client, sock=inherited)

    async def serve(self, socket_path: str | os.PathLike[str]) -> None:
        server = await self.start(socket_path)
        try:
            async with server:
                await server.serve_forever()
        finally:
            self.cleanup_socket()

    def cleanup_socket(self) -> None:
        path = self._socket_path
        identity = self._socket_identity
        self._socket_path = None
        self._socket_identity = None
        if path is None or identity is None:
            return
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == identity:
            path.unlink()


__all__ = [
    "API_VERSION",
    "DEFAULT_RPC_TIMEOUT_SECONDS",
    "EmptyParams",
    "MAX_RPC_BYTES",
    "MethodBinding",
    "MethodKind",
    "PluginHost",
    "RpcClientError",
    "RpcError",
    "RpcRequest",
    "RpcResponse",
    "RpcSuccess",
    "TicketedEffectParams",
    "VerifiedInvocation",
    "decode_request_frame",
    "decode_response_frame",
    "effect_fields_digest",
    "encode_response",
    "read_bounded_frame",
]

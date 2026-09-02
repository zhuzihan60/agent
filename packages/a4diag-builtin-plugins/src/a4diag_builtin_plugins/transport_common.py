"""Shared strict contract types for the built-in transport plugins.

Both transports expose the same narrow typed surface for identity, reads, and
the five target lifecycle phases.  They share the identity model, result
model, process-runner protocol, and method bindings defined here. There is no
generic shell execution method: every execution path runs a fixed helper
executable with a bounded canonical JSON request on stdin.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from a4diag.domain import Operation, Risk, canonical_json_bytes
from a4diag.plugin_api.target_protocol import SignedTargetRequest, TargetLifecycle, TargetRequest
from a4diag.plugin_api.protocol import (
    EmptyParams,
    MethodBinding,
    MethodKind,
    TicketedEffectParams,
)

TRANSPORT_HELPER_EXECUTABLE = "/usr/libexec/a4diag/a4diag-transport-helper"
API_VERSION = "1.0"
PLUGIN_TYPE = "transport"
DEFAULT_OUTPUT_LIMIT_BYTES = 262_144
IDENTITY_PROBE_TIMEOUT_SECONDS = 15.0
TRANSPORT_READ_TIMEOUT_SECONDS = 20.0
MAX_ABS_PATH_LENGTH = 4096

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHELL_METACHARACTERS = frozenset(";|&$`<>(){}[]*?'\"")


def validate_absolute_path(value: str, label: str) -> str:
    """Return an unambiguous absolute POSIX path safe for a fixed argv element."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        raise ValueError(f"{label} must be an unambiguous absolute POSIX path")
    components = value.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError(f"{label} must not contain ambiguous path segments")
    if len(value) > MAX_ABS_PATH_LENGTH:
        raise ValueError(f"{label} must not exceed {MAX_ABS_PATH_LENGTH} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    if any(character in _SHELL_METACHARACTERS for character in value):
        raise ValueError(f"{label} must not contain shell metacharacters")
    return value


def validate_sha256_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA256 digest")
    return value


def _validate_bounded_text(value: str, label: str, *, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    value = unicodedata.normalize("NFC", value)
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    if len(value) > max_length:
        raise ValueError(f"{label} must not exceed {max_length} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


class TransportError(RuntimeError):
    """Base typed transport failure carrying a stable reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TransportIdentityError(TransportError):
    """The transport could not obtain or verify the target identity."""


class TransportReadError(TransportError):
    """A typed read request could not be satisfied."""


class TransportStatus(StrEnum):
    IDENTITY_VERIFIED = "identity_verified"
    IDENTITY_MISMATCH = "identity_mismatch"
    READ_COMPLETED = "read_completed"
    APPLIED = "applied"
    FAILED = "failed"
    EXECUTION_UNKNOWN = "execution_unknown"


class TargetIdentity(BaseModel):
    """Strict immutable target identity pinned by every write dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    machine_id: str
    host_key_sha256: str | None
    os_id: str
    os_version_id: str
    systemd_version: str

    @field_validator("machine_id")
    @classmethod
    def validate_machine_id(cls, value: str) -> str:
        return _validate_bounded_text(value, "machine_id", max_length=128)

    @field_validator("host_key_sha256")
    @classmethod
    def validate_host_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha256_digest(value, "host_key_sha256")

    @field_validator("os_id", "os_version_id", "systemd_version")
    @classmethod
    def validate_identity_component(cls, value: str, info: object) -> str:
        return _validate_bounded_text(
            value, getattr(info, "field_name", "identity component"), max_length=64
        )


def identity_fingerprint(identity: TargetIdentity) -> str:
    """Canonical fingerprint that changes when any identity component changes."""
    if not isinstance(identity, TargetIdentity):
        raise TypeError("identity must be TargetIdentity")
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(identity.model_dump(mode="json"))
    ).hexdigest()


class HealthResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool = True


class DescribeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    plugin_type: str
    version: str
    api_version: str


class CapabilityProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    read_capable: bool
    write_capable: bool
    read_risk_floor: Risk
    write_risk_floor: Risk
    reason: str | None = None


class TransportResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    status: TransportStatus
    reason: str | None = None
    stdout: str = ""
    stderr: str = ""
    data: dict[str, JsonValue] = Field(default_factory=dict)


class VerifyIdentityParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReadKind(StrEnum):
    MACHINE_ID = "machine_id"
    OS_RELEASE = "os_release"
    SYSTEMD_VERSION = "systemd_version"
    FILE = "file"


class ReadParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ReadKind
    path: str | None = None
    output_limit_bytes: int = Field(
        default=DEFAULT_OUTPUT_LIMIT_BYTES,
        ge=1,
        le=DEFAULT_OUTPUT_LIMIT_BYTES,
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_absolute_path(value, "read path")

    @model_validator(mode="after")
    def validate_kind_path(self) -> ReadParams:
        if self.kind is ReadKind.FILE and self.path is None:
            raise ValueError("path is required for file reads")
        if self.kind is not ReadKind.FILE and self.path is not None:
            raise ValueError("path is only valid for file reads")
        return self


class HelperAction(StrEnum):
    DISPATCH = "dispatch"


class ExecuteTypedParams(TicketedEffectParams):
    """Ticket-bound typed helper dispatch; the payload is digest-pinned."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    helper_action: HelperAction
    payload: dict[str, JsonValue]

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        try:
            canonical_json_bytes(value, max_bytes=DEFAULT_OUTPUT_LIMIT_BYTES)
        except (ValueError, TypeError) as error:
            raise ValueError(
                f"payload is not a bounded canonical JSON object: {error}"
            ) from error
        return value


class TransportPrepareParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)
    envelope: SignedTargetRequest


class TransportApplyParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)
    marker: dict[str, JsonValue]
    envelope: SignedTargetRequest


class TransportUndoParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)
    marker: dict[str, JsonValue]
    undo: dict[str, JsonValue] | None = None
    envelope: SignedTargetRequest


class TransportVerifyParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    transaction_id: str
    step_id: str
    operation: Operation
    marker: dict[str, JsonValue]
    envelope: SignedTargetRequest


class TransportReconcileParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    transaction_id: str
    step_id: str
    operation: Operation
    marker: dict[str, JsonValue] | None
    envelope: SignedTargetRequest


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """Outcome of one fixed-argv process run with bounded output."""

    started: bool
    timed_out: bool
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class ProcessRunner(Protocol):
    """Runs a fixed argv array; the transport owns the dispatch deadline."""

    async def run(
        self,
        argv: Sequence[str],
        *,
        payload: bytes,
        output_limit_bytes: int,
    ) -> RunOutcome: ...


class IdentityProbe(Protocol):
    async def probe(self) -> TargetIdentity: ...


async def _read_bounded(stream: asyncio.StreamReader, limit: int) -> tuple[str, bool]:
    """Read at most ``limit`` bytes from a stream without ever draining more."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            if total + len(chunk) > limit:
                truncated = True
                chunks.append(chunk[: limit - total])
                total = limit
                break
            chunks.append(chunk)
            total += len(chunk)
    except (OSError, ValueError):
        pass
    return b"".join(chunks).decode("utf-8", errors="replace"), truncated


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """Terminate the whole session started with start_new_session=True."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


class SubprocessRunner:
    """Real process runner: new session, bounded output, group kill on cancel.

    POSIX-only by construction: ``start_new_session`` is required so the
    transport can terminate the entire process group on timeout. On platforms
    without it, ``run`` reports a deterministic pre-spawn failure.
    """

    async def run(
        self,
        argv: Sequence[str],
        *,
        payload: bytes,
        output_limit_bytes: int,
    ) -> RunOutcome:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except (OSError, ValueError):
            return RunOutcome(started=False, timed_out=False, returncode=None)
        started = True
        stdout_task = asyncio.create_task(
            _read_bounded(proc.stdout, output_limit_bytes)  # type: ignore[arg-type]
        )
        stderr_task = asyncio.create_task(
            _read_bounded(proc.stderr, output_limit_bytes)  # type: ignore[arg-type]
        )
        try:
            proc.stdin.write(payload)  # type: ignore[union-attr]
            await proc.stdin.drain()  # type: ignore[union-attr]
            proc.stdin.close()  # type: ignore[union-attr]
        except (OSError, ValueError):
            # The child closed its stdin before reading everything; it may
            # already have dispatched the request, so the outcome is unknown.
            _kill_process_group(proc)
            await proc.wait()
            stdout, stdout_truncated = await stdout_task
            stderr, stderr_truncated = await stderr_task
            return RunOutcome(
                started=started,
                timed_out=True,
                returncode=None,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        try:
            await proc.wait()
            stdout, stdout_truncated = await stdout_task
            stderr, stderr_truncated = await stderr_task
            return RunOutcome(
                started=started,
                timed_out=False,
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        except asyncio.CancelledError:
            _kill_process_group(proc)
            for task in (stdout_task, stderr_task):
                task.cancel()
            await proc.wait()
            raise


class BaseTransport:
    """Shared transport behavior: identity pinning, typed reads, ticketed exec."""

    def __init__(
        self,
        *,
        name: str,
        version: str,
        runner: ProcessRunner,
        read_risk_floor: Risk = Risk.LOW,
        write_risk_floor: Risk = Risk.HIGH,
    ) -> None:
        self._name = name
        self._version = version
        self._runner = runner
        self._read_risk_floor = read_risk_floor
        self._write_risk_floor = write_risk_floor

    async def health(self, params: EmptyParams) -> HealthResult:
        return HealthResult(ok=True)

    async def describe(self, params: EmptyParams) -> DescribeResult:
        return DescribeResult(
            name=self._name,
            plugin_type=PLUGIN_TYPE,
            version=self._version,
            api_version=API_VERSION,
        )

    async def capability_probe(self, params: EmptyParams) -> CapabilityProbeResult:
        return CapabilityProbeResult(
            read_capable=True,
            write_capable=True,
            read_risk_floor=self._read_risk_floor,
            write_risk_floor=self._write_risk_floor,
        )

    async def verify_identity(self, params: VerifyIdentityParams) -> TransportResult:
        identity = await self._probe_identity()
        return TransportResult(
            ok=True,
            status=TransportStatus.IDENTITY_VERIFIED,
            data={
                "identity": identity.model_dump(mode="json"),
                "fingerprint": identity_fingerprint(identity),
            },
        )

    async def read(self, params: ReadParams) -> TransportResult:
        try:
            content, truncated = await self._perform_read(params)
        except TransportReadError as error:
            return TransportResult(
                ok=False, status=TransportStatus.FAILED, reason=error.code
            )
        return TransportResult(
            ok=True,
            status=TransportStatus.READ_COMPLETED,
            stdout=content,
            data={"kind": params.kind.value, "truncated": truncated},
        )

    async def execute_typed(
        self, params: ExecuteTypedParams, invocation: object
    ) -> TransportResult:
        """Verify identity before dispatch; mismatches spawn nothing."""
        try:
            identity = await self._probe_identity()
        except TransportIdentityError as error:
            return TransportResult(
                ok=False, status=TransportStatus.FAILED, reason=error.code
            )
        if identity_fingerprint(identity) != params.target_fingerprint:
            return TransportResult(
                ok=False,
                status=TransportStatus.IDENTITY_MISMATCH,
                reason="target_identity_mismatch",
            )
        request: dict[str, JsonValue] = {
            "method": "execute",
            "action": params.helper_action.value,
            "operation": params.operation.model_dump(mode="json"),
            "payload": params.payload,
        }
        payload = canonical_json_bytes(request)
        limit = int(params.operation.output_limit_bytes)
        timeout = float(params.operation.timeout_seconds)
        try:
            outcome = await asyncio.wait_for(
                self._runner.run(
                    self._build_helper_argv(),
                    payload=payload,
                    output_limit_bytes=limit,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # The runner was cancelled after dispatch may have started and has
            # killed its process group; the outcome stays unknown.
            return TransportResult(
                ok=False,
                status=TransportStatus.EXECUTION_UNKNOWN,
                reason="execution_unknown",
            )
        # CancelledError deliberately propagates: the effect host requires a
        # quiescent cancellation, and the runner terminates the process group
        # before re-raising.
        if not outcome.started:
            return TransportResult(
                ok=False, status=TransportStatus.FAILED, reason="spawn_failed"
            )
        if outcome.timed_out:
            return TransportResult(
                ok=False,
                status=TransportStatus.EXECUTION_UNKNOWN,
                reason="execution_unknown",
            )
        if outcome.returncode != 0:
            return TransportResult(
                ok=False,
                status=TransportStatus.FAILED,
                reason="helper_failed",
                stdout=outcome.stdout,
                stderr=outcome.stderr,
            )
        return TransportResult(
            ok=True,
            status=TransportStatus.APPLIED,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            data={"returncode": outcome.returncode},
        )

    @staticmethod
    def _validated_signed_request(
        params: TransportPrepareParams | TransportApplyParams | TransportUndoParams |
        TransportVerifyParams | TransportReconcileParams,
        lifecycle: TargetLifecycle,
    ) -> TargetRequest:
        try:
            request = TargetRequest.model_validate_json(params.envelope.payload)
        except ValueError as error:
            raise TransportError("target_envelope_invalid") from error
        if (
            request.lifecycle is not lifecycle
            or request.transaction_id != params.transaction_id
            or request.step_id != params.step_id
            or request.operation != params.operation
            or request.target_fingerprint != getattr(params, "target_fingerprint", request.target_fingerprint)
            or request.marker != getattr(params, "marker", None)
            or request.undo != getattr(params, "undo", None)
        ):
            raise TransportError("target_envelope_binding_mismatch")
        if isinstance(params, TicketedEffectParams) and (
            request.target_id != params.target_id
            or request.plan_digest != params.plan_digest
            or request.risk is not params.risk
            or request.approval_id != params.approval_id
        ):
            raise TransportError("target_envelope_binding_mismatch")
        return request

    async def _relay_signed(
        self,
        params: TransportPrepareParams | TransportApplyParams | TransportUndoParams |
        TransportVerifyParams | TransportReconcileParams,
        lifecycle: TargetLifecycle,
    ) -> TransportResult:
        try:
            request = self._validated_signed_request(params, lifecycle)
            identity = await self._probe_identity()
        except (TransportError, TransportIdentityError) as error:
            return TransportResult(ok=False, status=TransportStatus.FAILED, reason=error.code)
        if identity_fingerprint(identity) != request.target_fingerprint:
            return TransportResult(
                ok=False, status=TransportStatus.IDENTITY_MISMATCH,
                reason="target_identity_mismatch",
            )
        try:
            outcome = await asyncio.wait_for(
                self._runner.run(
                    self._build_helper_argv(),
                    payload=canonical_json_bytes(params.envelope.model_dump(mode="json")),
                    output_limit_bytes=int(request.operation.output_limit_bytes),
                ),
                timeout=float(request.operation.timeout_seconds),
            )
        except asyncio.TimeoutError:
            return TransportResult(ok=False, status=TransportStatus.EXECUTION_UNKNOWN, reason="execution_unknown")
        if not outcome.started or outcome.returncode != 0:
            return TransportResult(
                ok=False,
                status=TransportStatus.EXECUTION_UNKNOWN if outcome.timed_out else TransportStatus.FAILED,
                reason="execution_unknown" if outcome.timed_out else "helper_failed",
                stdout=outcome.stdout,
                stderr=outcome.stderr,
            )
        try:
            result = json.loads(outcome.stdout)
            if type(result) is not dict:
                raise ValueError("result must be object")
        except (json.JSONDecodeError, ValueError):
            return TransportResult(ok=False, status=TransportStatus.FAILED, reason="helper_result_invalid")
        return TransportResult(
            ok=True, status=TransportStatus.APPLIED,
            stdout=outcome.stdout, stderr=outcome.stderr, data={"result": result},
        )

    async def prepare_typed(self, params: TransportPrepareParams, invocation: object) -> TransportResult:
        return await self._relay_signed(params, TargetLifecycle.PREPARE)

    async def apply_typed(self, params: TransportApplyParams, invocation: object) -> TransportResult:
        return await self._relay_signed(params, TargetLifecycle.APPLY)

    async def undo_typed(self, params: TransportUndoParams, invocation: object) -> TransportResult:
        return await self._relay_signed(params, TargetLifecycle.UNDO)

    async def verify_typed(self, params: TransportVerifyParams) -> TransportResult:
        return await self._relay_signed(params, TargetLifecycle.VERIFY)

    async def reconcile_typed(self, params: TransportReconcileParams) -> TransportResult:
        return await self._relay_signed(params, TargetLifecycle.RECONCILE)

    async def _run_helper(
        self,
        argv: Sequence[str],
        request: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> RunOutcome:
        """Run the fixed helper for an unticketed typed request."""
        payload = canonical_json_bytes(dict(request))
        try:
            return await asyncio.wait_for(
                self._runner.run(
                    argv, payload=payload, output_limit_bytes=output_limit_bytes
                ),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            return RunOutcome(started=True, timed_out=True, returncode=None)

    async def _probe_identity(self) -> TargetIdentity:  # pragma: no cover - abstract
        raise NotImplementedError

    def _build_helper_argv(self) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    async def _perform_read(
        self, params: ReadParams
    ) -> tuple[str, bool]:  # pragma: no cover - abstract
        raise NotImplementedError


def build_transport_bindings(
    transport: BaseTransport,
) -> dict[str, MethodBinding[Any, Any]]:
    """Register the fixed transport method surface with the shared host."""
    return {
        "health": MethodBinding(
            "health", EmptyParams, HealthResult, transport.health, kind=MethodKind.READ
        ),
        "describe": MethodBinding(
            "describe",
            EmptyParams,
            DescribeResult,
            transport.describe,
            kind=MethodKind.READ,
        ),
        "capability_probe": MethodBinding(
            "capability_probe",
            EmptyParams,
            CapabilityProbeResult,
            transport.capability_probe,
            kind=MethodKind.READ,
        ),
        "verify_identity": MethodBinding(
            "verify_identity",
            VerifyIdentityParams,
            TransportResult,
            transport.verify_identity,
            kind=MethodKind.READ,
        ),
        "read": MethodBinding(
            "read", ReadParams, TransportResult, transport.read, kind=MethodKind.READ
        ),
        "prepare_typed": MethodBinding(
            "prepare_typed", TransportPrepareParams, TransportResult,
            transport.prepare_typed, kind=MethodKind.PREPARE,
        ),
        "apply_typed": MethodBinding(
            "apply_typed", TransportApplyParams, TransportResult,
            transport.apply_typed, kind=MethodKind.APPLY,
        ),
        "verify_typed": MethodBinding(
            "verify_typed", TransportVerifyParams, TransportResult,
            transport.verify_typed, kind=MethodKind.VERIFY,
        ),
        "undo_typed": MethodBinding(
            "undo_typed", TransportUndoParams, TransportResult,
            transport.undo_typed, kind=MethodKind.UNDO,
        ),
        "reconcile_typed": MethodBinding(
            "reconcile_typed", TransportReconcileParams, TransportResult,
            transport.reconcile_typed, kind=MethodKind.RECONCILE,
        ),
        "execute_typed": MethodBinding(
            "execute_typed",
            ExecuteTypedParams,
            TransportResult,
            transport.execute_typed,
            kind=MethodKind.APPLY,
        ),
    }


__all__ = [
    "API_VERSION",
    "BaseTransport",
    "CapabilityProbeResult",
    "DEFAULT_OUTPUT_LIMIT_BYTES",
    "DescribeResult",
    "ExecuteTypedParams",
    "HealthResult",
    "HelperAction",
    "IDENTITY_PROBE_TIMEOUT_SECONDS",
    "IdentityProbe",
    "PLUGIN_TYPE",
    "ProcessRunner",
    "ReadKind",
    "ReadParams",
    "RunOutcome",
    "SubprocessRunner",
    "TRANSPORT_HELPER_EXECUTABLE",
    "TRANSPORT_READ_TIMEOUT_SECONDS",
    "TargetIdentity",
    "TransportError",
    "TransportIdentityError",
    "TransportReadError",
    "TransportResult",
    "TransportPrepareParams",
    "TransportApplyParams",
    "TransportVerifyParams",
    "TransportUndoParams",
    "TransportReconcileParams",
    "TransportStatus",
    "VerifyIdentityParams",
    "build_transport_bindings",
    "identity_fingerprint",
    "validate_absolute_path",
    "validate_sha256_digest",
]

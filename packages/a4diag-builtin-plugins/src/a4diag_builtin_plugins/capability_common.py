"""Shared strict contract types for the built-in capability plugins.

Capability plugins expose the fixed ticketed effect surface — ``prepare``,
``apply``, ``undo`` — plus unticketed ``verify`` and ``reconcile``. They
consume a narrow typed transport adapter and never construct arbitrary
commands: every command argv is a fixed template built from core-validated
typed parameters. Every reversible operation persists a bounded typed marker
and reconcile never claims success it cannot prove.
"""

from __future__ import annotations

import itertools
import asyncio
import os
import re
import signal
import stat
from collections.abc import Sequence
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from a4diag.domain import Operation, Risk
from a4diag.plugin_api.protocol import (
    EmptyParams,
    MethodBinding,
    MethodKind,
    TicketedEffectParams,
)

from a4diag_builtin_plugins.transport_common import (
    CapabilityProbeResult,
    DescribeResult,
    HealthResult,
    PLUGIN_TYPE,
)

API_VERSION = "1.0"
DEFAULT_OUTPUT_LIMIT_BYTES = 262_144
_TEMP_COUNTER = itertools.count()

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class CapabilityError(RuntimeError):
    """Stable typed capability failure carrying a reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReconcileState(StrEnum):
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class StatInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: int
    uid: int
    gid: int

    @field_validator("mode", "uid", "gid")
    @classmethod
    def validate_non_negative(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("mode/uid/gid must be non-negative integers")
        return value


class CommandOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    returncode: int
    stdout: str = ""
    stderr: str = ""


class ServiceState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    active_state: str
    sub_state: str
    unit_file_state: str
    invocation_id: str

    @field_validator("active_state", "sub_state", "unit_file_state", "invocation_id")
    @classmethod
    def validate_state_component(cls, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("service state component must be a bounded string")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("service state component must not contain control characters")
        return value


class TransportAdapter(Protocol):
    """Narrow typed target channel consumed by capability plugins."""

    async def lstat(self, path: str) -> StatInfo: ...
    async def read_file(self, path: str, limit: int) -> bytes: ...
    async def write_file(self, path: str, content: bytes, mode: int | None) -> None: ...
    async def set_mode(self, path: str, mode: int) -> None: ...
    async def chown(self, path: str, uid: int, gid: int) -> None: ...
    async def run_command(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandOutcome: ...
    async def os_release(self) -> tuple[str, str]: ...


class CapabilityPrepareParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CapabilityApplyParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)

    marker: dict[str, JsonValue]


class CapabilityUndoParams(TicketedEffectParams):
    model_config = ConfigDict(extra="forbid", frozen=True)

    marker: dict[str, JsonValue]
    undo: dict[str, JsonValue] | None = None


class CapabilityVerifyParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str
    step_id: str
    operation: Operation
    marker: dict[str, JsonValue]

    @field_validator("transaction_id", "step_id")
    @classmethod
    def validate_ids(cls, value: str, info: object) -> str:
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise ValueError(
                f"{getattr(info, 'field_name', 'identifier')} must be a safe identifier"
            )
        return value


class CapabilityReconcileParams(CapabilityVerifyParams):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PrepareResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    marker: dict[str, JsonValue]


class EffectResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    changed: bool = False
    reason: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class VerifyResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    reason: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class ReconcileResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    state: ReconcileState
    reason: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


def validate_sha256(value: str, label: str = "sha256") -> str:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise CapabilityError("invalid_digest")
    return value


def marker_from(
    marker_cls: type[BaseModel], marker: dict[str, JsonValue]
) -> BaseModel:
    """Strictly validate a stored marker; anything else fails closed."""
    try:
        return marker_cls.model_validate(marker)
    except (ValueError, TypeError):
        raise CapabilityError("invalid_marker") from None


class BaseCapabilityPlugin:
    """Shared capability behavior: mandatory methods and fixed bindings."""

    def __init__(
        self,
        *,
        transport: TransportAdapter,
        name: str,
        version: str,
        actions: frozenset[str],
    ) -> None:
        self._transport = transport
        self._name = name
        self._version = version
        self._actions = actions

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
            read_risk_floor=Risk.LOW,
            write_risk_floor=Risk.HIGH,
        )

    def _require_action(self, action: str) -> None:
        if action not in self._actions:
            raise CapabilityError("unsupported_action")

    def _timeout(self, params: BaseModel) -> float:
        operation = getattr(params, "operation", None)
        if isinstance(operation, Operation):
            return float(operation.timeout_seconds)
        return 20.0

    def _output_limit(self, params: BaseModel) -> int:
        operation = getattr(params, "operation", None)
        if isinstance(operation, Operation):
            return int(operation.output_limit_bytes)
        return DEFAULT_OUTPUT_LIMIT_BYTES


def build_capability_bindings(
    plugin: BaseCapabilityPlugin,
) -> dict[str, MethodBinding[Any, Any]]:
    """Register the fixed capability method surface with the shared host."""
    return {
        "health": MethodBinding(
            "health", EmptyParams, HealthResult, plugin.health, kind=MethodKind.READ
        ),
        "describe": MethodBinding(
            "describe",
            EmptyParams,
            DescribeResult,
            plugin.describe,
            kind=MethodKind.READ,
        ),
        "capability_probe": MethodBinding(
            "capability_probe",
            EmptyParams,
            CapabilityProbeResult,
            plugin.capability_probe,
            kind=MethodKind.READ,
        ),
        "prepare": MethodBinding(
            "prepare",
            CapabilityPrepareParams,
            PrepareResult,
            plugin.prepare,
            kind=MethodKind.PREPARE,
        ),
        "apply": MethodBinding(
            "apply",
            CapabilityApplyParams,
            EffectResult,
            plugin.apply,
            kind=MethodKind.APPLY,
        ),
        "undo": MethodBinding(
            "undo",
            CapabilityUndoParams,
            EffectResult,
            plugin.undo,
            kind=MethodKind.UNDO,
        ),
        "verify": MethodBinding(
            "verify",
            CapabilityVerifyParams,
            VerifyResult,
            plugin.verify,
            kind=MethodKind.VERIFY,
        ),
        "reconcile": MethodBinding(
            "reconcile",
            CapabilityReconcileParams,
            ReconcileResult,
            plugin.reconcile,
            kind=MethodKind.RECONCILE,
        ),
    }


class LocalFileAdapter:
    """Real local-target file adapter; commands route through the helper."""

    async def lstat(self, path: str) -> StatInfo:
        try:
            info = os.lstat(path)
        except OSError:
            raise CapabilityError("path_not_found") from None
        return StatInfo(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid)

    async def read_file(self, path: str, limit: int) -> bytes:
        try:
            info = os.lstat(path)
        except OSError:
            raise CapabilityError("read_failed") from None
        if not stat.S_ISREG(info.st_mode):
            raise CapabilityError("read_failed")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            handle = os.fdopen(fd, "rb")
        except OSError:
            os.close(fd)
            raise CapabilityError("read_failed") from None
        try:
            with handle:
                return handle.read(limit)
        except OSError:
            raise CapabilityError("read_failed") from None

    async def write_file(self, path: str, content: bytes, mode: int | None) -> None:
        directory = os.path.dirname(path)
        try:
            info = os.lstat(directory)
        except OSError:
            raise CapabilityError("write_failed") from None
        if not stat.S_ISDIR(info.st_mode):
            raise CapabilityError("write_failed")
        temp_name = os.path.join(
            directory, f".a4diag-{os.getpid()}-{next(_TEMP_COUNTER)}.tmp"
        )
        try:
            temp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError:
            raise CapabilityError("write_failed") from None
        try:
            with os.fdopen(temp_fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                if mode is not None and hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), mode)
            os.replace(temp_name, path)
        except OSError:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise CapabilityError("write_failed") from None

    async def set_mode(self, path: str, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except OSError:
            raise CapabilityError("set_mode_failed") from None

    async def chown(self, path: str, uid: int, gid: int) -> None:
        if not hasattr(os, "chown"):
            return
        try:
            os.chown(path, uid, gid)
        except OSError:
            raise CapabilityError("chown_failed") from None

    async def run_command(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandOutcome:
        allowed = {
            "/usr/bin/systemctl",
            "/usr/bin/rpm",
            "/usr/bin/dpkg-query",
            "/usr/bin/dnf",
            "/usr/bin/apt-get",
            "/usr/bin/apt-cache",
        }
        values = list(argv)
        if (
            not values
            or values[0] not in allowed
            or any(type(value) is not str or "\x00" in value for value in values)
        ):
            raise CapabilityError("command_unavailable")
        try:
            process = await asyncio.create_subprocess_exec(
                *values,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            async def drain(stream: asyncio.StreamReader) -> bytes:
                kept = bytearray()
                while True:
                    chunk = await stream.read(65_536)
                    if not chunk:
                        return bytes(kept)
                    remaining = output_limit_bytes - len(kept)
                    if remaining > 0:
                        kept.extend(chunk[:remaining])

            stdout_task = asyncio.create_task(drain(process.stdout))  # type: ignore[arg-type]
            stderr_task = asyncio.create_task(drain(process.stderr))  # type: ignore[arg-type]
            await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
            stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            await process.wait()
            for task in (stdout_task, stderr_task):
                task.cancel()
            raise CapabilityError("command_timeout") from None
        except OSError:
            raise CapabilityError("command_unavailable") from None
        return CommandOutcome(
            returncode=int(process.returncode or 0),
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
        )

    async def os_release(self) -> tuple[str, str]:
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as handle:
                content = handle.read(65_536)
        except (OSError, UnicodeDecodeError):
            raise CapabilityError("os_release_unavailable") from None
        values: dict[str, str] = {}
        for line in content.splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            if key in {"ID", "VERSION_ID"}:
                values[key] = value.strip().strip('"').strip("'")
        if not values.get("ID") or not values.get("VERSION_ID"):
            raise CapabilityError("os_release_unavailable")
        return values["ID"], values["VERSION_ID"]


__all__ = [
    "API_VERSION",
    "BaseCapabilityPlugin",
    "CapabilityApplyParams",
    "CapabilityError",
    "CapabilityPrepareParams",
    "CapabilityReconcileParams",
    "CapabilityUndoParams",
    "CapabilityVerifyParams",
    "CommandOutcome",
    "DEFAULT_OUTPUT_LIMIT_BYTES",
    "EffectResult",
    "LocalFileAdapter",
    "PrepareResult",
    "ReconcileResult",
    "ReconcileState",
    "ServiceState",
    "StatInfo",
    "TransportAdapter",
    "VerifyResult",
    "build_capability_bindings",
    "marker_from",
    "validate_sha256",
]

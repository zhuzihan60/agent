"""Deterministic generic initialization.

``InitService`` validates a strict ``InitRequest`` (probing the model provider
and every target's identity through injected probes), then writes the config
atomically: a 0600 temporary file in the destination directory, fsync, atomic
replace, and a read-back validation through the Phase 1 settings loader. A
failed probe or write leaves the previous config byte-for-byte unchanged.
Interactive request building requires the literal ``ENABLE`` confirmation
before any target may be write-enabled.
"""

from __future__ import annotations

import itertools
import asyncio
import json
import os
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, field_validator, model_validator

from a4diag.domain import CapabilityGrant, TargetConfig, TargetMode
from a4diag.settings import (
    AgentSettings,
    ModelSettings,
    NotificationSettings,
    load_settings,
)

_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SAFE_REF = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_IPV6 = re.compile(r"^[0-9A-Fa-f:]+$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_TEMP_COUNTER = itertools.count()


class InitError(ValueError):
    """Stable typed initialization failure carrying a reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


class IdentityError(InitError):
    """A target identity probe failed."""


class ModelProbeError(InitError):
    """A model structured-output probe failed."""


def _validate_bounded_text(value: str, label: str, *, max_length: int = 128) -> str:
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


class ModelInit(BaseModel):
    """Strict model-provider initialization; the key is a reference only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: str
    api_key_ref: str | None = None
    model: str
    plugin: str = "model-openai-compatible"
    api_style: Literal["openai", "azure", "ollama"] = "openai"
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    deployment: str | None = None
    api_version: str | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        from urllib.parse import urlparse

        if not isinstance(value, str) or not value or len(value) > 2048:
            raise ValueError("base_url must be a bounded URL")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("base_url must not contain control characters")
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("base_url must be an absolute https URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment or parsed.params:
            raise ValueError("base_url must not contain query, fragment, or params")
        return value

    @field_validator("api_key_ref")
    @classmethod
    def validate_api_key_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_REF.fullmatch(value):
            raise ValueError("api_key_ref must be a safe secret reference")
        return value

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        return _validate_bounded_text(value, "model", max_length=128)


class CapabilityInit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
            raise ValueError("capability name must be a safe identifier")
        return value

    @field_validator("resources")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        from a4diag.domain import normalize_resource

        normalized = tuple(
            normalize_resource(value, allow_descendant_pattern=True)
            for value in values
        )
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate capability resource")
        return normalized


class TargetInit(BaseModel):
    """Strict target registration; identity_ref is derived, never accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    mode: TargetMode
    host: str | None = None
    port: int | None = None
    user: str | None = None
    transport: str | None = None
    identity_file_ref: str | None = None
    known_hosts_ref: str | None = None
    operation_signing_key_ref: str | None = None
    host_key_sha256: str | None = None
    write_enabled: bool = False
    auto_execute_low: bool = False
    capabilities: tuple[CapabilityInit, ...] = ()
    notification_required: bool = False

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _TARGET_ID.fullmatch(value):
            raise ValueError("target id must be a safe identifier")
        return value

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > 253:
            raise ValueError("host must be a bounded hostname or IP address")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("host must not contain control characters")
        if not (_HOSTNAME.fullmatch(value) or _IPV6.fullmatch(value)):
            raise ValueError("host must be a hostname or IP address")
        return value

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return value

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _USERNAME.fullmatch(value):
            raise ValueError("user must be a safe SSH username")
        return value

    @field_validator(
        "identity_file_ref", "known_hosts_ref", "operation_signing_key_ref"
    )
    @classmethod
    def validate_file_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("file:"):
            raise ValueError("target secret references must use file:")
        relative = value[5:]
        if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
            raise ValueError("unsafe target secret reference")
        return value

    @field_validator("host_key_sha256")
    @classmethod
    def validate_host_key_sha256(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("host_key_sha256 must be a lowercase SHA256 digest")
        return value

    @model_validator(mode="after")
    def validate_mode_fields(self) -> TargetInit:
        if self.mode is TargetMode.SSH:
            if self.host is None or self.port is None or self.user is None:
                raise ValueError("ssh targets require host, port, and user")
        else:
            if self.host is not None or self.port is not None or self.user is not None:
                raise ValueError("local targets must not specify host, port, or user")
        return self


class NotificationInit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel: str
    config: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
            raise ValueError("channel must be a safe identifier")
        return value


class InitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    global_mode: Literal["read_only", "read_write"] = "read_only"
    model: ModelInit | None = None
    targets: tuple[TargetInit, ...] = ()
    notifications: tuple[NotificationInit, ...] = ()
    write_confirmation: Literal["ENABLE"] | None = None

    @model_validator(mode="after")
    def require_write_confirmation(self) -> InitRequest:
        if self.global_mode == "read_write" or any(
            target.write_enabled for target in self.targets
        ):
            if self.write_confirmation != "ENABLE":
                raise ValueError("write_enabled requires write_confirmation=ENABLE")
        return self


@dataclass(frozen=True, slots=True)
class InitResult:
    settings: AgentSettings
    fingerprints: Mapping[str, str]
    config_bytes: bytes


class TargetIdentityProbe(Protocol):
    def probe(self, target: TargetInit) -> str: ...


class ModelProbe(Protocol):
    def probe(self, config: ModelInit) -> None: ...


class UnavailableProbe:
    """Placeholder probe until the runtime wires plugin-backed probes."""

    def __init__(self, label: str = "probe_unavailable") -> None:
        self._label = label

    def probe(self, _target_or_config: object) -> None:
        raise InitError(self._label)


class ProductionTargetProbe:
    """Probe identities through a configured transport plugin socket."""

    def __init__(self, client_factory: Callable[[str], object] | None = None) -> None:
        if client_factory is None:
            from a4diag.plugin_client import PluginClient

            client_factory = lambda name: PluginClient(f"/run/a4diag/{name}.sock")
        self._client_factory = client_factory

    def probe(self, target: TargetInit) -> str:
        name = target.transport or f"transport-{target.mode.value}"
        client = self._client_factory(name)
        result = asyncio.run(client.call("verify_identity", {}))  # type: ignore[attr-defined]
        data = result.get("data") if isinstance(result, dict) else None
        fingerprint = data.get("fingerprint") if isinstance(data, dict) else None
        if not isinstance(fingerprint, str) or not fingerprint:
            raise IdentityError("identity_probe_failed", target.id)
        return fingerprint


class ProductionModelProbe:
    """Require the selected model plugin to pass structured-output probing."""

    def __init__(self, client_factory: Callable[[str], object] | None = None) -> None:
        if client_factory is None:
            from a4diag.plugin_client import PluginClient

            client_factory = lambda name: PluginClient(f"/run/a4diag/{name}.sock")
        self._client_factory = client_factory

    def probe(self, config: ModelInit) -> None:
        client = self._client_factory(config.plugin)
        result = asyncio.run(client.call("capability_probe", {}))  # type: ignore[attr-defined]
        if not isinstance(result, dict) or result.get("write_capable") is not True:
            raise ModelProbeError("model_probe_failed")


def settings_to_yaml(settings: AgentSettings) -> bytes:
    return yaml.safe_dump(
        settings.model_dump(mode="json"),
        sort_keys=False,
        allow_unicode=True,
    ).encode("utf-8")


class InitService:
    """Validates a request and atomically writes the resulting config."""

    def __init__(
        self,
        *,
        transport: TargetIdentityProbe,
        model: ModelProbe,
    ) -> None:
        self.transport = transport
        self.model = model

    def validate(self, request: InitRequest) -> InitResult:
        if not isinstance(request, InitRequest):
            raise InitError("invalid_request")
        if request.model is not None:
            try:
                self.model.probe(request.model)
            except ModelProbeError:
                raise
            except Exception as error:
                raise InitError("model_probe_failed") from error
        fingerprints: dict[str, str] = {}
        for target in request.targets:
            try:
                fingerprints[target.id] = self.transport.probe(target)
            except InitError:
                raise
            except Exception as error:
                raise InitError("identity_probe_failed") from error
        settings = self._build_settings(request, fingerprints)
        try:
            config_bytes = settings_to_yaml(settings)
        except (ValueError, TypeError) as error:
            raise InitError("invalid_config") from error
        return InitResult(
            settings=settings,
            fingerprints=MappingProxyType(fingerprints),
            config_bytes=config_bytes,
        )

    def write_atomic(self, request: InitRequest, destination: Path) -> InitResult:
        result = self.validate(request)
        destination = Path(destination)
        directory = destination.parent
        temp = directory / (
            f".{destination.name}.a4diag-init-{os.getpid()}-{next(_TEMP_COUNTER)}.tmp"
        )
        try:
            fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as error:
            raise InitError("write_failed") from error
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(result.config_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            # Validate the staged content before it can replace the target.
            load_settings(temp)
        except (OSError, ValueError) as error:
            _unlink(temp)
            if isinstance(error, OSError):
                raise InitError("write_failed") from error
            raise InitError("invalid_config") from error
        try:
            os.replace(temp, destination)
        except OSError as error:
            _unlink(temp)
            raise InitError("write_failed") from error
        try:
            reloaded = load_settings(destination)
        except ValueError as error:
            raise InitError("invalid_config") from error
        return InitResult(
            settings=reloaded,
            fingerprints=result.fingerprints,
            config_bytes=result.config_bytes,
        )

    def _build_settings(
        self, request: InitRequest, fingerprints: Mapping[str, str]
    ) -> AgentSettings:
        targets = tuple(
            self._build_target(target, fingerprints[target.id])
            for target in request.targets
        )
        try:
            return AgentSettings(
                global_mode="read_write"
                if request.global_mode == "read_write"
                or any(target.write_enabled for target in targets)
                else "read_only",
                targets=targets,
                plugins=self._plugin_names(request),
                auto_execute_low=any(
                    target.auto_execute_low for target in targets
                ),
                max_write_targets=2,
                model=None if request.model is None else ModelSettings(
                    **request.model.model_dump(mode="python")
                ),
                notifications=tuple(
                    NotificationSettings(**item.model_dump(mode="python"))
                    for item in request.notifications
                ),
            )
        except ValueError as error:
            raise InitError("invalid_request", str(error)) from error

    def _build_target(self, target: TargetInit, fingerprint: str) -> TargetConfig:
        capabilities = tuple(
            CapabilityGrant(
                name=capability.name,
                actions=capability.actions,
                resources=capability.resources,
            )
            for capability in target.capabilities
        )
        try:
            return TargetConfig(
                id=target.id,
                mode=target.mode,
                identity_ref=f"target/{target.id}",
                identity_fingerprint=fingerprint,
                transport=target.transport or f"transport-{target.mode.value}",
                host=target.host,
                port=target.port,
                user=target.user,
                identity_file_ref=target.identity_file_ref,
                known_hosts_ref=target.known_hosts_ref,
                operation_signing_key_ref=target.operation_signing_key_ref,
                host_key_sha256=target.host_key_sha256,
                write_enabled=target.write_enabled,
                auto_execute_low=target.auto_execute_low,
                capabilities=capabilities,
                notification_required=target.notification_required,
            )
        except ValueError as error:
            raise InitError("invalid_request", str(error)) from error

    @staticmethod
    def _plugin_names(request: InitRequest) -> tuple[str, ...]:
        names = {
            target.transport or f"transport-{target.mode.value}"
            for target in request.targets
        }
        if request.model is not None:
            names.add(request.model.plugin)
        names.update(
            item.channel
            if item.channel.startswith("notification-")
            else f"notification-{item.channel}"
            for item in request.notifications
        )
        return tuple(sorted(names))


def load_init_request(path: Path) -> InitRequest:
    """Strictly parse a non-interactive init request from canonical JSON."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise InitError("input_missing") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise InitError("invalid_request", str(error)) from error
    if type(value) is not dict:
        raise InitError("invalid_request", "request must be a JSON object")
    try:
        return InitRequest.model_validate(value)
    except ValidationError as error:
        raise InitError("invalid_request", str(error)) from error


def interactive_init_request(*, input_fn: Callable[[str], str]) -> InitRequest:
    """Build a request from interactive prompts; ENABLE gates write_enabled."""

    def ask(question: str) -> str:
        return input_fn(question).strip()

    def yes_no(question: str) -> bool:
        return ask(question).lower() in {"y", "yes"}

    model = None
    if yes_no("configure model provider? (yes/no) "):
        model = ModelInit(
            base_url=ask("model base_url: "),
            api_key_ref=ask("model api_key_ref (empty for none): ") or None,
            model=ask("model name: "),
            api_style=ask("api style (openai/azure/ollama) [openai]: ") or "openai",
            timeout_seconds=int(ask("timeout seconds [30]: ") or 30),
        )
    targets: list[TargetInit] = []
    while yes_no("add target? (yes/no) "):
        target_id = ask("target id: ")
        mode = ask("target mode (local/ssh): ")
        host = port = user = None
        if mode == "ssh":
            host = ask("ssh host: ")
            port = int(ask("ssh port [22]: ") or 22)
            user = ask("ssh user: ")
        capabilities: list[CapabilityInit] = []
        while yes_no("add capability? (yes/no) "):
            capabilities.append(
                CapabilityInit(
                    name=ask("capability name (files/services/packages): "),
                    actions=tuple(
                        item.strip()
                        for item in ask("actions (comma separated): ").split(",")
                        if item.strip()
                    ),
                    resources=tuple(
                        item.strip()
                        for item in ask("resources (comma separated): ").split(",")
                        if item.strip()
                    ),
                )
            )
        write_enabled = False
        if yes_no("enable writes? (yes/no) "):
            if ask("type ENABLE to enable writes: ") == "ENABLE":
                write_enabled = True
        targets.append(
            TargetInit(
                id=target_id,
                mode=mode,
                host=host,
                port=port,
                user=user,
                write_enabled=write_enabled,
                auto_execute_low=yes_no("auto execute LOW? (yes/no) "),
                capabilities=tuple(capabilities),
            )
        )
    notifications: list[NotificationInit] = []
    while yes_no("add notification? (yes/no) "):
        notifications.append(
            NotificationInit(
                channel=ask("notification channel (cli/flashduty/smtp/webhook): ")
            )
        )
    return InitRequest(
        model=model,
        targets=tuple(targets),
        notifications=tuple(notifications),
        write_confirmation="ENABLE"
        if any(target.write_enabled for target in targets)
        else None,
    )


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> object:
    raise ValueError(f"floating-point JSON value is forbidden: {value}")


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


__all__ = [
    "CapabilityInit",
    "IdentityError",
    "InitError",
    "InitRequest",
    "InitResult",
    "InitService",
    "ModelInit",
    "ModelProbe",
    "ModelProbeError",
    "NotificationInit",
    "TargetIdentityProbe",
    "TargetInit",
    "UnavailableProbe",
    "interactive_init_request",
    "load_init_request",
    "settings_to_yaml",
]

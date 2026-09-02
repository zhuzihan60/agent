"""Fail-closed lifecycle management for built-in plugin instances.

Validation and staging are deliberately separate from activation.  A staged
instance cannot affect systemd or the live instance configuration.  Activation
uses an atomic configuration replacement and restores both the previous bytes
and the previous socket state if the health check fails.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml
from pydantic import BaseModel, ConfigDict, JsonValue, field_validator, model_validator

from a4diag.plugin_api.manifest import PluginManifest
from a4diag.secrets import SecretError, SecretResolver

_SAFE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_FORBIDDEN_EXECUTION_KEYS = frozenset(
    {"argv", "cmd", "command", "exec", "script", "shell"}
)


class InstanceValidationError(ValueError):
    """A stable, fail-closed instance validation error."""


class InstanceActivationError(RuntimeError):
    """Activation failed after the prior state was restored."""


class SystemdController(Protocol):
    def is_enabled(self, unit: str) -> bool: ...
    def is_active(self, unit: str) -> bool: ...
    def enable(self, unit: str) -> None: ...
    def disable(self, unit: str) -> None: ...
    def start(self, unit: str) -> None: ...
    def stop(self, unit: str) -> None: ...
    def health(self, instance: str, socket: str) -> bool: ...


def _reject_execution_keys(value: JsonValue, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in _FORBIDDEN_EXECUTION_KEYS:
                raise ValueError(f"forbidden execution field: {path}.{key}")
            _reject_execution_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_execution_keys(item, f"{path}[{index}]")


class PluginInstanceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    instance: str
    manifest: str
    socket: str
    ticket_key_ref: str
    config: dict[str, JsonValue]

    @field_validator("instance", "manifest")
    @classmethod
    def safe_identifier(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_INSTANCE.fullmatch(value):
            raise ValueError("unsafe plugin instance identifier")
        return value

    @field_validator("ticket_key_ref")
    @classmethod
    def file_secret_only(cls, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("file:"):
            raise ValueError("ticket key must use a file secret reference")
        return value

    @model_validator(mode="after")
    def validate_binding(self) -> PluginInstanceSpec:
        expected = f"/run/a4diag/{self.instance}.sock"
        if self.socket != expected:
            raise ValueError("instance socket does not match instance identity")
        _reject_execution_keys(self.config)
        return self


@dataclass(frozen=True, slots=True)
class StagedInstance:
    spec: PluginInstanceSpec
    staged_path: Path
    final_path: Path
    prior_content: bytes | None
    prior_mode: int | None
    prior_enabled: bool
    prior_active: bool


@dataclass(frozen=True, slots=True)
class ActivationReceipt:
    instance: str
    final_path: Path
    prior_content: bytes | None
    prior_mode: int | None
    prior_enabled: bool
    prior_active: bool


class PluginInstanceManager:
    def __init__(
        self,
        *,
        config_root: Path,
        manifest_root: Path,
        secrets_root: Path,
        systemd: SystemdController,
        config_gid: int | None = None,
    ) -> None:
        self._config_root = Path(config_root)
        self._manifest_root = Path(manifest_root)
        self._secrets_root = Path(secrets_root)
        self._systemd = systemd
        self._config_gid = config_gid

    def stage(self, spec: PluginInstanceSpec) -> StagedInstance:
        self._validate_manifest(spec)
        self._validate_ticket_key(spec)

        self._config_root.mkdir(parents=True, exist_ok=True)
        final_path = self._config_root / f"{spec.instance}.yaml"
        if final_path.is_symlink():
            raise InstanceValidationError("instance_config_symlink")
        prior_content: bytes | None = None
        prior_mode: int | None = None
        if final_path.exists():
            info = final_path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise InstanceValidationError("instance_config_not_regular")
            prior_content = final_path.read_bytes()
            prior_mode = stat.S_IMODE(info.st_mode)

        unit = self._socket_unit(spec.instance)
        prior_enabled = self._systemd.is_enabled(unit)
        prior_active = self._systemd.is_active(unit)
        staged_path = self._config_root / f".{spec.instance}.yaml.stage.{os.getpid()}"
        payload = yaml.safe_dump(
            spec.model_dump(mode="json", exclude={"instance"}),
            allow_unicode=False,
            sort_keys=True,
        ).encode("utf-8")
        descriptor = os.open(
            staged_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            staged_path.unlink(missing_ok=True)
            raise
        return StagedInstance(
            spec=spec,
            staged_path=staged_path,
            final_path=final_path,
            prior_content=prior_content,
            prior_mode=prior_mode,
            prior_enabled=prior_enabled,
            prior_active=prior_active,
        )

    def activate(self, staged: StagedInstance) -> ActivationReceipt:
        if not staged.staged_path.is_file():
            raise InstanceActivationError("staged_config_missing")
        receipt = ActivationReceipt(
            instance=staged.spec.instance,
            final_path=staged.final_path,
            prior_content=staged.prior_content,
            prior_mode=staged.prior_mode,
            prior_enabled=staged.prior_enabled,
            prior_active=staged.prior_active,
        )
        unit = self._socket_unit(staged.spec.instance)
        try:
            os.replace(staged.staged_path, staged.final_path)
            os.chmod(staged.final_path, 0o640)
            if self._config_gid is not None:
                os.chown(staged.final_path, -1, self._config_gid)
            self._fsync_directory(self._config_root)
            if not self._systemd.is_enabled(unit):
                self._systemd.enable(unit)
            if not self._systemd.is_active(unit):
                self._systemd.start(unit)
            if not self._systemd.health(staged.spec.instance, staged.spec.socket):
                raise InstanceActivationError("plugin_health_failed")
            return receipt
        except BaseException as exc:
            self._restore(receipt)
            if isinstance(exc, InstanceActivationError):
                raise
            raise InstanceActivationError("plugin_activation_failed") from exc

    def rollback(self, receipt: ActivationReceipt) -> None:
        self._restore(receipt)

    def _validate_manifest(self, spec: PluginInstanceSpec) -> None:
        path = self._manifest_root / f"{spec.manifest}.json"
        if path.is_symlink() or not path.is_file():
            raise InstanceValidationError("manifest_not_installed")
        try:
            manifest = PluginManifest.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise InstanceValidationError("manifest_invalid") from exc
        if manifest.name != spec.manifest:
            raise InstanceValidationError("manifest_identity_mismatch")

    def _validate_ticket_key(self, spec: PluginInstanceSpec) -> None:
        try:
            SecretResolver(self._secrets_root, env={}).resolve(spec.ticket_key_ref)
        except SecretError as exc:
            raise InstanceValidationError("ticket_key_invalid") from exc

    def _restore(self, receipt: ActivationReceipt) -> None:
        if receipt.prior_content is None:
            receipt.final_path.unlink(missing_ok=True)
        else:
            temporary = receipt.final_path.with_name(
                f".{receipt.final_path.name}.restore.{os.getpid()}"
            )
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                receipt.prior_mode or 0o640,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(receipt.prior_content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, receipt.final_path)
            os.chmod(receipt.final_path, receipt.prior_mode or 0o640)
            if self._config_gid is not None:
                os.chown(receipt.final_path, -1, self._config_gid)
        self._fsync_directory(receipt.final_path.parent)
        self._restore_systemd(
            self._socket_unit(receipt.instance),
            enabled=receipt.prior_enabled,
            active=receipt.prior_active,
        )

    def _restore_systemd(self, unit: str, *, enabled: bool, active: bool) -> None:
        if not active and self._systemd.is_active(unit):
            self._systemd.stop(unit)
        if not enabled and self._systemd.is_enabled(unit):
            self._systemd.disable(unit)
        if enabled and not self._systemd.is_enabled(unit):
            self._systemd.enable(unit)
        if active and not self._systemd.is_active(unit):
            self._systemd.start(unit)

    @staticmethod
    def _socket_unit(instance: str) -> str:
        return f"a4diag-plugin@{instance}.socket"

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


__all__ = [
    "ActivationReceipt",
    "InstanceActivationError",
    "InstanceValidationError",
    "PluginInstanceManager",
    "PluginInstanceSpec",
    "StagedInstance",
    "SystemdController",
]

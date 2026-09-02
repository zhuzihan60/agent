"""All-or-nothing activation for production initialization."""

from __future__ import annotations

import os
import stat
import subprocess
import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from a4diag.domain import TargetMode
from a4diag.init_config import InitRequest, InitResult, InitService, NotificationInit, TargetInit
from a4diag.plugin_instances import ActivationReceipt, PluginInstanceManager, PluginInstanceSpec


class InitTransactionError(RuntimeError):
    """Initialization failed and every activated resource was rolled back."""


class NotificationProbe(Protocol):
    def probe(self, notification: NotificationInit) -> None: ...


class TargetWriteProbe(Protocol):
    def probe(self, target: TargetInit, fingerprint: str) -> None: ...


class CoreController(Protocol):
    def snapshot(self) -> tuple[bool, bool]: ...
    def restart(self) -> None: ...
    def restore(self, enabled: bool, active: bool) -> None: ...


@dataclass(frozen=True, slots=True)
class _PriorFile:
    existed: bool
    content: bytes
    mode: int


class InitTransaction:
    def __init__(
        self,
        *,
        service: InitService,
        instances: PluginInstanceManager,
        notification: NotificationProbe,
        target_write: TargetWriteProbe,
        core: CoreController,
        self_check: Callable[[Path], bool],
        instance_specs: Callable[[InitRequest], tuple[PluginInstanceSpec, ...]],
    ) -> None:
        self._service = service
        self._instances = instances
        self._notification = notification
        self._target_write = target_write
        self._core = core
        self._self_check = self_check
        self._instance_specs = instance_specs

    def execute(self, request: InitRequest, destination: Path) -> InitResult:
        destination = Path(destination)
        prior = self._snapshot(destination)
        core_state = self._core.snapshot()
        staged: list[object] = []
        receipts: list[ActivationReceipt] = []
        try:
            for spec in self._instance_specs(request):
                staged.append(self._instances.stage(spec))
            for item in staged:
                receipts.append(self._instances.activate(item))  # type: ignore[arg-type]
            validated = self._service.validate(request)
            for item in request.notifications:
                self._notification.probe(item)
            for target in request.targets:
                if target.write_enabled:
                    self._target_write.probe(
                        target, validated.fingerprints[target.id]
                    )
            result = self._service.write_atomic(request, destination)
            self._core.restart()
            if not self._self_check(destination):
                raise InitTransactionError("self_check_failed")
            return result
        except BaseException as error:
            self._restore_file(destination, prior)
            for receipt in reversed(receipts):
                try:
                    self._instances.rollback(receipt)
                except Exception:
                    pass
            for item in staged:
                staged_path = getattr(item, "staged_path", None)
                if isinstance(staged_path, Path):
                    staged_path.unlink(missing_ok=True)
            try:
                self._core.restore(*core_state)
            except Exception:
                pass
            if isinstance(error, InitTransactionError):
                raise
            raise InitTransactionError("initialization_rolled_back") from error

    def write_atomic(self, request: InitRequest, destination: Path) -> InitResult:
        """Compatibility entry point used by the existing CLI."""
        return self.execute(request, destination)

    @staticmethod
    def _snapshot(path: Path) -> _PriorFile:
        if not path.exists():
            return _PriorFile(False, b"", 0o600)
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise InitTransactionError("config_not_regular")
        return _PriorFile(True, path.read_bytes(), stat.S_IMODE(info.st_mode))

    @staticmethod
    def _restore_file(path: Path, prior: _PriorFile) -> None:
        if not prior.existed:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.init-restore.{os.getpid()}")
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, prior.mode
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(prior.content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, prior.mode)


def build_builtin_instance_specs(
    request: InitRequest,
    *,
    secrets_root: Path = Path("/etc/a4diag/secrets"),
    ticket_key_ref: str = "file:core-ticket.key",
) -> tuple[PluginInstanceSpec, ...]:
    """Build only the model, notification and target transport instances.

    Capability manifests remain policy contracts; no capability service is
    started in the controller for an SSH target.
    """
    specs: list[PluginInstanceSpec] = []
    if request.model is not None:
        specs.append(
            PluginInstanceSpec(
                instance=request.model.plugin,
                manifest=request.model.plugin,
                socket=f"/run/a4diag/{request.model.plugin}.sock",
                ticket_key_ref=ticket_key_ref,
                config=request.model.model_dump(mode="json", exclude={"plugin"}),
            )
        )
    for notification in request.notifications:
        manifest = (
            notification.channel
            if notification.channel.startswith("notification-")
            else f"notification-{notification.channel}"
        )
        specs.append(
            PluginInstanceSpec(
                instance=manifest,
                manifest=manifest,
                socket=f"/run/a4diag/{manifest}.sock",
                ticket_key_ref=ticket_key_ref,
                config=notification.config,
            )
        )
    for target in request.targets:
        instance = target.transport or f"transport-{target.mode.value}"
        manifest = f"transport-{target.mode.value}"
        config: dict[str, object] = {}
        if target.mode is TargetMode.SSH:
            if (
                target.identity_file_ref is None
                or target.known_hosts_ref is None
                or target.host is None
                or target.port is None
                or target.user is None
            ):
                raise InitTransactionError("ssh_transport_material_missing")
            config = {
                "host": target.host,
                "port": target.port,
                "user": target.user,
                "identity_file": _secret_path(
                    target.identity_file_ref, secrets_root
                ),
                "known_hosts": _secret_path(target.known_hosts_ref, secrets_root),
                "host_key_sha256": target.host_key_sha256,
            }
        specs.append(
            PluginInstanceSpec(
                instance=instance,
                manifest=manifest,
                socket=f"/run/a4diag/{instance}.sock",
                ticket_key_ref=ticket_key_ref,
                config=config,  # type: ignore[arg-type]
            )
        )
    instances = [spec.instance for spec in specs]
    if len(instances) != len(set(instances)):
        raise InitTransactionError("duplicate_plugin_instance")
    return tuple(specs)


def _secret_path(reference: str, root: Path) -> str:
    if not reference.startswith("file:"):
        raise InitTransactionError("file_secret_required")
    relative = reference[5:]
    parts = relative.split("/")
    if not relative or any(part in {"", ".", ".."} for part in parts):
        raise InitTransactionError("unsafe_secret_reference")
    return str(Path(root).joinpath(*parts))


class SystemdInitController:
    """Fixed-unit systemd adapter for plugin sockets and the core service."""

    CORE_UNIT = "a4diag-core.service"

    @staticmethod
    def _run(action: str, unit: str, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["/usr/bin/systemctl", action, unit],
            check=check,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )

    def is_enabled(self, unit: str) -> bool:
        return self._run("is-enabled", unit, check=False).returncode == 0

    def is_active(self, unit: str) -> bool:
        return self._run("is-active", unit, check=False).returncode == 0

    def enable(self, unit: str) -> None:
        self._run("enable", unit)

    def disable(self, unit: str) -> None:
        self._run("disable", unit)

    def start(self, unit: str) -> None:
        self._run("start", unit)

    def stop(self, unit: str) -> None:
        self._run("stop", unit)

    def health(self, instance: str, socket: str) -> bool:
        from a4diag.plugin_client import PluginClient

        try:
            result = asyncio.run(PluginClient(socket).call("health", {}))
        except Exception:
            return False
        return isinstance(result, dict) and result.get("ok") is True

    def snapshot(self) -> tuple[bool, bool]:
        return self.is_enabled(self.CORE_UNIT), self.is_active(self.CORE_UNIT)

    def restart(self) -> None:
        self._run("enable", self.CORE_UNIT)
        self._run("restart", self.CORE_UNIT)

    def restore(self, enabled: bool, active: bool) -> None:
        if active:
            self._run("start", self.CORE_UNIT)
        else:
            self._run("stop", self.CORE_UNIT)
        if enabled:
            self._run("enable", self.CORE_UNIT)
        else:
            self._run("disable", self.CORE_UNIT)


class ProductionNotificationProbe:
    def probe(self, notification: NotificationInit) -> None:
        from a4diag.plugin_client import PluginClient

        instance = (
            notification.channel
            if notification.channel.startswith("notification-")
            else f"notification-{notification.channel}"
        )
        result = asyncio.run(
            PluginClient(f"/run/a4diag/{instance}.sock").call("health", {})
        )
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise InitTransactionError("notification_probe_failed")


class ProductionTargetWriteProbe:
    def probe(self, target: TargetInit, fingerprint: str) -> None:
        from a4diag.plugin_client import PluginClient

        instance = target.transport or f"transport-{target.mode.value}"
        result = asyncio.run(
            PluginClient(f"/run/a4diag/{instance}.sock").call(
                "capability_probe", {}
            )
        )
        if (
            not fingerprint.startswith("sha256:")
            or not isinstance(result, dict)
            or result.get("write_capable") is not True
        ):
            raise InitTransactionError("target_write_probe_failed")


def production_self_check(config_path: Path) -> bool:
    environment = dict(os.environ)
    environment["A4DIAG_CONFIG"] = str(config_path)
    result = subprocess.run(
        ["/opt/a4diag/current/venv/bin/a4diag", "self-check", "--offline"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        env=environment,
    )
    return result.returncode == 0


__all__ = [
    "InitTransaction",
    "InitTransactionError",
    "ProductionNotificationProbe",
    "ProductionTargetWriteProbe",
    "SystemdInitController",
    "build_builtin_instance_specs",
    "production_self_check",
]

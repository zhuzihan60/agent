"""All-or-nothing activation for production initialization."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

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


__all__ = ["InitTransaction", "InitTransactionError"]

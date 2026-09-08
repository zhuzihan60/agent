from __future__ import annotations

import asyncio
import base64
import os
import stat
from pathlib import Path

import pytest

from a4diag.domain import Operation, Risk
from a4diag_builtin_plugins.capability_common import (
    CapabilityApplyParams,
    CapabilityError,
    CapabilityPrepareParams,
    CapabilityReconcileParams,
    CapabilityVerifyParams,
    LocalFileAdapter,
    ReconcileState,
    StatInfo,
)
from a4diag_builtin_plugins.capability_files import FilesPlugin, MAX_MANAGED_FILE_BYTES


class MemoryFileAdapter:
    """Old-shape adapter proving FilesPlugin remains duck-type compatible."""

    def __init__(self, content: bytes, *, mode: int = 0o100644) -> None:
        self.content = content
        self.mode = mode
        self.uid = 1000
        self.gid = 1001

    async def lstat(self, path: str) -> StatInfo:
        if path in {"/etc", "/etc/example"}:
            return StatInfo(mode=0o40755, uid=0, gid=0)
        if path != "/etc/example/app.conf":
            raise CapabilityError("path_not_found")
        return StatInfo(mode=self.mode, uid=self.uid, gid=self.gid)

    async def read_file(self, path: str, limit: int) -> bytes:
        return self.content[:limit]

    async def write_file(self, path: str, content: bytes, mode: int | None) -> None:
        self.content = content
        if mode is not None:
            self.mode = mode

    async def set_mode(self, path: str, mode: int) -> None:
        self.mode = mode

    async def chown(self, path: str, uid: int, gid: int) -> None:
        self.uid = uid
        self.gid = gid


def _operation(
    *,
    action: str = "replace_managed_file",
    content: bytes = b"after",
    mode: int | None = None,
    resource: str = "/etc/example/app.conf",
) -> Operation:
    parameters: dict[str, object]
    if action == "set_mode":
        assert mode is not None
        parameters = {"mode": mode}
    else:
        parameters = {"content": base64.b64encode(content).decode("ascii")}
        if mode is not None:
            parameters["mode"] = mode
    return Operation(
        capability="files",
        action=action,
        resource=resource,
        parameters=parameters,
        model_risk=Risk.LOW,
        verify={},
        undo={"restore": True},
    )


def _prepare(operation: Operation) -> CapabilityPrepareParams:
    return CapabilityPrepareParams(
        transaction_id="tx-1",
        step_id="step-1",
        target_id="lab",
        target_fingerprint="machine-1",
        operation=operation,
        plan_digest="a" * 64,
        risk=Risk.LOW,
        approval_id=None,
    )


def _apply(operation: Operation, marker: dict[str, object]) -> CapabilityApplyParams:
    return CapabilityApplyParams(
        **_prepare(operation).model_dump(),
        marker=marker,
    )


def _verify(operation: Operation, marker: dict[str, object]) -> CapabilityVerifyParams:
    return CapabilityVerifyParams(
        transaction_id="tx-1",
        step_id="step-1",
        operation=operation,
        marker=marker,
    )


def _reconcile(operation: Operation, marker: dict[str, object]) -> CapabilityReconcileParams:
    return CapabilityReconcileParams(
        transaction_id="tx-1",
        step_id="step-1",
        operation=operation,
        marker=marker,
    )


def test_set_mode_reconcile_uses_complete_file_state() -> None:
    adapter = MemoryFileAdapter(b"same", mode=0o100644)
    plugin = FilesPlugin(transport=adapter)  # type: ignore[arg-type]
    operation = _operation(action="set_mode", mode=0o600)
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))

    before = asyncio.run(plugin.reconcile(_reconcile(operation, prepared.marker)))
    asyncio.run(plugin.apply(_apply(operation, prepared.marker)))
    after = asyncio.run(plugin.reconcile(_reconcile(operation, prepared.marker)))

    assert before.state is ReconcileState.NOT_APPLIED
    assert after.state is ReconcileState.APPLIED


def test_same_content_replace_reconcile_uses_mode_change() -> None:
    adapter = MemoryFileAdapter(b"same", mode=0o100644)
    plugin = FilesPlugin(transport=adapter)  # type: ignore[arg-type]
    operation = _operation(content=b"same", mode=0o600)
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))

    before = asyncio.run(plugin.reconcile(_reconcile(operation, prepared.marker)))
    asyncio.run(plugin.apply(_apply(operation, prepared.marker)))
    after = asyncio.run(plugin.reconcile(_reconcile(operation, prepared.marker)))

    assert before.state is ReconcileState.NOT_APPLIED
    assert after.state is ReconcileState.APPLIED


def test_verify_rejects_ownership_drift() -> None:
    adapter = MemoryFileAdapter(b"before")
    plugin = FilesPlugin(transport=adapter)  # type: ignore[arg-type]
    operation = _operation()
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))
    asyncio.run(plugin.apply(_apply(operation, prepared.marker)))
    adapter.uid = 2000

    result = asyncio.run(plugin.verify(_verify(operation, prepared.marker)))

    assert result.ok is False
    assert result.reason == "ownership_mismatch"


def test_verify_rejects_mode_drift_when_replace_omits_mode() -> None:
    adapter = MemoryFileAdapter(b"before", mode=0o100640)
    plugin = FilesPlugin(transport=adapter)  # type: ignore[arg-type]
    operation = _operation()
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))
    asyncio.run(plugin.apply(_apply(operation, prepared.marker)))
    adapter.mode = 0o100600

    result = asyncio.run(plugin.verify(_verify(operation, prepared.marker)))

    assert result.ok is False
    assert result.reason == "mode_mismatch"


def test_reconcile_reports_ownership_drift_as_partial() -> None:
    adapter = MemoryFileAdapter(b"before")
    plugin = FilesPlugin(transport=adapter)  # type: ignore[arg-type]
    operation = _operation()
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))
    asyncio.run(plugin.apply(_apply(operation, prepared.marker)))
    adapter.gid = 2001

    result = asyncio.run(plugin.reconcile(_reconcile(operation, prepared.marker)))

    assert result.state is ReconcileState.PARTIAL


def test_verify_restored_requires_complete_prior_state() -> None:
    adapter = MemoryFileAdapter(b"before", mode=0o100640)
    plugin = FilesPlugin(transport=adapter)  # type: ignore[arg-type]
    operation = _operation()
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))

    restored = asyncio.run(plugin.verify_restored(_verify(operation, prepared.marker)))
    adapter.uid = 2000
    drifted = asyncio.run(plugin.verify_restored(_verify(operation, prepared.marker)))

    assert restored.ok is True
    assert drifted.ok is False
    assert drifted.reason == "restored_state_mismatch"


@pytest.mark.skipif(os.name != "posix", reason="POSIX metadata semantics")
def test_replace_without_mode_preserves_local_file_metadata(tmp_path: Path) -> None:
    target = tmp_path / "app.conf"
    target.write_bytes(b"before")
    target.chmod(0o640)
    if os.geteuid() == 0:
        os.chown(target, 65534, 65534)
    prior = target.stat()
    plugin = FilesPlugin(transport=LocalFileAdapter())
    operation = _operation(content=b"after", resource=str(target))
    prepared = asyncio.run(plugin.prepare(_prepare(operation)))

    asyncio.run(plugin.apply(_apply(operation, prepared.marker)))

    current = target.stat()
    assert target.read_bytes() == b"after"
    assert stat.S_IMODE(current.st_mode) == 0o640
    assert (current.st_uid, current.st_gid) == (prior.st_uid, prior.st_gid)


def test_local_bounded_read_rejects_oversized_file(tmp_path: Path) -> None:
    target = tmp_path / "large.conf"
    target.write_bytes(b"x" * (MAX_MANAGED_FILE_BYTES + 1))

    with pytest.raises(CapabilityError, match="read_limit_exceeded"):
        asyncio.run(LocalFileAdapter().read_file(str(target), MAX_MANAGED_FILE_BYTES))


@pytest.mark.skipif(os.name != "posix", reason="managed paths are POSIX paths")
def test_prepare_rejects_oversized_local_file_instead_of_backing_up_a_prefix(
    tmp_path: Path,
) -> None:
    target = tmp_path / "large.conf"
    target.write_bytes(b"x" * (MAX_MANAGED_FILE_BYTES + 1))
    plugin = FilesPlugin(transport=LocalFileAdapter())
    operation = _operation(resource=str(target))

    with pytest.raises(CapabilityError, match="managed_file_too_large"):
        asyncio.run(plugin.prepare(_prepare(operation)))

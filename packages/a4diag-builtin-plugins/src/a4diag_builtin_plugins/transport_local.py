"""Local transport plugin: identity-pinned execution on the agent host.

The local transport reads ``/etc/machine-id`` and ``/etc/os-release`` through
injected readers, runs a fixed helper executable for typed operations, and
never shells through a command string. Every argv array is fixed; output is
bounded; a timed-out dispatch terminates the process group and reports
``execution_unknown``.
"""

from __future__ import annotations

import asyncio
import os
import re
import stat
from collections.abc import Awaitable, Callable

from a4diag_builtin_plugins.transport_common import (
    BaseTransport,
    IdentityProbe,
    ProcessRunner,
    ReadKind,
    ReadParams,
    SubprocessRunner,
    TRANSPORT_HELPER_EXECUTABLE,
    TargetIdentity,
    TransportIdentityError,
    TransportReadError,
)

_VERSION = "0.4.0"
_MAX_IDENTITY_TEXT_BYTES = 65_536


def parse_os_release(content: str) -> tuple[str, str]:
    """Extract ``ID`` and ``VERSION_ID`` from an os-release file body."""
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key not in {"ID", "VERSION_ID"}:
            continue
        values[key] = value.strip().strip('"').strip("'")
    os_id = values.get("ID", "").strip()
    version = values.get("VERSION_ID", "").strip()
    if not os_id or not version:
        raise TransportIdentityError("os_release_unreadable")
    return os_id, version


async def _read_identity_text(path: str) -> str:
    """Read a bounded regular file without following symlinks."""
    try:
        info = os.lstat(path)
    except OSError:
        raise TransportIdentityError("identity_file_unreadable") from None
    if not stat.S_ISREG(info.st_mode):
        raise TransportIdentityError("identity_file_unreadable")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        handle = os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        raise TransportIdentityError("identity_file_unreadable") from None
    try:
        with handle:
            data = handle.read(_MAX_IDENTITY_TEXT_BYTES + 1)
    except OSError:
        raise TransportIdentityError("identity_file_unreadable") from None
    if len(data) > _MAX_IDENTITY_TEXT_BYTES:
        raise TransportIdentityError("identity_file_unreadable")
    return data.decode("utf-8", errors="replace")


class LocalIdentityReader:
    """Default identity probe: machine-id, os-release, and systemd version."""

    def __init__(
        self,
        *,
        machine_id_path: str = "/etc/machine-id",
        os_release_path: str = "/etc/os-release",
        systemd_version_reader: Callable[[], Awaitable[str]] | None = None,
    ) -> None:
        self._machine_id_path = machine_id_path
        self._os_release_path = os_release_path
        self._systemd_version_reader = systemd_version_reader or self._read_systemd_version

    async def probe(self) -> TargetIdentity:
        machine_id = (await _read_identity_text(self._machine_id_path)).strip()
        if not machine_id:
            raise TransportIdentityError("machine_id_missing")
        os_id, os_version_id = parse_os_release(
            await _read_identity_text(self._os_release_path)
        )
        systemd_version = (await self._systemd_version_reader()).strip()
        if not systemd_version:
            raise TransportIdentityError("systemd_version_unavailable")
        return TargetIdentity(
            machine_id=machine_id,
            host_key_sha256=None,
            os_id=os_id,
            os_version_id=os_version_id,
            systemd_version=systemd_version,
        )

    async def _read_systemd_version(self) -> str:
        proc = await asyncio.create_subprocess_exec(
            "/usr/bin/systemctl",
            "--version",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TransportIdentityError("systemd_version_unavailable") from None
        if proc.returncode != 0:
            raise TransportIdentityError("systemd_version_unavailable")
        first_line = stdout.decode("utf-8", errors="replace").splitlines()[0:1]
        match = re.search(r"systemd\s+([0-9]+)", first_line[0]) if first_line else None
        if match is None:
            raise TransportIdentityError("systemd_version_unavailable")
        return match.group(1)


async def read_file_bounded(path: str, limit: int) -> tuple[str, bool]:
    """Read a regular file with a hard byte bound; never follows symlinks."""
    try:
        info = os.lstat(path)
    except OSError:
        raise TransportReadError("read_failed") from None
    if not stat.S_ISREG(info.st_mode):
        raise TransportReadError("not_regular_file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        handle = os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        raise TransportReadError("read_failed") from None
    try:
        with handle:
            data = handle.read(limit + 1)
    except OSError:
        raise TransportReadError("read_failed") from None
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


class LocalTransport(BaseTransport):
    """Local identity-pinned transport over the fixed helper executable."""

    def __init__(
        self,
        *,
        identity: IdentityProbe | None = None,
        runner: ProcessRunner | None = None,
        read_file: Callable[[str, int], Awaitable[tuple[str, bool]]] | None = None,
    ) -> None:
        super().__init__(
            name="transport-local",
            version=_VERSION,
            runner=runner or SubprocessRunner(),
        )
        self._identity = identity or LocalIdentityReader()
        self._read_file = read_file or read_file_bounded

    async def _probe_identity(self) -> TargetIdentity:
        return await self._identity.probe()

    def _build_helper_argv(self) -> list[str]:
        return [TRANSPORT_HELPER_EXECUTABLE]

    async def _perform_read(self, params: ReadParams) -> tuple[str, bool]:
        if params.kind is ReadKind.FILE:
            assert params.path is not None
            return await self._read_file(params.path, int(params.output_limit_bytes))
        identity = await self._probe_identity()
        if params.kind is ReadKind.MACHINE_ID:
            return identity.machine_id, False
        if params.kind is ReadKind.OS_RELEASE:
            return f"ID={identity.os_id}\nVERSION_ID={identity.os_version_id}\n", False
        if params.kind is ReadKind.SYSTEMD_VERSION:
            return identity.systemd_version, False
        raise TransportReadError("unsupported_read_kind")


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "transport-local is started by the plugin supervisor with its manifest"
    )


__all__ = [
    "LocalIdentityReader",
    "LocalTransport",
    "main",
    "parse_os_release",
    "read_file_bounded",
]

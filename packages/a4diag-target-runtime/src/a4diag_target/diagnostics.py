"""Unsigned, policy-authorized diagnostics with fixed commands and byte bounds."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

from a4diag_builtin_plugins.transport_common import MAX_DIAGNOSTIC_BODY_BYTES, ReadKind, ReadParams, SubprocessRunner
from a4diag_target.policy import TargetPolicy

DIAGNOSTIC_TIMEOUT_SECONDS = 10.0
_STATE_PROPERTIES = ("ActiveState", "SubState", "LoadState", "Result", "ExecMainStatus", "MainPID", "UnitFileState")


def _bounded_response(raw: bytes, limit: int, *, truncated: bool = False) -> dict[str, object]:
    return {"content": raw[:limit].decode("utf-8", errors="ignore"),
            "truncated": truncated or len(raw) > limit}


def _read_regular_file(root: Path, path: str, limit: int) -> bytes:
    # Open each ancestor relative to a pinned directory fd. O_NONBLOCK avoids
    # blocking on a malicious FIFO before fstat rejects non-regular files.
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure_file_read_unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(root, directory_flags)
    try:
        parts = path.lstrip("/").split("/")
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise ValueError("not_regular_file")
            with os.fdopen(file_fd, "rb", closefd=False) as handle:
                return handle.read(limit + 1)
        finally:
            os.close(file_fd)
    finally:
        os.close(descriptor)


async def read_diagnostic(root: Path, request: dict[str, object], policy: TargetPolicy) -> dict[str, object]:
    if set(request) - {"method", "kind", "limit", "path", "unit"} or request.get("method") != "read":
        return {"ok": False, "reason": "read_request_invalid"}
    limit = request.get("limit")
    if type(limit) is not int or not 1 <= limit <= MAX_DIAGNOSTIC_BODY_BYTES:
        return {"ok": False, "reason": "read_limit_invalid"}
    try:
        params = ReadParams(kind=request.get("kind"), path=request.get("path"),
                            unit=request.get("unit"), output_limit_bytes=limit)
    except ValueError:
        return {"ok": False, "reason": "read_request_invalid"}
    if params.kind is ReadKind.FILE:
        assert params.path is not None
        policy.authorize_file_read(params.path)
        try:
            return _bounded_response(_read_regular_file(root, params.path, limit), limit)
        except OSError:
            return {"ok": False, "reason": "read_failed"}
    if params.kind not in (ReadKind.SERVICE_STATE, ReadKind.SERVICE_LOGS):
        return {"ok": False, "reason": "read_kind_not_allowed"}
    assert params.unit is not None
    policy.authorize_service_read(params.unit)
    if params.kind is ReadKind.SERVICE_STATE:
        argv = ["/usr/bin/systemctl", "show", "--no-pager",
                "--property=" + ",".join(_STATE_PROPERTIES), "--", params.unit]
        command_limit = 65_536
    else:
        argv = ["/usr/bin/journalctl", "--no-pager", "--quiet", "--output=short-iso", "--lines=200", "--unit=" + params.unit]
        command_limit = limit
    try:
        outcome = await asyncio.wait_for(SubprocessRunner().run(
            argv, payload=b"", output_limit_bytes=command_limit,
        ), timeout=DIAGNOSTIC_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        return {"ok": False, "reason": "read_timeout"}
    if not outcome.started or outcome.timed_out or outcome.returncode != 0:
        return {"ok": False, "reason": "read_failed"}
    if params.kind is ReadKind.SERVICE_LOGS:
        return _bounded_response(outcome.stdout.encode("utf-8"), limit, truncated=outcome.stdout_truncated)
    if outcome.stdout_truncated:
        return {"ok": False, "reason": "read_failed"}
    values = {}
    for line in outcome.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in _STATE_PROPERTIES:
            values[key] = value
    if not all(key in values for key in ("ActiveState", "SubState", "LoadState")):
        return {"ok": False, "reason": "read_failed"}
    return _bounded_response(json.dumps(values, separators=(",", ":")).encode(), limit)

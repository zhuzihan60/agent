"""Bounded, read-only Linux diagnostics selected by target-owned definitions."""
from __future__ import annotations

import asyncio
import errno
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path

from a4diag.linux_probes import LinuxProbe
from a4diag_builtin_plugins.transport_common import SubprocessRunner

PROBE_TIMEOUT_SECONDS = 5.0


@contextmanager
def _open(root: Path, resource: str, *, directory: bool = False):
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure_probe_read_unavailable")
    if not resource.startswith("/") or (resource != "/" and any(p in (".", "..", "") for p in resource.split("/")[1:])):
        raise ValueError("probe_path_invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        parts = resource.strip("/").split("/") if resource != "/" else []
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            child_flags = flags if directory or not final else os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            child = os.open(part, child_flags, dir_fd=fd)
            os.close(fd)
            fd = child
        if not directory and not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("probe_not_regular_file")
        yield fd
    finally:
        os.close(fd)


def _read(root: Path, resource: str, limit: int) -> str:
    with _open(root, resource) as fd:
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("probe_truncated")
    return raw.decode("ascii", errors="strict")


def _percent(total: int, available: int) -> int:
    if total <= 0 or not 0 <= available <= total:
        raise ValueError("probe_invalid_capacity")
    return (total - available) * 100 // total


async def _command(runner, argv: list[str], limit: int):
    result = await asyncio.wait_for(runner.run(argv, payload=b"", output_limit_bytes=limit), PROBE_TIMEOUT_SECONDS)
    if not result.started or result.timed_out or result.stdout_truncated or result.stderr_truncated:
        raise ValueError("probe_command_failed")
    if len(result.stdout.encode()) > limit or len(result.stderr.encode()) > limit:
        raise ValueError("probe_truncated")
    return result


async def _package(root: Path, probe: LinuxProbe, runner) -> dict:
    try:
        release = _read(root, "/etc/os-release", probe.max_bytes)
    except OSError as exc:
        # Many distributions install /etc/os-release as a symlink. Never follow
        # its target; use only the standard vendor path, secured independently.
        if exc.errno not in {errno.ENOENT, errno.ELOOP}:
            raise
        release = _read(root, "/usr/lib/os-release", probe.max_bytes)
    entries = {}
    for line in release.splitlines():
        if line.startswith(("ID=", "ID_LIKE=")):
            key, value = line.split("=", 1)
            if key in entries:
                raise ValueError("probe_invalid_os_release")
            entries[key] = value.strip().strip('\"\'')
    families = set((entries.get("ID", "") + " " + entries.get("ID_LIKE", "")).split())
    name = probe.resource
    if families & {"debian", "ubuntu"}:
        result = await _command(runner, ["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${db:Status-Status}\t${Version}\\n", "--", name], probe.max_bytes)
        if result.returncode == 1 and not result.stdout and result.stderr.strip() == f"dpkg-query: no packages found matching {name}":
            return {"installed": False, "version": ""}
        if result.returncode != 0 or result.stderr:
            raise ValueError("probe_package_failed")
        fields = result.stdout.rstrip("\n").split("\t")
        if len(fields) != 3 or fields[0] not in {name, name.split(":")[0]} or "\n" in result.stdout.rstrip("\n"):
            raise ValueError("probe_invalid_package")
        if fields[1] in {"not-installed", "config-files"}:
            return {"installed": False, "version": ""}
        if fields[1] != "installed" or not fields[2] or any(c.isspace() for c in fields[2]):
            raise ValueError("probe_invalid_package")
        return {"installed": True, "version": fields[2]}
    if families & {"rhel", "fedora", "centos", "rocky", "almalinux", "suse", "opensuse"}:
        result = await _command(runner, ["/usr/bin/rpm", "--query", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\\n", "--", name], probe.max_bytes)
        if result.returncode == 1 and not result.stderr and result.stdout.strip() == f"package {name} is not installed":
            return {"installed": False, "version": ""}
        fields = result.stdout.rstrip("\n").split("\t")
        if result.returncode != 0 or result.stderr or len(fields) != 2 or fields[0] != name or not fields[1] or any(c.isspace() for c in fields[1]):
            raise ValueError("probe_package_failed")
        return {"installed": True, "version": fields[1]}
    raise ValueError("probe_package_unsupported")


async def run_probe(root: Path, probe: LinuxProbe, runner=None) -> dict:
    """Return exact contract fields; failures raise rather than imply health."""
    runner = runner if runner is not None else SubprocessRunner()
    kind = probe.kind
    if kind == "filesystem":
        with _open(root, probe.resource, directory=True) as fd:
            capacity = os.fstatvfs(fd)
        total = capacity.f_blocks * capacity.f_frsize
        available = capacity.f_bavail * capacity.f_frsize
        if capacity.f_favail < 0:
            raise ValueError("probe_invalid_capacity")
        return {"total_bytes": total, "available_bytes": available, "used_percent": _percent(total, available), "free_inodes": capacity.f_favail}
    if kind == "file":
        try:
            with _open(root, probe.resource) as fd:
                before = os.fstat(fd)
                digest = ""
                if before.st_size <= probe.max_bytes:
                    with os.fdopen(fd, "rb", closefd=False) as handle:
                        raw = handle.read(probe.max_bytes + 1)
                    after = os.fstat(fd)
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise ValueError("probe_file_changed")
                    if len(raw) == before.st_size and len(raw) <= probe.max_bytes:
                        digest = hashlib.sha256(raw).hexdigest()
                return {"exists": True, "mode": stat.S_IMODE(before.st_mode), "size_bytes": before.st_size, "sha256": digest}
        except FileNotFoundError:
            return {"exists": False, "mode": 0, "size_bytes": 0, "sha256": ""}
    if kind == "memory":
        values = {}
        needed = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
        for line in _read(root, "/proc/meminfo", probe.max_bytes).splitlines():
            key = line.split(":", 1)[0]
            if key in needed:
                match = re.fullmatch(r"([A-Za-z]+):\s+([0-9]+) kB", line)
                if not match or key in values:
                    raise ValueError("probe_invalid_memory")
                values[key] = int(match[2]) * 1024
        if set(values) != needed or values["SwapFree"] > values["SwapTotal"]:
            raise ValueError("probe_invalid_memory")
        return {"total_bytes": values["MemTotal"], "available_bytes": values["MemAvailable"], "used_percent": _percent(values["MemTotal"], values["MemAvailable"]), "swap_total_bytes": values["SwapTotal"], "swap_free_bytes": values["SwapFree"]}
    if kind == "load":
        fields = _read(root, "/proc/loadavg", probe.max_bytes).split()
        if len(fields) != 5 or not all(re.fullmatch(r"[0-9]+\.[0-9]{1,3}", x) for x in fields[:3]) or not re.fullmatch(r"[0-9]+/[0-9]+", fields[3]) or not fields[4].isdigit():
            raise ValueError("probe_invalid_load")
        runnable, tasks = map(int, fields[3].split("/"))
        if runnable > tasks or tasks == 0:
            raise ValueError("probe_invalid_load")
        cpu_lines = _read(root, "/proc/stat", probe.max_bytes).splitlines()
        cpu_rows = [line.split() for line in cpu_lines if re.match(r"cpu[0-9]+\s", line)]
        if any(len(row) < 5 or not all(re.fullmatch(r"[0-9]+", value) for value in row[1:]) for row in cpu_rows):
            raise ValueError("probe_invalid_cpu_count")
        cpus = [row[0] for row in cpu_rows]
        if not cpus or len(cpus) != len(set(cpus)):
            raise ValueError("probe_invalid_cpu_count")
        try:
            loads = [int(Decimal(x) * 1000) for x in fields[:3]]
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("probe_invalid_load") from exc
        return dict(zip(("load_1_milli", "load_5_milli", "load_15_milli", "cpu_count"), loads + [len(cpus)]))
    if kind == "package":
        return await _package(root, probe, runner)
    if kind in {"tcp", "dns"}:
        argv = [sys.executable, "-m", "a4diag_target.probe_network", kind, probe.resource]
        result = await _command(runner, argv, probe.max_bytes)
        if result.returncode != 0 or result.stderr:
            raise ValueError("probe_network_failed")
        try:
            data = json.loads(result.stdout, object_pairs_hook=_unique_object)
        except (ValueError, TypeError, RecursionError) as exc:
            raise ValueError("probe_invalid_network") from exc
        if kind == "tcp":
            if not isinstance(data, dict) or set(data) != {"reachable"} or type(data["reachable"]) is not bool:
                raise ValueError("probe_invalid_network")
        else:
            if not isinstance(data, dict) or set(data) != {"resolved", "addresses"} or type(data["resolved"]) is not bool or not isinstance(data["addresses"], list) or len(data["addresses"]) > 16:
                raise ValueError("probe_invalid_network")
            addresses = data["addresses"]
            if any(not isinstance(x, str) or str(ipaddress.ip_address(x)) != x or "%" in x for x in addresses) or len(set(addresses)) != len(addresses) or data["resolved"] != bool(addresses):
                raise ValueError("probe_invalid_network")
        return data
    raise ValueError("probe_unsupported")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("probe_duplicate_field")
        result[key] = value
    return result

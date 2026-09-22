"""Bounded, read-only disk-cache candidate preparation.

Candidate metadata is evidence for later revalidation, never permission to unlink.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import json
import os
import re
import stat
import signal
from contextlib import contextmanager

from a4diag.repair_profiles import _PROTECTED_SERVICES, _SERVICE

MAX_SCAN_DEPTH = 8
MAX_SCAN_ENTRIES = 4096
MAX_MARKER_BYTES = 196608
_PATH = re.compile(r'/(?:[A-Za-z0-9._+@:-]+/)*[A-Za-z0-9._+@:-]+')


@dataclass(frozen=True)
class DiskLimits:
    root: str
    min_age_seconds: int
    max_files: int
    max_bytes: int
    min_free_bytes: int
    min_free_inodes: int
    writer_unit: str

    def __post_init__(self):
        if (not isinstance(self.root, str) or not _PATH.fullmatch(self.root)
                or len(self.root) > 1024 or len(self.root.split('/')) > 33
                or any(p in ('.', '..') for p in self.root.split('/'))
                or self.root in ('/var', '/var/cache', '/opt', '/srv', '/home', '/tmp')
                or self.root.split('/')[1] in ('etc', 'proc', 'sys', 'dev', 'usr', 'bin', 'sbin', 'boot', 'run')):
            raise ValueError('invalid_cache_root')
        if (not isinstance(self.writer_unit, str) or not _SERVICE.fullmatch(self.writer_unit)
                or self.writer_unit.casefold().startswith(_PROTECTED_SERVICES)):
            raise ValueError('invalid_writer_unit')
        for name, lower, upper in (
            ('min_age_seconds', 1, 315360000), ('max_files', 1, 1024),
            ('max_bytes', 1, 1 << 40), ('min_free_bytes', 0, 1 << 50),
            ('min_free_inodes', 0, 1 << 40),
        ):
            value = getattr(self, name)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError('invalid_disk_limits')


@dataclass(frozen=True)
class DiskEntry:
    relative_path: str
    dev: int
    ino: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class DiskMarker:
    root_dev: int
    root_ino: int
    entries: tuple[DiskEntry, ...]
    writer_stop_marker: dict | None
    initial_free_bytes: int
    initial_free_inodes: int


def entry_unchanged(entry: DiskEntry, current: os.stat_result) -> bool:
    """Require a singly linked regular file with every saved binding intact."""
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_nlink == 1
        and (entry.dev, entry.ino, entry.size, entry.mtime_ns, entry.ctime_ns)
        == (current.st_dev, current.st_ino, current.st_size,
            current.st_mtime_ns, current.st_ctime_ns)
    )


def _directory_signature(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_mtime_ns, st.st_ctime_ns)


def _trusted_directory(st):
    return stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022


def _mount_id(fd):
    # st_dev does not distinguish a bind mount on the same filesystem.
    with open(f'/proc/self/fdinfo/{fd}', 'rb') as info:
        body = info.read(4097)
    if len(body) > 4096:
        raise ValueError('cache_mount_identity_unavailable')
    matches = re.findall(rb'^mnt_id:\s*(\d+)$', body, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('cache_mount_identity_unavailable')
    return int(matches[0])


@contextmanager
def _open_root(root):
    """Keep every ancestor open and verify names still refer to those FDs."""
    descriptors = []
    names = root.split('/')[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptors.append(os.open('/', flags))
        for name in names:
            if not _trusted_directory(os.fstat(descriptors[-1])):
                raise ValueError('unsafe_cache_path')
            descriptors.append(os.open(name, flags, dir_fd=descriptors[-1]))
        if not _trusted_directory(os.fstat(descriptors[-1])):
            raise ValueError('unsafe_cache_path')
        yield descriptors[-1]
        for index, name in enumerate(names):
            named = os.stat(name, dir_fd=descriptors[index], follow_symlinks=False)
            held = os.fstat(descriptors[index + 1])
            if not _trusted_directory(held) or not _trusted_directory(os.fstat(descriptors[index])):
                raise ValueError('unsafe_cache_path')
            if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                raise ValueError('cache_changed')
    except OSError as error:
        raise ValueError('unsafe_cache_path') from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _scan_candidates(limits: DiskLimits, *, now_ns: int) -> DiskMarker:
    """Scan only; the caller must separately establish the writer boundary."""
    if type(now_ns) is not int or now_ns < 0:
        raise ValueError('invalid_clock')
    entries = []
    directory_bindings = {}
    encoded_bytes = 512
    scanned = logical_bytes = 0
    cutoff = now_ns - limits.min_age_seconds * 1_000_000_000
    with _open_root(limits.root) as root_fd:
        root_info = os.fstat(root_fd)
        root_mount = _mount_id(root_fd)
        initial = os.fstatvfs(root_fd)

        def walk(fd, prefix, depth):
            nonlocal scanned, logical_bytes, encoded_bytes
            before = os.fstat(fd)
            if before.st_dev != root_info.st_dev or _mount_id(fd) != root_mount:
                raise ValueError('cache_mount_boundary')
            if not _trusted_directory(before):
                raise ValueError('unsafe_cache_entry')
            if depth > MAX_SCAN_DEPTH:
                raise ValueError('preparation_budget_exceeded')
            directory_bindings[prefix] = _directory_signature(before)
            with os.scandir(fd) as directory:
                for item in directory:
                    scanned += 1
                    if scanned > MAX_SCAN_ENTRIES:
                        raise ValueError('preparation_budget_exceeded')
                    relative = prefix + item.name
                    current = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                    if current.st_dev != root_info.st_dev:
                        raise ValueError('cache_mount_boundary')
                    if stat.S_ISDIR(current.st_mode):
                        child = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            if _directory_signature(os.fstat(child)) != _directory_signature(current):
                                raise ValueError('cache_changed')
                            walk(child, relative + '/', depth + 1)
                            if _directory_signature(os.stat(item.name, dir_fd=fd, follow_symlinks=False)) != _directory_signature(current):
                                raise ValueError('cache_changed')
                        finally:
                            os.close(child)
                    else:
                        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                                or current.st_uid != 0 or current.st_mode & 0o022):
                            raise ValueError('unsafe_cache_entry')
                        candidate_fd = os.open(item.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            if _mount_id(candidate_fd) != root_mount:
                                raise ValueError('cache_mount_boundary')
                            held = os.fstat(candidate_fd)
                            if (held.st_dev, held.st_ino, held.st_ctime_ns) != (current.st_dev, current.st_ino, current.st_ctime_ns):
                                raise ValueError('cache_changed')
                        finally:
                            os.close(candidate_fd)
                        if current.st_mtime_ns > cutoff:
                            continue
                        entry = DiskEntry(relative, current.st_dev, current.st_ino,
                                          current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                        logical_bytes += current.st_size
                        encoded_bytes += len(json.dumps(asdict(entry), ensure_ascii=True).encode('ascii')) + 1
                        if (len(entries) >= limits.max_files or logical_bytes > limits.max_bytes
                                or encoded_bytes > MAX_MARKER_BYTES):
                            raise ValueError('preparation_budget_exceeded')
                        entries.append(entry)
            if _directory_signature(before) != _directory_signature(os.fstat(fd)):
                raise ValueError('cache_changed')

        try:
            walk(root_fd, '', 0)
            def check_directory(fd, prefix):
                current = os.fstat(fd)
                if not _trusted_directory(current):
                    raise ValueError('unsafe_cache_entry')
                if current.st_dev != root_info.st_dev or _mount_id(fd) != root_mount:
                    raise ValueError('cache_mount_boundary')
                if _directory_signature(current) != directory_bindings.get(prefix):
                    raise ValueError('cache_changed')

            # A second bounded FD walk catches file modifications which do not
            # change directory metadata, and preserves the first pass's exact
            # directory trust/identity and mount boundary at every component.
            for entry in entries:
                parts = entry.relative_path.split('/')
                parent = os.dup(root_fd)
                prefix = ''
                try:
                    check_directory(parent, prefix)
                    for part in parts[:-1]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        os.close(parent)
                        parent = child
                        prefix += part + '/'
                        check_directory(parent, prefix)
                    candidate_fd = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    try:
                        if _mount_id(candidate_fd) != root_mount:
                            raise ValueError('cache_mount_boundary')
                        if not entry_unchanged(entry, os.fstat(candidate_fd)):
                            raise ValueError('cache_changed')
                    finally:
                        os.close(candidate_fd)
                finally:
                    os.close(parent)
            check_directory(root_fd, '')
        except OSError as error:
            raise ValueError('cache_changed') from error
        marker = DiskMarker(root_info.st_dev, root_info.st_ino,
                            tuple(sorted(entries, key=lambda entry: entry.relative_path)), None,
                            initial.f_bavail * initial.f_frsize, initial.f_favail)
    return marker


_WRITER_REQUIRED = {
    'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead',
    'MainPID': '0', 'ControlPID': '0', 'KillMode': 'control-group',
    'Delegate': 'no', 'Restart': 'no', 'TriggeredBy': '', 'WantedBy': '',
    'RequiredBy': '', 'UpheldBy': '', 'BoundBy': '', 'ConsistsOf': '',
    'OnFailureOf': '', 'OnSuccessOf': '',
    'DynamicUser': 'no', 'RemainAfterExit': 'no', 'SendSIGKILL': 'yes', 'Job': '',
}
_WRITER_PROPERTIES = (*_WRITER_REQUIRED, 'Id', 'ControlGroup', 'UnitFileState',
                      'FragmentPath', 'DropInPaths', 'User')
_MAX_WRITER_OUTPUT = 16384


def _systemctl_show(unit: str) -> str:
    """Fixed diagnostic command with no inherited bus/environment overrides."""
    async def read():
        process = await asyncio.create_subprocess_exec(
            '/usr/bin/systemctl', 'show', unit, '--no-pager',
            '--property=' + ','.join(_WRITER_PROPERTIES),
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        )
        async def bounded(stream):
            body = await stream.read(_MAX_WRITER_OUTPUT + 1)
            if len(body) > _MAX_WRITER_OUTPUT:
                raise ValueError('writer_boundary_unproven')
            # read(n) may return a short chunk before EOF.
            while True:
                chunk = await stream.read(_MAX_WRITER_OUTPUT + 1 - len(body))
                if not chunk:
                    return body
                body += chunk
                if len(body) > _MAX_WRITER_OUTPUT:
                    raise ValueError('writer_boundary_unproven')
        tasks = [asyncio.create_task(bounded(process.stdout)),
                 asyncio.create_task(bounded(process.stderr)),
                 asyncio.create_task(process.wait())]
        try:
            stdout, _stderr, code = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
            if code != 0:
                raise ValueError('writer_boundary_unproven')
            return stdout.decode('utf-8', errors='strict')
        finally:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    try:
        return asyncio.run(read())
    except (OSError, ValueError, asyncio.TimeoutError) as error:
        raise ValueError('writer_boundary_unproven') from error


def _protected_file_signature(path):
    if not _PATH.fullmatch(path) or any(part in ('.', '..') for part in path.split('/')):
        raise ValueError('writer_boundary_unproven')
    parent, _, name = path.rpartition('/')
    with _open_root(parent) as fd:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(file_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError('writer_boundary_unproven')
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        finally:
            os.close(file_fd)


def _writer_snapshot(unit):
    try:
        output = _systemctl_show(unit)
        if len(output.encode('utf-8')) > _MAX_WRITER_OUTPUT:
            raise ValueError('writer_boundary_unproven')
        values = {}
        for line in output.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key in values or key not in _WRITER_PROPERTIES:
                raise ValueError('writer_boundary_unproven')
            values[key] = value
        if (set(values) != set(_WRITER_PROPERTIES)
                or any(values[key] != value for key, value in _WRITER_REQUIRED.items())
                or values['Id'] != unit or values['User'] not in ('', 'root')
                or values['UnitFileState'] not in ('disabled', 'static')
                or not values['FragmentPath']):
            raise ValueError('writer_boundary_unproven')
        # Reject delegated/user writers and every reported activation/dependency
        # route. These v1 bounds deliberately exclude enabled and socket units.
        signatures = [_protected_file_signature(path) for path in
                      (values['FragmentPath'], *values['DropInPaths'].split())]
        group = values['ControlGroup']
        if group:
            if not _PATH.fullmatch(group) or any(p in ('.', '..') for p in group.split('/')):
                raise ValueError('writer_boundary_unproven')
            with _open_root('/sys/fs/cgroup' + group) as fd:
                events_fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    body = os.read(events_fd, 4097)
                finally:
                    os.close(events_fd)
            if len(body) > 4096 or re.findall(rb'^populated (\d+)$', body, re.MULTILINE) != [b'0']:
                raise ValueError('writer_boundary_unproven')
        return (tuple(sorted(values.items())), tuple(signatures))
    except (OSError, ValueError) as error:
        raise ValueError('writer_boundary_unproven') from error


def prepare_cleanup(limits: DiskLimits, *, now_ns: int) -> DiskMarker:
    """Observe an already stopped administrator writer and freeze candidates.

    This neither stops nor authorizes a writer. The absence of a stop marker is
    intentional: a later capability must attach independently authenticated
    history before relying on compensating restoration. Async callers must run
    this synchronous diagnostic in a worker thread.
    """
    before = _writer_snapshot(limits.writer_unit)
    marker = _scan_candidates(limits, now_ns=now_ns)
    if before != _writer_snapshot(limits.writer_unit):
        raise ValueError('writer_boundary_unproven')
    return marker

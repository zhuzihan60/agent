"""Read-only cache candidate checks; no writer-stop or cleanup acceptance."""
import os
import asyncio
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

import pytest


def test_replaced_candidate_is_not_accepted(tmp_path):
    from a4diag_target.repair_disk import DiskEntry, entry_unchanged
    p = tmp_path / 'cache'
    p.write_bytes(b'old')
    st = p.stat()
    saved = DiskEntry(relative_path='cache', dev=st.st_dev, ino=st.st_ino,
        size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)
    p.rename(tmp_path / 'kept-old')
    p.write_bytes(b'new')
    assert not entry_unchanged(saved, p.stat())


@pytest.fixture
def cache_root():
    # The isolated Linux runner copies the repository below protected /opt.
    # Unlike /tmp, every parent here is administrator-owned and not writable
    # by another account. This fixture proves scanning only, never writer stop.
    if sys.platform != 'linux' or os.geteuid() != 0:
        pytest.fail('cache_root requires Linux root in a protected test path')
    parent = Path.cwd().parent.resolve()
    for ancestor in (parent, *parent.parents):
        stat = ancestor.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o022:
            pytest.fail('cache_root requires root-owned non-writable ancestry')
    root = Path(tempfile.mkdtemp(prefix='.disk-candidates-', dir=parent))
    try:
        yield root
    finally:
        shutil.rmtree(root)


def limits(root, **changes):
    from a4diag_target.repair_disk import DiskLimits
    values = dict(root=str(root), min_age_seconds=60, max_files=10,
                  max_bytes=1000, min_free_bytes=0, min_free_inodes=0,
                  writer_unit='cache-worker.service')
    return DiskLimits(**(values | changes))


def old_file(path, body=b'old'):
    path.write_bytes(body)
    stamp = time.time_ns() - 120_000_000_000
    os.utime(path, ns=(stamp, stamp))


def scan(root, **changes):
    from a4diag_target.repair_disk import _scan_candidates
    return _scan_candidates(limits(root, **changes), now_ns=time.time_ns())


def test_scan_freezes_old_regular_candidates_without_changing_files(cache_root):
    nested = cache_root / 'nested'
    nested.mkdir()
    old_file(nested / 'old', b'abc')
    (cache_root / 'new').write_bytes(b'new')
    marker = scan(cache_root)
    assert [entry.relative_path for entry in marker.entries] == ['nested/old']
    assert marker.entries[0].size == 3
    assert (nested / 'old').read_bytes() == b'abc'
    assert marker.root_ino == cache_root.stat().st_ino
    assert marker.root_dev == cache_root.stat().st_dev
    assert marker.initial_free_bytes > 0
    assert marker.initial_free_inodes > 0
    assert marker.writer_stop_marker is None


@pytest.mark.parametrize('kind', ['fifo', 'hardlink', 'symlink', 'writable', 'foreign_owner'])
def test_scan_rejects_unbounded_or_untrusted_entries(cache_root, kind):
    path = cache_root / 'entry'
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'symlink':
        path.symlink_to('/etc/passwd')
    else:
        old_file(path)
        if kind == 'hardlink':
            os.link(path, cache_root / 'alias')
        elif kind == 'writable':
            path.chmod(0o666)
        else:
            os.chown(path, 12345, 12345)
    with pytest.raises(ValueError, match='unsafe_cache_entry'):
        scan(cache_root)


def test_parent_symlink_cannot_redirect_scan(cache_root):
    (cache_root / 'real').mkdir()
    (cache_root / 'alias').symlink_to(cache_root / 'real', target_is_directory=True)
    with pytest.raises(ValueError, match='unsafe_cache_path'):
        scan(cache_root / 'alias')


@pytest.mark.parametrize('root', ['/', '/etc', '/var', '/var/cache', '/proc/x', '/x/../y', 'relative', '/' + '/'.join(['a'] * 65)])
def test_unsafe_roots_are_rejected(root):
    with pytest.raises(ValueError, match='invalid_cache_root'):
        limits(root)


@pytest.mark.parametrize('unit', ['ssh.service', 'a4diag-target.service', '-bad.service', 'x;id.service', 'x.socket', '../x.service'])
def test_dangerous_or_nonservice_writers_are_rejected(cache_root, unit):
    with pytest.raises(ValueError, match='invalid_writer_unit'):
        limits(cache_root, writer_unit=unit)


@pytest.mark.parametrize('budget', ['files', 'bytes', 'depth', 'scan', 'output'])
def test_scan_fails_at_budget_without_truncating_candidates(cache_root, monkeypatch, budget):
    from a4diag_target import repair_disk
    changes = {}
    if budget == 'depth':
        monkeypatch.setattr(repair_disk, 'MAX_SCAN_DEPTH', 1)
        (cache_root / 'a').mkdir()
        (cache_root / 'a' / 'b').mkdir()
    elif budget == 'scan':
        monkeypatch.setattr(repair_disk, 'MAX_SCAN_ENTRIES', 1)
        (cache_root / 'one').write_bytes(b'new')
        (cache_root / 'two').write_bytes(b'new')
    elif budget == 'output':
        monkeypatch.setattr(repair_disk, 'MAX_MARKER_BYTES', 128)
        old_file(cache_root / ('x' * 200))
    else:
        old_file(cache_root / 'one', b'ab')
        old_file(cache_root / 'two', b'cd')
        changes = {'max_files': 1} if budget == 'files' else {'max_bytes': 3}
    with pytest.raises(ValueError, match='preparation_budget_exceeded'):
        scan(cache_root, **changes)


def test_root_replacement_during_scan_is_rejected(cache_root, monkeypatch):
    from a4diag_target import repair_disk
    old_file(cache_root / 'old')
    original = repair_disk.os.scandir
    moved = cache_root.with_name(cache_root.name + '-moved')
    def replace(fd):
        cache_root.rename(moved)
        cache_root.mkdir()
        return original(fd)
    monkeypatch.setattr(repair_disk.os, 'scandir', replace)
    try:
        with pytest.raises(ValueError, match='cache_changed'):
            scan(cache_root)
    finally:
        monkeypatch.setattr(repair_disk.os, 'scandir', original)
        if moved.exists():
            shutil.rmtree(moved)


@pytest.mark.parametrize('kind', ['tmpfs', 'same_device_bind'])
def test_scan_refuses_actual_mount_boundary(cache_root, kind):
    destination = cache_root / 'mounted'
    destination.mkdir()
    if kind == 'tmpfs':
        command = ['/usr/bin/mount', '-t', 'tmpfs', '-o', 'size=1m', 'tmpfs', str(destination)]
    else:
        source = cache_root / 'source'
        source.mkdir()
        old_file(source / 'old')
        command = ['/usr/bin/mount', '--bind', str(source), str(destination)]
    subprocess.run(command, check=True, capture_output=True)
    try:
        with pytest.raises(ValueError, match='cache_mount_boundary'):
            scan(cache_root)
    finally:
        subprocess.run(['/usr/bin/umount', str(destination)], check=True, capture_output=True)


def test_changed_file_after_scan_is_rejected(cache_root, monkeypatch):
    from a4diag_target import repair_disk
    old_file(cache_root / 'one')
    original = repair_disk.os.scandir
    class ChangeAfterScan:
        def __init__(self, fd):
            self.iterator = original(fd)
        def __enter__(self):
            return self.iterator.__enter__()
        def __exit__(self, *args):
            self.iterator.__exit__(*args)
            (cache_root / 'one').write_bytes(b'replaced-content')
    monkeypatch.setattr(repair_disk.os, 'scandir', ChangeAfterScan)
    with pytest.raises(ValueError, match='cache_changed'):
        scan(cache_root)


def test_parent_becoming_writable_during_scan_is_rejected(cache_root, monkeypatch):
    from a4diag_target import repair_disk
    nested = cache_root / 'nested'
    nested.mkdir()
    old_file(nested / 'one')
    original = repair_disk.os.scandir
    def make_parent_writable(fd):
        cache_root.chmod(0o777)
        return original(fd)
    monkeypatch.setattr(repair_disk.os, 'scandir', make_parent_writable)
    with pytest.raises(ValueError, match='unsafe_cache_path'):
        scan(nested)


def writer_output(cache_root, **changes):
    unit_file = cache_root / 'cache-worker.service'
    if not unit_file.exists():
        unit_file.write_text('[Service]\nExecStart=/usr/bin/true\n')
    values = dict(Id='cache-worker.service', LoadState='loaded', ActiveState='inactive',
                  SubState='dead', MainPID='0', ControlPID='0', ControlGroup='',
                  KillMode='control-group', Delegate='no', Restart='no',
                  TriggeredBy='', WantedBy='', RequiredBy='', UpheldBy='', BoundBy='',
                  ConsistsOf='', OnFailureOf='', OnSuccessOf='',
                  UnitFileState='disabled', FragmentPath=str(unit_file),
                  DropInPaths='', User='root', DynamicUser='no', RemainAfterExit='no',
                  SendSIGKILL='yes', Job='')
    values.update(changes)
    return ''.join(f'{key}={value}\n' for key, value in values.items())


def test_prepare_already_stopped_writer_never_invents_stop_history(cache_root, monkeypatch):
    from a4diag_target import repair_disk
    output = writer_output(cache_root)
    monkeypatch.setattr(repair_disk, '_systemctl_show', lambda unit: output)
    old_file(cache_root / 'old')
    marker = repair_disk.prepare_cleanup(limits(cache_root), now_ns=time.time_ns())
    assert [entry.relative_path for entry in marker.entries] == ['old']
    assert marker.writer_stop_marker is None
    assert (cache_root / 'old').read_bytes() == b'old'


@pytest.mark.parametrize('changes', [
    {'ActiveState': 'active'}, {'SubState': 'running'}, {'MainPID': '22'},
    {'ControlPID': '23'}, {'Restart': 'always'}, {'TriggeredBy': 'cache.socket'},
    {'WantedBy': 'other.service'}, {'RequiredBy': 'other.service'},
    {'UpheldBy': 'other.service'}, {'BoundBy': 'other.service'},
    {'ConsistsOf': 'other.service'}, {'UnitFileState': 'enabled'},
    {'KillMode': 'process'}, {'Delegate': 'yes'}, {'User': 'app'},
    {'DynamicUser': 'yes'}, {'RemainAfterExit': 'yes'}, {'SendSIGKILL': 'no'},
    {'Job': '42'}, {'Id': 'different.service'}, {'LoadState': 'not-found'},
    {'ControlGroup': '/system.slice/missing-test-group'},
])
def test_unproven_writer_boundary_refuses_preparation(cache_root, monkeypatch, changes):
    from a4diag_target import repair_disk
    monkeypatch.setattr(repair_disk, '_systemctl_show', lambda unit: writer_output(cache_root, **changes))
    with pytest.raises(ValueError, match='writer_boundary_unproven'):
        repair_disk.prepare_cleanup(limits(cache_root), now_ns=time.time_ns())


def test_writer_change_between_snapshots_refuses_marker(cache_root, monkeypatch):
    from a4diag_target import repair_disk
    snapshots = iter([writer_output(cache_root), writer_output(cache_root, ActiveState='active')])
    monkeypatch.setattr(repair_disk, '_systemctl_show', lambda unit: next(snapshots))
    with pytest.raises(ValueError, match='writer_boundary_unproven'):
        repair_disk.prepare_cleanup(limits(cache_root), now_ns=time.time_ns())


@pytest.mark.parametrize('damage', ['missing', 'duplicate', 'overflow', 'writable_fragment'])
def test_incomplete_or_untrusted_writer_diagnostics_fail_closed(cache_root, monkeypatch, damage):
    from a4diag_target import repair_disk
    output = writer_output(cache_root)
    if damage == 'missing':
        output = output.replace('Delegate=no\n', '')
    elif damage == 'duplicate':
        output += 'Delegate=no\n'
    elif damage == 'overflow':
        output += 'X=' + 'x' * 16385
    else:
        (cache_root / 'cache-worker.service').chmod(0o666)
    monkeypatch.setattr(repair_disk, '_systemctl_show', lambda unit: output)
    with pytest.raises(ValueError, match='writer_boundary_unproven'):
        repair_disk.prepare_cleanup(limits(cache_root), now_ns=time.time_ns())


def test_real_systemd_empty_job_format_is_supported(cache_root, monkeypatch):
    from a4diag_target import repair_disk
    output = writer_output(cache_root, Job='')
    monkeypatch.setattr(repair_disk, '_systemctl_show', lambda unit: output)
    marker = repair_disk.prepare_cleanup(limits(cache_root), now_ns=time.time_ns())
    assert marker.writer_stop_marker is None


@pytest.mark.parametrize('script', [
    'import sys; sys.stdout.write("x" * 20000)',
    'import sys; sys.stderr.write("x" * 20000)',
    'raise SystemExit(2)',
    'import time; time.sleep(20)',
])
def test_fixed_diagnostic_process_bounds_are_enforced(monkeypatch, script):
    from a4diag_target import repair_disk
    original = asyncio.create_subprocess_exec
    async def process(*argv, **kwargs):
        assert argv[:4] == ('/usr/bin/systemctl', 'show', 'cache-worker.service', '--no-pager')
        assert len(argv) == 5 and argv[4].startswith('--property=')
        assert kwargs['env'] == {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
        return await original(sys.executable, '-c', script, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', process)
    with pytest.raises(ValueError, match='writer_boundary_unproven'):
        repair_disk._systemctl_show('cache-worker.service')


@pytest.mark.parametrize('property_name', ['OnFailureOf', 'OnSuccessOf'])
@pytest.mark.parametrize('state', ['activation_route', 'unsupported'])
def test_reverse_outcome_activation_must_be_queried_and_excluded(cache_root, monkeypatch, property_name, state):
    from a4diag_target import repair_disk
    output = writer_output(cache_root, **{property_name: 'other.service'})
    if state == 'unsupported':
        output = output.replace(f'{property_name}=other.service\n', '')
    original = asyncio.create_subprocess_exec
    async def process(*argv, **kwargs):
        # A real systemctl show only returns requested, supported properties.
        # Simulating that boundary exposes an omitted query, not just a parser.
        requested = set(argv[-1].removeprefix('--property=').split(','))
        selected = ''.join(line + '\n' for line in output.splitlines()
                           if line.partition('=')[0] in requested)
        return await original(sys.executable, '-c',
                              'import sys; sys.stdout.write(sys.argv[1])', selected, **kwargs)
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', process)
    with pytest.raises(ValueError, match='writer_boundary_unproven'):
        repair_disk.prepare_cleanup(limits(cache_root), now_ns=time.time_ns())


@pytest.mark.parametrize('change', ['writable_directory', 'directory_bind_mount', 'file_bind_mount'])
def test_final_traversal_rejects_changed_trust_or_mount(cache_root, monkeypatch, change):
    from a4diag_target import repair_disk
    nested = cache_root / 'nested'
    nested.mkdir()
    old_file(nested / 'old')
    root_identity = (cache_root.stat().st_dev, cache_root.stat().st_ino)
    original = os.scandir
    mounted = []
    class ChangeAfterRootScan:
        def __init__(self, fd):
            self.fd = fd
            self.iterator = original(fd)
        def __enter__(self):
            return self.iterator.__enter__()
        def __exit__(self, *args):
            self.iterator.__exit__(*args)
            info = os.fstat(self.fd)
            if (info.st_dev, info.st_ino) != root_identity:
                return
            if change == 'writable_directory':
                nested.chmod(0o777)
            else:
                target = nested if change == 'directory_bind_mount' else nested / 'old'
                # Binding a path onto itself preserves dev/ino and all saved
                # file metadata while changing its mount identity.
                subprocess.run(['/usr/bin/mount', '--bind', str(target), str(target)],
                               check=True, capture_output=True)
                mounted.append(target)
    monkeypatch.setattr(repair_disk.os, 'scandir', ChangeAfterRootScan)
    try:
        expected = 'unsafe_cache_entry' if change == 'writable_directory' else 'cache_mount_boundary'
        with pytest.raises(ValueError, match=expected):
            scan(cache_root)
    finally:
        monkeypatch.setattr(repair_disk.os, 'scandir', original)
        for target in reversed(mounted):
            subprocess.run(['/usr/bin/umount', str(target)], check=True, capture_output=True)


@pytest.mark.parametrize('change', ['size', 'mtime', 'hardlink', 'fifo'])
def test_candidate_metadata_and_type_must_remain_bound(tmp_path, change):
    from a4diag_target.repair_disk import DiskEntry, entry_unchanged
    p = tmp_path / 'cache'
    p.write_bytes(b'old')
    st = p.stat()
    saved = DiskEntry(relative_path='cache', dev=st.st_dev, ino=st.st_ino,
        size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)
    assert entry_unchanged(saved, st)
    if change == 'size':
        p.write_bytes(b'changed')
    elif change == 'mtime':
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns - 1))
    elif change == 'hardlink':
        os.link(p, tmp_path / 'alias')
    else:
        p.unlink()
        os.mkfifo(p)
    assert not entry_unchanged(saved, p.stat())

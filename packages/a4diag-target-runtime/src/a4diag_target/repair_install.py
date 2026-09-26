"""Closed repair adapter registry and protected installation bindings.

New adapters are code registrations, never module names from configuration.
The sandbox callback and plugin factory must describe the same exact profile.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import sqlite3
import tempfile
from typing import Callable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from a4diag.repair_profiles import RepairProfile
from a4diag.builtin_catalog import REPAIR_ADAPTER_IDS

CONFIG_ROOT = Path('/etc/a4diag-target/repair-helpers')
STATE_ROOT = Path('/var/lib/a4diag-target/repair-helpers')
ROUTES_PATH = Path('/etc/a4diag-target/repair-routes.json')
SAFE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
SAFE_PATH = re.compile(r'/(?:[A-Za-z0-9._+@:-]+/)*[A-Za-z0-9._+@:-]+')
MAX_CONFIG_BYTES = 262144


def safe_id(value: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise ValueError('invalid_helper_id')
    return value


def exact_path(value: str) -> str:
    if not SAFE_PATH.fullmatch(value) or any(p in ('.', '..') for p in value.split('/')):
        raise ValueError('invalid_sandbox_path')
    return value


def protected_json(path: Path):
    """Bounded root-owned regular file; reject symlinks throughout its path."""
    path = Path(path)
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected_helper_configuration')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected_helper_configuration')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            body = handle.read(MAX_CONFIG_BYTES + 1)
        if len(body) > MAX_CONFIG_BYTES:
            raise ValueError('helper_configuration_too_large')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('duplicate_helper_configuration_key')
                value[key] = item
            return value
        return json.loads(body, object_pairs_hook=unique)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Sandbox:
    write_paths: tuple[str, ...] = ()
    socket_paths: tuple[str, ...] = ()
    run_uid: int = 0

    def __post_init__(self):
        if type(self.run_uid) is not int or self.run_uid < 0:
            raise ValueError('invalid_helper_uid')
        for path in (*self.write_paths, *self.socket_paths):
            exact_path(path)


@dataclass(frozen=True)
class AdapterSpec:
    capability: str
    sandbox: Callable[[RepairProfile], Sandbox]
    plugin: Callable[[RepairProfile], object]


def _disk_plugin(profile):
    from a4diag_target.disk_plugin import DiskPlugin
    return DiskPlugin(profile)


def _container_plugin(profile):
    from a4diag_target.repair_containers import ContainerPlugin
    return ContainerPlugin(profile)


def _kubernetes_plugin(profile):
    from a4diag_target.repair_kubernetes import KubernetesPlugin
    return KubernetesPlugin(profile)


def _container_sandbox(profile, runtime):
    from a4diag_target.repair_containers import profile_identity, runtime_socket
    if profile_identity(profile).runtime != runtime:
        raise ValueError('runtime_adapter_mismatch')
    # Trusted orchestration remains root-private. Podman API child drops to the
    # registered owner before connecting; it cannot read policy/key/job stores.
    return Sandbox(socket_paths=(runtime_socket(profile),))


ADAPTERS: dict[str, AdapterSpec] = {
    'kubernetes': AdapterSpec('kubernetes', lambda p: Sandbox(), _kubernetes_plugin),
    'disk-cache': AdapterSpec('disk', lambda p: Sandbox(write_paths=(p.resource,)), _disk_plugin),
    'docker': AdapterSpec('containers', lambda p: _container_sandbox(p, 'docker'), _container_plugin),
    'podman': AdapterSpec('containers', lambda p: _container_sandbox(p, 'podman'), _container_plugin),
}
if set(ADAPTERS) != set(REPAIR_ADAPTER_IDS):
    raise RuntimeError('repair_adapter_catalog_mismatch')


class SocketAttestation(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    device: int = Field(ge=0, strict=True)
    inode: int = Field(gt=0, strict=True)
    owner_uid: int = Field(ge=0, strict=True)


def attest_runtime_socket(path, owner_uid):
    from a4diag_target.repair_docker import socket_identity
    device, inode = socket_identity(Path(path), owner_uid)
    return SocketAttestation(device=device, inode=inode, owner_uid=owner_uid)


class HelperBinding(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    adapter: str
    profile: RepairProfile
    peer_uid: int = Field(ge=0, strict=True)
    socket_attestation: SocketAttestation | None = None

    @field_validator('adapter')
    @classmethod
    def adapter_name(cls, value):
        return safe_id(value)

    @property
    def id(self):
        return self.profile.id

    @property
    def state(self):
        return STATE_ROOT / self.id

    @property
    def socket(self):
        return f'/run/a4diag-target/repair-{self.id}.sock'

    def spec(self):
        spec = ADAPTERS.get(self.adapter)
        if spec is None:
            raise ValueError('adapter_not_registered')
        if spec.capability != self.profile.capability:
            raise ValueError('adapter_capability_mismatch')
        return spec


def load_binding(helper_id: str) -> HelperBinding:
    binding = HelperBinding.model_validate(protected_json(CONFIG_ROOT / f'{safe_id(helper_id)}.json'))
    if binding.id != helper_id:
        raise ValueError('helper_binding_mismatch')
    binding.spec()
    return binding


def helper_route(profile_id: str, *, routes_path: Path = ROUTES_PATH) -> str | None:
    """Registration is distinct from routing; inconsistent scope never falls back."""
    profile_id = safe_id(profile_id)
    try:
        try:
            routes = protected_json(routes_path)
        except FileNotFoundError:
            routes = {}
        if type(routes) is not dict:
            raise ValueError('invalid_routes')
        for registered, path in routes.items():
            if path != f'/run/a4diag-target/repair-{safe_id(registered)}.sock':
                raise ValueError('invalid_route')
        config = CONFIG_ROOT / f'{profile_id}.json'
        try:
            info = config.lstat()
        except FileNotFoundError:
            if profile_id in routes:
                raise ValueError('helper_binding_missing')
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected_helper_configuration')
        if profile_id not in routes:
            raise ValueError('helper_route_missing')
        return routes[profile_id]
    except (OSError, ValueError, TypeError) as error:
        raise ValueError('repair_route_unavailable') from error


def plan_helpers(profiles, selections, *, peer_uid: int) -> tuple[HelperBinding, ...]:
    profiles = tuple(RepairProfile.model_validate(p) for p in profiles)
    by_id = {p.id: p for p in profiles}
    if len(by_id) != len(profiles):
        raise ValueError('duplicate_profile_id')
    bindings = []
    seen_resources = set()
    seen_ids = set()
    for selection in selections:
        if type(selection) is not dict or set(selection) != {'profile_id', 'adapter'}:
            raise ValueError('invalid_helper_selection')
        if selection['adapter'] not in ADAPTERS:
            raise ValueError('adapter_not_registered')
        profile = by_id.get(selection['profile_id'])
        if profile is None:
            raise ValueError('helper_profile_missing')
        if profile.capability == 'containers' and profile.constraints.service_unit is not None:
            service=by_id.get(profile.constraints.service_profile_id)
            if service is None or service.capability != 'services' or service.resource != profile.constraints.service_unit or not set(profile.actions) <= set(service.actions):
                raise ValueError('registered_service_route_required')
        if profile.id in seen_ids or profile.resource in seen_resources:
            raise ValueError('duplicate_helper_scope')
        if profile.capability == 'disk' and not any(
            p.capability == 'services' and p.resource == profile.constraints.writer_unit
            and 'stop' in p.actions for p in profiles
        ):
            raise ValueError('disk_writer_stop_profile_required')
        binding = HelperBinding(adapter=selection['adapter'], profile=profile, peer_uid=peer_uid)
        if binding.spec().sandbox(profile).run_uid != 0:
            # C2 must add protected per-UID policy/store access before enabling
            # rootless adapters. Never silently run a rootless profile as root.
            raise ValueError('rootless_helper_not_wired')
        bindings.append(binding)
        seen_ids.add(profile.id)
        seen_resources.add(profile.resource)
    for profile in profiles:
        if profile.id not in seen_ids:
            if profile.capability != 'services':
                raise ValueError('repair_profile_helper_required')
            if profile.resource in seen_resources:
                raise ValueError('duplicate_helper_scope')
    return tuple(bindings)


def sandbox_properties(binding: HelperBinding, *, worker: bool = True) -> tuple[str, ...]:
    scope = binding.spec().sandbox(binding.profile)
    socket_binds = tuple('BindReadOnlyPaths=' + path for path in scope.socket_paths if worker)
    if binding.adapter == 'podman':
        from a4diag_target.repair_containers import profile_identity
        uid = profile_identity(binding.profile).owner_uid
        # ProtectHome hides /run/user. Bind ONLY the registered API socket to a
        # fixed private alias, never the user's runtime directory or manager bus.
        socket_binds = (f'BindReadOnlyPaths={scope.socket_paths[0]}:/run/a4diag-podman-{uid}.sock',)
    return (
        f'User={scope.run_uid if worker else 0}', f'Group={scope.run_uid if worker else 0}', 'Restart=no',
        'NoNewPrivileges=yes', 'PrivateTmp=yes', 'PrivateDevices=yes',
        'ProtectSystem=strict', 'ProtectHome=yes', 'ProtectKernelTunables=yes',
        'ProtectKernelModules=yes', 'ProtectKernelLogs=yes', 'ProtectControlGroups=yes',
        'RestrictRealtime=yes', 'LockPersonality=yes', 'MemoryDenyWriteExecute=yes',
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' if binding.adapter == 'kubernetes' else 'RestrictAddressFamilies=AF_UNIX',
        *(('IPAddressDeny=any', 'IPAddressAllow='+urlsplit(binding.profile.constraints.endpoint).hostname) if binding.adapter == 'kubernetes' else ()),
        'CapabilityBoundingSet=CAP_SETUID CAP_SETGID' if binding.adapter == 'podman' else 'CapabilityBoundingSet=',
        *(('AmbientCapabilities=CAP_SETUID CAP_SETGID',) if binding.adapter == 'podman' else ()),
        'ReadOnlyPaths=/etc/a4diag-target /opt/a4diag-target/current',
        'ReadWritePaths=' + ' '.join((str(binding.state), *scope.write_paths)),
        # Only the trusted dispatcher can reach the systemd manager. Workers
        # cannot reach private, system-bus, or rootless user-bus manager routes.
        *(('TemporaryFileSystem=/run:ro',) if worker else ()),
        *socket_binds,
        'MemoryMax=256M', 'TasksMax=32', 'LimitNOFILE=1024',
        'StandardOutput=null', 'StandardError=journal',
    )


def render_drop_in(binding: HelperBinding) -> str:
    return '[Service]\n' + '\n'.join(sandbox_properties(binding, worker=False)) + '\n'


def installation_plan(source: dict, *, peer_uid: int):
    profiles = source.get('repair_profiles', [])
    selections = source.get('repair_helpers', [])
    if (profiles or selections) and source.get('confirm_repair_helpers') != 'ENABLE':
        raise ValueError('repair_helpers_require_ENABLE')
    bindings = plan_helpers(profiles, selections, peer_uid=peer_uid)
    legacy_resources = {item['resource'] for item in source.get('managed_resources', [])}
    if any(binding.profile.resource in legacy_resources for binding in bindings):
        raise ValueError('duplicate_helper_scope')
    return bindings


def ensure_drained(root: Path):
    """Conservative installation gate: no automatic kill, resume, or unlock."""
    directory = root / 'var/lib/a4diag-target/repair-helpers'
    if directory.is_symlink():
        raise ValueError('unprotected_helper_state')
    scopes = list(directory.iterdir()) if directory.exists() else []
    ordinary = root / 'var/lib/a4diag-target/executor'
    if ordinary.exists():
        scopes.append(ordinary)
    for scope in scopes:
        if scope.is_symlink() or not scope.is_dir():
            raise ValueError('unprotected_helper_state')
        if (scope/'disk-reservation').exists():
            from a4diag_target.disk_reservation import control, _terminal_owner
            with control(scope) as (_,_,value):
                if value['owner'] is not None and not _terminal_owner(scope,value['owner'],ordinary/'repair-jobs.sqlite3'):
                    raise ValueError('disk_reservation_requires_drain')
        path = scope / 'repair-jobs.sqlite3'
        if path.is_symlink():
            raise ValueError('unprotected_helper_state')
        if path.exists():
            with sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True) as db:
                if db.execute("SELECT count(*) FROM repair_jobs WHERE state NOT IN ('succeeded', 'failed', 'partial', 'cancelled')").fetchone()[0]:
                    raise ValueError('repair_helpers_require_drain')
                if db.execute("SELECT 1 FROM repair_jobs WHERE state='partial' AND changed IS NULL AND json_extract(request,'$.operation.capability')='disk' LIMIT 1").fetchone():
                    raise ValueError('repair_helpers_require_drain')
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'writer_holds' in tables and db.execute('SELECT 1 FROM writer_holds WHERE restored=0 LIMIT 1').fetchone():
                    raise ValueError('repair_helpers_require_drain')


def install_helpers(source: dict, *, root: Path, peer_uid: int):
    """Install exact scope artifacts; caller owns the surrounding transaction."""
    bindings = installation_plan(source, peer_uid=peer_uid)
    ensure_drained(root)
    registered = []
    for binding in bindings:
        if binding.adapter == 'podman':
            from a4diag_target.repair_containers import profile_identity, runtime_socket
            identity = profile_identity(binding.profile)
            attestation = attest_runtime_socket(root / runtime_socket(binding.profile).lstrip('/'), identity.owner_uid)
            binding = binding.model_copy(update={'socket_attestation':attestation})
        registered.append(binding)
    bindings = tuple(registered)
    etc = root / 'etc/a4diag-target/repair-helpers'
    units = root / 'etc/systemd/system'
    states = root / 'var/lib/a4diag-target/repair-helpers'
    etc.mkdir(parents=True, exist_ok=True)
    states.mkdir(parents=True, exist_ok=True, mode=0o700)
    if states.is_symlink() or states.stat().st_mode & 0o077:
        raise ValueError('unprotected_helper_state')
    old_ids = set()
    for path in etc.glob('*.json'):
        old_ids.add(safe_id(path.stem))
    selected = {binding.id for binding in bindings}
    for helper_id in old_ids - selected:
        if root.resolve() == Path('/'):
            import subprocess
            subprocess.run(['/usr/bin/systemctl', 'disable',
                f'a4diag-repair-helper@{helper_id}.socket'],
                check=True, capture_output=True, timeout=15)
        (etc / f'{helper_id}.json').unlink()
        (units / f'a4diag-repair-helper@{helper_id}.service.d/scope.conf').unlink(missing_ok=True)
    for binding in bindings:
        scope = states / binding.id
        if scope.is_symlink():
            raise ValueError('unprotected_helper_state')
        scope.mkdir(mode=0o700, exist_ok=True)
        if scope.stat().st_mode & 0o077 or scope.stat().st_uid != 0:
            raise ValueError('unprotected_helper_state')
        if binding.adapter == 'disk-cache':
            from a4diag_target.disk_reservation import provision
            provision(scope,binding.profile,service_database=root/'var/lib/a4diag-target/executor/repair-jobs.sqlite3')
        drop = units / f'a4diag-repair-helper@{binding.id}.service.d'
        drop.mkdir(parents=True, exist_ok=True)
        (drop / 'scope.conf').write_text(render_drop_in(binding))
        config = etc / f'{binding.id}.json'
        config.write_text(binding.model_dump_json() + '\n')
        config.chmod(0o600)
    routes = root / 'etc/a4diag-target/repair-routes.json'
    routes.write_text(json.dumps({b.id: b.socket for b in bindings}, sort_keys=True) + '\n')
    routes.chmod(0o644)
    summary = {'new_write_helpers_enabled': sorted(selected)}
    (root / 'etc/a4diag-target/repair-self-check.json').write_text(json.dumps(summary) + '\n')
    return summary


def _install_paths(root: Path, ids):
    paths = {
        'etc/a4diag-target/policy.json', 'etc/a4diag-target/operation-public.pem',
        'etc/a4diag-target/repair-routes.json', 'etc/a4diag-target/repair-self-check.json',
        'etc/systemd/system/a4diag-target-executor.service.d/managed-roots.conf',
        'var/lib/a4diag-target/.ssh/authorized_keys', 'usr/libexec/a4diag/a4diag-transport-helper',
    }
    for name in ('a4diag-target-executor.service', 'a4diag-target-executor.socket',
                 'a4diag-repair-helper@.service', 'a4diag-repair-helper@.socket'):
        paths.add('etc/systemd/system/' + name)
    for helper_id in ids:
        safe_id(helper_id)
        paths.add(f'etc/a4diag-target/repair-helpers/{helper_id}.json')
        paths.add(f'etc/systemd/system/a4diag-repair-helper@{helper_id}.service.d/scope.conf')
    for relative in paths:
        path = root / relative
        for ancestor in (path, *path.parents):
            if ancestor == root:
                break
            if ancestor.is_symlink():
                raise ValueError('symlink_install_artifact')
    return paths


def _atomic_file(path, body, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.repair-install-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(name).unlink(missing_ok=True)


def install_transaction(action, root: Path, source=None):
    """Recoverable file publication; stopped sockets prevent mixed admission."""
    journal = root / 'opt/a4diag-target/.repair-install-journal.json'
    current = root / 'opt/a4diag-target/current'
    if action == 'begin':
        if journal.exists():
            raise ValueError('installation_recovery_required')
        ids = {p.stem for p in (root/'etc/a4diag-target/repair-helpers').glob('*.json')}
        ids.update(p['profile_id'] for p in source.get('repair_helpers', []))
        files = {}
        for relative in _install_paths(root, ids):
            path = root / relative
            files[relative] = None
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('invalid_install_artifact')
                files[relative] = [path.read_bytes().hex(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid]
        if current.exists() and not current.is_symlink():
            raise ValueError('current_must_be_symlink')
        payload = {'ids': sorted(ids), 'files': files, 'current': os.readlink(current) if current.is_symlink() else None}
        _atomic_file(journal, json.dumps(payload).encode(), 0o600)
    elif action == 'rollback' and journal.exists():
        info = journal.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('unprotected_install_journal')
        payload = json.loads(journal.read_bytes())
        if set(payload['files']) != _install_paths(root, payload['ids']):
            raise ValueError('invalid_install_journal')
        managed_systemd = root.resolve() == Path('/') and (root/'etc/systemd/system/a4diag-repair-helper@.socket').exists()
        try:
            if managed_systemd:
                import subprocess
                for helper_id in payload['ids']:
                    subprocess.run(['/usr/bin/systemctl', 'stop',
                        f'a4diag-repair-helper@{helper_id}.socket',
                        f'a4diag-repair-helper@{helper_id}.service'],
                        check=True, capture_output=True, timeout=30)
            ensure_drained(root)
        except BaseException:
            # An accepted worker forbids restoring the journal's old binding.
            # Keep current artifacts and journal, but restore their observation
            # sockets even when this is a new process recovering interruption.
            if managed_systemd:
                for helper_id in payload['ids']:
                    if (root/f'etc/a4diag-target/repair-helpers/{helper_id}.json').is_file():
                        subprocess.run(['/usr/bin/systemctl', 'start',
                            f'a4diag-repair-helper@{helper_id}.socket'],
                            check=True, capture_output=True, timeout=30)
            raise
        for relative, saved in payload['files'].items():
            path = root / relative
            if saved is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_file(path, bytes.fromhex(saved[0]), saved[1])
                os.chown(path, saved[2], saved[3])
        old = payload['current']
        if current.is_symlink():
            current.unlink()
        if old is not None:
            current.symlink_to(old)
        journal.unlink()
    elif action == 'commit':
        journal.unlink()


def main():
    import argparse
    import pwd
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('check', 'install', 'drain', 'begin', 'rollback', 'commit'))
    parser.add_argument('root', type=Path)
    parser.add_argument('config', nargs='?', type=Path)
    args = parser.parse_args()
    if args.action in ('begin', 'rollback', 'commit'):
        install_transaction(args.action, args.root, json.loads(args.config.read_text()) if args.config else None)
        return 0
    ensure_drained(args.root)
    if args.action == 'drain':
        return 0
    source = json.loads(args.config.read_text())
    peer_uid = pwd.getpwnam('a4diag-target').pw_uid if source.get('repair_helpers') else 0
    if args.action == 'check':
        installation_plan(source, peer_uid=peer_uid)
    else:
        print(json.dumps(install_helpers(source, root=args.root, peer_uid=peer_uid)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

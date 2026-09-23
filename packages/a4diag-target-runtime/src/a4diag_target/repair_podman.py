"""Podman uses the bounded compatibility API under one registered runtime UID."""
from a4diag_target.repair_containers import ContainerIdentityError
from a4diag_target.repair_docker import DockerAdapter


def validate_runtime_owner(*, expected_uid, peer_uid, path_owner_uid):
    if any(type(uid) is not int or uid < 0 for uid in (expected_uid, peer_uid, path_owner_uid)) or not expected_uid == peer_uid == path_owner_uid:
        raise ContainerIdentityError('runtime_owner_mismatch')


class PodmanAdapter(DockerAdapter):
    runtime = 'podman'
    api_version = 'v1.40'

    def __init__(self, owner_uid, socket_path, *, timeout_seconds=5, attestation=None):
        validate_runtime_owner(expected_uid=owner_uid, peer_uid=owner_uid, path_owner_uid=owner_uid)
        super().__init__(socket_path, timeout_seconds=timeout_seconds)
        self.owner_uid = owner_uid
        self.attestation = attestation


class OwnerBoundPodman:
    """Root broker keeps trust state; the fixed child alone connects as owner."""
    def __init__(self, profile):
        from a4diag_target.repair_containers import profile_identity
        from a4diag_target.repair_install import load_binding
        self.identity = profile_identity(profile)
        binding = load_binding(profile.id)
        if binding.profile != profile or binding.adapter != 'podman' or binding.socket_attestation is None:
            raise ContainerIdentityError('runtime_socket_re_registration_required')
        self.attestation = binding.socket_attestation
        self.timeout_seconds = 5

    def _call(self, action, identifier, timeout_seconds=None):
        import json
        import subprocess
        timeout_seconds = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        from a4diag_target.repair_containers import ContainerSnapshot, require_same_container
        if identifier != self.identity.container_id or action not in ('inspect','start','restart','logs'):
            raise ContainerIdentityError('container_scope_mismatch')
        from pathlib import Path
        from a4diag_target.repair_docker import socket_identity
        endpoint = socket_identity(Path(f'/run/a4diag-podman-{self.identity.owner_uid}.sock'), self.identity.owner_uid)
        if endpoint != (self.attestation.device, self.attestation.inode) or self.attestation.owner_uid != self.identity.owner_uid:
            raise ContainerIdentityError('runtime_socket_re_registration_required')
        # Python's user/group arguments drop groups before exec without preexec_fn
        # in a multithreaded dispatcher. Neither caller environment nor user bus
        # is inherited. All paths are compiled or derived from installed scope.
        result = subprocess.run(['/opt/a4diag-target/current/venv/bin/python', '-I', '-m', 'a4diag_target.repair_podman'],
            input=json.dumps({'identity':self.identity.model_dump(),'action':action,'timeout':timeout_seconds,
                              'attestation':self.attestation.model_dump()}),
            text=True, capture_output=True, timeout=timeout_seconds, env={}, cwd='/',
            user=self.identity.owner_uid, group=self.identity.owner_uid, extra_groups=[])
        if result.returncode or len(result.stdout) > (131072 if action == 'logs' else 16384):
            raise ValueError('owner_runtime_unavailable')
        value = json.loads(result.stdout)
        if value['euid'] != self.identity.owner_uid:
            raise ContainerIdentityError('runtime_execution_uid_mismatch')
        self.last_execution = value['execution']
        if self.last_execution['peer_uid'] != self.identity.owner_uid:
            raise ContainerIdentityError('runtime_peer_mismatch')
        snapshot = ContainerSnapshot.model_validate(value['snapshot'])
        require_same_container(self.identity, snapshot.identity)
        return value['logs'] if action == 'logs' else snapshot

    def inspect(self, identifier):
        return self._call('inspect', identifier)

    def start(self, identifier):
        self._call('start', identifier)

    def restart(self, identifier, timeout_seconds):
        self._call('restart', identifier, timeout_seconds)

    def logs(self, identifier, *, expected_identity):
        from a4diag_target.repair_containers import require_same_container
        require_same_container(self.identity,expected_identity)
        return self._call('logs',identifier)


def main():
    import json
    import os
    import sys
    from pathlib import Path
    from a4diag_target.repair_containers import ContainerIdentity, require_same_container
    # The broker needs only UID/GID switch capabilities. The API child must
    # carry none, including inheritable/ambient sets after credential dropping.
    import ctypes
    class Header(ctypes.Structure):
        _fields_ = [('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Caps(ctypes.Structure):
        _fields_ = [('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(47,4,0,0,0) != 0 or libc.capset(ctypes.byref(Header(0x20080522,0)),ctypes.byref((Caps*2)())) != 0:
        raise ContainerIdentityError('runtime_capability_drop_failed')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps={name:int(status[name].strip(),16) for name in ('CapEff','CapPrm','CapInh','CapAmb')}
    if any(caps.values()):
        raise ContainerIdentityError('runtime_capability_drop_failed')
    body = sys.stdin.buffer.read(4097)
    if len(body) > 4096:
        raise ValueError('owner_request_too_large')
    value = json.loads(body)
    if set(value) != {'identity','action','timeout','attestation'} or value['action'] not in ('inspect','start','restart','logs'):
        raise ValueError('owner_request_invalid')
    identity = ContainerIdentity.model_validate(value['identity'])
    if identity.runtime != 'podman' or os.geteuid() != identity.owner_uid or os.getgroups():
        raise ContainerIdentityError('runtime_execution_uid_mismatch')
    path = Path(f'/run/a4diag-podman-{identity.owner_uid}.sock')
    from a4diag_target.repair_install import SocketAttestation
    import time
    deadline = time.monotonic() + value['timeout']
    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:raise TimeoutError('container_operation_budget_exhausted')
        return budget
    adapter = PodmanAdapter(identity.owner_uid, path, timeout_seconds=remaining(),
                            attestation=SocketAttestation.model_validate(value['attestation']))
    snapshot = adapter.inspect(identity.container_id)
    require_same_container(identity, snapshot.identity)
    adapter.timeout_seconds = remaining()
    if value['action'] == 'start':
        adapter.start(identity.container_id)
    elif value['action'] == 'restart':
        adapter.restart(identity.container_id, remaining())
    logs = adapter.logs(identity.container_id,expected_identity=identity) if value['action'] == 'logs' else None
    if value['action'] != 'inspect':
        adapter.timeout_seconds = remaining()
        snapshot = adapter.inspect(identity.container_id)
    require_same_container(identity, snapshot.identity)
    print(json.dumps({'euid':os.geteuid(),'execution':{**adapter.last_execution,'caps':caps},'snapshot':snapshot.model_dump(mode='json'),'logs':logs}))


if __name__ == '__main__':
    main()

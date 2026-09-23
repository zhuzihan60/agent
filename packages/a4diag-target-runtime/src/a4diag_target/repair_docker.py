"""Bounded HTTP over a local, owner-checked Unix socket; no arbitrary API route."""
import http.client
import io
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

from a4diag_target.repair_containers import ContainerIdentity, ContainerIdentityError, ContainerSnapshot

MAX_RESPONSE = 262144
MAX_LOG_WIRE = 32768
MAX_LOG_TEXT = 16384


def decode_logs(body, *, truncated, tty):
    output = bytearray()
    if tty:
        output.extend(body)
    else:
        offset = 0
        while offset < len(body):
            if len(body)-offset < 8:
                if truncated:break
                raise ValueError('invalid_container_log_frame')
            header=body[offset:offset+8];offset+=8
            if header[0] not in (1,2) or header[1:4] != b'\0\0\0':
                raise ValueError('invalid_container_log_frame')
            length=int.from_bytes(header[4:8],'big')
            if length>len(body)-offset and not truncated:
                raise ValueError('truncated_container_log_frame')
            output.extend(body[offset:min(offset+length,len(body))])
            offset+=length
    text = bytes(output[:MAX_LOG_TEXT]).decode('utf-8','replace').encode('utf-8')
    truncated = truncated or len(output)>MAX_LOG_TEXT or len(text)>MAX_LOG_TEXT
    return {'content':text[:MAX_LOG_TEXT].decode('utf-8','ignore'), 'truncated':truncated}


class _DeadlineReader(io.RawIOBase):
    def __init__(self, channel, deadline):
        self.channel, self.deadline = channel, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('runtime_api_timeout')
        self.channel.settimeout(remaining)
        return self.channel.recv_into(buffer)

    def makefile(self, mode):
        return io.BufferedReader(self)


def container_id(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ContainerIdentityError('full_container_id_required')
    return value


def socket_identity(path, owner_uid):
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ContainerIdentityError('runtime_socket_symlink')
        if parent != path and (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner_uid)
                               or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
            raise ContainerIdentityError('runtime_directory_unprotected')
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid:
        raise ContainerIdentityError('runtime_socket_owner_mismatch')
    return info.st_dev, info.st_ino


class DockerAdapter:
    runtime = 'docker'
    api_version = 'v1.44'

    def __init__(self, socket_path=Path('/run/docker.sock'), *, timeout_seconds=5):
        path = Path(socket_path)
        if not path.is_absolute() or '..' in path.parts or '://' in str(socket_path):
            raise ContainerIdentityError('local_runtime_socket_required')
        if not 0 < timeout_seconds <= 120:
            raise ValueError('invalid_runtime_timeout')
        self.socket_path, self.owner_uid, self.timeout_seconds = path, 0, timeout_seconds

    def _request(self, action, identifier, *, timeout_seconds=None):
        identifier = container_id(identifier)
        if action not in ('inspect', 'start', 'restart', 'logs'):
            raise ValueError('runtime_action_denied')
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise ValueError('invalid_runtime_timeout')
        prior = socket_identity(self.socket_path, self.owner_uid)
        expected = getattr(self, 'attestation', None)
        if expected is not None and (prior != (expected.device, expected.inode) or expected.owner_uid != self.owner_uid):
            raise ContainerIdentityError('runtime_socket_re_registration_required')
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(timeout)
            channel.connect(str(self.socket_path))
            peer_uid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
            if peer_uid != self.owner_uid or socket_identity(self.socket_path, self.owner_uid) != prior:
                raise ContainerIdentityError('runtime_peer_mismatch')
            self.last_execution = {'euid':os.geteuid(),'peer_uid':peer_uid,'socket':str(self.socket_path)}
            suffix = 'json' if action == 'inspect' else action
            route = f'/{self.api_version}/containers/{identifier}/{suffix}'
            if action == 'restart':
                route += f'?t={math.ceil(timeout)}'
            if action == 'logs':
                route += '?stdout=true&stderr=true&follow=false&tail=100'
            method = 'GET' if action in ('inspect','logs') else 'POST'
            channel.sendall(f'{method} {route} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
            # HTTPResponse's normal makefile resets only an idle timeout. This
            # reader enforces the same total deadline even for drip-fed headers.
            response = http.client.HTTPResponse(_DeadlineReader(channel, deadline))
            response.begin()
            if response.status not in ((200,) if action in ('inspect','logs') else (204, 304)):
                raise ValueError(f'runtime_api_status_{response.status}')
            if action != 'logs' and response.length is not None and response.length > MAX_RESPONSE:
                raise ValueError('runtime_response_too_large')
            body = bytearray()
            limit = MAX_LOG_WIRE if action == 'logs' else MAX_RESPONSE
            while len(body) <= limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('runtime_api_timeout')
                channel.settimeout(remaining)
                chunk = response.read1(min(8192, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if action == 'logs':
                if len(body)<=limit and response.length not in (None,0):
                    raise ValueError('truncated_runtime_response')
                return bytes(body[:limit]),len(body)>limit
            if len(body) > MAX_RESPONSE:
                raise ValueError('runtime_response_too_large')
            return json.loads(body) if action == 'inspect' else None

    def inspect(self, identifier):
        raw = self._request('inspect', identifier)
        try:
            labels = raw['Config']['Labels'] or {}
            environment = raw['Config'].get('Env') or []
            if any(str(item).startswith('PODMAN_SYSTEMD_UNIT=') for item in environment) or type(labels) is not dict or any(
                name.startswith(('com.docker.swarm.', 'io.kubernetes.', 'io.containers.autoupdate'))
                or name in ('PODMAN_SYSTEMD_UNIT', 'io.containers.systemd.unit') for name in labels
            ):
                raise ContainerIdentityError('orchestrated_container_requires_registered_service')
            state = raw['State']
            self._tty = raw['Config'].get('Tty',False)
            if type(self._tty) is not bool:
                raise ValueError('invalid_container_tty')
            health = state.get('Health', {}).get('Status') or 'unknown'
            snapshot = ContainerSnapshot(identity=ContainerIdentity(runtime=self.runtime,
                container_id=raw['Id'], image_digest=raw['Image'], owner_uid=self.owner_uid),
                running=state['Running'], health=health, exit_code=state['ExitCode'],
                oom_killed=state['OOMKilled'], restart_count=raw['RestartCount'], started_at=state['StartedAt'])
            if snapshot.identity.container_id != identifier:
                raise ContainerIdentityError('container_identity_changed')
            return snapshot
        except (KeyError, TypeError, AttributeError) as error:
            raise ContainerIdentityError('invalid_container_evidence') from error

    def start(self, identifier):
        self._request('start', identifier)

    def logs(self, identifier, *, expected_identity):
        from a4diag_target.repair_containers import require_same_container
        deadline = time.monotonic()+self.timeout_seconds
        def remaining():
            budget=deadline-time.monotonic()
            if budget<=0:raise TimeoutError('runtime_api_timeout')
            self.timeout_seconds=budget
        remaining();before=self.inspect(identifier)
        require_same_container(expected_identity,before.identity)
        tty=self._tty
        remaining();body,truncated=self._request('logs',identifier)
        remaining();after=self.inspect(identifier)
        require_same_container(expected_identity,after.identity)
        remaining()
        return decode_logs(body,truncated=truncated,tty=tty)

    def restart(self, identifier, timeout_seconds):
        self._request('restart', identifier, timeout_seconds=timeout_seconds)

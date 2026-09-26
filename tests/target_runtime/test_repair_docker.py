"""Container identity and bounded local API contract (real Unix transport)."""
import json
import os
import socket
import threading
from contextlib import contextmanager

import pytest

pytestmark = pytest.mark.privileged_linux

CID = 'a' * 64
IMAGE = 'sha256:' + 'c' * 64


@contextmanager
def daemon(tmp_path, body, *, status=200):
    path = tmp_path / 'daemon.sock'
    requests = []
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path))
        server.listen()
        server.settimeout(3)
        def run():
            try:
                connection, _ = server.accept()
                with connection:
                    requests.append(connection.recv(8192).decode())
                    payload = body if isinstance(body,bytes) else json.dumps(body).encode()
                    connection.sendall(f'HTTP/1.1 {status} OK\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n'.encode() + payload)
            except (OSError, TimeoutError):
                pass
        thread = threading.Thread(target=run)
        thread.start()
        try:
            yield path, requests
        finally:
            thread.join(4)
            path.unlink(missing_ok=True)


def inspect_body(**state):
    return {'Id': CID, 'Image': IMAGE, 'RestartCount': 0,
            'State': {'Running': True, 'ExitCode': 0, 'OOMKilled': False,
                      'StartedAt': '2026-09-23T00:00:00Z', **state},
            'Config': {'Labels': {}}}


def test_same_name_different_id_is_rejected():
    from a4diag_target.repair_containers import ContainerIdentity, ContainerIdentityError, require_same_container
    identity = ContainerIdentity(runtime='docker', container_id=CID, image_digest=IMAGE, owner_uid=0)
    for changes in ({'container_id':'b'*64}, {'image_digest':'sha256:'+'d'*64}, {'owner_uid':1001}, {'runtime':'podman'}):
        with pytest.raises(ContainerIdentityError):
            require_same_container(identity, identity.model_copy(update=changes))


def test_docker_real_socket_inspect_does_not_invent_health(tmp_path):
    from a4diag_target.repair_docker import DockerAdapter
    with daemon(tmp_path, inspect_body()) as (path, requests):
        snapshot = DockerAdapter(socket_path=path).inspect(CID)
    assert snapshot.identity.container_id == CID
    assert snapshot.identity.image_digest == IMAGE
    assert snapshot.health == 'unknown'
    assert snapshot.running is True
    assert requests[0].startswith(f'GET /v1.44/containers/{CID}/json HTTP/1.1')


@pytest.mark.parametrize('value', ['demo', 'a'*12, '../exec', 'a'*64+'/exec'])
def test_names_abbreviations_and_api_injection_are_rejected(value):
    from a4diag_target.repair_docker import DockerAdapter
    with pytest.raises(ValueError):
        DockerAdapter().inspect(value)


def test_socket_symlink_and_remote_daemon_denied(tmp_path):
    from a4diag_target.repair_docker import DockerAdapter
    with pytest.raises(ValueError):
        DockerAdapter(socket_path='https://127.0.0.1:2376')
    link = tmp_path / 'link'
    link.symlink_to('/run/docker.sock')
    with pytest.raises(ValueError):
        DockerAdapter(socket_path=link).inspect(CID)


@pytest.mark.parametrize('bad', [
    {'Id':'b'*64}, {'Image':'latest'}, {'RestartCount':-1},
    {'State':{'Running':'yes','ExitCode':0,'OOMKilled':False}},
    {'Config':{'Labels':{'com.docker.swarm.service.id':'managed'}}},
])
def test_invalid_or_orchestrated_inspect_is_rejected(tmp_path, bad):
    from a4diag_target.repair_docker import DockerAdapter
    with daemon(tmp_path, {**inspect_body(), **bad}) as (path, _):
        with pytest.raises(ValueError):
            DockerAdapter(socket_path=path).inspect(CID)


def test_restart_has_only_exact_bounded_api_route(tmp_path):
    from a4diag_target.repair_docker import DockerAdapter
    with daemon(tmp_path, {}, status=204) as (path, requests):
        DockerAdapter(socket_path=path).restart(CID, timeout_seconds=7)
    assert requests[0].startswith(f'POST /v1.44/containers/{CID}/restart?t=7 HTTP/1.1')


def test_slow_header_bytes_cannot_extend_total_api_deadline(tmp_path):
    import time
    from a4diag_target.repair_docker import DockerAdapter
    path=tmp_path/'slow.sock'
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path));server.listen();server.settimeout(2)
        def serve():
            try:
                connection,_=server.accept()
                with connection:
                    connection.recv(8192)
                    for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n':
                        connection.sendall(bytes([byte]));time.sleep(.02)
            except OSError:pass
        worker=threading.Thread(target=serve);worker.start()
        started=time.monotonic()
        try:
            with pytest.raises(TimeoutError):DockerAdapter(path,timeout_seconds=.12).inspect(CID)
            assert time.monotonic()-started<.4
        finally:worker.join(3)


def test_logs_are_fixed_readonly_bounded_and_demultiplexed(tmp_path):
    from a4diag_target.repair_docker import DockerAdapter, decode_logs
    frame=lambda stream,body:bytes([stream,0,0,0])+len(body).to_bytes(4,'big')+body
    wire=frame(1,b'one\n')+frame(2,b'two\n')
    with daemon(tmp_path,wire) as (path,requests):
        raw,truncated=DockerAdapter(path)._request('logs',CID)
    assert decode_logs(raw,truncated=truncated,tty=False)=={'content':'one\ntwo\n','truncated':False}
    assert requests[0].startswith(f'GET /v1.44/containers/{CID}/logs?stdout=true&stderr=true&follow=false&tail=100 HTTP/1.1')
    with daemon(tmp_path,frame(1,b'x'*65536)) as (path,_):
        raw,truncated=DockerAdapter(path)._request('logs',CID)
    result=decode_logs(raw,truncated=truncated,tty=False)
    assert result['truncated'] and len(result['content'].encode())<=16384
    for malformed in (b'bad',frame(1,b'test')[:-1],frame(3,b'invalid')):
        with pytest.raises(ValueError):decode_logs(malformed,truncated=False,tty=False)
    assert decode_logs(b'plain',truncated=False,tty=True)['content']=='plain'


def test_unsupported_log_driver_is_unavailable(tmp_path):
    from a4diag_target.repair_docker import DockerAdapter
    with daemon(tmp_path,{'message':'configured logging driver does not support reading'},status=501) as (path,_):
        with pytest.raises(ValueError,match='runtime_api_status_501'):DockerAdapter(path)._request('logs',CID)


@pytest.mark.parametrize('when',['before','after'])
def test_logs_require_registered_image_before_and_after_read(monkeypatch,when):
    from a4diag_target.repair_docker import DockerAdapter
    from a4diag_target.repair_containers import ContainerIdentity
    expected=ContainerIdentity(runtime='docker',owner_uid=0,container_id=CID,image_digest=IMAGE)
    adapter=DockerAdapter();calls=[]
    def request(action,identifier):
        calls.append(action)
        if action=='logs':return b'',False
        changed=(when=='before' or len(calls)>1)
        return {**inspect_body(),'Image':'sha256:'+'d'*64 if changed else IMAGE}
    monkeypatch.setattr(adapter,'_request',request)
    with pytest.raises(ValueError,match='identity_changed'):adapter.logs(CID,expected_identity=expected)
    assert calls==(['inspect'] if when=='before' else ['inspect','logs','inspect'])

"""Exercise HTTP framing and total deadlines against real loopback sockets."""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager

from a4diag.recovery import RecoveryCheck, check_http


@contextmanager
def raw_http_server(chunks: list[tuple[float, bytes]]):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    address = f"http://127.0.0.1:{listener.getsockname()[1]}/health"
    stopped = threading.Event()

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                connection.recv(8192)
                for delay, chunk in chunks:
                    if stopped.wait(delay):
                        return
                    connection.sendall(chunk)
        except OSError:
            # The deadline may close the client while the server is writing.
            pass

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield address
    finally:
        stopped.set()
        listener.close()
        worker.join(timeout=3)


def test_http_body_match_rejects_early_eof_before_content_length() -> None:
    with raw_http_server([
        (0, b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nready"),
    ]) as address:
        result = check_http(RecoveryCheck(
            id="api", kind="http", resource=address,
            body_contains="ready", timeout_seconds=1, attempts=1,
        ))
    assert result["ok"] is False


def test_http_total_deadline_includes_slow_response_headers() -> None:
    with raw_http_server([
        (0, b"HTTP/1.1 200 OK\r\n"),
        (0.4, b"X-First: yes\r\n"),
        (0.4, b"X-Second: yes\r\n"),
        (0.4, b"X-Third: yes\r\n"),
        (0.4, b"X-Fourth: yes\r\n"),
        (0.4, b"Content-Length: 0\r\n\r\n"),
    ]) as address:
        started = time.monotonic()
        result = check_http(RecoveryCheck(
            id="api", kind="http", resource=address,
            timeout_seconds=1, attempts=1,
        ))
        elapsed = time.monotonic() - started
    assert result["ok"] is False
    assert elapsed < 1.6, "socket inactivity timeouts must not replace the total deadline"


def test_http_close_delimited_body_uses_remaining_total_deadline() -> None:
    with raw_http_server([
        (0, b"HTTP/1.0 200 OK\r\n\r\nready"),
        (0.7, b"x"),
        (0.7, b"x"),
    ]) as address:
        started = time.monotonic()
        result = check_http(RecoveryCheck(
            id="api", kind="http", resource=address,
            body_contains="ready", timeout_seconds=1, attempts=1,
        ))
        elapsed = time.monotonic() - started
    assert result["ok"] is False
    assert elapsed < 1.3, "the HTTP/1.0 response socket must obey the remaining deadline"

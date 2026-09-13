"""Administrator-owned evidence and recovery criteria; never supplied by a model."""

from __future__ import annotations

import http.client
import queue
import re
import socket
import threading
import time
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,239}\.service")
_HTTP_SLOTS = threading.BoundedSemaphore(8)


def _service(value: str) -> None:
    if not _UNIT.fullmatch(value):
        raise ValueError("resource must be an exact safe .service unit")


class EvidenceSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    kind: Literal["service_state", "service_logs", "file"]
    resource: str = Field(min_length=1, max_length=1024)
    initial: bool = True
    max_bytes: int = Field(default=8192, ge=256, le=16384)

    @model_validator(mode="after")
    def validate_resource(self) -> EvidenceSource:
        if self.kind == "file":
            if (not self.resource.startswith("/") or "\\" in self.resource
                or any(part in {"", ".", ".."} for part in self.resource[1:].split("/"))
                or any(ord(c) < 32 or ord(c) == 127 for c in self.resource)
                or any(c in self.resource for c in "*?[]")):
                raise ValueError("file evidence requires an exact absolute POSIX path")
        else:
            _service(self.resource)
        return self


class RecoveryCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    kind: Literal["service_active", "http"]
    resource: str = Field(min_length=1, max_length=2048)
    expected_status: int = Field(default=200, ge=200, le=299)
    body_contains: str | None = Field(default=None, min_length=1, max_length=256)
    attempts: int = Field(default=3, ge=1, le=3)
    timeout_seconds: int = Field(default=3, ge=1, le=5)

    @model_validator(mode="after")
    def validate_resource(self) -> RecoveryCheck:
        if self.kind == "service_active":
            _service(self.resource)
            if self.body_contains is not None or self.expected_status != 200:
                raise ValueError("HTTP expectations only apply to http checks")
        else:
            url = urlsplit(self.resource)
            if (url.scheme not in {"http", "https"} or not url.hostname
                or url.username is not None or url.password is not None
                or url.fragment or any(ord(c) <= 32 or ord(c) == 127 for c in self.resource)):
                raise ValueError("HTTP check requires an absolute URL without credentials or fragment")
            try:
                url.port
            except ValueError as error:
                raise ValueError("invalid HTTP port") from error
        return self


def validate_catalog(sources: tuple[EvidenceSource, ...], checks: tuple[RecoveryCheck, ...]) -> None:
    for label, entries in (("evidence", sources), ("recovery", checks)):
        if len({item.id for item in entries}) != len(entries):
            raise ValueError(f"duplicate {label} id")
    if sum(source.max_bytes for source in sources) > 65536:
        raise ValueError("total evidence budget exceeds 65536 bytes")


def check_http(check: RecoveryCheck) -> dict:
    """GET an admin URL from the controller, no redirects, cookies or proxy env.

    TLS verification uses the platform trust store. Response content is bounded
    and never returned in the report. A failed/truncated body match fails closed.
    """
    # A socket timeout alone is an inactivity timeout, so a trickling response
    # can exceed it indefinitely. Bound the entire call, including DNS, and
    # cap outstanding workers if a platform resolver cannot be interrupted.
    if not _HTTP_SLOTS.acquire(blocking=False):
        return {"ok": False, "status": "http_probe_busy"}
    replies: queue.Queue = queue.Queue(maxsize=1)
    sockets: list[socket.socket] = []
    cancelled = threading.Event()

    def probe() -> None:
        try:
            replies.put(_check_http(check, sockets, cancelled))
        except Exception:
            replies.put({"ok": False, "status": "http_unavailable"})
        finally:
            _HTTP_SLOTS.release()

    threading.Thread(target=probe, name="a4diag-http-health", daemon=True).start()
    try:
        return replies.get(timeout=check.timeout_seconds)
    except queue.Empty:
        cancelled.set()
        for connection_socket in sockets:
            try:
                connection_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return {"ok": False, "status": "http_timeout"}


def _check_http(check: RecoveryCheck, sockets: list[socket.socket], cancelled: threading.Event) -> dict:
    url = urlsplit(check.resource)
    connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(url.hostname, url.port, timeout=check.timeout_seconds)
    deadline = time.monotonic() + check.timeout_seconds
    try:
        connection.connect()
        if cancelled.is_set():
            return {"ok": False, "status": "http_timeout"}
        if connection.sock is not None:
            sockets.append(connection.sock)
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        connection.request("GET", path, headers={"Accept": "text/plain, application/json", "Connection": "close"})
        response = connection.getresponse()
        result = {"ok": response.status == check.expected_status, "status": "http_checked", "http_status": response.status}
        if check.body_contains is not None and result["ok"]:
            body = bytearray()
            while len(body) <= 65536:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                # read1 performs at most one underlying read; reset the timeout
                # to the remaining deadline to bound slowly streaming bodies.
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, 65537 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            complete = response.length in {None, 0}
            result["ok"] = complete and len(body) <= 65536 and check.body_contains in body.decode("utf-8", errors="replace")
            result["body_matched"] = result["ok"]
        if not result["ok"]:
            result["status"] = "http_unhealthy"
        return result
    except (OSError, ValueError, http.client.HTTPException):
        return {"ok": False, "status": "http_unavailable"}
    finally:
        connection.close()

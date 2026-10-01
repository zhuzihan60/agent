"""Read-only status page for the controller and its registered targets.

The page only reads: configuration, systemd unit states, report files, the
approval count and a cached identity probe per target. It exposes no action.
By default it listens on loopback only and rejects any Host header other than
the loopback names, so a hostile web page cannot reach it through DNS
rebinding. Listening on another address requires an access token.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import re
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import yaml

from a4diag import __version__
from a4diag.redaction import redact
from a4diag.status_labels import SETTLED_STATUSES, status_label

DEFAULT_LISTEN = "127.0.0.1"
DEFAULT_PORT = 8765
REPORT_LIMIT = 20
MAX_REPORT_BYTES = 1_048_576
IDENTITY_CACHE_SECONDS = 30.0
IDENTITY_TIMEOUT_SECONDS = 10.0
TOKEN_COOKIE = "a4diag_dashboard"
_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_STATIC_ROOT = Path(__file__).with_name("dashboard_static")
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def run_systemctl_show(units: list[str]) -> dict[str, dict[str, str]]:
    """Return ActiveState/SubState for each unit in one systemctl call."""
    if not units:
        return {}
    completed = subprocess.run(
        ["/usr/bin/systemctl", "show", "--property=Id,ActiveState,SubState", "--", *units],
        check=False, capture_output=True, text=True, timeout=10,
    )
    states: dict[str, dict[str, str]] = {}
    for block in completed.stdout.split("\n\n"):
        values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if values.get("Id"):
            states[values["Id"]] = {
                "active": values.get("ActiveState", "unknown"),
                "sub": values.get("SubState", "unknown"),
            }
    return states


def probe_identity(transport: str) -> str:
    """Ask a transport plugin instance for the live target fingerprint."""
    from a4diag.plugin_client import PluginClient

    client = PluginClient(f"/run/a4diag/{transport}.sock", timeout_seconds=IDENTITY_TIMEOUT_SECONDS)
    result = asyncio.run(client.call("verify_identity", {}))
    data = result.get("data") if isinstance(result, dict) else None
    fingerprint = data.get("fingerprint") if isinstance(data, dict) else None
    if not isinstance(fingerprint, str) or not fingerprint:
        raise RuntimeError("identity_probe_failed")
    return fingerprint


class StatusCollector:
    """Builds a redacted, read-only snapshot of controller and target status."""

    def __init__(
        self,
        *,
        config_path: Path,
        report_root: Path,
        approvals_path: Path,
        systemctl: Callable[[list[str]], Mapping[str, Mapping[str, str]]] = run_systemctl_show,
        identity_probe: Callable[[str], str] = probe_identity,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config_path = config_path
        self._report_root = report_root
        self._approvals_path = approvals_path
        self._systemctl = systemctl
        self._identity_probe = identity_probe
        self._clock = clock
        self._identity_cache: dict[str, tuple[float, dict[str, str]]] = {}
        self._lock = threading.Lock()

    def snapshot(self) -> dict[str, object]:
        from a4diag.settings import load_settings

        generated_at = datetime.now(timezone.utc).isoformat()
        try:
            settings = load_settings(self._config_path)
        except Exception as error:  # an unreadable config is itself a status to show
            return {"generated_at": generated_at, "version": __version__,
                    "configured": False, "error": f"{type(error).__name__}: {error}"}
        reports = self._recent_reports()
        instances = sorted({target.transport for target in settings.targets}
                           | ({settings.model.plugin} if settings.model else set()))
        units = ["a4diag-core.service", "a4diag-dashboard.service"]
        units += [f"a4diag-plugin@{name}.socket" for name in instances]
        if any(target.mode.value == "local" for target in settings.targets):
            units.append("a4diag-target-executor.socket")
        try:
            unit_states = dict(self._systemctl(units))
        except (OSError, subprocess.SubprocessError):
            unit_states = {}
        controller = {
            "version": __version__,
            "global_mode": settings.global_mode,
            "auto_execute_low": settings.auto_execute_low,
            "model": None if settings.model is None else {
                "plugin": settings.model.plugin,
                "model": settings.model.model,
                "base_url": settings.model.base_url,
            },
            "units": [{"unit": unit, **unit_states.get(unit, {"active": "unknown", "sub": "unknown"})}
                      for unit in units if unit != "a4diag-target-executor.socket"],
            "pending_approvals": self._pending_approvals(),
        }
        targets = []
        for target in settings.targets:
            latest = next((report for report in reports if report["target_id"] == target.id), None)
            entry = {
                "id": target.id,
                "mode": target.mode.value,
                "host": target.host,
                "port": target.port,
                "write_enabled": target.write_enabled,
                "watched": sorted({source.resource for source in target.evidence_sources}),
                "identity": self._identity(target.id, target.transport, target.identity_fingerprint),
                "latest_report": latest,
            }
            if target.mode.value == "local":
                entry["executor"] = unit_states.get(
                    "a4diag-target-executor.socket", {"active": "unknown", "sub": "unknown"})
            targets.append(entry)
        return redact({  # type: ignore[return-value]
            "generated_at": generated_at,
            "configured": bool(settings.targets) and settings.model is not None,
            "controller": controller,
            "targets": targets,
            "reports": reports,
        })

    def report(self, task_id: str) -> dict[str, object] | None:
        if not _TASK_ID.fullmatch(task_id):
            return None
        for path in sorted(self._report_root.glob(f"*/{task_id}.yaml")):
            loaded = self._load_report(path)
            if loaded is not None:
                return redact(loaded)  # type: ignore[return-value]
        return None

    # ------------------------------------------------------------------

    def _identity(self, target_id: str, transport: str, expected: str) -> dict[str, str]:
        now = self._clock()
        with self._lock:
            cached = self._identity_cache.get(target_id)
            if cached is not None and now - cached[0] < IDENTITY_CACHE_SECONDS:
                return cached[1]
        try:
            actual = self._identity_probe(transport)
            result = {"state": "ok" if hmac.compare_digest(actual, expected) else "changed"}
        except Exception as error:
            result = {"state": "unreachable", "detail": str(error) or type(error).__name__}
        with self._lock:
            self._identity_cache[target_id] = (now, result)
        return result

    def _pending_approvals(self) -> int | None:
        if not self._approvals_path.is_file():
            return 0
        try:
            connection = sqlite3.connect(f"file:{self._approvals_path}?mode=ro", uri=True, timeout=2)
            try:
                row = connection.execute(
                    "SELECT COUNT(*) FROM approvals WHERE status = 'pending' AND expires_at > ?",
                    (int(time.time()),),
                ).fetchone()
            finally:
                connection.close()
        except sqlite3.Error:
            return None
        return int(row[0])

    def _recent_reports(self) -> list[dict[str, object]]:
        try:
            paths = sorted(self._report_root.glob("*/*.yaml"),
                           key=lambda path: path.stat().st_mtime, reverse=True)
        except OSError:
            return []
        summaries = []
        for path in paths[:REPORT_LIMIT]:
            report = self._load_report(path)
            if report is None:
                continue
            status = str(report.get("status", ""))
            diagnosis = report.get("diagnosis") if isinstance(report.get("diagnosis"), dict) else {}
            cause = str(diagnosis.get("cause") or report.get("error") or "")
            summaries.append({
                "task_id": str(report.get("task_id") or path.stem),
                "target_id": str(report.get("target_id", "")),
                "status": status,
                "status_label": status_label(status),
                "settled": status in SETTLED_STATUSES,
                "finished_at": str(report.get("finished_at", "")),
                "cause": cause[:300] + ("…" if len(cause) > 300 else ""),
            })
        return summaries

    @staticmethod
    def _load_report(path: Path) -> dict[str, object] | None:
        try:
            if path.is_symlink() or path.stat().st_size > MAX_REPORT_BYTES:
                return None
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            return None
        return loaded if isinstance(loaded, dict) else None


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_handler(collector: StatusCollector, *, port: int, token: str | None,
                 loopback_only: bool) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"{name}:{port}" for name in ("127.0.0.1", "localhost", "[::1]")}

    class Handler(BaseHTTPRequestHandler):
        server_version = "a4diag-dashboard"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            if loopback_only and self.headers.get("Host", "") not in allowed_hosts:
                self._send(421, b"misdirected request\n", "text/plain; charset=utf-8")
                return
            url = urlsplit(self.path)
            extra: dict[str, str] = {}
            if token is not None:
                supplied = parse_qs(url.query).get("token", [""])[0] or self._cookie_token()
                if not hmac.compare_digest(supplied.encode(), token.encode()):
                    self._send(401, "需要访问令牌：在地址后加 ?token=<令牌>\n".encode(),
                               "text/plain; charset=utf-8")
                    return
                extra["Set-Cookie"] = (f"{TOKEN_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")
            if url.path in _STATIC_FILES:
                name, content_type = _STATIC_FILES[url.path]
                self._send(200, (_STATIC_ROOT / name).read_bytes(), content_type, extra)
            elif url.path == "/api/status":
                self._json(collector.snapshot(), extra)
            elif url.path.startswith("/api/report/"):
                report = collector.report(url.path.removeprefix("/api/report/"))
                if report is None:
                    self._send(404, b"not found\n", "text/plain; charset=utf-8")
                else:
                    self._json(report, extra)
            elif url.path == "/healthz":
                self._send(200, b"ok\n", "text/plain; charset=utf-8")
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")

        def _reject(self) -> None:
            self._send(405, b"read-only dashboard\n", "text/plain; charset=utf-8", {"Allow": "GET"})

        do_POST = do_PUT = do_PATCH = do_DELETE = _reject  # noqa: N815

        def _cookie_token(self) -> str:
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == TOKEN_COOKIE:
                    return value
            return ""

        def _json(self, value: object, extra: Mapping[str, str]) -> None:
            body = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8", extra)

        def _send(self, status: int, body: bytes, content_type: str,
                  extra: Mapping[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in {**_SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return  # request lines could carry the access token

    return Handler


def serve(collector: StatusCollector, *, listen: str = DEFAULT_LISTEN, port: int = DEFAULT_PORT,
          token: str | None = None) -> None:
    loopback_only = is_loopback(listen)
    if not loopback_only and not token:
        raise ValueError("listening beyond loopback requires an access token")
    handler = make_handler(collector, port=port, token=None if loopback_only else token,
                           loopback_only=loopback_only)
    server = ThreadingHTTPServer((listen, port), handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        server.server_close()


__all__ = ["DEFAULT_LISTEN", "DEFAULT_PORT", "StatusCollector", "is_loopback", "make_handler", "serve"]

from __future__ import annotations

import http.client
import json
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from a4diag.dashboard import StatusCollector, is_loopback, make_handler, serve
from a4diag.init_config import InitService
from a4diag.setup_wizard import SetupAnswers, build_init_request

FINGERPRINT = "sha256:" + "a" * 64


class FakeProbe:
    def probe(self, _value: object) -> str:
        return FINGERPRINT


def write_config(path: Path) -> None:
    request = build_init_request(
        SetupAnswers(preset="deepseek", base_url="https://api.deepseek.com/v1", api_style="openai",
                     model="deepseek-chat", api_key=None, services=("nginx.service",)),
        secret_ref="file:model-api-key",
    )
    path.write_bytes(InitService(transport=FakeProbe(), model=FakeProbe()).validate(request).config_bytes)


def write_report(root: Path, task_id: str, **fields: object) -> None:
    directory = root / "2026-10-01"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{task_id}.yaml").write_text(
        yaml.safe_dump({"task_id": task_id, "target_id": "local", "finished_at": "2026-10-01T12:00:00+00:00",
                        **fields}, allow_unicode=True), encoding="utf-8")


@pytest.fixture
def collector(tmp_path: Path) -> StatusCollector:
    config = tmp_path / "config.yaml"
    write_config(config)
    reports = tmp_path / "reports"
    write_report(reports, "cli-1", status="read_only",
                 diagnosis={"cause": "nginx stopped; password=c2VjcmV0"})
    probes: list[str] = []

    def systemctl(units: list[str]) -> dict[str, dict[str, str]]:
        return {unit: {"active": "active", "sub": "running"} for unit in units}

    def identity(transport: str) -> str:
        probes.append(transport)
        return FINGERPRINT

    instance = StatusCollector(config_path=config, report_root=reports,
                               approvals_path=tmp_path / "approvals.sqlite3",
                               systemctl=systemctl, identity_probe=identity)
    instance.probes = probes  # type: ignore[attr-defined]
    return instance


def test_snapshot_reports_controller_target_and_redacted_reports(collector: StatusCollector) -> None:
    snapshot = collector.snapshot()
    assert snapshot["configured"] is True
    controller = snapshot["controller"]
    assert controller["global_mode"] == "read_only"
    assert controller["model"] == {"plugin": "model-openai-compatible", "model": "deepseek-chat",
                                   "base_url": "https://api.deepseek.com/v1"}
    assert {unit["unit"] for unit in controller["units"]} == {
        "a4diag-core.service", "a4diag-dashboard.service",
        "a4diag-plugin@model-openai-compatible.socket", "a4diag-plugin@transport-local.socket"}
    assert controller["pending_approvals"] == 0
    (target,) = snapshot["targets"]
    assert target["identity"] == {"state": "ok"}
    assert target["watched"] == ["nginx.service"]
    assert target["executor"] == {"active": "active", "sub": "running"}
    assert target["latest_report"]["task_id"] == "cli-1"
    assert "c2VjcmV0" not in json.dumps(snapshot)


def test_identity_is_cached_and_mismatch_or_failure_is_reported(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    write_config(config)
    results = iter([FINGERPRINT.replace("a", "b"), RuntimeError("plugin down")])
    now = [0.0]

    def identity(_transport: str) -> str:
        value = next(results)
        if isinstance(value, Exception):
            raise value
        return value

    collector = StatusCollector(config_path=config, report_root=tmp_path / "reports",
                                approvals_path=tmp_path / "none", systemctl=lambda units: {},
                                identity_probe=identity, clock=lambda: now[0])
    assert collector.snapshot()["targets"][0]["identity"] == {"state": "changed"}
    now[0] = 10.0
    assert collector.snapshot()["targets"][0]["identity"] == {"state": "changed"}  # cached
    now[0] = 40.0
    assert collector.snapshot()["targets"][0]["identity"] == {"state": "unreachable",
                                                             "detail": "plugin down"}


def test_unreadable_config_is_shown_not_raised(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("targets: [", encoding="utf-8")
    collector = StatusCollector(config_path=tmp_path / "config.yaml", report_root=tmp_path,
                                approvals_path=tmp_path / "none", systemctl=lambda units: {},
                                identity_probe=lambda transport: FINGERPRINT)
    snapshot = collector.snapshot()
    assert snapshot["configured"] is False and snapshot["error"]


def test_report_lookup_rejects_traversal(collector: StatusCollector) -> None:
    assert collector.report("cli-1")["status"] == "read_only"
    for hostile in ("../config", "..", "a/b", "", "cli-1.yaml/../x"):
        assert collector.report(hostile) is None


class Server:
    def __init__(self, collector: StatusCollector, *, token: str | None = None,
                 loopback_only: bool = True) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            collector, port=0, token=token, loopback_only=loopback_only))
        self.port = self.httpd.server_address[1]
        self.httpd.RequestHandlerClass = make_handler(collector, port=self.port, token=token,
                                                      loopback_only=loopback_only)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def request(self, method: str, path: str, host: str | None = None,
                headers: dict[str, str] | None = None) -> http.client.HTTPResponse:
        for attempt in range(40):
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            try:
                connection.connect()
                break
            except ConnectionRefusedError:
                # Some virtualized loopbacks (WSL proxy mode) lag right after bind.
                if attempt == 39:
                    raise
                time.sleep(0.05)
        connection.putrequest(method, path, skip_host=True)
        connection.putheader("Host", host or f"127.0.0.1:{self.port}")
        for name, value in (headers or {}).items():
            connection.putheader(name, value)
        connection.endheaders()
        return connection.getresponse()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def test_http_serves_page_and_api_with_security_headers(collector: StatusCollector) -> None:
    server = Server(collector)
    try:
        page = server.request("GET", "/")
        assert page.status == 200
        assert "script-src 'self'" in page.getheader("Content-Security-Policy")
        assert page.getheader("X-Frame-Options") == "DENY"
        assert "A4Diag" in page.read().decode()
        status = server.request("GET", "/api/status")
        assert status.status == 200 and json.loads(status.read())["configured"] is True
        assert server.request("GET", "/app.js").status == 200
        assert server.request("GET", "/api/report/cli-1").status == 200
        assert server.request("GET", "/api/report/..%2Fconfig").status == 404
        assert server.request("GET", "/etc/passwd").status == 404
    finally:
        server.close()


def test_http_is_read_only_and_rejects_foreign_host_headers(collector: StatusCollector) -> None:
    server = Server(collector)
    try:
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            assert server.request(method, "/api/status").status == 405
        assert server.request("GET", "/api/status", host="attacker.example:80").status == 421
        assert server.request("GET", "/api/status", host=f"localhost:{server.port}").status == 200
    finally:
        server.close()


def test_token_mode_requires_the_token_then_uses_a_cookie(collector: StatusCollector) -> None:
    server = Server(collector, token="s3cret-token", loopback_only=False)
    try:
        assert server.request("GET", "/api/status").status == 401
        assert server.request("GET", "/api/status?token=wrong").status == 401
        first = server.request("GET", "/?token=s3cret-token")
        assert first.status == 200
        cookie = first.getheader("Set-Cookie").split(";")[0]
        assert "HttpOnly" in first.getheader("Set-Cookie")
        assert server.request("GET", "/api/status", headers={"Cookie": cookie}).status == 200
    finally:
        server.close()


def test_listening_beyond_loopback_requires_a_token(collector: StatusCollector) -> None:
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0")
    with pytest.raises(ValueError, match="token"):
        serve(collector, listen="0.0.0.0", port=0, token=None)

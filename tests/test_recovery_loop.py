from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from pydantic import ValidationError

from a4diag.domain import TargetConfig
from a4diag.recovery import EvidenceSource, RecoveryCheck, check_http
from a4diag.plugin_ports import _RpcCollectorPort, _RpcModelPort
from a4diag.runtime import RuntimeFailure
from a4diag.workflow import build_graph, run_event
from test_workflow_v3 import deps_factory, event_for, with_settings  # noqa: F401


def target(**values):
    return TargetConfig(id="target-1", mode="local", identity_ref="target/target-1", **values)


@pytest.mark.parametrize("resource", ["../app.service", "--help", "app.service;id", "app*"])
def test_evidence_rejects_unsafe_units(resource):
    with pytest.raises(ValidationError):
        EvidenceSource(id="state", kind="service_state", resource=resource)


@pytest.mark.parametrize("resource", ["file:///etc/passwd", "http://u:p@host/health", "http://host/health#x"])
def test_http_check_rejects_unsafe_urls(resource):
    with pytest.raises(ValidationError):
        RecoveryCheck(id="health", kind="http", resource=resource)


def test_duplicate_evidence_ids_rejected():
    source = EvidenceSource(id="state", kind="service_state", resource="app.service")
    with pytest.raises(ValidationError):
        target(evidence_sources=(source, source))


class Client:
    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply

    async def call(self, method, params):
        self.calls.append((method, params))
        if self.reply is not None:
            return self.reply
        if method == "verify_identity":
            return {"ok": True, "data": {"fingerprint": "machine-1"}}
        content = json.dumps({"ActiveState": "active", "LoadState": "loaded", "SubState": "running"})
        if params["kind"] == "service_logs":
            content = "password=do-not-send failure"
        return {"ok": True, "stdout": content, "data": {"truncated": False}}


class Registry:
    def require(self, *args):
        pass


def collector(client):
    return _RpcCollectorPort(Registry(), lambda _: client)


def test_only_registered_sources_collected_and_secrets_redacted():
    client = Client()
    t = target(evidence_sources=(EvidenceSource(id="logs", kind="service_logs", resource="app.service", initial=False),))
    port = collector(client)
    assert all(row.get("source_id") != "logs" for row in port.collect(t, "machine-1"))
    rows = port.collect_requested(t, "machine-1", ["logs"])
    assert "do-not-send" not in json.dumps(rows)
    assert rows[0]["source_id"] == "logs"
    with pytest.raises(RuntimeFailure):
        port.collect_requested(t, "machine-1", ["arbitrary-command"])


def test_identity_alone_is_not_business_recovery():
    result = collector(Client()).final_verify(target(), "machine-1", [])
    assert not result.ok
    assert result.status == "recovery_checks_missing"


def test_service_health_is_checked_independently_of_model_evidence():
    t = target(recovery_checks=(RecoveryCheck(id="service", kind="service_active", resource="app.service"),))
    client = Client()
    result = collector(client).final_verify(t, "machine-1", [{"healthy": False}])
    assert result.ok
    assert result.data["checks"][0]["id"] == "service"
    assert any(params.get("kind") == "service_state" for _, params in client.calls)


def test_critic_incomplete_cannot_become_low_risk():
    from test_workflow_v3 import make_plan
    port = _RpcModelPort(Client({"risk": "low", "complete": False, "issues": ["missing rollback"]}))
    with pytest.raises(RuntimeFailure, match="model_plan_incomplete"):
        port.critic(target(), [], make_plan())


def configure_sources(deps):
    t = deps.settings.targets[0].model_copy(update={"evidence_sources": (EvidenceSource(id="logs", kind="service_logs", resource="app.service", initial=False),)})
    return with_settings(deps, deps.settings.model_copy(update={"targets": (t,)}))


def test_missing_evidence_is_collected_then_diagnosed_again(deps_factory):
    deps = configure_sources(deps_factory())
    seen = []

    def diagnose(t, evidence):
        seen.append(evidence)
        return {"cause": "bad config", "confidence": 0.9, "missing_evidence": [] if len(seen) > 1 else ["logs"]}

    deps.plugins.model.diagnose = diagnose
    deps.plugins.collector.collect_requested = lambda t, view, ids: [{"source_id": "logs", "content": "invalid configuration", "available": True}]
    state = run_event(build_graph(deps), event_for())
    assert state["status"] == "succeeded"
    assert len(seen) == 2
    assert any(row.get("source_id") == "logs" for row in seen[1])
    assert state["recovery_result"]["ok"] is True
    assert any(row.get("source_id") == "logs" for row in state["evidence"])


@pytest.mark.parametrize("missing,confidence", [(["unknown"], 0.9), ([], 0.2), (["logs"], 0.9)])
def test_unreliable_diagnosis_never_dispatches_writes(deps_factory, missing, confidence):
    deps = configure_sources(deps_factory())
    calls = []
    def diagnose(t, evidence):
        calls.append(1)
        return {"cause": "uncertain", "confidence": confidence, "missing_evidence": missing}
    deps.plugins.model.diagnose = diagnose
    deps.plugins.collector.collect_requested = lambda t, view, ids: [{"source_id": "logs", "content": "still unclear", "available": True}]
    state = run_event(build_graph(deps), event_for())
    assert state["status"] == "insufficient_evidence"
    assert not deps.plugins.executor.calls
    assert len(calls) <= 3


def test_recovery_failure_retained_after_rollback(deps_factory):
    from a4diag.domain import StepResult
    deps = deps_factory()
    deps.plugins.collector.final_result = StepResult(ok=False, status="http_unhealthy", data={"checks": [{"id": "api", "ok": False}]})
    state = run_event(build_graph(deps), event_for())
    assert state["status"] == "rollback_succeeded"
    assert state["recovery_result"]["ok"] is False
    assert state["recovery_result"]["data"]["checks"][0]["id"] == "api"


@pytest.fixture
def health_server():
    class Handler(BaseHTTPRequestHandler):
        paths = []
        def do_GET(self):
            self.paths.append(self.path)
            status = 503 if self.path == "/down" else 302 if self.path == "/redirect" else 200
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/healthy")
            self.end_headers()
            self.wfile.write(b"x" * 70000 if self.path == "/huge" else b'{"ready":true}')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler.paths
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize("path,contains,healthy", [("/healthy", '"ready":true', True), ("/healthy", '"ready":false', False), ("/down", None, False), ("/redirect", None, False), ("/huge", "x", False)])
def test_real_http_probe_uses_status_body_and_never_follows_redirect(health_server, path, contains, healthy):
    url, paths = health_server
    result = check_http(RecoveryCheck(id="api", kind="http", resource=url + path, body_contains=contains, attempts=1))
    assert result["ok"] is healthy
    assert paths == [path]
    assert "body" not in result


def test_production_preflight_denies_write_without_recovery_checks(deps_factory):
    deps = deps_factory()
    deps.plugins.collector.validate_recovery = collector(Client()).validate_recovery
    state = run_event(build_graph(deps), event_for())
    assert state["status"] == "policy_denied"
    assert state["error"] == "recovery_checks_missing"
    assert not deps.plugins.executor.calls


def test_inactive_service_is_not_recovered():
    t = target(recovery_checks=(RecoveryCheck(id="service", kind="service_active", resource="app.service", attempts=1),))
    class Inactive(Client):
        async def call(self, method, params):
            if method == "read":
                return {"ok": True, "stdout": '{"LoadState":"loaded","ActiveState":"failed"}', "data": {"truncated": False}}
            return await super().call(method, params)
    result = collector(Inactive()).final_verify(t, "machine-1", [])
    assert result.ok is False
    assert result.data["checks"][0]["status"] == "service_unhealthy"


def test_approval_resume_rechecks_current_confidence_threshold(deps_factory):
    from a4diag.domain import Risk
    from test_workflow_v3 import make_plan, resume_for
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    state = run_event(build_graph(deps), event_for())
    approval = deps.approvals.get(state["approval_id"])
    deps.approvals.approve(approval.id, approved_digest=approval.plan_digest, actor="uid:1000", now=101)
    changed = deps.settings.targets[0].model_copy(update={"minimum_confidence": 1.0})
    resumed_deps = with_settings(deps, deps.settings.model_copy(update={"targets": (changed,)}))
    resumed = run_event(build_graph(resumed_deps), resume_for(state["transaction_id"]))
    assert resumed["status"] == "policy_denied"
    assert deps.plugins.executor.calls == []


def test_business_failure_remains_visible_when_undo_succeeds():
    from a4diag.report import residual_risk
    assert residual_risk({"status": "rollback_succeeded", "recovery_result": {"ok": False}}) != "none"
    assert residual_risk({"status": "rollback_succeeded"}) != "none"

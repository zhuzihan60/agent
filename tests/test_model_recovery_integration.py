"""Exercise the production harness fixtures through actual model and HTTP code."""

from __future__ import annotations

import json
from pathlib import Path

from a4diag.domain import Risk, TargetConfig
from a4diag.plugin_ports import _RpcModelPort
from a4diag.recovery import RecoveryCheck, check_http
from a4diag_builtin_plugins.model_openai import ModelEvidenceParams
from e2e import run_production_wiring as wiring


def test_protected_path_fixture_has_real_registered_evidence_before_policy_check(tmp_path: Path) -> None:
    with wiring.ModelHttpFixture(tmp_path) as fixture:
        fixture.mode = "protected"
        request = {"task": "diagnose", "evidence": {"observations": []}}
        assert fixture._response(request)["missing_evidence"] == ["low-file"]
        request["evidence"]["observations"] = [
            {"source_id": "low-file", "available": True, "content": "before\n"}
        ]
        result = fixture._response(request)
        assert result["missing_evidence"] == []
        assert result["evidence_refs"] == [{"source_id": "low-file", "quote": "before\n", "relation": "supports"}]


def test_model_fixture_requests_registered_evidence_before_diagnosing(tmp_path: Path) -> None:
    with wiring.ModelHttpFixture(tmp_path) as fixture:
        fixture.mode = "low"
        assert fixture.plugin.capability_probe().write_capable is True
        evidence = {
            "target_fingerprint": "actual-fingerprint",
            "allowed_capabilities": [{"name": "files"}],
            "evidence_sources": [{"id": "low-file", "kind": "file"}],
            "recovery_checks": [{"id": "business-http", "kind": "http"}],
            "observations": [],
        }
        diagnosis = fixture.plugin.diagnose(ModelEvidenceParams(evidence=evidence))
        assert diagnosis.missing_evidence == ["low-file"]
        evidence["observations"] = [
            {"kind": "file", "source_id": "low-file", "available": True, "content": "before\n"}
        ]
        diagnosis = fixture.plugin.diagnose(ModelEvidenceParams(evidence=evidence))
        assert diagnosis.missing_evidence == []
        assert diagnosis.confidence >= 0.7
        assert diagnosis.evidence_refs[0].source_id == "low-file"
        assert diagnosis.evidence_refs[0].quote == "before\n"
        sent = fixture.requests[-1]
        assert sent["format"] == "json"
        schema = json.loads(sent["messages"][0]["content"].split("JSON Schema:\n", 1)[1])
        assert schema["required"] == ["cause", "confidence"]
        assert schema["additionalProperties"] is False


def test_business_http_requires_actual_managed_file_change(tmp_path: Path) -> None:
    resource = tmp_path / "low.conf"
    resource.write_bytes(b"before\n")
    with wiring.ModelHttpFixture(tmp_path) as fixture:
        fixture.mode = "low"
        check = RecoveryCheck(
            id="business-http", kind="http", resource=fixture.url + "/health",
            body_contains="recovered", attempts=1,
        )
        assert check_http(check)["ok"] is False
        resource.write_bytes(b"after-low\n")
        assert check_http(check)["ok"] is True
        resource.write_bytes(b"before\n")
        assert check_http(check)["ok"] is False


def test_business_http_failure_scenario_stays_unhealthy_after_apply(tmp_path: Path) -> None:
    (tmp_path / "unhealthy.conf").write_bytes(b"after-unhealthy\n")
    with wiring.ModelHttpFixture(tmp_path) as fixture:
        fixture.mode = "unhealthy"
        check = RecoveryCheck(id="business-http", kind="http", resource=fixture.url + "/health")
        assert check_http(check)["ok"] is False


def test_production_model_adapter_uses_http_plugin_for_all_decisions() -> None:
    target = TargetConfig.model_validate({
        "id": "target-1", "mode": "local", "identity_ref": "target/target-1",
        "capabilities": [{"name": "files", "actions": ["replace_managed_file"],
                          "resources": ["/srv/managed/**"]}],
        "evidence_sources": [{"id": "low-file", "kind": "file", "resource": "/srv/managed/low.conf"}],
        "recovery_checks": [{"id": "business-http", "kind": "http", "resource": "http://127.0.0.1/health"}],
    })
    observations = [
        {"kind": "target_fingerprint", "content": "actual-fingerprint"},
        {"kind": "file", "source_id": "low-file", "available": True,
         "resource": "/srv/managed/low.conf", "content": "before\n",
         "truncated": False, "collected_at": 1_000},
    ]
    with wiring.ModelHttpFixture(Path("/srv/managed")) as fixture:
        port = _RpcModelPort(wiring._ModelPluginClient(fixture.plugin), clock=lambda: 1_000)
        diagnosis = port.diagnose(target, observations)
        plan = port.plan(target, observations, diagnosis)
        risk = port.critic(target, observations, plan)

        assert plan.target_fingerprint == "actual-fingerprint"
        assert diagnosis["model_confidence"] == 0.95
        assert diagnosis["confidence"] == 0.7
        assert diagnosis["grounding_status"] == "supported"
        assert plan.operations[0].resource.replace("\\", "/") == "/srv/managed/low.conf"
        assert risk is Risk.LOW
        envelopes = [json.loads(request["messages"][1]["content"]) for request in fixture.requests]
        assert [envelope["task"] for envelope in envelopes] == ["diagnose", "plan", "critic"]
        for envelope in envelopes:
            assert envelope["evidence"]["target_fingerprint"] == "actual-fingerprint"
            assert envelope["evidence"]["allowed_capabilities"][0]["name"] == "files"
            assert envelope["evidence"]["evidence_sources"][0]["id"] == "low-file"
            assert envelope["evidence"]["recovery_checks"][0]["id"] == "business-http"

"""Controller-side citation checks: quotes support hypotheses, not causal proof."""

from __future__ import annotations

import json
import pytest

from a4diag.domain import TargetConfig
from a4diag.evidence_grounding import assess_diagnosis
from a4diag.plugin_ports import _RpcCollectorPort, _RpcModelPort
from a4diag.recovery import EvidenceSource
from a4diag.domain import Risk
from a4diag.workflow import build_graph, run_event
from test_workflow_v3 import deps_factory, event_for, make_plan, resume_for, with_settings


NOW = 1_000


def target() -> TargetConfig:
    return TargetConfig.model_validate({
        "id": "lab", "mode": "local", "identity_ref": "target/lab",
        "evidence_sources": [
            {"id": "config", "kind": "file", "resource": "/srv/managed/app.conf"},
            {"id": "logs", "kind": "service_logs", "resource": "app.service"},
            {"id": "other-config", "kind": "file", "resource": "/srv/managed/other.conf"},
        ],
    })


def rows() -> list[dict[str, object]]:
    return [
        {"source_id": "config", "kind": "file", "resource": "/srv/managed/app.conf",
         "available": True, "truncated": False, "content": "listen=wrong\n", "collected_at": NOW},
        {"source_id": "logs", "kind": "service_logs", "resource": "app.service",
         "available": True, "truncated": False, "content": "failed to bind\n", "collected_at": NOW},
        {"source_id": "other-config", "kind": "file", "resource": "/srv/managed/other.conf",
         "available": True, "truncated": False, "content": "mode=old\n", "collected_at": NOW},
    ]


def ref(source_id: str, quote: str, relation: str = "supports") -> dict[str, str]:
    return {"source_id": source_id, "quote": quote, "relation": relation}


def assess(refs: list[dict[str, str]], evidence: list[dict[str, object]] | None = None):
    return assess_diagnosis(target(), rows() if evidence is None else evidence,
                            {"cause": "configuration hypothesis", "confidence": 0.99,
                             "missing_evidence": [], "evidence_refs": refs,
                             "grounding_status": "supported", "model_confidence": 1.0}, now=NOW)


def test_model_score_and_forged_grounding_cannot_override_missing_citation() -> None:
    result = assess([])
    assert result["model_confidence"] == 0.99
    assert result["confidence"] == 0.0
    assert result["grounding_status"] == "insufficient_evidence"
    assert result["diagnostic_label"] == "hypothesis_not_causal_proof"


def test_untrusted_model_assessment_fields_are_discarded() -> None:
    result = assess_diagnosis(target(), rows(), {
        "cause": "hypothesis", "confidence": 0.99, "missing_evidence": [],
        "evidence_refs": [ref("config", "listen=wrong")],
        "grounding": {"confirmed_cause": True}, "effective_confidence": 1.0,
    }, now=NOW)
    assert "grounding" not in result
    assert "effective_confidence" not in result
    assert result["confidence"] == 0.7


def test_independent_sources_raise_bounded_support_score() -> None:
    one = assess([ref("config", "listen=wrong")])
    two = assess([ref("config", "listen=wrong"), ref("logs", "failed to bind")])
    same_kind = assess([ref("config", "listen=wrong"), ref("other-config", "mode=old")])
    assert one["confidence"] == 0.7
    assert two["confidence"] == 0.85
    assert same_kind["confidence"] == 0.85
    assert two["grounding_status"] == "supported"


def test_counterevidence_caps_score_below_default_write_threshold() -> None:
    result = assess([ref("config", "listen=wrong"), ref("logs", "failed to bind", "contradicts")])
    assert result["confidence"] == 0.5


@pytest.mark.parametrize("refs", [
    [ref("invented", "listen=wrong")],
    [ref("config", "not in the source")],
    [ref("config", "listen=wrong"), ref("config", "listen=wrong")],
    [ref("config", "listen=wrong", "proves")],
])
def test_forged_duplicate_or_invalid_citation_fails_closed(refs: list[dict[str, str]]) -> None:
    result = assess(refs)
    assert result["confidence"] == 0.0
    assert result["grounding_status"] == "insufficient_evidence"


@pytest.mark.parametrize("mutation", [
    {"kind": "service_logs"}, {"resource": "/not-registered"},
    {"available": False}, {"truncated": True},
    {"collected_at": NOW - 301}, {"collected_at": NOW + 1},
])
def test_unavailable_or_untrusted_snapshot_cannot_support_citation(mutation: dict[str, object]) -> None:
    evidence = rows()
    evidence[0].update(mutation)
    result = assess([ref("config", "listen=wrong")], evidence)
    assert result["confidence"] == 0.0
    assert result["grounding_status"] == "insufficient_evidence"


def test_duplicate_snapshot_and_unbounded_quote_fail_closed() -> None:
    assert assess([ref("config", "listen=wrong")], rows() + [rows()[0]])["confidence"] == 0.0
    assert assess([ref("config", "x" * 257)])["confidence"] == 0.0


@pytest.mark.parametrize("inner", [
    {"partial": True, "truncated": False},
    {"partial": False, "truncated": True},
])
def test_kubernetes_payload_internal_partial_flags_fail_closed(inner: dict[str, bool]) -> None:
    configured = TargetConfig.model_validate({
        "id": "lab", "mode": "local", "identity_ref": "target/lab",
        "evidence_sources": [{"id": "k8s", "kind": "kubernetes_evidence", "resource": "profile-a"}],
    })
    snapshot = {"source_id": "k8s", "kind": "kubernetes_evidence", "resource": "profile-a",
                "available": True, "truncated": False, "collected_at": NOW,
                "content": json.dumps({"message": "pod crashloop", **inner})}
    diagnosis = {"cause": "hypothesis", "confidence": 0.99, "missing_evidence": [],
                 "evidence_refs": [ref("k8s", "pod crashloop")]}
    assert assess_diagnosis(configured, [snapshot], diagnosis, now=NOW)["confidence"] == 0.0


def test_collector_stamps_redacted_snapshot_with_controller_time() -> None:
    class Client:
        async def call(self, method, _params):
            if method == "verify_identity":
                return {"ok": True, "data": {"fingerprint": "fingerprint"}}
            return {"ok": True, "stdout": "password=sample listen=wrong\n",
                    "data": {"truncated": False}}

    class Registry:
        def require(self, *_args):
            return None

    collector = _RpcCollectorPort(Registry(), lambda _instance: Client(), clock=lambda: NOW)
    result = collector.collect_requested(target(), "fingerprint", ["config"])[0]
    assert result["collected_at"] == NOW
    assert result["content"] == "password=[REDACTED] listen=wrong\n"
    assert assess([ref("config", "listen=wrong")], [result])["confidence"] == 0.7


def test_production_model_port_replaces_claimed_grounding_and_model_score() -> None:
    class Client:
        async def call(self, _method, _params):
            return {"cause": "hypothesis", "confidence": 0.99,
                    "missing_evidence": [], "evidence_refs": [ref("invented", "listen=wrong")],
                    "grounding_status": "supported", "model_confidence": 1.0}

    diagnosis = _RpcModelPort(Client(), clock=lambda: NOW).diagnose(target(), rows())
    assert diagnosis["model_confidence"] == 0.99
    assert diagnosis["confidence"] == 0.0
    assert diagnosis["grounding_status"] == "insufficient_evidence"


def test_pending_approval_rechecks_evidence_freshness_before_write(deps_factory) -> None:
    deps = deps_factory()
    configured = deps.settings.targets[0].model_copy(update={
        "evidence_sources": (EvidenceSource(id="config", kind="file",
                                            resource="/srv/managed/app.conf"),),
    })
    deps = with_settings(deps, deps.settings.model_copy(update={"targets": (configured,)}))
    deps.plugins.collector.collect = lambda _target, _view: [
        {"source_id": "config", "kind": "file", "resource": "/srv/managed/app.conf",
         "available": True, "truncated": False, "content": "listen=wrong\n", "collected_at": 100},
    ]
    deps.plugins.model.diagnose = lambda selected, evidence: assess_diagnosis(
        selected, evidence, {"cause": "hypothesis", "confidence": 0.99,
                             "missing_evidence": [],
                             "evidence_refs": [ref("config", "listen=wrong")]}, now=deps.clock())
    deps.plugins.model.assess_diagnosis = lambda selected, evidence, diagnosis, *, now: assess_diagnosis(
        selected, evidence, diagnosis, now=now)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    from dataclasses import replace
    deps = replace(deps, approval_ttl_seconds=900)
    graph = build_graph(deps)
    pending = run_event(graph, event_for())
    assert pending["status"] == "pending_approval"
    assert pending["diagnosis"]["confidence"] == 0.7
    deps.clock.value = 401
    approval = deps.approvals.get(pending["approval_id"])
    deps.approvals.approve(approval.id, approved_digest=approval.plan_digest,
                          actor="uid:1000", now=deps.clock())
    resumed = run_event(graph, resume_for(pending["transaction_id"]))
    assert resumed["status"] == "policy_denied"
    assert resumed["error"] == "diagnostic_evidence_missing"
    assert deps.plugins.executor.calls == []


def test_counterevidence_blocks_low_threshold_without_executor(deps_factory) -> None:
    deps = deps_factory()
    configured = deps.settings.targets[0].model_copy(update={
        "minimum_confidence": 0.2, "evidence_sources": target().evidence_sources[:2],
    })
    deps = with_settings(deps, deps.settings.model_copy(update={"targets": (configured,)}))
    deps.plugins.collector.collect = lambda _target, _view: [
        {**row, "collected_at": deps.clock()} for row in rows()[:2]
    ]
    deps.plugins.model.diagnose = lambda selected, evidence: assess_diagnosis(
        selected, evidence, {"cause": "hypothesis", "confidence": 0.99,
                             "missing_evidence": [], "evidence_refs": [
                                 ref("config", "listen=wrong"),
                                 ref("logs", "failed to bind", "contradicts"),
                             ]}, now=deps.clock())
    deps.plugins.model.assess_diagnosis = lambda selected, evidence, diagnosis, *, now: assess_diagnosis(
        selected, evidence, diagnosis, now=now)
    state = run_event(build_graph(deps), event_for())
    assert state["diagnosis"]["confidence"] == 0.5
    assert state["status"] == "insufficient_evidence"
    assert state["error"] == "diagnostic_counterevidence_present"
    assert deps.plugins.executor.calls == []


def test_pending_approval_rechecks_new_counterevidence_even_with_low_threshold(deps_factory) -> None:
    deps = deps_factory()
    configured = deps.settings.targets[0].model_copy(update={
        "minimum_confidence": 0.2, "evidence_sources": target().evidence_sources[:2],
    })
    deps = with_settings(deps, deps.settings.model_copy(update={"targets": (configured,)}))
    deps.plugins.collector.collect = lambda _target, _view: [
        {**row, "collected_at": deps.clock()} for row in rows()[:2]
    ]
    deps.plugins.model.diagnose = lambda selected, evidence: assess_diagnosis(
        selected, evidence, {"cause": "hypothesis", "confidence": 0.99,
                             "missing_evidence": [],
                             "evidence_refs": [ref("config", "listen=wrong")]}, now=deps.clock())
    deps.plugins.model.assess_diagnosis = lambda selected, evidence, diagnosis, *, now: assess_diagnosis(
        selected, evidence, diagnosis, now=now)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)
    pending = run_event(graph, event_for())
    assert pending["status"] == "pending_approval"
    changed = dict(pending["diagnosis"])
    changed["evidence_refs"] = [ref("config", "listen=wrong"),
                                ref("logs", "failed to bind", "contradicts")]
    # Keep the pending interrupt intact; simulate a recheck that now recognizes
    # the contradictory registered snapshot in the persisted evidence.
    deps.plugins.model.assess_diagnosis = lambda selected, evidence, _diagnosis, *, now: assess_diagnosis(
        selected, evidence, changed, now=now)
    approval = deps.approvals.get(pending["approval_id"])
    deps.approvals.approve(approval.id, approved_digest=approval.plan_digest,
                          actor="uid:1000", now=deps.clock())
    resumed = run_event(graph, resume_for(pending["transaction_id"]))
    assert resumed["status"] == "policy_denied"
    assert resumed["error"] == "diagnostic_counterevidence_present"
    assert deps.plugins.executor.calls == []

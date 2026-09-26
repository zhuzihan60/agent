"""Bounded, controller-side checks for model citations to collected evidence.

An exact quote supports only a diagnostic hypothesis. It cannot establish that
the model's proposed cause is true, or that an operation will repair it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from a4diag.domain import TargetConfig


MAX_EVIDENCE_AGE_SECONDS = 300
MAX_EVIDENCE_REFS = 8
MAX_QUOTE_LENGTH = 256


def assess_diagnosis(
    target: TargetConfig,
    evidence: list[dict[str, Any]],
    diagnosis: dict[str, Any],
    *,
    now: int,
) -> dict[str, Any]:
    """Return a bounded assessment, replacing every model-supplied assessment field."""
    model_confidence = diagnosis.get("confidence")
    if type(model_confidence) not in (int, float) or not 0 <= model_confidence <= 1:
        model_confidence = 0.0
    result = {
        key: diagnosis[key] for key in
        ("cause", "missing_evidence", "recommended_actions", "evidence_refs")
        if key in diagnosis
    }
    result.update(
        model_confidence=model_confidence,
        confidence=0.0,
        grounding_status="insufficient_evidence",
        diagnostic_label="hypothesis_not_causal_proof",
    )
    refs = diagnosis.get("evidence_refs")
    if not isinstance(refs, list) or not 1 <= len(refs) <= MAX_EVIDENCE_REFS:
        return result
    if type(now) is not int or now < 0:
        return result

    catalog = {source.id: source for source in target.evidence_sources}
    snapshots: dict[str, dict[str, Any]] = {}
    for row in evidence:
        if not isinstance(row, dict):
            return result
        source_id = row.get("source_id")
        if isinstance(source_id, str) and source_id in catalog:
            if source_id in snapshots:
                return result
            snapshots[source_id] = row

    seen: set[str] = set()
    supports: list[tuple[str, str]] = []
    contradicts = False
    for citation in refs:
        if not isinstance(citation, dict) or set(citation) != {"source_id", "quote", "relation"}:
            return result
        source_id = citation["source_id"]
        quote = citation["quote"]
        relation = citation["relation"]
        if (
            not isinstance(source_id, str) or source_id in seen
            or source_id not in catalog or source_id not in snapshots
            or not isinstance(quote, str) or not 1 <= len(quote) <= MAX_QUOTE_LENGTH
            or not isinstance(relation, str) or relation not in {"supports", "contradicts"}
        ):
            return result
        seen.add(source_id)
        source = catalog[source_id]
        row = snapshots[source_id]
        content = row.get("content")
        collected_at = row.get("collected_at")
        if (
            row.get("kind") != source.kind or row.get("resource") != source.resource
            or row.get("available") is not True or row.get("truncated") is not False
            or not isinstance(content, str)
            or len(content.encode("utf-8")) > source.max_bytes
            or type(collected_at) is not int
            or not 0 <= now - collected_at <= MAX_EVIDENCE_AGE_SECONDS
            or quote not in content
            or (len(quote) < 4 and len(content) >= 4)
        ):
            return result
        if source.kind == "kubernetes_evidence":
            try:
                payload = json.loads(content)
            except (TypeError, ValueError):
                return result
            if (not isinstance(payload, dict) or payload.get("partial") is not False
                or payload.get("truncated") is not False):
                return result
        digest = row.get("content_sha256")
        if digest is not None and digest != hashlib.sha256(content.encode("utf-8")).hexdigest():
            return result
        if relation == "supports":
            supports.append((source.kind, source.resource))
        else:
            contradicts = True

    if not supports or diagnosis.get("missing_evidence"):
        return result
    score = 0.85 if len(set(supports)) >= 2 else 0.7
    if contradicts:
        score = min(score, 0.5)
    result["confidence"] = score
    result["grounding_status"] = "supported" if not contradicts else "counterevidence_present"
    return result

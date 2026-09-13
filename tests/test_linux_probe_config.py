from __future__ import annotations

import pytest
import yaml

from a4diag.domain import TargetConfig
from a4diag.init_config import InitRequest, InitService, TargetInit
from a4diag.recovery import EvidenceSource, RecoveryCheck


def catalog() -> dict[str, object]:
    return {
        "diagnostic_probes": [{"id": "memory", "kind": "memory", "resource": "host"}],
        "evidence_sources": [{"id": "memory-evidence", "kind": "probe", "resource": "memory"}],
        "recovery_checks": [{"id": "memory-recovered", "kind": "probe", "resource": "memory",
                             "conditions": [{"field": "used_percent", "operator": "le", "value": 80}]}],
    }


def target(model: type[TargetConfig] | type[TargetInit], **changes: object) -> TargetConfig | TargetInit:
    data = {"id": "node", "mode": "local", **changes}
    if model is TargetConfig:
        data["identity_ref"] = "target/node"
    return model.model_validate(data)


@pytest.mark.parametrize("model", [TargetConfig, TargetInit])
def test_probe_catalog_is_preserved_through_model_roundtrip(model: type[TargetConfig] | type[TargetInit]) -> None:
    configured = target(model, **catalog())
    restored = model.model_validate_json(configured.model_dump_json())
    assert restored == configured
    assert restored.recovery_checks[0].conditions[0].value == 80


@pytest.mark.parametrize("model", [TargetConfig, TargetInit])
@pytest.mark.parametrize("field", ["evidence_sources", "recovery_checks"])
def test_unknown_probe_references_fail_at_configuration_time(model: type[TargetConfig] | type[TargetInit], field: str) -> None:
    values = catalog()
    values[field][0]["resource"] = "unregistered"
    with pytest.raises(ValueError):
        target(model, **values)


@pytest.mark.parametrize("model", [TargetConfig, TargetInit])
@pytest.mark.parametrize("count", [2, 9])
def test_duplicate_and_excessive_probe_registration_is_rejected(model: type[TargetConfig] | type[TargetInit], count: int) -> None:
    values = catalog()
    values["diagnostic_probes"] = values["diagnostic_probes"] * count
    with pytest.raises(ValueError):
        target(model, **values)


@pytest.mark.parametrize("model", [TargetConfig, TargetInit])
@pytest.mark.parametrize("condition", [
    {"field": "unknown", "operator": "eq", "value": 1},
    {"field": "used_percent", "operator": "eq", "value": True},
    {"field": "used_percent", "operator": "eq", "value": "80"},
    {"field": "used_percent", "operator": "contains", "value": 80},
    {"field": "used_percent", "operator": "le", "value": 80.0},
])
def test_probe_condition_must_match_registered_output_type(model: type[TargetConfig] | type[TargetInit], condition: dict[str, object]) -> None:
    values = catalog()
    values["recovery_checks"][0]["conditions"] = [condition]
    with pytest.raises(ValueError):
        target(model, **values)


@pytest.mark.parametrize("resource", ["/memory", "memory*", "memory.child", "", "memory\n"])
def test_probe_evidence_requires_exact_id(resource: str) -> None:
    with pytest.raises(ValueError):
        EvidenceSource(id="evidence", kind="probe", resource=resource)


@pytest.mark.parametrize("changes", [{}, {"conditions": []}, {"resource": "memory*", "conditions": [{"field": "used_percent", "operator": "le", "value": 80}]}])
def test_probe_recovery_requires_id_and_nonempty_conditions(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RecoveryCheck.model_validate({"id": "recovered", "kind": "probe", "resource": "memory", **changes})


@pytest.mark.parametrize(("kind", "resource"), [("http", "https://example.com/health"), ("service_active", "app.service")])
@pytest.mark.parametrize("conditions", [[], [{"field": "reachable", "operator": "eq", "value": True}]])
def test_legacy_checks_cannot_configure_probe_conditions(kind: str, resource: str, conditions: list[object]) -> None:
    with pytest.raises(ValueError, match="conditions only"):
        RecoveryCheck.model_validate({"id": "health", "kind": kind, "resource": resource, "conditions": conditions})


@pytest.mark.parametrize("model", [TargetConfig, TargetInit])
def test_legacy_check_roundtrip_omits_probe_conditions(model: type[TargetConfig] | type[TargetInit]) -> None:
    configured = target(model, recovery_checks=[{"id": "service", "kind": "service_active", "resource": "app.service"}])
    assert configured.diagnostic_probes == ()
    dumped = configured.model_dump(mode="json")
    assert "conditions" not in dumped["recovery_checks"][0]
    assert model.model_validate(dumped) == configured


def test_initialization_emits_registered_probe_definitions_and_conditions() -> None:
    class IdentityProbe:
        def probe(self, target: object) -> str:
            return "sha256:" + "a" * 64

    request = InitRequest(targets=(target(TargetInit, **catalog()),))
    result = InitService(transport=IdentityProbe(), model=IdentityProbe()).validate(request)
    generated = yaml.safe_load(result.config_bytes)["targets"][0]
    assert generated["diagnostic_probes"][0]["id"] == "memory"
    assert generated["recovery_checks"][0]["conditions"][0] == {"field": "used_percent", "operator": "le", "value": 80}
    assert TargetConfig.model_validate(generated) == result.settings.targets[0]


@pytest.mark.parametrize("model", [TargetConfig, TargetInit])
@pytest.mark.parametrize(("kind", "resource", "field", "value", "presence"), [
    ("file", "/srv/app/config", "mode", 420, "exists"),
    ("package", "app-package", "version", "1.2.3", "installed"),
])
def test_attribute_recovery_requires_positive_presence_condition(
    model: type[TargetConfig] | type[TargetInit], kind: str, resource: str,
    field: str, value: object, presence: str,
) -> None:
    values = {
        "diagnostic_probes": [{"id": "state", "kind": kind, "resource": resource}],
        "recovery_checks": [{"id": "recovered", "kind": "probe", "resource": "state",
                             "conditions": [{"field": field, "operator": "eq", "value": value}]}],
    }
    with pytest.raises(ValueError, match="presence"):
        target(model, **values)
    values["recovery_checks"][0]["conditions"].append({"field": presence, "operator": "eq", "value": True})
    assert len(target(model, **values).recovery_checks[0].conditions) == 2

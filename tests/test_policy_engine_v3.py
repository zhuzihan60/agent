from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from a4diag.domain import (
    CanonicalPlanError,
    CapabilityGrant,
    Operation,
    Plan,
    Risk,
    TargetConfig,
    canonical_plan_bytes,
    plan_digest,
)
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.plugin_api.ticket import (
    OperationTicketExpectation,
    OperationTicketRequest,
    TicketError,
    TicketIssuer,
    TicketVerifier,
)
from a4diag.policy_engine import (
    PolicyAuthorization,
    PolicyDecision,
    PolicyEngine,
    canonical_operation_digest,
    policy_authorization_is_authentic,
)
from a4diag.settings import AgentSettings


POLICY_KEY = b"p" * 32
TICKET_KEY = b"t" * 32


def operation_schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {"content": {"type": "string"}},
        "required": ["content"],
        "additionalProperties": False,
    }


def write_registry(
    root: Path,
    *,
    capability: str = "files",
    action: str = "replace",
    risk_floor: Risk = Risk.LOW,
    reversible: bool = True,
    supports_prepare: bool = True,
    supports_verify: bool = True,
    supports_reconcile: bool = True,
    supports_undo: bool = True,
    parameters_schema: dict[str, object] | None = None,
) -> PluginRegistry:
    plugin_name = f"capability-{capability}"
    plugin_dir = root / "plugins"
    plugin_dir.mkdir()
    artifact = plugin_dir / f"{plugin_name}.whl"
    artifact.write_bytes(b"signed capability wheel")
    manifest = {
        "name": plugin_name,
        "plugin_type": "capability",
        "version": "1.0.0",
        "api_min": "1.0",
        "api_max": "1.0",
        "executable": f"a4diag_plugins.{plugin_name.replace('-', '_')}:main",
        "socket": f"/run/a4diag/{plugin_name}.sock",
        "config_schema": f"schemas/{plugin_name}.json",
        "operations": [
            {
                "name": f"{capability}.{action}",
                "risk_floor": risk_floor.value,
                "reversible": reversible,
                "supports_prepare": supports_prepare,
                "supports_verify": supports_verify,
                "supports_reconcile": supports_reconcile,
                "supports_undo": supports_undo,
                "parameters_schema": parameters_schema or operation_schema(),
            }
        ],
    }
    manifest_path = root / f"{plugin_name}.json"
    manifest_path.write_bytes(json.dumps(manifest, separators=(",", ":")).encode("utf-8"))
    pin = PluginPin(
        name=plugin_name,
        version="1.0.0",
        api_version="1.0",
        artifact_path=f"plugins/{plugin_name}.whl",
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        enabled=True,
    )
    return PluginRegistry.load((pin,), root, core_api="1.0")


def make_operation(**overrides: object) -> Operation:
    values: dict[str, object] = {
        "capability": "files",
        "action": "replace",
        "resource": "/etc/example/app.conf",
        "parameters": {"content": "enabled=true\n"},
        "model_risk": Risk.LOW,
        "verify": {"content_sha256": "a" * 64},
        "undo": {"restore_backup": True},
    }
    values.update(overrides)
    return Operation.model_validate(values)


def make_plan(operation: Operation | None = None, **overrides: object) -> Plan:
    values: dict[str, object] = {
        "target_id": "lab",
        "target_fingerprint": "machine-1",
        "operations": (operation or make_operation(),),
    }
    values.update(overrides)
    return Plan.model_validate(values)


def make_target(
    *,
    capability: str = "files",
    action: str = "replace",
    resources: tuple[str, ...] = ("/etc/example/**",),
    write_enabled: bool = True,
    auto_execute_low: bool = True,
    target_id: str = "lab",
) -> TargetConfig:
    return TargetConfig(
        id=target_id,
        mode="local",
        identity_ref=f"target/{target_id}",
        write_enabled=write_enabled,
        auto_execute_low=auto_execute_low,
        capabilities=(
            CapabilityGrant(name=capability, actions=(action,), resources=resources),
        ),
    )


def make_engine(
    registry: PluginRegistry,
    target: TargetConfig,
    *,
    global_mode: str = "read_write",
    auto_execute_low: bool = True,
) -> PolicyEngine:
    settings = AgentSettings(
        global_mode=global_mode,
        auto_execute_low=auto_execute_low,
        targets=(target,),
    )
    return PolicyEngine(settings, registry, authorization_key=POLICY_KEY)


def ticket_request_for(
    plan: Plan,
    *,
    operation: Operation | None = None,
    risk: Risk = Risk.LOW,
    approval_id: str | None = None,
) -> OperationTicketRequest:
    return OperationTicketRequest(
        transaction_id="tx-1",
        step_id="step-1",
        target_id=plan.target_id,
        target_fingerprint=plan.target_fingerprint,
        operation=operation or plan.operations[0],
        plan_digest=plan_digest(plan),
        risk=risk,
        approval_id=approval_id,
        ttl_seconds=30,
    )


def ticket_issuer() -> TicketIssuer:
    return TicketIssuer(
        TICKET_KEY,
        authorization_key=POLICY_KEY,
        clock=lambda: 100,
        ticket_id_factory=lambda: "ticket-1",
    )


def test_canonical_plan_is_nfc_sorted_compact_utf8_and_sha256_bound() -> None:
    decomposed = make_operation(
        parameters={"z": "cafe\u0301", "a": [1, True, None]},
    )
    composed = make_operation(
        parameters={"a": [1, True, None], "z": "caf\u00e9"},
    )
    first = make_plan(decomposed, target_fingerprint="machine-e\u0301")
    second = make_plan(composed, target_fingerprint="machine-\u00e9")

    encoded = canonical_plan_bytes(first)

    assert encoded == canonical_plan_bytes(second)
    assert b" " not in encoded
    assert "caf\u00e9".encode("utf-8") in encoded
    assert plan_digest(first) == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize(
    "parameters",
    [
        {"ratio": 0.5},
        {"payload": b"bytes"},
        {1: "non-string-key"},
    ],
)
def test_operation_rejects_non_canonical_json_values(parameters: object) -> None:
    with pytest.raises(ValidationError, match="JSON"):
        make_operation(parameters=parameters)


def test_operation_rejects_excessive_json_nesting() -> None:
    nested: object = "leaf"
    for _ in range(34):
        nested = [nested]

    with pytest.raises(ValidationError, match="nesting"):
        make_operation(parameters={"nested": nested})


def test_operation_rejects_json_objects_with_normalized_key_collisions() -> None:
    with pytest.raises(ValidationError, match="collide"):
        make_operation(parameters={"e\u0301": 1, "\u00e9": 2})


def test_operation_rejects_excessive_json_value_size() -> None:
    with pytest.raises(ValidationError, match="exceeds"):
        make_operation(parameters={"content": "x" * 262_144})


def test_canonical_plan_rejects_excessive_total_size() -> None:
    operations = tuple(
        make_operation(
            resource=f"service-{index}",
            parameters={"content": "x" * 220_000},
        )
        for index in range(5)
    )
    plan = Plan(
        target_id="lab",
        target_fingerprint="machine-1",
        operations=operations,
    )

    with pytest.raises(CanonicalPlanError, match="exceeds"):
        canonical_plan_bytes(plan)


def test_canonicalization_revalidates_mutable_model_dumps() -> None:
    operation = make_operation()
    plan = make_plan(operation)
    operation.parameters["content"] = 0.5

    with pytest.raises(CanonicalPlanError, match="invalid plan"):
        canonical_plan_bytes(plan)


def test_plan_rejects_duplicate_normalized_operation_triples() -> None:
    first = make_operation(resource="service-cafe\u0301")
    second = make_operation(resource="service-caf\u00e9")

    with pytest.raises(ValidationError, match="duplicate operation"):
        Plan(
            target_id="lab",
            target_fingerprint="machine-1",
            operations=(first, second),
        )


def test_plan_rejects_more_than_twenty_operations() -> None:
    operations = tuple(
        make_operation(resource=f"service-{index}") for index in range(21)
    )

    with pytest.raises(ValidationError, match="20"):
        Plan(
            target_id="lab",
            target_fingerprint="machine-1",
            operations=operations,
        )


def test_empty_plan_is_a_policy_budget_denial(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = Plan(
        target_id="lab",
        target_fingerprint="machine-1",
        operations=(),
    )

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is False
    assert decision.reason == "budget_exceeded"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", 121),
        ("output_limit_bytes", 0),
        ("output_limit_bytes", 262_145),
    ],
)
def test_operation_rejects_out_of_budget_values(field: str, value: int) -> None:
    with pytest.raises(ValidationError, match=field):
        make_operation(**{field: value})


@pytest.mark.parametrize(
    "resource",
    ["/etc/example/../shadow", "//etc/example/app.conf", "/etc/example/app.conf/", "C:\\temp"],
)
def test_operation_rejects_ambiguous_or_unsafe_path_resources(resource: str) -> None:
    with pytest.raises(ValidationError, match="resource"):
        make_operation(resource=resource)


def test_out_of_allowlist_is_denied_even_with_high_approval(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(resource="/etc/shadow"))

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.HIGH,
        approval_digest=plan_digest(plan),
    )

    assert decision.allowed is False
    assert decision.reason == "resource_not_allowed"


@pytest.mark.parametrize(
    ("grant_resources", "operation_resource", "allowed"),
    [
        (("/etc/example/app.conf",), "/etc/example/app.conf", True),
        (("/etc/example/**",), "/etc/example/app.conf", True),
        (("/etc/example/**",), "/etc/example", False),
        (("/etc/example/**",), "/etc/example-other/app.conf", False),
        (("example.service",), "example.service", True),
        (("example.service",), "other.service", False),
    ],
)
def test_resource_matching_is_exact_or_safe_descendant_only(
    tmp_path: Path,
    grant_resources: tuple[str, ...],
    operation_resource: str,
    allowed: bool,
) -> None:
    registry = write_registry(tmp_path)
    target = make_target(resources=grant_resources)
    engine = make_engine(registry, target)

    decision = engine.evaluate(
        target,
        make_plan(make_operation(resource=operation_resource)),
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is allowed
    assert decision.reason == ("auto_execute_low" if allowed else "resource_not_allowed")


def test_empty_action_grant_authorizes_no_write(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = TargetConfig(
        id="lab",
        mode="local",
        identity_ref="target/lab",
        write_enabled=True,
        auto_execute_low=True,
        capabilities=(
            CapabilityGrant(name="files", resources=("/etc/example/**",)),
        ),
    )
    engine = make_engine(registry, target)

    decision = engine.evaluate(
        target,
        make_plan(),
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.reason == "action_not_allowed"


def test_missing_capability_grant_is_denied(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target(capability="services")
    engine = make_engine(registry, target)

    decision = engine.evaluate(
        target,
        make_plan(),
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is False
    assert decision.reason == "capability_not_allowed"


def test_unregistered_operation_contract_is_denied(tmp_path: Path) -> None:
    registry = write_registry(tmp_path, action="create")
    target = make_target(action="replace")
    engine = make_engine(registry, target)

    decision = engine.evaluate(
        target,
        make_plan(),
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.reason == "operation_not_registered"


def test_parameter_schema_error_is_a_boundary_denial(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(parameters={"content": 123}))

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.HIGH,
        approval_digest=plan_digest(plan),
    )

    assert decision.allowed is False
    assert decision.reason == "parameter_schema_error"


@pytest.mark.parametrize("capability", ["network", "firewall", "ssh", "virtualization", "script"])
def test_core_high_capabilities_cannot_be_downgraded(
    tmp_path: Path, capability: str
) -> None:
    registry = write_registry(tmp_path, capability=capability)
    target = make_target(capability=capability)
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(capability=capability))

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.risk is Risk.HIGH
    assert decision.allowed is False
    assert decision.reason == "approval_required"


def test_high_risk_manifest_cannot_be_downgraded(tmp_path: Path) -> None:
    registry = write_registry(tmp_path, risk_floor=Risk.HIGH)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan()

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.risk is Risk.HIGH
    assert decision.allowed is False
    assert decision.reason == "approval_required"


def test_contract_floor_is_reflected_even_when_an_earlier_boundary_denies(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path, risk_floor=Risk.HIGH)
    target = make_target()
    engine = make_engine(registry, target, global_mode="read_only")

    decision = engine.evaluate(
        target,
        make_plan(),
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is False
    assert decision.risk is Risk.HIGH
    assert decision.reason == "global_read_only"


def test_non_reversible_write_is_high_and_can_only_use_matching_approval(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path, reversible=False)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(undo=None))

    missing = engine.evaluate(
        target, plan, critic_risk=Risk.LOW, approval_digest=None
    )
    mismatch = engine.evaluate(
        target, plan, critic_risk=Risk.LOW, approval_digest="0" * 64
    )
    approved = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=plan_digest(plan),
        approval_id="approval-1",
    )

    assert missing.risk is Risk.HIGH
    assert missing.reason == "approval_required"
    assert mismatch.reason == "approval_mismatch"
    assert approved.allowed is True
    assert approved.reason == "approved"
    assert approved.authorization is not None
    assert approved.authorization.approval_id == "approval-1"


def test_malformed_approval_digest_is_a_denial_not_an_exception(tmp_path: Path) -> None:
    registry = write_registry(tmp_path, risk_floor=Risk.HIGH)
    target = make_target()
    engine = make_engine(registry, target)

    decision = engine.evaluate(
        target,
        make_plan(),
        critic_risk=Risk.LOW,
        approval_digest="not-a-digest-\u00e9",
    )

    assert decision.allowed is False
    assert decision.reason == "approval_mismatch"


def test_policy_evaluates_the_same_snapshot_that_it_digests(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan()
    original_require = registry.require_operation

    def mutating_lookup(capability: str, action: str):  # type: ignore[no-untyped-def]
        plan.operations[0].parameters["content"] = 123
        return original_require(capability, action)

    object.__setattr__(registry, "require_operation", mutating_lookup)

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is True
    assert decision.reason == "auto_execute_low"


@pytest.mark.parametrize(
    "contract_overrides",
    [
        {"supports_prepare": False},
        {"supports_verify": False},
        {"supports_reconcile": False},
        {"supports_undo": False},
    ],
)
def test_executable_contract_requires_prepare_verify_and_reconcile(
    tmp_path: Path, contract_overrides: dict[str, bool]
) -> None:
    registry = write_registry(tmp_path, **contract_overrides)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan()

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.HIGH,
        approval_digest=plan_digest(plan),
    )

    assert decision.allowed is False
    assert decision.reason == "missing_recovery_support"
    assert decision.authorization is None


def test_irreversibility_raises_risk_even_when_recovery_boundary_denies(
    tmp_path: Path,
) -> None:
    registry = write_registry(
        tmp_path,
        reversible=False,
        supports_reconcile=False,
    )
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(undo=None))

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=plan_digest(plan),
    )

    assert decision.allowed is False
    assert decision.risk is Risk.HIGH
    assert decision.reason == "missing_recovery_support"


def test_reversible_contract_requires_non_null_undo(tmp_path: Path) -> None:
    registry = write_registry(tmp_path, reversible=True)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(undo=None))

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.HIGH,
        approval_digest=plan_digest(plan),
    )

    assert decision.reason == "missing_recovery_support"


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("global_read_only", "global_read_only"),
        ("target_not_registered", "target_not_registered"),
        ("target_mismatch", "target_mismatch"),
        ("target_read_only", "target_read_only"),
        ("target_id_mismatch", "target_id_mismatch"),
        ("target_fingerprint_missing", "target_fingerprint_missing"),
    ],
)
def test_policy_denies_target_and_global_boundary_failures(
    tmp_path: Path, case: str, reason: str
) -> None:
    registry = write_registry(tmp_path)
    configured = make_target()
    supplied = configured
    plan = make_plan()
    global_mode = "read_write"

    if case == "global_read_only":
        global_mode = "read_only"
    elif case == "target_not_registered":
        supplied = make_target(target_id="other")
        plan = make_plan(target_id="other")
    elif case == "target_mismatch":
        supplied = configured.model_copy(update={"notification_required": True})
    elif case == "target_read_only":
        configured = make_target(write_enabled=False)
        supplied = configured
    elif case == "target_id_mismatch":
        plan = make_plan(target_id="other")
    elif case == "target_fingerprint_missing":
        plan = make_plan(target_fingerprint="   ")

    engine = make_engine(registry, configured, global_mode=global_mode)
    decision = engine.evaluate(
        supplied,
        plan,
        critic_risk=Risk.HIGH,
        approval_digest=plan_digest(plan),
    )

    assert decision.allowed is False
    assert decision.reason == reason


@pytest.mark.parametrize(
    ("global_auto", "target_auto"),
    [(False, True), (True, False)],
)
def test_low_auto_execution_requires_global_and_target_opt_in(
    tmp_path: Path, global_auto: bool, target_auto: bool
) -> None:
    registry = write_registry(tmp_path)
    target = make_target(auto_execute_low=target_auto)
    engine = make_engine(registry, target, auto_execute_low=global_auto)

    decision = engine.evaluate(
        target,
        make_plan(),
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is False
    assert decision.reason == "auto_execute_disabled"


@pytest.mark.parametrize(
    ("planner_risk", "critic_risk"),
    [(Risk.HIGH, Risk.LOW), (Risk.LOW, Risk.HIGH)],
)
def test_planner_or_critic_high_vote_requires_approval(
    tmp_path: Path, planner_risk: Risk, critic_risk: Risk
) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(model_risk=planner_risk))

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=critic_risk,
        approval_digest=None,
    )

    assert decision.risk is Risk.HIGH
    assert decision.reason == "approval_required"


def test_low_plan_is_allowed_only_after_all_low_boundaries_pass(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan()

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
    )

    assert decision.allowed is True
    assert decision.risk is Risk.LOW
    assert decision.reason == "auto_execute_low"
    assert decision.digest == plan_digest(plan)


def test_allowed_low_decision_contains_authenticated_operation_authorization(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan()

    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
        approval_id=None,
    )

    assert decision.allowed is True
    assert decision.authorization is not None
    assert decision.authorization.target_id == plan.target_id
    assert decision.authorization.target_fingerprint == plan.target_fingerprint
    assert decision.authorization.plan_digest == plan_digest(plan)
    assert decision.authorization.risk is Risk.LOW
    assert decision.authorization.approval_id is None
    assert decision.authorization.operation_digests == (
        canonical_operation_digest(plan.operations[0]),
    )
    assert policy_authorization_is_authentic(decision.authorization, POLICY_KEY)


def test_authorization_supports_every_policy_valid_fingerprint_size(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    plan = make_plan(target_fingerprint="f" * 20_000)

    decision = make_engine(registry, target).evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
        approval_id=None,
    )

    assert decision.allowed is True
    assert decision.authorization is not None
    assert policy_authorization_is_authentic(decision.authorization, POLICY_KEY)


def test_denied_decision_has_no_authorization_and_cannot_mint(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    engine = make_engine(registry, target)
    plan = make_plan(make_operation(resource="/etc/shadow"))
    decision = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
        approval_id=None,
    )

    assert decision.allowed is False
    assert decision.authorization is None
    with pytest.raises(TicketError, match="authorization") as caught:
        ticket_issuer().issue(ticket_request_for(plan), decision.authorization)
    assert caught.value.code == "invalid_authorization"


def test_manually_constructed_allowed_decision_cannot_mint(tmp_path: Path) -> None:
    plan = make_plan()
    fake_authorization = PolicyAuthorization(
        target_id=plan.target_id,
        target_fingerprint=plan.target_fingerprint,
        plan_digest=plan_digest(plan),
        risk=Risk.LOW,
        approval_id=None,
        operation_digests=(canonical_operation_digest(plan.operations[0]),),
        mac="0" * 64,
    )
    fake_decision = PolicyDecision(
        allowed=True,
        risk=Risk.LOW,
        reason="auto_execute_low",
        digest=plan_digest(plan),
        authorization=fake_authorization,
    )

    with pytest.raises(TicketError, match="authorization") as caught:
        ticket_issuer().issue(ticket_request_for(plan), fake_decision.authorization)

    assert caught.value.code == "invalid_authorization"


def test_tampered_allowed_authorization_cannot_mint(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    plan = make_plan()
    decision = make_engine(registry, target).evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
        approval_id=None,
    )
    assert decision.authorization is not None
    tampered = decision.authorization.model_copy(update={"target_id": "other"})

    with pytest.raises(TicketError, match="authorization") as caught:
        ticket_issuer().issue(ticket_request_for(plan), tampered)

    assert caught.value.code == "invalid_authorization"


@pytest.mark.parametrize("high_source", ["critic", "manifest", "irreversible"])
def test_policy_high_sources_cannot_mint_a_low_ticket(
    tmp_path: Path, high_source: str
) -> None:
    risk_floor = Risk.HIGH if high_source == "manifest" else Risk.LOW
    reversible = high_source != "irreversible"
    registry = write_registry(
        tmp_path,
        risk_floor=risk_floor,
        reversible=reversible,
    )
    target = make_target()
    operation = (
        make_operation(undo=None)
        if high_source == "irreversible"
        else make_operation()
    )
    plan = make_plan(operation)
    critic_risk = Risk.HIGH if high_source == "critic" else Risk.LOW
    decision = make_engine(registry, target).evaluate(
        target,
        plan,
        critic_risk=critic_risk,
        approval_digest=plan_digest(plan),
        approval_id="approval-1",
    )
    assert decision.allowed is True
    assert decision.risk is Risk.HIGH
    assert decision.authorization is not None
    low_request = ticket_request_for(plan, risk=Risk.LOW, approval_id=None)

    with pytest.raises(TicketError) as caught:
        ticket_issuer().issue(low_request, decision.authorization)

    assert caught.value.code == "authorization_risk_mismatch"


def test_high_authorization_requires_and_binds_exact_approval(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path, risk_floor=Risk.HIGH)
    target = make_target()
    plan = make_plan()
    engine = make_engine(registry, target)

    missing_id = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=plan_digest(plan),
        approval_id=None,
    )
    mismatched_digest = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest="0" * 64,
        approval_id="approval-1",
    )
    approved = engine.evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=plan_digest(plan),
        approval_id="approval-1",
    )

    assert missing_id.allowed is False
    assert missing_id.reason == "approval_required"
    assert missing_id.authorization is None
    assert mismatched_digest.allowed is False
    assert mismatched_digest.reason == "approval_mismatch"
    assert approved.allowed is True
    assert approved.authorization is not None
    assert approved.authorization.approval_id == "approval-1"

    correct_request = ticket_request_for(
        plan,
        risk=Risk.HIGH,
        approval_id="approval-1",
    )
    token = ticket_issuer().issue(correct_request, approved.authorization)

    class Replay:
        def consume(self, ticket_id: str) -> bool:
            return True

    claims = TicketVerifier(TICKET_KEY, Replay(), clock=lambda: 110).verify(
        token,
        OperationTicketExpectation(
            transaction_id=correct_request.transaction_id,
            step_id=correct_request.step_id,
            target_id=correct_request.target_id,
            target_fingerprint=correct_request.target_fingerprint,
            operation=correct_request.operation,
            plan_digest=correct_request.plan_digest,
            risk=correct_request.risk,
            approval_id=correct_request.approval_id,
        ),
    )
    assert claims.approval_id == "approval-1"

    wrong_approval = ticket_request_for(
        plan,
        risk=Risk.HIGH,
        approval_id="approval-2",
    )
    with pytest.raises(TicketError) as approval_error:
        ticket_issuer().issue(wrong_approval, approved.authorization)
    assert approval_error.value.code == "authorization_approval_mismatch"

    wrong_plan = correct_request.model_copy(update={"plan_digest": "b" * 64})
    with pytest.raises(TicketError) as plan_error:
        ticket_issuer().issue(wrong_plan, approved.authorization)
    assert plan_error.value.code == "authorization_plan_mismatch"


def test_operation_absent_from_authorized_plan_cannot_mint(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    plan = make_plan()
    decision = make_engine(registry, target).evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
        approval_id=None,
    )
    assert decision.authorization is not None
    different_operation = make_operation(resource="/etc/example/other.conf")
    request = ticket_request_for(plan, operation=different_operation)

    with pytest.raises(TicketError) as caught:
        ticket_issuer().issue(request, decision.authorization)

    assert caught.value.code == "operation_not_authorized"


def test_correct_low_authorization_mints_and_verifies(tmp_path: Path) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    plan = make_plan()
    decision = make_engine(registry, target).evaluate(
        target,
        plan,
        critic_risk=Risk.LOW,
        approval_digest=None,
        approval_id=None,
    )
    assert decision.authorization is not None
    request = ticket_request_for(plan)
    token = ticket_issuer().issue(request, decision.authorization)

    class Replay:
        def consume(self, ticket_id: str) -> bool:
            return True

    claims = TicketVerifier(TICKET_KEY, Replay(), clock=lambda: 110).verify(
        token,
        OperationTicketExpectation(
            transaction_id=request.transaction_id,
            step_id=request.step_id,
            target_id=request.target_id,
            target_fingerprint=request.target_fingerprint,
            operation=request.operation,
            plan_digest=request.plan_digest,
            risk=request.risk,
            approval_id=request.approval_id,
        ),
    )
    assert claims.risk is Risk.LOW


def test_policy_authorization_key_must_be_at_least_thirty_two_bytes(
    tmp_path: Path,
) -> None:
    registry = write_registry(tmp_path)
    target = make_target()
    settings = AgentSettings(
        global_mode="read_write",
        auto_execute_low=True,
        targets=(target,),
    )

    with pytest.raises(ValueError, match="key"):
        PolicyEngine(settings, registry, authorization_key=b"short")

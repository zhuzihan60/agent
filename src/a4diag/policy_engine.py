from __future__ import annotations

import hashlib
import hmac
import re

from jsonschema import Draft202012Validator
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from a4diag.domain import (
    CanonicalPlanError,
    CORE_HIGH_CAPABILITIES,
    Operation,
    Plan,
    Risk,
    TargetConfig,
    canonical_json_bytes,
    plan_digest,
)
from a4diag.plugin_api.manifest import OperationContract
from a4diag.plugin_registry import PluginRegistry, PluginRegistryError
from a4diag.settings import AgentSettings


MAX_PLAN_OPERATIONS = 20
MAX_PLAN_TIMEOUT_SECONDS = MAX_PLAN_OPERATIONS * 120
MAX_PLAN_OUTPUT_BYTES = MAX_PLAN_OPERATIONS * 262_144
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
POLICY_AUTHORIZATION_PREFIX = b"a4diag-policy-authorization-v1\x00"
_POLICY_AUTHORIZATION_MAX_BYTES = 1_052_672


class PolicyAuthorizationError(ValueError):
    """Policy authorization configuration or canonicalization is invalid."""


class PolicyAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    target_fingerprint: str
    plan_digest: str
    risk: Risk
    approval_id: str | None
    operation_digests: tuple[str, ...] = Field(min_length=1, max_length=20)
    mac: str

    @field_validator("target_id")
    @classmethod
    def validate_target_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _TARGET_ID.fullmatch(value):
            raise ValueError("target_id must be a safe identifier")
        return value

    @field_validator("target_fingerprint")
    @classmethod
    def validate_target_fingerprint(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("target_fingerprint must not be blank")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("target_fingerprint must not contain control characters")
        return value

    @field_validator("plan_digest")
    @classmethod
    def validate_plan_digest(cls, value: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValueError("plan_digest must be a lowercase SHA256 digest")
        return value

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise ValueError("approval_id must be a safe nonblank identifier")
        return value

    @field_validator("operation_digests")
    @classmethod
    def validate_operation_digests(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if any(
            not isinstance(value, str) or not _SHA256.fullmatch(value)
            for value in values
        ):
            raise ValueError("operation digests must be lowercase SHA256 digests")
        if len(values) != len(set(values)):
            raise ValueError("duplicate authorized operation digest")
        return values

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValueError("authorization MAC must be lowercase HMAC-SHA256")
        return value

    @model_validator(mode="after")
    def validate_approval_binding(self) -> PolicyAuthorization:
        if self.risk is Risk.HIGH and self.approval_id is None:
            raise ValueError("approval_id is required for HIGH authorization")
        if self.risk is Risk.LOW and self.approval_id is not None:
            raise ValueError("LOW authorization must not contain approval_id")
        return self


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    risk: Risk
    reason: str
    digest: str
    authorization: PolicyAuthorization | None = None

    @model_validator(mode="after")
    def validate_authorization_state(self) -> PolicyDecision:
        if not self.allowed:
            if self.authorization is not None:
                raise ValueError("denied policy decision must not contain authorization")
            return self
        if self.authorization is None:
            raise ValueError("allowed policy decision requires authorization")
        if self.authorization.risk is not self.risk:
            raise ValueError("authorization risk must match policy decision")
        if self.authorization.plan_digest != self.digest:
            raise ValueError("authorization digest must match policy decision")
        return self


class PolicyEngine:
    """Fail-closed core gate for immutable plans and enabled contracts."""

    def __init__(
        self,
        settings: AgentSettings,
        registry: PluginRegistry,
        *,
        authorization_key: bytes,
    ) -> None:
        if not isinstance(settings, AgentSettings):
            raise TypeError("settings must be AgentSettings")
        if not isinstance(registry, PluginRegistry):
            raise TypeError("registry must be PluginRegistry")
        self._settings = settings
        self._registry = registry
        self._authorization_key = _validate_authorization_key(authorization_key)

    @property
    def settings(self) -> AgentSettings:
        return self._settings

    @property
    def registry(self) -> PluginRegistry:
        return self._registry

    def evaluate(
        self,
        target: TargetConfig,
        plan: Plan,
        *,
        critic_risk: Risk,
        approval_digest: str | None,
        approval_id: str | None = None,
    ) -> PolicyDecision:
        if not isinstance(target, TargetConfig):
            raise TypeError("target must be TargetConfig")
        if not isinstance(plan, Plan):
            raise TypeError("plan must be Plan")
        if not isinstance(critic_risk, Risk):
            raise TypeError("critic_risk must be Risk")

        try:
            evaluated_plan = Plan.model_validate(plan.model_dump(mode="python"))
            digest = plan_digest(evaluated_plan)
        except (CanonicalPlanError, ValueError, TypeError):
            return _decision(False, Risk.HIGH, "invalid_plan", "")
        risk = _initial_risk(evaluated_plan, critic_risk)
        contracts: list[OperationContract | None] = []
        for operation in evaluated_plan.operations:
            try:
                contract = self._registry.require_operation(
                    operation.capability, operation.action
                )
            except PluginRegistryError:
                contract = None
            contracts.append(contract)
            if contract is not None and (
                contract.risk_floor is Risk.HIGH or not contract.reversible
            ):
                risk = Risk.HIGH

        if self._settings.global_mode != "read_write":
            return _decision(False, risk, "global_read_only", digest)

        configured = next(
            (candidate for candidate in self._settings.targets if candidate.id == target.id),
            None,
        )
        if configured is None:
            return _decision(False, risk, "target_not_registered", digest)
        if target != configured:
            return _decision(False, risk, "target_mismatch", digest)
        if not configured.write_enabled:
            return _decision(False, risk, "target_read_only", digest)
        if evaluated_plan.target_id != configured.id:
            return _decision(False, risk, "target_id_mismatch", digest)
        if not evaluated_plan.target_fingerprint.strip():
            return _decision(False, risk, "target_fingerprint_missing", digest)
        if not _within_budgets(evaluated_plan):
            return _decision(False, risk, "budget_exceeded", digest)

        for operation, contract in zip(evaluated_plan.operations, contracts, strict=True):
            grant = next(
                (
                    candidate
                    for candidate in configured.capabilities
                    if candidate.name == operation.capability
                ),
                None,
            )
            if grant is None:
                return _decision(False, risk, "capability_not_allowed", digest)
            if operation.action not in grant.actions:
                return _decision(False, risk, "action_not_allowed", digest)
            if not any(
                _resource_matches(allowed, operation.resource)
                for allowed in grant.resources
            ):
                return _decision(False, risk, "resource_not_allowed", digest)

            if contract is None:
                return _decision(False, risk, "operation_not_registered", digest)

            validator = Draft202012Validator(contract.parameters_schema)
            if next(validator.iter_errors(operation.parameters), None) is not None:
                return _decision(False, risk, "parameter_schema_error", digest)

            if not (
                contract.supports_prepare
                and contract.supports_verify
                and contract.supports_reconcile
                and (not contract.reversible or contract.supports_undo)
            ):
                return _decision(False, risk, "missing_recovery_support", digest)
            if not operation.verify:
                return _decision(False, risk, "missing_recovery_support", digest)
            if contract.reversible and operation.undo is None:
                return _decision(False, risk, "missing_recovery_support", digest)

        if risk is Risk.HIGH:
            if approval_digest is None or (
                isinstance(approval_digest, str) and not approval_digest.strip()
            ):
                return _decision(False, risk, "approval_required", digest)
            if not isinstance(approval_digest, str) or not _SHA256.fullmatch(
                approval_digest
            ):
                return _decision(False, risk, "approval_mismatch", digest)
            if not hmac.compare_digest(approval_digest, digest):
                return _decision(False, risk, "approval_mismatch", digest)
            if approval_id is None or (
                isinstance(approval_id, str) and not approval_id.strip()
            ):
                return _decision(False, risk, "approval_required", digest)
            if not isinstance(approval_id, str) or not _SAFE_ID.fullmatch(approval_id):
                return _decision(False, risk, "approval_mismatch", digest)
            authorization = _issue_authorization(
                evaluated_plan,
                digest,
                risk,
                approval_id,
                self._authorization_key,
            )
            return _decision(True, risk, "approved", digest, authorization)

        if not self._settings.auto_execute_low or not configured.auto_execute_low:
            return _decision(False, risk, "auto_execute_disabled", digest)
        authorization = _issue_authorization(
            evaluated_plan,
            digest,
            risk,
            None,
            self._authorization_key,
        )
        return _decision(True, risk, "auto_execute_low", digest, authorization)


def _initial_risk(plan: Plan, critic_risk: Risk) -> Risk:
    if critic_risk is Risk.HIGH:
        return Risk.HIGH
    for operation in plan.operations:
        if (
            operation.model_risk is Risk.HIGH
            or operation.capability in CORE_HIGH_CAPABILITIES
        ):
            return Risk.HIGH
    return Risk.LOW


def _within_budgets(plan: Plan) -> bool:
    if not 1 <= len(plan.operations) <= MAX_PLAN_OPERATIONS:
        return False
    if any(
        not 1 <= operation.timeout_seconds <= 120
        or not 1 <= operation.output_limit_bytes <= 262_144
        for operation in plan.operations
    ):
        return False
    return (
        sum(operation.timeout_seconds for operation in plan.operations)
        <= MAX_PLAN_TIMEOUT_SECONDS
        and sum(operation.output_limit_bytes for operation in plan.operations)
        <= MAX_PLAN_OUTPUT_BYTES
    )


def _resource_matches(allowed: str, requested: str) -> bool:
    if allowed == requested:
        return True
    if not allowed.endswith("/**"):
        return False
    base = allowed[:-3]
    return requested.startswith(f"{base}/")


def canonical_operation_digest(operation: Operation) -> str:
    if not isinstance(operation, Operation):
        raise CanonicalPlanError("invalid operation: expected Operation")
    try:
        snapshot = Operation.model_validate(operation.model_dump(mode="python"))
        encoded = canonical_json_bytes(
            snapshot.model_dump(mode="json"),
            max_bytes=1_048_576,
        )
    except (CanonicalPlanError, ValueError, TypeError) as error:
        raise CanonicalPlanError(f"invalid operation: {error}") from error
    return hashlib.sha256(encoded).hexdigest()


def policy_authorization_is_authentic(
    authorization: PolicyAuthorization,
    key: bytes,
) -> bool:
    if not isinstance(authorization, PolicyAuthorization):
        return False
    if type(key) is not bytes or len(key) < 32:
        return False
    if not isinstance(authorization.mac, str) or not _SHA256.fullmatch(
        authorization.mac
    ):
        return False
    try:
        expected = _authorization_mac(authorization, key)
    except (CanonicalPlanError, ValueError, TypeError):
        return False
    return hmac.compare_digest(authorization.mac, expected)


def _validate_authorization_key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) < 32:
        raise PolicyAuthorizationError(
            "policy authorization key must be at least 32 bytes"
        )
    return key


def _authorization_mac(authorization: PolicyAuthorization, key: bytes) -> str:
    payload = canonical_json_bytes(
        authorization.model_dump(mode="json", exclude={"mac"}),
        max_bytes=_POLICY_AUTHORIZATION_MAX_BYTES,
    )
    return hmac.new(
        key,
        POLICY_AUTHORIZATION_PREFIX + payload,
        hashlib.sha256,
    ).hexdigest()


def _issue_authorization(
    plan: Plan,
    digest: str,
    risk: Risk,
    approval_id: str | None,
    key: bytes,
) -> PolicyAuthorization:
    unsigned = {
        "target_id": plan.target_id,
        "target_fingerprint": plan.target_fingerprint,
        "plan_digest": digest,
        "risk": risk,
        "approval_id": approval_id,
        "operation_digests": tuple(
            canonical_operation_digest(operation) for operation in plan.operations
        ),
    }
    placeholder = PolicyAuthorization(**unsigned, mac="0" * 64)
    return placeholder.model_copy(update={"mac": _authorization_mac(placeholder, key)})


def _decision(
    allowed: bool,
    risk: Risk,
    reason: str,
    digest: str,
    authorization: PolicyAuthorization | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        allowed=allowed,
        risk=risk,
        reason=reason,
        digest=digest,
        authorization=authorization,
    )

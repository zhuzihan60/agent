from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, TypedDict, cast

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, interrupt
from pydantic import BaseModel, ConfigDict, JsonValue

from a4diag.approvals import (
    ApprovalStateError,
    ApprovalStatus,
    ApprovalStore,
    NotificationStatus,
)
from a4diag.domain import (
    Operation,
    Plan,
    Risk,
    StepResult,
    TargetConfig,
    canonical_json_bytes,
    plan_digest,
)
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketRequest,
    TicketIssuer,
    effect_payload_digest,
)
from a4diag.plugin_registry import PluginRegistry
from a4diag.policy_engine import PolicyAuthorization, PolicyEngine
from a4diag.settings import AgentSettings
from a4diag.redaction import redact
from a4diag.transaction_store import (
    DispatchStatus,
    EffectPhase,
    PreparedStep,
    RecoveryAction,
    TransactionResultRecord,
    TransactionStatus,
    TransactionStore,
    UnknownTransactionError,
)


ReconcileResult = Literal["not_applied", "applied", "partial", "unknown"]


class CollectorPort(Protocol):
    def verify_identity(self, target: TargetConfig) -> str: ...

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str: ...

    def collect(
        self, target: TargetConfig, read_view: str
    ) -> list[dict[str, JsonValue]]: ...

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, JsonValue]],
    ) -> StepResult: ...


class ModelPort(Protocol):
    def diagnose(
        self, target: TargetConfig, evidence: list[dict[str, JsonValue]]
    ) -> dict[str, JsonValue]: ...

    def plan(
        self,
        target: TargetConfig,
        evidence: list[dict[str, JsonValue]],
        diagnosis: dict[str, JsonValue],
    ) -> Plan: ...

    def critic(
        self,
        target: TargetConfig,
        evidence: list[dict[str, JsonValue]],
        plan: Plan,
    ) -> Risk: ...


class PreparedEffect(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pre_state: dict[str, JsonValue]
    marker: dict[str, JsonValue]


class ReconcileEffect(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: ReconcileResult
    prepared: PreparedEffect | None = None


class ExecutorPort(Protocol):
    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        ticket: str,
    ) -> PreparedEffect: ...

    def apply(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, JsonValue],
        ticket: str,
    ) -> StepResult: ...

    def verify(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, JsonValue],
    ) -> StepResult: ...

    def undo(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, JsonValue],
        undo: dict[str, JsonValue] | None,
        ticket: str,
    ) -> StepResult: ...

    def reconcile(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        phase: OperationPhase,
        dispatch_id: str,
        marker: dict[str, JsonValue] | None,
    ) -> ReconcileEffect: ...

    def verify_restored(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, JsonValue],
        pre_state: dict[str, JsonValue],
    ) -> StepResult: ...


class NotificationPort(Protocol):
    def send_approval(
        self,
        target: TargetConfig,
        transaction_id: str,
        digest: str,
        plan: Plan,
        risk: Risk,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class PluginPorts:
    model: ModelPort
    collector: CollectorPort
    executor: ExecutorPort
    notifier: NotificationPort


@dataclass(frozen=True, slots=True)
class WorkflowDependencies:
    settings: AgentSettings
    registry: PluginRegistry
    policy: PolicyEngine
    approvals: ApprovalStore
    transactions: TransactionStore
    tickets: TicketIssuer
    plugins: PluginPorts
    checkpointer: BaseCheckpointSaver
    clock: Callable[[], int] = lambda: int(time.time())
    approval_ttl_seconds: int = 900
    ticket_ttl_seconds: int = 30

    def __post_init__(self) -> None:
        if not isinstance(self.settings, AgentSettings):
            raise TypeError("settings must be AgentSettings")
        if not isinstance(self.registry, PluginRegistry):
            raise TypeError("registry must be PluginRegistry")
        if not isinstance(self.policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        if self.policy.settings != self.settings or self.policy.registry is not self.registry:
            raise ValueError("policy must be bound to the current settings and registry")
        if not isinstance(self.approvals, ApprovalStore):
            raise TypeError("approvals must be ApprovalStore")
        if not isinstance(self.transactions, TransactionStore):
            raise TypeError("transactions must be TransactionStore")
        if not isinstance(self.tickets, TicketIssuer):
            raise TypeError("tickets must be TicketIssuer")
        if not isinstance(self.plugins, PluginPorts):
            raise TypeError("plugins must be PluginPorts")
        if not isinstance(self.checkpointer, BaseCheckpointSaver):
            raise TypeError("checkpointer must be a LangGraph checkpointer")
        if not callable(self.clock):
            raise TypeError("clock must be callable")
        if not 1 <= self.approval_ttl_seconds <= 86_400:
            raise ValueError("approval_ttl_seconds must be between 1 and 86400")
        if not 1 <= self.ticket_ttl_seconds <= 300:
            raise ValueError("ticket_ttl_seconds must be between 1 and 300")


class AgentState(TypedDict, total=False):
    event_id: str
    transaction_id: str
    target_id: str
    target_fingerprint: str
    request: JsonValue
    read_view: str
    evidence: list[dict[str, JsonValue]]
    diagnosis: dict[str, JsonValue]
    missing_evidence: list[str]
    evidence_rounds: int
    recovery_result: dict[str, JsonValue]
    recovery_evidence: list[dict[str, JsonValue]]
    plan: dict[str, JsonValue]
    digest: str
    risk: str
    critic_risk: str
    policy_reason: str
    authorization: dict[str, JsonValue]
    approval_id: str
    notification_delivered: bool
    next_step: int
    verify_step: int
    applied_steps: list[int]
    undo_steps: list[int]
    rollback_failed: bool
    rollback_unknown: bool
    restored_steps: list[int]
    uncertain_step: int
    unknown_phase: str
    dispatch_id: str
    reconcile_attempted: bool
    incomplete_after_reconcile: bool
    status: str
    error: str
    audit_events: list[dict[str, JsonValue]]
    report: dict[str, JsonValue]


def build_graph(deps: WorkflowDependencies) -> CompiledStateGraph:
    """Compile the policy-owned workflow around injected, effect-only plugin ports."""

    if not isinstance(deps, WorkflowDependencies):
        raise TypeError("deps must be WorkflowDependencies")

    def target_for(state: AgentState) -> TargetConfig:
        target_id = state.get("target_id", "")
        for target in deps.settings.targets:
            if target.id == target_id:
                return target
        raise LookupError(f"unregistered target: {target_id}")

    def now() -> int:
        value = deps.clock()
        if type(value) is not int or value < 0:
            raise ValueError("workflow clock must return a non-negative integer")
        return value

    def audit(
        state: AgentState, kind: str, **details: JsonValue
    ) -> list[dict[str, JsonValue]]:
        events = list(state.get("audit_events", []))
        events.append({"kind": kind, "at": now(), **details})
        return events

    def plan_for(state: AgentState) -> Plan:
        return Plan.model_validate(state["plan"])

    def prepared_for(state: AgentState, index: int) -> tuple[Operation, dict[str, JsonValue]]:
        prepared = deps.transactions.get_steps(state["transaction_id"])[index]
        operation = Operation.model_validate(json.loads(prepared.operation_json))
        marker = cast(dict[str, JsonValue], json.loads(prepared.plugin_marker_json))
        return operation, marker

    def durable_completed_results(
        state: AgentState, phase: EffectPhase
    ) -> dict[int, TransactionResultRecord]:
        transaction_id = state["transaction_id"]
        completed = {
            (dispatch.step_id, dispatch.phase)
            for dispatch in deps.transactions.get_dispatches(transaction_id)
            if dispatch.status is DispatchStatus.COMPLETED
        }
        return {
            int(result.step_id): result
            for result in deps.transactions.get_results(transaction_id)
            if result.phase == phase.value
            and (result.step_id, phase) in completed
        }

    def write_authorization(
        state: AgentState, operation: Operation
    ) -> tuple[TargetConfig, PolicyAuthorization]:
        target = target_for(state)
        current_fingerprint = deps.plugins.collector.verify_identity(target)
        candidate = plan_for(state)
        if (
            current_fingerprint != state["target_fingerprint"]
            or current_fingerprint != candidate.target_fingerprint
            or candidate.target_id != target.id
            or plan_digest(candidate) != state["digest"]
            or operation not in candidate.operations
        ):
            raise PermissionError("target_or_plan_identity_changed")
        approval_digest: str | None = None
        approval_id: str | None = None
        if Risk(state["risk"]) is Risk.HIGH:
            approval = deps.approvals.valid_approval(
                state["transaction_id"],
                expected_digest=state["digest"],
                expected_target=state["target_id"],
                now=now(),
            )
            if approval is None or approval.id != state.get("approval_id"):
                raise PermissionError("approval_expired_or_changed")
            approval_digest = approval.plan_digest
            approval_id = approval.id
        decision = deps.policy.evaluate(
            target,
            candidate,
            critic_risk=Risk(state["critic_risk"]),
            approval_digest=approval_digest,
            approval_id=approval_id,
        )
        if (
            not decision.allowed
            or decision.authorization is None
            or decision.digest != state["digest"]
        ):
            raise PermissionError(f"policy_revalidation_failed:{decision.reason}")
        return target, decision.authorization

    def issue_effect_ticket(
        state: AgentState,
        operation: Operation,
        step_id: str,
        phase: OperationPhase,
        effect_fields: dict[str, JsonValue] | None = None,
    ) -> tuple[TargetConfig, str]:
        if phase in {OperationPhase.PREPARE, OperationPhase.APPLY}:
            ready = decision_readiness(state)
            if not ready.ok:
                raise PermissionError(ready.status)
        target, authorization = write_authorization(state, operation)
        request = OperationTicketRequest(
            transaction_id=state["transaction_id"],
            step_id=step_id,
            target_id=state["target_id"],
            target_fingerprint=state["target_fingerprint"],
            operation=operation,
            phase=phase,
            plan_digest=state["digest"],
            risk=Risk(state["risk"]),
            approval_id=state.get("approval_id"),
            effect_payload_digest=effect_payload_digest(effect_fields or {}),
            ttl_seconds=deps.ticket_ttl_seconds,
        )
        return target, deps.tickets.issue(request, authorization)

    def dispatch_id(state: AgentState, phase: OperationPhase, step_id: str) -> str:
        return f"{state['transaction_id']}:{phase.value}:{step_id}"

    def ingest(state: AgentState) -> AgentState:
        event_id = state.get("event_id")
        target_id = state.get("target_id")
        if not event_id or not target_id:
            return {
                "status": "failed",
                "error": "event_id_and_target_id_required",
                "audit_events": audit(state, "invalid_event"),
            }
        transaction_id = state.get("transaction_id") or event_id
        if transaction_id != event_id:
            return {
                "status": "failed",
                "error": "transaction_id_must_equal_event_id",
                "audit_events": audit(state, "invalid_event"),
            }
        return {
            "transaction_id": transaction_id,
            "status": "read_only",
            "audit_events": audit(state, "event_ingested"),
        }

    def resolve_target(state: AgentState) -> AgentState:
        if state.get("status") == "failed":
            return {}
        try:
            target = target_for(state)
            fingerprint = deps.plugins.collector.verify_identity(target)
        except Exception as error:
            return {
                "status": "policy_denied",
                "error": f"target_resolution_failed:{type(error).__name__}",
                "audit_events": audit(state, "target_resolution_failed"),
            }
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            return {
                "status": "policy_denied",
                "error": "target_identity_missing",
                "audit_events": audit(state, "target_identity_missing"),
            }
        return {
            "target_fingerprint": fingerprint,
            "audit_events": audit(state, "target_resolved"),
        }

    def acquire_read_view(state: AgentState) -> AgentState:
        try:
            view = deps.plugins.collector.acquire_read_view(
                target_for(state), state["target_fingerprint"]
            )
        except Exception as error:
            return {
                "status": "failed",
                "error": f"read_view_failed:{type(error).__name__}",
                "audit_events": audit(state, "read_view_failed"),
            }
        if not isinstance(view, str) or not view:
            return {
                "status": "failed",
                "error": "read_view_missing",
                "audit_events": audit(state, "read_view_failed"),
            }
        return {
            "read_view": view,
            "audit_events": audit(state, "read_view_acquired"),
        }

    def collect(state: AgentState) -> AgentState:
        try:
            evidence = deps.plugins.collector.collect(
                target_for(state), state["read_view"]
            )
        except Exception as error:
            return {
                "status": "failed",
                "error": f"collection_failed:{type(error).__name__}",
                "audit_events": audit(state, "collection_failed"),
            }
        return {
            "evidence": cast(list[dict[str, JsonValue]], redact(evidence)),
            "audit_events": audit(state, "evidence_collected"),
        }

    def model_evidence(state: AgentState) -> list[dict[str, JsonValue]]:
        evidence = list(state.get("evidence", []))
        if state.get("request") is not None:
            evidence.append({"kind": "request", "content": redact(state["request"])})
        return evidence

    def diagnose(state: AgentState) -> AgentState:
        try:
            diagnosis = deps.plugins.model.diagnose(
                target_for(state), model_evidence(state)
            )
        except Exception as error:
            return {
                "status": "read_only_no_model",
                "error": f"model_diagnose_failed:{type(error).__name__}",
                "audit_events": audit(state, "model_failed", node="diagnose"),
            }
        missing = diagnosis.get("missing_evidence", [])
        target = target_for(state)
        catalog = {source.id for source in target.evidence_sources}
        unavailable = any(row.get("available") is False for row in state.get("evidence", []))
        if (not isinstance(missing, list) or any(not isinstance(item, str) or item not in catalog for item in missing)
            or len(missing) > 8 or unavailable
            or (missing and state.get("evidence_rounds", 0) >= 2)):
            return {"diagnosis": diagnosis, "status": "insufficient_evidence", "error": "evidence_unavailable_or_unresolved"}
        if missing:
            return {"diagnosis": diagnosis, "missing_evidence": missing, "status": "collecting_evidence"}
        confidence = diagnosis.get("confidence")
        if type(confidence) not in {int, float} or not target.minimum_confidence <= confidence <= 1:
            return {"diagnosis": diagnosis, "status": "insufficient_evidence", "error": "diagnostic_confidence_too_low"}
        return {"diagnosis": diagnosis, "missing_evidence": [], "status": "diagnosed"}

    def collect_missing(state: AgentState) -> AgentState:
        try:
            collect_requested = getattr(deps.plugins.collector, "collect_requested")
            requested = state["missing_evidence"]
            extra = collect_requested(target_for(state), state["read_view"], requested)
            if (not isinstance(extra, list) or {row.get("source_id") for row in extra} != set(requested)
                or any(row.get("available") is not True for row in extra)):
                raise ValueError("requested evidence not available")
            # Replace prior snapshots for requested IDs; keep total evidence
            # bounded instead of accumulating duplicate log payloads on retries.
            combined = [row for row in state.get("evidence", []) if row.get("source_id") not in requested] + extra
            return {"evidence": cast(list[dict[str, JsonValue]], redact(combined)),
                    "evidence_rounds": state.get("evidence_rounds", 0) + 1,
                    "audit_events": audit(state, "supplementary_evidence_collected", source_ids=requested)}
        except Exception:
            return {"status": "insufficient_evidence", "error": "supplementary_collection_failed"}

    def plan_node(state: AgentState) -> AgentState:
        try:
            candidate = deps.plugins.model.plan(
                target_for(state),
                model_evidence(state),
                state.get("diagnosis", {}),
            )
            frozen = Plan.model_validate(candidate.model_dump(mode="python"))
        except Exception as error:
            return {
                "status": "read_only_no_model",
                "error": f"model_plan_failed:{type(error).__name__}",
                "audit_events": audit(state, "model_failed", node="plan"),
            }
        return {"plan": cast(dict[str, JsonValue], frozen.model_dump(mode="json"))}

    def critic(state: AgentState) -> AgentState:
        try:
            risk = deps.plugins.model.critic(
                target_for(state), model_evidence(state), plan_for(state)
            )
            risk = Risk(risk)
        except Exception as error:
            return {
                "status": "read_only_no_model",
                "error": f"model_critic_failed:{type(error).__name__}",
                "audit_events": audit(state, "model_failed", node="critic"),
            }
        return {"critic_risk": risk.value}

    def decision_readiness(state: AgentState) -> StepResult:
        target = target_for(state)
        confidence = state.get("diagnosis", {}).get("confidence")
        if type(confidence) not in {int, float} or not target.minimum_confidence <= confidence <= 1:
            return StepResult(ok=False, status="diagnostic_confidence_too_low")
        if state.get("diagnosis", {}).get("missing_evidence"):
            return StepResult(ok=False, status="diagnostic_evidence_missing")
        validate_recovery = getattr(deps.plugins.collector, "validate_recovery", None)
        if plan_for(state).operations and callable(validate_recovery):
            try:
                ready = StepResult.model_validate(validate_recovery(target))
            except Exception:
                ready = StepResult(ok=False, status="recovery_configuration_invalid")
            if not ready.ok:
                return ready
            catalog = {source.id: source for source in target.evidence_sources}
            snapshots = [row for row in state.get("evidence", []) if row.get("source_id") in catalog]
            required = {source.id for source in target.evidence_sources if source.initial}
            if not snapshots or not required.issubset({row.get("source_id") for row in snapshots}) or any(row.get("available") is not True
                                    or row.get("resource") != catalog[row["source_id"]].resource
                                    or row.get("kind") != catalog[row["source_id"]].kind for row in snapshots):
                return StepResult(ok=False, status="diagnostic_evidence_missing")
        return StepResult(ok=True, status="decision_ready")

    def policy_gate(state: AgentState) -> AgentState:
        candidate = plan_for(state)
        ready = decision_readiness(state)
        if not ready.ok:
            return {"status": "policy_denied", "error": ready.status, "policy_reason": ready.status,
                    "audit_events": audit(state, "recovery_configuration_denied")}
        if (
            candidate.target_id != state["target_id"]
            or candidate.target_fingerprint != state["target_fingerprint"]
        ):
            return {
                "status": "policy_denied",
                "risk": Risk.HIGH.value,
                "digest": plan_digest(candidate),
                "policy_reason": "target_fingerprint_mismatch",
                "error": "target_fingerprint_mismatch",
                "audit_events": audit(state, "target_fingerprint_mismatch"),
            }
        decision = deps.policy.evaluate(
            target_for(state),
            plan_for(state),
            critic_risk=Risk(state["critic_risk"]),
            approval_digest=None,
            approval_id=None,
        )
        update: AgentState = {
            "digest": decision.digest,
            "risk": decision.risk.value,
            "policy_reason": decision.reason,
            "audit_events": audit(
                state,
                "policy_evaluated",
                allowed=decision.allowed,
                reason=decision.reason,
                risk=decision.risk.value,
            ),
        }
        if decision.allowed and decision.authorization is not None:
            update["authorization"] = cast(
                dict[str, JsonValue], decision.authorization.model_dump(mode="json")
            )
            update["status"] = "policy_allowed"
        elif decision.reason == "approval_required":
            update["status"] = "pending_approval"
        else:
            update["status"] = "policy_denied"
            update["error"] = decision.reason
        return update

    def freeze_plan(state: AgentState) -> AgentState:
        candidate = Plan.model_validate(plan_for(state).model_dump(mode="python"))
        digest = plan_digest(candidate)
        if not state.get("digest") or state["digest"] != digest:
            return {
                "status": "policy_denied",
                "error": "plan_digest_changed",
                "audit_events": audit(state, "plan_digest_changed"),
            }
        update: AgentState = {
            "plan": cast(dict[str, JsonValue], candidate.model_dump(mode="json")),
            "digest": digest,
            "audit_events": audit(state, "plan_frozen", digest=digest),
        }
        if state["status"] != "pending_approval":
            return update

        requested_at = now()
        approval = deps.approvals.for_transaction(state["transaction_id"])
        if approval is None:
            approval = deps.approvals.request(
                state["transaction_id"],
                state["target_id"],
                digest,
                expires_at=requested_at + deps.approval_ttl_seconds,
                now=requested_at,
                notification_required=target_for(state).notification_required,
            )
        elif (
            approval.plan_digest != digest
            or approval.target_id != state["target_id"]
            or approval.notification_required
            != target_for(state).notification_required
        ):
            return {
                "status": "policy_denied",
                "error": "approval_request_binding_changed",
            }

        notification_status = deps.approvals.notification_status(approval.id)
        if notification_status is NotificationStatus.NOT_STARTED:
            deps.approvals.begin_notification(approval.id, now=requested_at)
            try:
                acknowledgement = deps.plugins.notifier.send_approval(
                    target_for(state),
                    state["transaction_id"],
                    digest,
                    candidate,
                    Risk(state["risk"]),
                )
                delivered = (
                    acknowledgement
                    if type(acknowledgement) is bool
                    else False
                )
            except Exception:
                delivered = False
            deps.approvals.complete_notification(
                approval.id, delivered=delivered, now=now()
            )
        elif notification_status is NotificationStatus.DISPATCHED:
            # A crash after dispatch has an unknowable delivery result. Never
            # resend: optional mode can still use local CLI; required mode blocks.
            delivered = False
            deps.approvals.complete_notification(
                approval.id, delivered=False, now=now()
            )
        else:
            delivered = notification_status is NotificationStatus.DELIVERED
        update["approval_id"] = approval.id
        update["notification_delivered"] = delivered
        if delivered:
            update["audit_events"] = audit(
                state, "approval_notification_delivered", approval_id=approval.id
            )
        else:
            update["audit_events"] = audit(
                state, "notification_failed", approval_id=approval.id
            )
            if target_for(state).notification_required:
                update["status"] = "notification_blocked"
                if approval.status is ApprovalStatus.PENDING:
                    try:
                        deps.approvals.reject(
                            approval.id,
                            actor="core:notification-barrier",
                            now=now(),
                        )
                    except ApprovalStateError:
                        pass
        return update

    def approval_gate(state: AgentState) -> AgentState:
        if Risk(state["risk"]) is Risk.LOW:
            return {}

        interrupt(
            {
                "status": state["status"],
                "transaction_id": state["transaction_id"],
                "approval_id": state["approval_id"],
                "target_id": state["target_id"],
                "digest": state["digest"],
            }
        )
        target = target_for(state)
        if target.notification_required and not state.get(
            "notification_delivered", False
        ):
            return {
                "status": "notification_blocked",
                "error": "mandatory_notification_failed",
            }

        ready = decision_readiness(state)
        if not ready.ok:
            return {"status": "policy_denied", "error": ready.status,
                    "audit_events": audit(state, "decision_revalidation_denied")}

        approval = deps.approvals.valid_approval(
            state["transaction_id"],
            expected_digest=state["digest"],
            expected_target=state["target_id"],
            now=now(),
        )
        if approval is None:
            record = deps.approvals.get(state["approval_id"])
            if record.status is ApprovalStatus.PENDING:
                interrupt(
                    {
                        "status": "pending_approval",
                        "transaction_id": state["transaction_id"],
                        "approval_id": record.id,
                        "target_id": state["target_id"],
                        "digest": state["digest"],
                    }
                )
            return {
                "status": "approval_expired",
                "error": f"approval_{record.status.value}",
                "audit_events": audit(
                    state, "approval_unavailable", status=record.status.value
                ),
            }

        try:
            current_fingerprint = deps.plugins.collector.verify_identity(target)
        except Exception as error:
            return {
                "status": "policy_denied",
                "error": f"target_revalidation_failed:{type(error).__name__}",
            }
        if current_fingerprint != state["target_fingerprint"]:
            return {
                "status": "policy_denied",
                "error": "target_identity_changed",
                "audit_events": audit(state, "target_identity_changed"),
            }

        decision = deps.policy.evaluate(
            target,
            plan_for(state),
            critic_risk=Risk(state["critic_risk"]),
            approval_digest=approval.plan_digest,
            approval_id=approval.id,
        )
        if not decision.allowed or decision.authorization is None:
            return {
                "status": "policy_denied",
                "error": decision.reason,
                "audit_events": audit(
                    state, "approval_policy_denied", reason=decision.reason
                ),
            }
        return {
            "status": "policy_allowed",
            "authorization": cast(
                dict[str, JsonValue], decision.authorization.model_dump(mode="json")
            ),
            "audit_events": audit(
                state, "approval_accepted", approval_id=approval.id
            ),
        }

    def prepare(state: AgentState) -> AgentState:
        transaction_id = state["transaction_id"]

        def invalid_durable_evidence(error: str) -> AgentState:
            try:
                current = deps.transactions.get(transaction_id)
                if current.status is TransactionStatus.EXECUTING:
                    deps.transactions.mark_unknown(transaction_id, now=now())
            except Exception:
                pass
            return {
                "status": "execution_unknown",
                "error": error,
                "reconcile_attempted": True,
            }

        candidate = plan_for(state)
        expected_operations = tuple(
            canonical_json_bytes(operation.model_dump(mode="json")).decode("utf-8")
            for operation in candidate.operations
        )
        try:
            existing = deps.transactions.get(transaction_id)
        except UnknownTransactionError:
            existing = deps.transactions.begin(
                transaction_id,
                state["target_id"],
                state["digest"],
                expected_operations=expected_operations,
                now=now(),
            )
        if existing.status is TransactionStatus.CREATED:
            deps.transactions.transition(
                transaction_id, TransactionStatus.PREPARING, now=now()
            )
        elif existing.status not in {
            TransactionStatus.PREPARING,
            TransactionStatus.PREPARED,
            TransactionStatus.EXECUTING,
        }:
            return {
                "status": existing.status.value,
                "error": "transaction_already_started",
            }
        if existing.status is TransactionStatus.EXECUTING:
            try:
                apply_dispatch_exists = any(
                    dispatch.phase is EffectPhase.APPLY
                    for dispatch in deps.transactions.get_dispatches(transaction_id)
                )
                evidence_matches = (
                    existing.plan_digest == state["digest"]
                    and deps.transactions.pre_first_apply_evidence_matches(
                        transaction_id, expected_operations
                    )
                )
            except Exception:
                return invalid_durable_evidence(
                    "durable_prepare_evidence_invalid"
                )
            if not apply_dispatch_exists and not evidence_matches:
                return invalid_durable_evidence(
                    "incomplete_frozen_plan_recovery_evidence"
                )
        try:
            durable_steps = deps.transactions.get_steps(transaction_id)
        except Exception:
            return invalid_durable_evidence("durable_prepare_evidence_invalid")
        if len(durable_steps) > len(candidate.operations):
            return {
                "status": "execution_unknown",
                "error": "durable_prepare_plan_mismatch",
                "reconcile_attempted": True,
            }
        for index, prepared in enumerate(durable_steps):
            operation_json = canonical_json_bytes(
                candidate.operations[index].model_dump(mode="json")
            ).decode("utf-8")
            if prepared.step_id != str(index) or prepared.operation_json != operation_json:
                return {
                    "status": "execution_unknown",
                    "error": "durable_prepare_plan_mismatch",
                }
        for index in range(len(durable_steps), len(candidate.operations)):
            operation = candidate.operations[index]
            step_id = str(index)
            try:
                target, ticket = issue_effect_ticket(
                    state, operation, step_id, OperationPhase.PREPARE
                )
            except Exception as error:
                deps.transactions.mark_unknown(transaction_id, now=now())
                return {
                    "status": "execution_unknown",
                    "error": f"prepare_revalidation_failed:{type(error).__name__}",
                    "reconcile_attempted": True,
                }
            current_dispatch = dispatch_id(state, OperationPhase.PREPARE, step_id)
            deps.transactions.begin_dispatch(
                transaction_id,
                step_id,
                phase=EffectPhase.PREPARE,
                dispatch_id=current_dispatch,
                ticket=ticket,
                now=now(),
            )
            try:
                effect = PreparedEffect.model_validate(
                    deps.plugins.executor.prepare(
                        target, step_id, operation, ticket
                    )
                )
                prepared = PreparedStep(
                    step_id=step_id,
                    operation_json=canonical_json_bytes(
                        operation.model_dump(mode="json")
                    ).decode("utf-8"),
                    pre_state_json=canonical_json_bytes(effect.pre_state).decode(
                        "utf-8"
                    ),
                    plugin_marker_json=canonical_json_bytes(effect.marker).decode(
                        "utf-8"
                    ),
                )
            except Exception as error:
                deps.transactions.mark_unknown(transaction_id, now=now())
                return {
                    "status": "execution_unknown",
                    "uncertain_step": index,
                    "unknown_phase": OperationPhase.PREPARE.value,
                    "dispatch_id": current_dispatch,
                    "error": f"prepare_unknown:{type(error).__name__}",
                    "audit_events": audit(state, "prepare_unknown", step_id=step_id),
                }
            try:
                deps.transactions.complete_prepare_dispatch(
                    current_dispatch, prepared, now=now()
                )
            except Exception as error:
                deps.transactions.mark_unknown(transaction_id, now=now())
                return {
                    "status": "execution_unknown",
                    "uncertain_step": index,
                    "unknown_phase": OperationPhase.PREPARE.value,
                    "dispatch_id": current_dispatch,
                    "error": f"prepare_persistence_unknown:{type(error).__name__}",
                }

        durable_status = deps.transactions.get(transaction_id).status
        if durable_status is TransactionStatus.PREPARING:
            deps.transactions.finish_prepared(
                transaction_id, expected_steps=len(candidate.operations), now=now()
            )
            durable_status = TransactionStatus.PREPARED
        if durable_status is TransactionStatus.PREPARED:
            deps.transactions.transition(
                transaction_id, TransactionStatus.EXECUTING, now=now()
            )
        return {
            "status": "executing",
            "next_step": len(durable_completed_results(state, EffectPhase.APPLY)),
            "verify_step": 0,
            "applied_steps": sorted(
                durable_completed_results(state, EffectPhase.APPLY)
            ),
            "audit_events": audit(state, "transaction_prepared"),
        }

    def begin_rollback(
        state: AgentState, applied_steps: list[int], *, reason: str
    ) -> AgentState:
        deps.transactions.transition(
            state["transaction_id"], TransactionStatus.ROLLBACK_RUNNING, now=now()
        )
        return {
            "status": "rollback_running",
            "applied_steps": applied_steps,
            "undo_steps": list(reversed(applied_steps)),
            "restored_steps": [],
            "rollback_failed": False,
            "rollback_unknown": False,
            "error": reason,
            "audit_events": audit(state, "rollback_started", reason=reason),
        }

    def reconcile_unknown(state: AgentState) -> AgentState:
        pending = deps.transactions.pending_dispatch(state["transaction_id"])
        if pending is None:
            return {
                "status": "execution_unknown",
                "error": "missing_dispatch_intent",
                "reconcile_attempted": True,
            }
        index = int(pending.step_id)
        operation = plan_for(state).operations[index]
        marker: dict[str, JsonValue] | None = None
        if pending.phase is not EffectPhase.PREPARE:
            operation, marker = prepared_for(state, index)
        operation_phase = OperationPhase(pending.phase.value)
        try:
            reconciled = ReconcileEffect.model_validate(
                deps.plugins.executor.reconcile(
                    target_for(state),
                    str(index),
                    operation,
                    operation_phase,
                    pending.dispatch_id,
                    marker,
                )
            )
        except Exception:
            reconciled = ReconcileEffect(outcome="unknown")
        result = reconciled.outcome
        applied = list(state.get("applied_steps", []))

        if pending.phase is EffectPhase.PREPARE:
            if result == "applied" and reconciled.prepared is not None:
                prepared = PreparedStep(
                    step_id=str(index),
                    operation_json=canonical_json_bytes(
                        operation.model_dump(mode="json")
                    ).decode("utf-8"),
                    pre_state_json=canonical_json_bytes(
                        reconciled.prepared.pre_state
                    ).decode("utf-8"),
                    plugin_marker_json=canonical_json_bytes(
                        reconciled.prepared.marker
                    ).decode("utf-8"),
                )
                try:
                    deps.transactions.complete_prepare_dispatch(
                        pending.dispatch_id, prepared, now=now()
                    )
                except Exception as error:
                    return {
                        "status": "execution_unknown",
                        "error": (
                            "reconciled_prepare_persistence_failed:"
                            f"{type(error).__name__}"
                        ),
                        "reconcile_attempted": True,
                    }
                resumed = prepare(state)
                resumed["reconcile_attempted"] = True
                resumed["audit_events"] = audit(
                    state, "prepare_reconciled", result=result
                )
                return resumed
            if result == "not_applied":
                deps.transactions.complete_dispatch(pending.dispatch_id, now=now())
                deps.transactions.transition(
                    state["transaction_id"], TransactionStatus.FAILED, now=now()
                )
                return {
                    "status": "failed",
                    "error": "fresh_revalidated_event_required",
                    "reconcile_attempted": True,
                }
            return {
                "status": "execution_unknown",
                "error": "prepare_reconciliation_requires_human",
                "reconcile_attempted": True,
            }

        if pending.phase is EffectPhase.UNDO:
            prepared = deps.transactions.get_steps(state["transaction_id"])[index]
            try:
                restored = StepResult.model_validate(
                    deps.plugins.executor.verify_restored(
                        target_for(state),
                        str(index),
                        operation,
                        marker,
                        cast(dict[str, JsonValue], json.loads(prepared.pre_state_json)),
                    )
                )
            except Exception:
                restored = StepResult(ok=False, status="unknown")
            if restored.ok:
                deps.transactions.complete_result_dispatch(
                    pending.dispatch_id,
                    phase="undo",
                    status="succeeded",
                    payload=restored.model_dump(mode="json"),
                    now=now(),
                )
                deps.transactions.transition(
                    state["transaction_id"], TransactionStatus.ROLLBACK_RUNNING, now=now()
                )
                restored_steps = list(state.get("restored_steps", []))
                if index not in restored_steps:
                    restored_steps.append(index)
                rollback_state = cast(
                    AgentState,
                    {
                        **state,
                        "status": "rollback_running",
                        "applied_steps": applied,
                        "restored_steps": restored_steps,
                    },
                )
                update = next_or_undo(rollback_state)
                update.setdefault("restored_steps", restored_steps)
                update["reconcile_attempted"] = True
                return update
            deps.transactions.complete_dispatch(pending.dispatch_id, now=now())
            deps.transactions.transition(
                state["transaction_id"], TransactionStatus.ROLLBACK_RUNNING, now=now()
            )
            deps.transactions.transition(
                state["transaction_id"], TransactionStatus.ROLLBACK_UNKNOWN, now=now()
            )
            return {
                "status": "rollback_unknown",
                "error": "undo_reconciliation_requires_human",
                "reconcile_attempted": True,
            }

        if result in {"applied", "partial"}:
            try:
                write_authorization(state, operation)
            except Exception as error:
                deps.transactions.complete_dispatch(pending.dispatch_id, now=now())
                return {
                    "status": "execution_unknown",
                    "error": f"recovery_revalidation_failed:{type(error).__name__}",
                    "reconcile_attempted": True,
                }
        if result in {"applied", "partial"}:
            deps.transactions.complete_result_dispatch(
                pending.dispatch_id,
                phase="apply",
                status="succeeded" if result == "applied" else "failed",
                payload=reconciled.model_dump(mode="json"),
                now=now(),
            )
        elif result == "not_applied":
            deps.transactions.complete_dispatch(pending.dispatch_id, now=now())
        if result == "applied":
            if index not in applied:
                applied.append(index)
            deps.transactions.transition(
                state["transaction_id"], TransactionStatus.VERIFYING, now=now()
            )
            return {
                "status": "verifying",
                "applied_steps": applied,
                "verify_step": 0,
                "reconcile_attempted": True,
                "incomplete_after_reconcile": len(applied)
                != len(plan_for(state).operations),
                "audit_events": audit(state, "execution_reconciled", result=result),
            }
        if result == "partial":
            if index not in applied:
                applied.append(index)
            update = begin_rollback(state, applied, reason="reconcile_partial")
            update["reconcile_attempted"] = True
            return update
        if result == "not_applied":
            deps.transactions.transition(
                state["transaction_id"], TransactionStatus.FAILED, now=now()
            )
            return {
                "status": "failed",
                "error": "fresh_revalidated_event_required",
                "reconcile_attempted": True,
                "audit_events": audit(state, "execution_reconciled", result=result),
            }
        return {
            "status": "execution_unknown",
            "error": "manual_reconciliation_required",
            "reconcile_attempted": True,
            "audit_events": audit(state, "execution_reconciled", result="unknown"),
        }

    def apply_step(state: AgentState) -> AgentState:
        if state.get("status") == "execution_unknown":
            return reconcile_unknown(state)

        candidate = plan_for(state)
        transaction = deps.transactions.get(state["transaction_id"])
        completed = durable_completed_results(state, EffectPhase.APPLY)
        applied = sorted(completed)
        if transaction.status is TransactionStatus.ROLLBACK_RUNNING:
            return {
                "status": "rollback_running",
                "applied_steps": applied,
                "undo_steps": list(reversed(applied)),
            }
        if transaction.status is TransactionStatus.VERIFYING:
            return {
                "status": "verifying",
                "applied_steps": applied,
                "verify_step": 0,
            }
        unknown = [index for index, result in completed.items() if result.status == "unknown"]
        if unknown:
            return {
                "status": "execution_unknown",
                "uncertain_step": unknown[0],
                "unknown_phase": OperationPhase.APPLY.value,
                "reconcile_attempted": True,
                "error": "durable_apply_outcome_unknown",
            }
        failed = [index for index, result in completed.items() if result.status == "failed"]
        if failed:
            return begin_rollback(state, applied, reason="apply_failed")
        index = 0
        while index in completed:
            index += 1
        if index >= len(candidate.operations):
            deps.transactions.transition(
                state["transaction_id"], TransactionStatus.VERIFYING, now=now()
            )
            return {
                "status": "verifying",
                "verify_step": 0,
                "applied_steps": applied,
            }

        operation, marker = prepared_for(state, index)
        step_id = str(index)
        try:
            target, ticket = issue_effect_ticket(
                state,
                operation,
                step_id,
                OperationPhase.APPLY,
                {"marker": marker},
            )
        except Exception as error:
            deps.transactions.mark_unknown(state["transaction_id"], now=now())
            return {
                "status": "execution_unknown",
                "error": f"write_revalidation_failed:{type(error).__name__}",
                "reconcile_attempted": True,
            }
        current_dispatch = dispatch_id(state, OperationPhase.APPLY, step_id)
        deps.transactions.begin_dispatch(
            state["transaction_id"],
            step_id,
            phase=EffectPhase.APPLY,
            dispatch_id=current_dispatch,
            ticket=ticket,
            now=now(),
        )
        try:
            result = StepResult.model_validate(
                deps.plugins.executor.apply(
                    target, step_id, operation, marker, ticket
                )
            )
        except Exception as error:
            deps.transactions.record_result(
                state["transaction_id"],
                str(index),
                phase="apply",
                status="unknown",
                payload={"error": type(error).__name__},
                now=now(),
            )
            deps.transactions.mark_unknown(state["transaction_id"], now=now())
            return {
                "status": "execution_unknown",
                "uncertain_step": index,
                "unknown_phase": OperationPhase.APPLY.value,
                "dispatch_id": current_dispatch,
                "next_step": index,
                "audit_events": audit(
                    state, "execution_unknown", step_id=str(index)
                ),
            }

        result_status = "succeeded" if result.ok else (
            "unknown" if result.status == "unknown" else "failed"
        )
        if result_status == "unknown":
            deps.transactions.record_result(
                state["transaction_id"],
                step_id,
                phase="apply",
                status=result_status,
                payload=result.model_dump(mode="json"),
                now=now(),
            )
            deps.transactions.mark_unknown(state["transaction_id"], now=now())
            return {
                "status": "execution_unknown",
                "uncertain_step": index,
                "unknown_phase": OperationPhase.APPLY.value,
                "dispatch_id": current_dispatch,
            }
        try:
            deps.transactions.complete_result_dispatch(
                current_dispatch,
                phase="apply",
                status=result_status,
                payload=result.model_dump(mode="json"),
                now=now(),
            )
        except Exception as error:
            deps.transactions.mark_unknown(state["transaction_id"], now=now())
            return {
                "status": "execution_unknown",
                "uncertain_step": index,
                "unknown_phase": OperationPhase.APPLY.value,
                "dispatch_id": current_dispatch,
                "error": f"apply_persistence_unknown:{type(error).__name__}",
            }
        if index not in applied:
            applied.append(index)
        if not result.ok:
            return begin_rollback(state, applied, reason="apply_failed")
        return {
            "status": "executing",
            "next_step": index + 1,
            "applied_steps": applied,
            "audit_events": audit(state, "step_applied", step_id=str(index)),
        }

    def verify_step(state: AgentState) -> AgentState:
        applied = state.get("applied_steps", [])
        offset = state.get("verify_step", 0)
        if offset >= len(applied):
            if state.get("incomplete_after_reconcile", False):
                return begin_rollback(
                    state, list(applied), reason="incomplete_plan_after_reconcile"
                )
            return {"status": "verifying"}
        index = applied[offset]
        operation, marker = prepared_for(state, index)
        try:
            result = StepResult.model_validate(
                deps.plugins.executor.verify(
                    target_for(state), str(index), operation, marker
                )
            )
        except Exception as error:
            result = StepResult(
                ok=False,
                status="unknown",
                data={"error": type(error).__name__},
            )
        deps.transactions.record_result(
            state["transaction_id"],
            str(index),
            phase="verify",
            status="succeeded" if result.ok else (
                "unknown" if result.status == "unknown" else "failed"
            ),
            payload=result.model_dump(mode="json"),
            now=now(),
        )
        if not result.ok:
            return begin_rollback(state, list(applied), reason="verification_failed")
        return {
            "verify_step": offset + 1,
            "audit_events": audit(state, "step_verified", step_id=str(index)),
        }

    def next_or_undo(state: AgentState) -> AgentState:
        if state["status"] == "verifying":
            return {}
        if state["status"] != "rollback_running":
            return {}

        durable_applied = set(durable_completed_results(state, EffectPhase.APPLY))
        applied = sorted(durable_applied | set(state.get("applied_steps", [])))
        completed_undos = durable_completed_results(state, EffectPhase.UNDO)
        remaining = [
            index for index in reversed(applied) if index not in completed_undos
        ]
        restored_steps = list(state.get("restored_steps", []))
        rollback_failed = state.get("rollback_failed", False)
        rollback_unknown = state.get("rollback_unknown", False)

        awaiting_restoration = [
            index
            for index in reversed(applied)
            if index in completed_undos and index not in restored_steps
        ]
        if awaiting_restoration:
            index = awaiting_restoration[0]
            operation, marker = prepared_for(state, index)
            prepared = deps.transactions.get_steps(state["transaction_id"])[index]
            try:
                restored = StepResult.model_validate(
                    deps.plugins.executor.verify_restored(
                        target_for(state),
                        str(index),
                        operation,
                        marker,
                        cast(
                            dict[str, JsonValue],
                            json.loads(prepared.pre_state_json),
                        ),
                    )
                )
            except Exception:
                restored = StepResult(ok=False, status="unknown")
            restored_steps.append(index)
            return {
                "status": "rollback_running",
                "applied_steps": applied,
                "undo_steps": remaining,
                "restored_steps": restored_steps,
                "rollback_failed": rollback_failed or not restored.ok,
                "rollback_unknown": rollback_unknown
                or (not restored.ok and restored.status == "unknown"),
                "audit_events": audit(
                    state,
                    "step_restoration_verified",
                    step_id=str(index),
                    restored=restored.ok,
                ),
            }

        if remaining:
            index = remaining[0]
            operation, marker = prepared_for(state, index)
            step_id = str(index)
            try:
                target, ticket = issue_effect_ticket(
                    state,
                    operation,
                    step_id,
                    OperationPhase.UNDO,
                    {"marker": marker, "undo": operation.undo},
                )
            except Exception as error:
                deps.transactions.transition(
                    state["transaction_id"],
                    TransactionStatus.ROLLBACK_UNKNOWN,
                    now=now(),
                )
                return {
                    "status": "rollback_unknown",
                    "error": f"undo_revalidation_failed:{type(error).__name__}",
                }
            current_dispatch = dispatch_id(state, OperationPhase.UNDO, step_id)
            deps.transactions.begin_dispatch(
                state["transaction_id"],
                step_id,
                phase=EffectPhase.UNDO,
                dispatch_id=current_dispatch,
                ticket=ticket,
                now=now(),
            )
            try:
                result = StepResult.model_validate(
                    deps.plugins.executor.undo(
                        target,
                        step_id,
                        operation,
                        marker,
                        operation.undo,
                        ticket,
                    )
                )
            except Exception as error:
                deps.transactions.record_result(
                    state["transaction_id"],
                    step_id,
                    phase="undo",
                    status="unknown",
                    payload={"error": type(error).__name__},
                    now=now(),
                )
                deps.transactions.mark_unknown(state["transaction_id"], now=now())
                return {
                    "status": "execution_unknown",
                    "uncertain_step": index,
                    "unknown_phase": OperationPhase.UNDO.value,
                    "dispatch_id": current_dispatch,
                    "undo_steps": remaining,
                }
            result_status = "succeeded" if result.ok else (
                "unknown" if result.status == "unknown" else "failed"
            )
            if result_status == "unknown":
                deps.transactions.record_result(
                    state["transaction_id"],
                    str(index),
                    phase="undo",
                    status=result_status,
                    payload=result.model_dump(mode="json"),
                    now=now(),
                )
                deps.transactions.mark_unknown(state["transaction_id"], now=now())
                return {
                    "status": "execution_unknown",
                    "uncertain_step": index,
                    "unknown_phase": OperationPhase.UNDO.value,
                    "dispatch_id": current_dispatch,
                    "undo_steps": remaining,
                }
            try:
                deps.transactions.complete_result_dispatch(
                    current_dispatch,
                    phase="undo",
                    status=result_status,
                    payload=result.model_dump(mode="json"),
                    now=now(),
                )
            except Exception as error:
                deps.transactions.mark_unknown(state["transaction_id"], now=now())
                return {
                    "status": "execution_unknown",
                    "uncertain_step": index,
                    "unknown_phase": OperationPhase.UNDO.value,
                    "dispatch_id": current_dispatch,
                    "undo_steps": remaining,
                    "error": f"undo_persistence_unknown:{type(error).__name__}",
                }
            prepared = deps.transactions.get_steps(state["transaction_id"])[index]
            try:
                restored = StepResult.model_validate(
                    deps.plugins.executor.verify_restored(
                        target,
                        step_id,
                        operation,
                        marker,
                        cast(dict[str, JsonValue], json.loads(prepared.pre_state_json)),
                    )
                )
            except Exception:
                restored = StepResult(ok=False, status="unknown")
            remaining.pop(0)
            restored_steps.append(index)
            return {
                "status": "rollback_running",
                "applied_steps": applied,
                "undo_steps": remaining,
                "restored_steps": restored_steps,
                "rollback_failed": rollback_failed or not restored.ok,
                "rollback_unknown": rollback_unknown
                or (not restored.ok and restored.status == "unknown"),
                "audit_events": audit(
                    state,
                    "step_undone",
                    step_id=step_id,
                    result=result_status,
                    restored=restored.ok,
                ),
            }

        if rollback_unknown:
            terminal = TransactionStatus.ROLLBACK_UNKNOWN
        elif rollback_failed:
            terminal = TransactionStatus.ROLLBACK_PARTIAL
        else:
            terminal = TransactionStatus.ROLLBACK_SUCCEEDED
        deps.transactions.transition(state["transaction_id"], terminal, now=now())
        return {
            "status": terminal.value,
            "audit_events": audit(state, "rollback_finished", result=terminal.value),
        }

    def final_verify(state: AgentState) -> AgentState:
        try:
            target = target_for(state)
            fingerprint = deps.plugins.collector.verify_identity(target)
            if (
                fingerprint != state["target_fingerprint"]
                or fingerprint != plan_for(state).target_fingerprint
            ):
                raise PermissionError("target identity changed before final verify")
            fresh_view = deps.plugins.collector.acquire_read_view(target, fingerprint)
            fresh_evidence = deps.plugins.collector.collect(target, fresh_view)
            result = StepResult.model_validate(
                deps.plugins.collector.final_verify(
                    target, fresh_view, fresh_evidence
                )
            )
        except Exception as error:
            result = StepResult(
                ok=False,
                status="unknown",
                data={"error": type(error).__name__},
            )
        if not result.ok:
            update = begin_rollback(
                state, list(state.get("applied_steps", [])), reason="final_verify_failed"
            )
            update["recovery_result"] = result.model_dump(mode="json")
            if "fresh_evidence" in locals():
                update["recovery_evidence"] = cast(list[dict[str, JsonValue]], redact(fresh_evidence))
            return update
        deps.transactions.transition(
            state["transaction_id"], TransactionStatus.SUCCEEDED, now=now()
        )
        return {
            "status": "succeeded",
            "read_view": fresh_view,
            "recovery_evidence": cast(list[dict[str, JsonValue]], redact(fresh_evidence)),
            "recovery_result": result.model_dump(mode="json"),
            "audit_events": audit(state, "final_verification_succeeded"),
        }

    def report(state: AgentState) -> AgentState:
        if state.get("status") == "execution_unknown" and not state.get(
            "reconcile_attempted", False
        ):
            interrupt(
                {
                    "status": "execution_unknown",
                    "transaction_id": state["transaction_id"],
                    "target_id": state["target_id"],
                    "uncertain_step": state["uncertain_step"],
                }
            )
            return {"status": "execution_unknown"}
        return {
            "report": {
                "status": state.get("status", "failed"),
                "target_id": state.get("target_id", ""),
                "transaction_id": state.get("transaction_id", ""),
                "digest": state.get("digest", ""),
                "error": state.get("error", ""),
                "recovery_result": state.get("recovery_result", {}),
            }
        }

    def close(state: AgentState) -> AgentState:
        transaction_id = state.get("transaction_id")
        if transaction_id:
            try:
                record = deps.transactions.get(transaction_id)
            except UnknownTransactionError:
                record = None
            if record is not None and record.status in {
                TransactionStatus.SUCCEEDED,
                TransactionStatus.FAILED,
                TransactionStatus.ROLLBACK_SUCCEEDED,
                TransactionStatus.ROLLBACK_PARTIAL,
            }:
                deps.transactions.release_target(transaction_id)
        return {"audit_events": audit(state, "workflow_closed")}

    graph = StateGraph(AgentState)
    graph.add_node("ingest", ingest)
    graph.add_node("resolve_target", resolve_target)
    graph.add_node("acquire_read_view", acquire_read_view)
    graph.add_node("collect", collect)
    graph.add_node("diagnose", diagnose)
    graph.add_node("collect_missing", collect_missing)
    graph.add_node("plan", plan_node)
    graph.add_node("critic", critic)
    graph.add_node("policy_gate", policy_gate)
    graph.add_node("freeze_plan", freeze_plan)
    graph.add_node("approval_gate", approval_gate)
    graph.add_node("prepare", prepare)
    graph.add_node("apply_step", apply_step)
    graph.add_node("verify_step", verify_step)
    graph.add_node("next_or_undo", next_or_undo)
    graph.add_node("final_verify", final_verify)
    graph.add_node("report", report)
    graph.add_node("close", close)

    graph.add_edge(START, "ingest")
    graph.add_conditional_edges(
        "ingest",
        lambda state: "report" if state.get("status") == "failed" else "resolve_target",
    )
    graph.add_conditional_edges(
        "resolve_target",
        lambda state: "report"
        if state.get("status") == "policy_denied"
        else "acquire_read_view",
    )
    graph.add_conditional_edges(
        "acquire_read_view",
        lambda state: "report" if state.get("status") == "failed" else "collect",
    )
    graph.add_conditional_edges(
        "collect",
        lambda state: "report" if state.get("status") == "failed" else "diagnose",
    )
    graph.add_conditional_edges(
        "diagnose",
        lambda state: "report"
        if state.get("status") in {"read_only_no_model", "insufficient_evidence"}
        else "collect_missing" if state.get("missing_evidence") else "plan",
    )
    graph.add_conditional_edges("collect_missing", lambda state: "report" if state.get("status") == "insufficient_evidence" else "diagnose")
    graph.add_conditional_edges(
        "plan",
        lambda state: "report"
        if state.get("status") == "read_only_no_model"
        else "critic",
    )
    graph.add_conditional_edges(
        "critic",
        lambda state: "report"
        if state.get("status") == "read_only_no_model"
        else "policy_gate",
    )
    graph.add_conditional_edges(
        "policy_gate",
        lambda state: "report"
        if state.get("status") == "policy_denied"
        else "freeze_plan",
    )
    graph.add_conditional_edges(
        "freeze_plan",
        lambda state: "report"
        if state.get("status") == "policy_denied"
        else "approval_gate",
    )
    graph.add_conditional_edges(
        "approval_gate",
        lambda state: "prepare"
        if state.get("status") == "policy_allowed"
        else "report",
    )
    graph.add_conditional_edges(
        "prepare",
        lambda state: "apply_step"
        if state.get("status") == "executing"
        else "report",
    )

    def after_apply(state: AgentState) -> str:
        if state["status"] == "executing":
            return "apply_step"
        if state["status"] == "verifying":
            return "verify_step"
        if state["status"] == "rollback_running":
            return "next_or_undo"
        return "report"

    graph.add_conditional_edges("apply_step", after_apply)
    graph.add_edge("verify_step", "next_or_undo")

    def after_next(state: AgentState) -> str:
        if state["status"] == "execution_unknown":
            return "report"
        if state["status"] == "rollback_running":
            return "next_or_undo"
        if state["status"] in {
            "rollback_succeeded",
            "rollback_partial",
            "rollback_unknown",
        }:
            return "report"
        if state.get("verify_step", 0) < len(state.get("applied_steps", [])):
            return "verify_step"
        return "final_verify"

    graph.add_conditional_edges("next_or_undo", after_next)
    graph.add_conditional_edges(
        "final_verify",
        lambda state: "next_or_undo"
        if state.get("status") == "rollback_running"
        else "report",
    )
    graph.add_conditional_edges(
        "report",
        lambda state: "apply_step"
        if state.get("status") == "execution_unknown"
        and not state.get("reconcile_attempted", False)
        else "close",
    )
    graph.add_edge("close", END)
    compiled = graph.compile(checkpointer=deps.checkpointer)
    setattr(compiled, "_a4diag_dependencies", deps)
    return compiled


def run_event(
    graph: CompiledStateGraph, event: dict[str, object]
) -> AgentState:
    """Run or resume one stable workflow thread.

    Resume payload fields are deliberately ignored. They only wake the persisted
    graph; approval identity, digest, target and plan are loaded from checkpoints
    and the approval store.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    resume = event.get("resume") is True
    dependencies = cast(
        WorkflowDependencies | None,
        getattr(graph, "_a4diag_dependencies", None),
    )

    def bind_transaction(transaction_id: str) -> None:
        if dependencies is None:
            return
        bind = getattr(dependencies.plugins.executor, "bind_transaction", None)
        if callable(bind):
            bind(transaction_id)
    if resume:
        transaction_id = event.get("transaction_id")
        if not isinstance(transaction_id, str) or not transaction_id:
            raise ValueError("resume requires transaction_id")
        bind_transaction(transaction_id)
        config = {"configurable": {"thread_id": transaction_id}}
        pending = None
        recovery_action = None
        recovery_error = None
        if dependencies is not None:
            try:
                transaction = dependencies.transactions.get(transaction_id)
            except UnknownTransactionError:
                pass
            else:
                recovery_action = dependencies.transactions.next_recovery_action(
                    transaction_id, now=dependencies.clock()
                )
                pending = dependencies.transactions.pending_dispatch(transaction_id)
                restore = getattr(dependencies.plugins.executor, "restore_read_context", None)
                if callable(restore):
                    try:
                        values = graph.get_state(config).values
                        plan = Plan.model_validate(values["plan"])
                        if (
                            plan_digest(plan) != transaction.plan_digest
                            or values.get("digest") != transaction.plan_digest
                            or plan.target_id != transaction.target_id
                            or values.get("target_fingerprint") != plan.target_fingerprint
                        ):
                            raise ValueError("recovery_plan_mismatch")
                        target = next(t for t in dependencies.settings.targets if t.id == plan.target_id)
                        prepared_steps = {
                            step.step_id: step
                            for step in dependencies.transactions.get_steps(transaction_id)
                        }
                        for step_id, prepared in prepared_steps.items():
                            index = int(step_id)
                            if (
                                index < 0
                                or str(index) != step_id
                                or Operation.model_validate_json(prepared.operation_json)
                                != plan.operations[index]
                            ):
                                raise ValueError("recovery_operation_mismatch")
                        claims = []
                        for dispatch in dependencies.transactions.get_dispatches(transaction_id):
                            claim = dependencies.tickets.inspect_for_recovery(dispatch.ticket)
                            if (
                                claim.transaction_id != transaction_id
                                or claim.step_id != dispatch.step_id
                                or claim.phase.value != dispatch.phase.value
                                or claim.risk.value != values.get("risk")
                                or claim.approval_id != values.get("approval_id")
                            ):
                                raise ValueError("recovery_dispatch_mismatch")
                            effect_fields: dict[str, JsonValue] = {}
                            if dispatch.phase is not EffectPhase.PREPARE:
                                prepared = prepared_steps[dispatch.step_id]
                                effect_fields["marker"] = json.loads(prepared.plugin_marker_json)
                                if dispatch.phase is EffectPhase.UNDO:
                                    effect_fields["undo"] = plan.operations[int(dispatch.step_id)].undo
                            if claim.effect_payload_digest != effect_payload_digest(effect_fields):
                                raise ValueError("recovery_effect_mismatch")
                            claims.append(claim)
                        restore(target, plan, tuple(claims))
                    except Exception:
                        recovery_error = "invalid_recovery_context"
        if recovery_error is not None:
            graph.update_state(config, {
                "status": "execution_unknown", "error": recovery_error,
                "reconcile_attempted": True,
            }, as_node="report")
            result = graph.invoke(None, config=config)
        elif pending is not None:
            graph.update_state(
                config,
                {
                    "status": "execution_unknown",
                    "uncertain_step": int(pending.step_id),
                    "unknown_phase": pending.phase.value,
                    "dispatch_id": pending.dispatch_id,
                    "reconcile_attempted": False,
                },
                as_node="report",
            )
            result = graph.invoke(None, config=config)
        elif recovery_action is RecoveryAction.RECONCILE:
            graph.update_state(
                config,
                {
                    "status": "execution_unknown",
                    "error": "durable_recovery_evidence_incomplete",
                    "reconcile_attempted": True,
                },
                as_node="report",
            )
            result = graph.invoke(None, config=config)
        else:
            snapshot = graph.get_state(config)
            has_interrupt = any(task.interrupts for task in snapshot.tasks)
            result = graph.invoke(
                Command(resume=True) if has_interrupt else None,
                config=config,
            )
    else:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("event requires event_id")
        bind_transaction(event_id)
        initial: AgentState = {
            "event_id": event_id,
            "transaction_id": event_id,
            "target_id": cast(str, event.get("target_id", "")),
            "request": redact(json.loads(canonical_json_bytes(
                event.get("request", None), max_bytes=65_536
            ))),
            "audit_events": [],
        }
        result = graph.invoke(
            initial,
            config={"configurable": {"thread_id": event_id}},
        )
    return cast(
        AgentState,
        {key: value for key, value in result.items() if key != "__interrupt__"},
    )

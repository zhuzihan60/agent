from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from a4diag.approvals import ApprovalStateError, ApprovalStore
from a4diag.domain import (
    CapabilityGrant,
    Operation,
    Plan,
    Risk,
    StepResult,
    TargetConfig,
)
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketRequest,
    TicketIssuer,
    effect_payload_digest,
)
from a4diag.policy_engine import PolicyAuthorization
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.policy_engine import PolicyEngine
from a4diag.settings import AgentSettings
from a4diag.transaction_store import (
    RecoveryAction,
    TargetBusyError,
    TransactionStatus,
    TransactionStore,
)
from a4diag.workflow import (
    PluginPorts,
    PreparedEffect,
    ReconcileEffect,
    WorkflowDependencies,
    build_graph,
    run_event,
)


POLICY_KEY = b"p" * 32
TICKET_KEY = b"t" * 32


class SimulatedCrash(BaseException):
    pass


class CapturingTicketIssuer(TicketIssuer):
    def __init__(self, clock: object) -> None:
        self.requests: list[OperationTicketRequest] = []
        self.counter = 0
        super().__init__(
            TICKET_KEY,
            authorization_key=POLICY_KEY,
            clock=clock,  # type: ignore[arg-type]
            ticket_id_factory=self.next_id,
        )

    def next_id(self) -> str:
        self.counter += 1
        return f"capture-{self.counter}"

    def issue(
        self,
        request: OperationTicketRequest,
        authorization: PolicyAuthorization | None,
    ) -> str:
        self.requests.append(request)
        return super().issue(request, authorization)


class FakeClock:
    def __init__(self, value: int = 100) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def make_operation(index: int = 0, *, risk: Risk = Risk.LOW) -> Operation:
    return Operation(
        capability="files",
        action="replace",
        resource=f"/etc/example/app-{index}.conf",
        parameters={"content": f"value={index}\n"},
        model_risk=risk,
        verify={"content_sha256": "a" * 64},
        undo={"restore_backup": True},
    )


def make_plan(
    *, count: int = 1, risk: Risk = Risk.LOW, fingerprint: str = "machine-1"
) -> Plan:
    return Plan(
        target_id="target-1",
        target_fingerprint=fingerprint,
        operations=tuple(make_operation(index, risk=risk) for index in range(count)),
    )


def write_registry(root: Path, *, supports_undo: bool = True) -> PluginRegistry:
    plugin_dir = root / "plugins"
    plugin_dir.mkdir()
    artifact = plugin_dir / "capability-files.whl"
    artifact.write_bytes(b"signed capability wheel")
    manifest = {
        "name": "capability-files",
        "plugin_type": "capability",
        "version": "1.0.0",
        "api_min": "1.0",
        "api_max": "1.0",
        "executable": "a4diag_plugins.files:main",
        "socket": "/run/a4diag/capability-files.sock",
        "config_schema": "schemas/capability-files.json",
        "operations": [
            {
                "name": "files.replace",
                "risk_floor": "low",
                "reversible": True,
                "supports_prepare": True,
                "supports_verify": True,
                "supports_reconcile": True,
                "supports_undo": supports_undo,
                "parameters_schema": {
                    "type": "object",
                    "properties": {"content": {"type": "string"}},
                    "required": ["content"],
                    "additionalProperties": False,
                },
            }
        ],
    }
    manifest_path = root / "capability-files.json"
    manifest_path.write_bytes(
        json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    )
    pin = PluginPin(
        name="capability-files",
        version="1.0.0",
        api_version="1.0",
        artifact_path="plugins/capability-files.whl",
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        enabled=True,
    )
    return PluginRegistry.load((pin,), root, core_api="1.0")


class FakeCollector:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fingerprint = "machine-1"
        self.final_result = StepResult(ok=True, status="healthy")
        self.view_count = 0
        self.collect_count = 0
        self.final_inputs: list[tuple[str, list[dict[str, object]]]] = []

    def verify_identity(self, target: TargetConfig) -> str:
        self.calls.append("verify_identity")
        return self.fingerprint

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str:
        assert fingerprint == self.fingerprint
        self.calls.append("acquire_read_view")
        self.view_count += 1
        return f"read-view-{self.view_count}"

    def collect(self, target: TargetConfig, read_view: str) -> list[dict[str, object]]:
        self.calls.append("collect")
        self.collect_count += 1
        return [
            {
                "kind": "service",
                "healthy": self.collect_count > 1,
                "view": read_view,
            }
        ]

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, object]],
    ) -> StepResult:
        self.calls.append("final_verify")
        self.final_inputs.append((read_view, evidence))
        return self.final_result


class FakeModel:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.plan_result = make_plan()
        self.critic_result = Risk.LOW
        self.diagnose_error: Exception | None = None

    def diagnose(
        self, target: TargetConfig, evidence: list[dict[str, object]]
    ) -> dict[str, object]:
        self.calls.append("diagnose")
        if self.diagnose_error is not None:
            raise self.diagnose_error
        return {"cause": "service configuration drift", "confidence": 90}

    def plan(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        diagnosis: dict[str, object],
    ) -> Plan:
        self.calls.append("plan")
        return self.plan_result

    def critic(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        plan: Plan,
    ) -> Risk:
        self.calls.append("critic")
        return self.critic_result


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.applied_resources: list[str] = []
        self.apply_error: Exception | None = None
        self.apply_error_step: str | None = None
        self.apply_result: object | None = None
        self.prepare_error_step: str | None = None
        self.verify_fail_step: str | None = None
        self.undo_fail_step: str | None = None
        self.undo_unknown_step: str | None = None
        self.reconcile_result = "unknown"
        self.prepare_crash_step: str | None = None
        self.apply_crash_step: str | None = None
        self.undo_crash_step: str | None = None
        self.prepare_result: object | None = None
        self.verify_result: object | None = None
        self.undo_result: object | None = None
        self.reconcile_response: object | None = None
        self.restore_result: object = StepResult(ok=True, status="restored")
        self.prepare_tickets: list[str] = []
        self.undo_tickets: list[str] = []

    @property
    def apply_count(self) -> int:
        return self.calls.count("apply")

    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        ticket: str,
    ) -> PreparedEffect:
        self.calls.append("prepare")
        self.prepare_tickets.append(ticket)
        if self.prepare_crash_step == step_id:
            self.prepare_crash_step = None
            raise SimulatedCrash("prepare effect completed before response")
        if self.prepare_error_step == step_id:
            raise RuntimeError("prepare failed")
        if self.prepare_result is not None:
            return self.prepare_result  # type: ignore[return-value]
        return PreparedEffect(
            pre_state={"content": "old"},
            marker={"marker": f"marker-{step_id}"},
        )

    def apply(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        ticket: str,
    ) -> StepResult:
        self.calls.append("apply")
        self.applied_resources.append(operation.resource)
        if self.apply_crash_step == step_id:
            self.apply_crash_step = None
            raise SimulatedCrash("apply effect completed before response")
        if self.apply_error is not None and (
            self.apply_error_step is None or self.apply_error_step == step_id
        ):
            error = self.apply_error
            self.apply_error = None
            raise error
        if self.apply_result is not None:
            return self.apply_result  # type: ignore[return-value]
        return StepResult(ok=True, status="succeeded", data={"changed": True})

    def verify(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
    ) -> StepResult:
        self.calls.append("verify")
        if self.verify_result is not None:
            return self.verify_result  # type: ignore[return-value]
        if self.verify_fail_step == step_id:
            return StepResult(ok=False, status="failed", data={"reason": "drift"})
        return StepResult(ok=True, status="succeeded")

    def undo(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        undo: dict[str, object] | None,
        ticket: str,
    ) -> StepResult:
        self.calls.append(f"undo:{step_id}")
        self.undo_tickets.append(ticket)
        if self.undo_crash_step == step_id:
            self.undo_crash_step = None
            raise SimulatedCrash("undo effect completed before response")
        if self.undo_result is not None:
            return self.undo_result  # type: ignore[return-value]
        if self.undo_unknown_step == step_id:
            return StepResult(ok=False, status="unknown")
        if self.undo_fail_step == step_id:
            return StepResult(ok=False, status="failed")
        return StepResult(ok=True, status="succeeded")

    def reconcile(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        phase: OperationPhase,
        dispatch_id: str,
        marker: dict[str, object] | None,
    ) -> ReconcileEffect:
        self.calls.append("reconcile")
        if self.reconcile_response is not None:
            return self.reconcile_response  # type: ignore[return-value]
        return ReconcileEffect(outcome=self.reconcile_result)

    def verify_restored(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        pre_state: dict[str, object],
    ) -> StepResult:
        self.calls.append(f"verify_restored:{step_id}")
        return self.restore_result  # type: ignore[return-value]


class FakeNotifier:
    def __init__(self) -> None:
        self.delivered = True
        self.calls: list[str] = []
        self.crash_after_delivery = False

    def send_approval(
        self,
        target: TargetConfig,
        transaction_id: str,
        digest: str,
        plan: Plan,
        risk: Risk,
    ) -> bool:
        self.calls.append("send_approval")
        if self.crash_after_delivery:
            self.crash_after_delivery = False
            raise SimulatedCrash("notification delivered before response")
        return self.delivered


@pytest.fixture
def deps_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    connections: list[sqlite3.Connection] = []

    def make(
        *, notification_required: bool = False, supports_undo: bool = True
    ) -> WorkflowDependencies:
        target = TargetConfig(
            id="target-1",
            mode="local",
            identity_ref="target/target-1",
            write_enabled=True,
            auto_execute_low=True,
            notification_required=notification_required,
            capabilities=(
                CapabilityGrant(
                    name="files",
                    actions=("replace",),
                    resources=("/etc/example/**",),
                ),
            ),
        )
        settings = AgentSettings(
            global_mode="read_write",
            targets=(target,),
            auto_execute_low=True,
        )
        registry_root = tmp_path / f"registry-{len(connections)}"
        registry_root.mkdir()
        registry = write_registry(registry_root, supports_undo=supports_undo)
        model = FakeModel()
        collector = FakeCollector()
        executor = FakeExecutor()
        notifier = FakeNotifier()
        clock = FakeClock()
        connection = sqlite3.connect(
            tmp_path / f"checkpoints-{len(connections)}.sqlite3",
            check_same_thread=False,
        )
        connections.append(connection)
        ticket_counter = iter(range(100))
        return WorkflowDependencies(
            settings=settings,
            registry=registry,
            policy=PolicyEngine(settings, registry, authorization_key=POLICY_KEY),
            approvals=ApprovalStore(
                tmp_path / f"approvals-{len(connections)}.sqlite3",
                request_id_factory=lambda: "approval-1",
            ),
            transactions=TransactionStore(
                tmp_path / f"transactions-{len(connections)}.sqlite3"
            ),
            tickets=TicketIssuer(
                TICKET_KEY,
                authorization_key=POLICY_KEY,
                clock=clock,
                ticket_id_factory=lambda: f"ticket-{next(ticket_counter)}",
            ),
            plugins=PluginPorts(
                model=model,
                collector=collector,
                executor=executor,
                notifier=notifier,
            ),
            checkpointer=SqliteSaver(connection),
            clock=clock,
            approval_ttl_seconds=300,
        )

    yield make
    for connection in connections:
        connection.close()


def event_for(target_id: str = "target-1", event_id: str = "event-1") -> dict[str, object]:
    return {"event_id": event_id, "target_id": target_id, "request": "repair"}


def resume_for(transaction_id: str, **untrusted: object) -> dict[str, object]:
    return {"transaction_id": transaction_id, "resume": True, **untrusted}


def with_settings(
    deps: WorkflowDependencies, settings: AgentSettings
) -> WorkflowDependencies:
    return replace(
        deps,
        settings=settings,
        policy=PolicyEngine(settings, deps.registry, authorization_key=POLICY_KEY),
    )


def crash_after_atomic_completion(
    store: TransactionStore, method_name: str, *, phase: str | None = None
) -> None:
    original = getattr(store, method_name)
    armed = True

    def complete_then_crash(*args: object, **kwargs: object) -> object:
        nonlocal armed
        result = original(*args, **kwargs)
        if armed and (phase is None or kwargs.get("phase") == phase):
            armed = False
            raise SimulatedCrash(f"crash after atomic {phase or 'prepare'} completion")
        return result

    setattr(store, method_name, complete_then_crash)


def crash_after_entering_executing(store: TransactionStore) -> None:
    original = store.transition
    armed = True

    def transition_then_crash(
        transaction_id: str,
        new_status: TransactionStatus | str,
        *,
        now: int,
    ) -> object:
        nonlocal armed
        result = original(transaction_id, new_status, now=now)
        if armed and TransactionStatus(new_status) is TransactionStatus.EXECUTING:
            armed = False
            raise SimulatedCrash("crash after entering executing before node return")
        return result

    setattr(store, "transition", transition_then_crash)


def test_dependencies_reject_stale_policy_settings_or_registry(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    read_only = deps.settings.model_copy(update={"global_mode": "read_only"})

    with pytest.raises(ValueError, match="policy"):
        replace(deps, settings=read_only)


def test_low_plan_applies_verifies_and_succeeds(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "succeeded"
    assert deps.plugins.executor.calls == ["prepare", "apply", "verify"]
    assert deps.plugins.collector.calls[:3] == [
        "verify_identity",
        "acquire_read_view",
        "collect",
    ]
    assert deps.plugins.collector.view_count == 2
    assert deps.plugins.collector.collect_count == 2
    assert deps.plugins.collector.final_inputs == [
        ("read-view-2", [{"kind": "service", "healthy": True, "view": "read-view-2"}])
    ]
    assert deps.plugins.executor.prepare_tickets


def test_high_plan_interrupts_before_executor_and_store_backed_approval_resumes(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)

    first = run_event(graph, event_for())

    assert first["status"] == "pending_approval"
    assert deps.plugins.executor.calls == []
    approval = deps.approvals.get(first["approval_id"])
    assert approval.plan_digest == first["digest"]

    deps.plugins.model.plan_result = make_plan(count=2, risk=Risk.HIGH)
    deps.approvals.approve(
        approval.id,
        approved_digest=approval.plan_digest,
        actor="uid:1000",
        now=101,
    )
    resumed = run_event(
        graph,
        resume_for(
            first["transaction_id"],
            approval_id="forged",
            digest="0" * 64,
            plan=make_plan(count=2).model_dump(mode="json"),
        ),
    )

    assert resumed["status"] == "succeeded"
    assert deps.plugins.model.calls == ["diagnose", "plan", "critic"]
    assert deps.plugins.executor.applied_resources == ["/etc/example/app-0.conf"]


def test_crash_after_dispatch_reconciles_without_replay(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_error = TimeoutError()
    graph = build_graph(deps)

    first = run_event(graph, event_for())

    assert first["status"] == "execution_unknown"
    assert deps.plugins.executor.apply_count == 1

    deps.plugins.executor.reconcile_result = "applied"
    resumed = run_event(build_graph(deps), resume_for(first["transaction_id"]))

    assert deps.plugins.executor.apply_count == 1
    assert deps.plugins.executor.calls.count("reconcile") == 1
    assert resumed["status"] == "succeeded"


def test_workflow_tickets_bind_exact_prepare_apply_and_undo_effect_fields(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    issuer = CapturingTicketIssuer(deps.clock)
    deps = replace(deps, tickets=issuer)
    deps.plugins.executor.verify_fail_step = "0"

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "rollback_succeeded"
    requests = {request.phase: request for request in issuer.requests}
    operation = make_operation()
    marker = {"marker": "marker-0"}
    assert requests[OperationPhase.PREPARE].effect_payload_digest == effect_payload_digest({})
    assert requests[OperationPhase.APPLY].effect_payload_digest == effect_payload_digest(
        {"marker": marker}
    )
    assert requests[OperationPhase.UNDO].effect_payload_digest == effect_payload_digest(
        {"marker": marker, "undo": operation.undo}
    )


def test_reversible_contract_without_undo_support_has_zero_ticket_or_effect_dispatch(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory(supports_undo=False)
    issuer = CapturingTicketIssuer(deps.clock)
    deps = replace(deps, tickets=issuer)

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "policy_denied"
    assert state["error"] == "missing_recovery_support"
    assert issuer.requests == []
    assert deps.plugins.executor.calls == []


def test_hard_crash_after_apply_effect_restarts_from_dispatch_intent_without_replay(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_crash_step = "0"

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    assert deps.plugins.executor.apply_count == 1
    deps.plugins.executor.reconcile_result = "applied"
    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "succeeded"
    assert deps.plugins.executor.apply_count == 1


def test_hard_crash_after_prepare_effect_never_reprepares(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.prepare_crash_step = "0"

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    deps.plugins.executor.reconcile_result = "not_applied"
    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "failed"
    assert deps.plugins.executor.calls.count("prepare") == 1
    assert "apply" not in deps.plugins.executor.calls


def test_crash_after_completed_prepare_outcome_resumes_from_durable_marker(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    crash_after_atomic_completion(
        deps.transactions, "complete_prepare_dispatch"
    )

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    assert len(deps.transactions.get_steps("event-1")) == 1
    assert deps.transactions.pending_dispatch("event-1") is None
    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "succeeded"
    assert deps.plugins.executor.calls.count("prepare") == 2


def test_crash_after_entering_executing_resumes_before_first_apply(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    crash_after_entering_executing(deps.transactions)

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    assert deps.transactions.get("event-1").status is TransactionStatus.EXECUTING
    assert deps.transactions.pending_dispatch("event-1") is None
    assert deps.plugins.executor.apply_count == 0
    identity_checks_before_resume = deps.plugins.collector.calls.count(
        "verify_identity"
    )

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "succeeded"
    assert deps.plugins.executor.apply_count == 1
    assert deps.plugins.collector.calls.count("verify_identity") >= (
        identity_checks_before_resume + 2
    )
    assert deps.transactions.get("event-1").status is TransactionStatus.SUCCEEDED


def test_incomplete_frozen_plan_evidence_after_entering_executing_safe_stops(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    crash_after_entering_executing(deps.transactions)
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    with sqlite3.connect(deps.transactions._path) as connection:  # type: ignore[attr-defined]
        connection.execute(
            "DELETE FROM effect_dispatches WHERE transaction_id = 'event-1' AND step_id = '1'"
        )
        connection.execute(
            "DELETE FROM plugin_markers WHERE transaction_id = 'event-1' AND step_id = '1'"
        )
        connection.execute(
            "DELETE FROM transaction_steps WHERE transaction_id = 'event-1' AND step_id = '1'"
        )

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "execution_unknown"
    assert deps.plugins.executor.apply_count == 0
    assert deps.plugins.executor.calls.count("prepare") == 2
    with pytest.raises(TargetBusyError):
        deps.transactions.begin("event-2", "target-1", "b" * 64, now=200)


@pytest.mark.parametrize("field", ["pre_state", "marker"])
def test_invalid_durable_prepare_json_safe_stops_without_effects(
    deps_factory, field: str
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    crash_after_entering_executing(deps.transactions)
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    with sqlite3.connect(deps.transactions._path) as connection:  # type: ignore[attr-defined]
        if field == "pre_state":
            connection.execute(
                """
                UPDATE transaction_steps SET pre_state_json = '[]'
                WHERE transaction_id = 'event-1' AND step_id = '0'
                """
            )
        else:
            connection.execute(
                """
                UPDATE plugin_markers SET marker_json = '{'
                WHERE transaction_id = 'event-1' AND step_id = '0'
                """
            )

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "execution_unknown"
    assert resumed["error"] == "durable_recovery_evidence_incomplete"
    assert deps.plugins.executor.apply_count == 0
    assert deps.plugins.executor.calls.count("prepare") == 1
    with pytest.raises(TargetBusyError):
        deps.transactions.begin("event-2", "target-1", "b" * 64, now=200)


def test_prepare_defensively_handles_corruption_after_resume_predicate(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    crash_after_entering_executing(deps.transactions)
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    with sqlite3.connect(deps.transactions._path) as connection:  # type: ignore[attr-defined]
        connection.execute(
            """
            UPDATE plugin_markers SET marker_json = 'null'
            WHERE transaction_id = 'event-1' AND step_id = '0'
            """
        )
    deps.transactions.next_recovery_action = (  # type: ignore[method-assign]
        lambda transaction_id, *, now: RecoveryAction.RESUME
    )
    deps.transactions.pre_first_apply_evidence_matches = (  # type: ignore[method-assign]
        lambda transaction_id, expected_operations: True
    )

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "execution_unknown"
    assert resumed["error"] == "durable_prepare_evidence_invalid"
    assert deps.plugins.executor.apply_count == 0
    assert deps.plugins.executor.calls.count("prepare") == 1
    with pytest.raises(TargetBusyError):
        deps.transactions.begin("event-2", "target-1", "b" * 64, now=200)


def test_reconciled_prepare_marker_is_persisted_and_consumed_without_reprepare(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.prepare_crash_step = "0"
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    deps.plugins.executor.reconcile_response = ReconcileEffect(
        outcome="applied",
        prepared=PreparedEffect(
            pre_state={"content": "reconciled-old"},
            marker={"marker": "reconciled-marker"},
        ),
    )

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "succeeded"
    assert deps.plugins.executor.calls.count("prepare") == 1
    durable = deps.transactions.get_steps("event-1")[0]
    assert json.loads(durable.plugin_marker_json) == {
        "marker": "reconciled-marker"
    }


def test_malformed_apply_response_is_execution_unknown_not_replayed(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_result = {"unexpected": True}

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "execution_unknown"
    assert deps.plugins.executor.apply_count == 1


def test_crash_after_completed_apply_outcome_advances_without_reapply(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    crash_after_atomic_completion(
        deps.transactions, "complete_result_dispatch", phase="apply"
    )

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    assert deps.plugins.executor.apply_count == 1
    assert deps.transactions.pending_dispatch("event-1") is None
    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "succeeded"
    assert deps.plugins.executor.apply_count == 2


def test_malformed_prepare_response_is_execution_unknown(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.prepare_result = {"unexpected": True}

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "execution_unknown"
    assert deps.plugins.executor.calls.count("prepare") == 1
    assert "apply" not in deps.plugins.executor.calls


def test_malformed_verify_response_rolls_back_and_verifies_restoration(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.verify_result = {"unexpected": True}

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "rollback_succeeded"
    assert deps.plugins.executor.calls.count("undo:0") == 1
    assert deps.plugins.executor.calls.count("verify_restored:0") == 1


def test_malformed_undo_response_is_rollback_unknown_and_retains_lock(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.verify_fail_step = "0"
    deps.plugins.executor.undo_result = {"unexpected": True}

    graph = build_graph(deps)
    first = run_event(graph, event_for())
    state = run_event(build_graph(deps), resume_for(first["transaction_id"]))

    assert state["status"] == "rollback_unknown"
    with pytest.raises(TargetBusyError):
        deps.transactions.begin("event-2", "target-1", "b" * 64, now=102)


def test_malformed_reconcile_response_stops_without_replay(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_crash_step = "0"
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    deps.plugins.executor.reconcile_response = {"unexpected": True}

    state = run_event(build_graph(deps), resume_for("event-1"))

    assert state["status"] == "execution_unknown"
    assert deps.plugins.executor.apply_count == 1


def test_identity_change_after_approval_invalidates_execution(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)
    first = run_event(graph, event_for())
    approval = deps.approvals.get(first["approval_id"])
    deps.approvals.approve(
        approval.id,
        approved_digest=approval.plan_digest,
        actor="uid:1000",
        now=101,
    )
    deps.plugins.collector.fingerprint = "machine-2"

    resumed = run_event(graph, resume_for(first["transaction_id"]))

    assert resumed["status"] == "policy_denied"
    assert resumed["error"] == "target_identity_changed"
    assert deps.plugins.executor.calls == []


def test_registry_revocation_after_approval_has_zero_execution(
    deps_factory, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)
    pending = run_event(graph, event_for())
    approval = deps.approvals.get(pending["approval_id"])
    deps.approvals.approve(
        approval.id,
        approved_digest=approval.plan_digest,
        actor="uid:1000",
        now=101,
    )
    empty_root = tmp_path / "empty-registry"
    empty_root.mkdir()
    empty_registry = PluginRegistry.load((), empty_root, core_api="1.0")
    revoked = replace(
        deps,
        registry=empty_registry,
        policy=PolicyEngine(
            deps.settings, empty_registry, authorization_key=POLICY_KEY
        ),
    )

    state = run_event(build_graph(revoked), resume_for("event-1"))

    assert state["status"] == "policy_denied"
    assert deps.plugins.executor.calls == []


def test_plan_fingerprint_mismatch_has_zero_effect_dispatches(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(fingerprint="different-machine")

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "policy_denied"
    assert deps.plugins.executor.calls == []


def test_write_revocation_before_crash_recovery_allows_no_additional_write(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_crash_step = "0"
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    revoked_settings = deps.settings.model_copy(update={"global_mode": "read_only"})
    revoked = with_settings(deps, revoked_settings)
    deps.plugins.executor.reconcile_result = "applied"

    resumed = run_event(build_graph(revoked), resume_for("event-1"))

    assert resumed["status"] in {"policy_denied", "execution_unknown", "rollback_unknown"}
    assert deps.plugins.executor.apply_count == 1
    assert not [call for call in deps.plugins.executor.calls if call.startswith("undo:")]


def test_fingerprint_change_before_crash_recovery_allows_no_additional_write(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_crash_step = "0"
    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())
    deps.plugins.collector.fingerprint = "machine-2"
    deps.plugins.executor.reconcile_result = "applied"

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] in {"policy_denied", "execution_unknown", "rollback_unknown"}
    assert deps.plugins.executor.apply_count == 1
    assert not [call for call in deps.plugins.executor.calls if call.startswith("undo:")]


def test_high_approval_expiry_before_crash_recovery_allows_no_additional_write(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    graph = build_graph(deps)
    pending = run_event(graph, event_for())
    approval = deps.approvals.get(pending["approval_id"])
    deps.approvals.approve(
        approval.id,
        approved_digest=approval.plan_digest,
        actor="uid:1000",
        now=101,
    )
    deps.plugins.executor.apply_crash_step = "0"
    with pytest.raises(SimulatedCrash):
        run_event(graph, resume_for("event-1"))
    deps.clock.value = 401  # type: ignore[attr-defined]
    deps.plugins.executor.reconcile_result = "applied"

    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] in {"approval_expired", "execution_unknown", "rollback_unknown"}
    assert deps.plugins.executor.apply_count == 1
    assert not [call for call in deps.plugins.executor.calls if call.startswith("undo:")]


def test_verification_failure_rolls_back_all_applied_steps_in_reverse(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=3)
    deps.plugins.executor.verify_fail_step = "2"

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "rollback_succeeded"
    rollback_calls = [call for call in deps.plugins.executor.calls if call.startswith("undo:")]
    assert rollback_calls == ["undo:2", "undo:1", "undo:0"]
    assert [
        call for call in deps.plugins.executor.calls if call.startswith("verify_restored:")
    ] == ["verify_restored:2", "verify_restored:1", "verify_restored:0"]
    assert len(deps.plugins.executor.undo_tickets) == 3


def test_hard_crash_after_completed_undo_reconciles_and_does_not_repeat_undo(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.verify_fail_step = "0"
    deps.plugins.executor.undo_crash_step = "0"

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    deps.plugins.executor.reconcile_result = "not_applied"
    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "rollback_succeeded"
    assert deps.plugins.executor.calls.count("undo:0") == 1
    assert deps.plugins.executor.calls.count("verify_restored:0") == 1


def test_crash_after_completed_undo_outcome_advances_reverse_rollback(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    deps.plugins.executor.verify_fail_step = "1"
    crash_after_atomic_completion(
        deps.transactions, "complete_result_dispatch", phase="undo"
    )

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    assert deps.plugins.executor.calls.count("undo:1") == 1
    assert deps.transactions.pending_dispatch("event-1") is None
    resumed = run_event(build_graph(deps), resume_for("event-1"))

    assert resumed["status"] == "rollback_succeeded"
    assert deps.plugins.executor.calls.count("undo:1") == 1
    assert deps.plugins.executor.calls.count("undo:0") == 1


def test_undo_failure_is_reported_as_rollback_partial(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=3)
    deps.plugins.executor.verify_fail_step = "2"
    deps.plugins.executor.undo_fail_step = "1"
    deps.plugins.executor.restore_result = StepResult(ok=False, status="not_restored")

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "rollback_partial"
    assert [call for call in deps.plugins.executor.calls if call.startswith("undo:")] == [
        "undo:2",
        "undo:1",
        "undo:0",
    ]


def test_unknown_undo_is_reported_as_rollback_unknown(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    deps.plugins.executor.verify_fail_step = "1"
    deps.plugins.executor.undo_unknown_step = "0"

    first = run_event(build_graph(deps), event_for())
    state = run_event(build_graph(deps), resume_for(first["transaction_id"]))

    assert state["status"] == "rollback_unknown"


def test_model_failure_degrades_to_read_only_without_executor_calls(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.diagnose_error = RuntimeError("model unavailable")

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "read_only_no_model"
    assert deps.plugins.executor.calls == []


def test_malformed_final_verification_cannot_claim_success(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.collector.final_result = {"unexpected": True}  # type: ignore[assignment]

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "rollback_succeeded"
    assert deps.plugins.executor.calls.count("verify_restored:0") == 1


def test_prepare_failure_is_terminal_and_never_applies(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    deps.plugins.executor.prepare_error_step = "1"

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "execution_unknown"
    assert "apply" not in deps.plugins.executor.calls
    assert deps.transactions.get("event-1").status.value == "execution_unknown"


def test_reconcile_not_applied_requires_fresh_revalidated_event(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_error = TimeoutError()
    graph = build_graph(deps)
    first = run_event(graph, event_for())
    deps.plugins.executor.reconcile_result = "not_applied"

    resumed = run_event(graph, resume_for(first["transaction_id"]))

    assert resumed["status"] == "failed"
    assert resumed["error"] == "fresh_revalidated_event_required"
    assert deps.plugins.executor.apply_count == 1


def test_reconcile_unknown_stops_and_retains_target_lock(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.executor.apply_error = TimeoutError()
    graph = build_graph(deps)
    first = run_event(graph, event_for())
    deps.plugins.executor.reconcile_result = "unknown"

    resumed = run_event(graph, resume_for(first["transaction_id"]))

    assert resumed["status"] == "execution_unknown"
    with pytest.raises(TargetBusyError):
        deps.transactions.begin("event-2", "target-1", "b" * 64, now=102)


def test_reconcile_partial_enters_reverse_rollback(deps_factory) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory()
    deps.plugins.model.plan_result = make_plan(count=2)
    deps.plugins.executor.apply_error = TimeoutError()
    deps.plugins.executor.apply_error_step = "1"
    graph = build_graph(deps)
    first = run_event(graph, event_for())
    deps.plugins.executor.reconcile_result = "partial"

    resumed = run_event(graph, resume_for(first["transaction_id"]))

    assert resumed["status"] == "rollback_succeeded"
    assert [call for call in deps.plugins.executor.calls if call.startswith("undo:")] == [
        "undo:1",
        "undo:0",
    ]
    assert deps.plugins.executor.apply_count == 2


def test_optional_notification_failure_stays_approvable_and_is_audited(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory(notification_required=False)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    deps.plugins.notifier.delivered = False
    graph = build_graph(deps)

    first = run_event(graph, event_for())

    assert first["status"] == "pending_approval"
    assert {event["kind"] for event in first["audit_events"]} >= {
        "notification_failed"
    }
    approval = deps.approvals.get(first["approval_id"])
    deps.approvals.approve(
        approval.id,
        approved_digest=approval.plan_digest,
        actor="uid:1000",
        now=101,
    )
    assert run_event(graph, resume_for(first["transaction_id"]))["status"] == "succeeded"


@pytest.mark.parametrize(
    "malformed_ack",
    ["true", 1, {"delivered": True}, None],
)
def test_required_notification_acknowledgement_requires_exact_bool(
    deps_factory, malformed_ack: object
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory(notification_required=True)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    deps.plugins.notifier.delivered = malformed_ack  # type: ignore[assignment]

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "notification_blocked"
    approval = deps.approvals.for_transaction("event-1")
    assert approval is not None
    with pytest.raises(ApprovalStateError):
        deps.approvals.approve(
            approval.id,
            approved_digest=approval.plan_digest,
            actor="uid:1000",
            now=101,
        )


def test_optional_malformed_truthy_notification_ack_is_failed_and_pending(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory(notification_required=False)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    deps.plugins.notifier.delivered = "yes"  # type: ignore[assignment]

    state = run_event(build_graph(deps), event_for())

    assert state["status"] == "pending_approval"
    assert {event["kind"] for event in state["audit_events"]} >= {
        "notification_failed"
    }
    approval = deps.approvals.for_transaction("event-1")
    assert approval is not None
    assert approval.status.value == "pending"


def test_notification_crash_is_idempotent_and_conservatively_blocks_required_mode(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory(notification_required=True)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    deps.plugins.notifier.crash_after_delivery = True

    with pytest.raises(SimulatedCrash):
        run_event(build_graph(deps), event_for())

    approval = deps.approvals.for_transaction("event-1")
    assert approval is not None
    with pytest.raises(ApprovalStateError, match="notification"):
        deps.approvals.approve(
            approval.id,
            approved_digest=approval.plan_digest,
            actor="uid:1000",
            now=101,
        )

    resumed = run_event(build_graph(deps), resume_for("event-1"))
    approval = deps.approvals.for_transaction("event-1")
    assert resumed["status"] == "notification_blocked"
    assert deps.plugins.notifier.calls == ["send_approval"]
    assert approval is not None
    with pytest.raises(ApprovalStateError):
        deps.approvals.approve(
            approval.id,
            approved_digest=approval.plan_digest,
            actor="uid:1000",
            now=101,
        )


def test_mandatory_notification_failure_blocks_even_persisted_approval(
    deps_factory,
) -> None:  # type: ignore[no-untyped-def]
    deps = deps_factory(notification_required=True)
    deps.plugins.model.plan_result = make_plan(risk=Risk.HIGH)
    deps.plugins.notifier.delivered = False
    graph = build_graph(deps)

    first = run_event(graph, event_for())

    assert first["status"] == "notification_blocked"
    approval = deps.approvals.get(first["approval_id"])
    with pytest.raises(ApprovalStateError):
        deps.approvals.approve(
            approval.id,
            approved_digest=approval.plan_digest,
            actor="uid:1000",
            now=101,
        )
    resumed = run_event(graph, resume_for(first["transaction_id"]))
    assert resumed["status"] == "notification_blocked"
    assert deps.plugins.executor.calls == []

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver
from pydantic import ValidationError

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
    OperationTicketExpectation,
    OperationTicketRequest,
    TicketError,
    TicketIssuer,
    TicketVerifier,
)
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.policy_engine import PolicyAuthorization, PolicyEngine
from a4diag.settings import AgentSettings
from a4diag.transaction_store import (
    GlobalWriteLimitError,
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


POLICY_KEY = b"acceptance-policy-key-material-32"
TICKET_KEY = b"acceptance-ticket-key-material-32"


class SimulatedProcessCrash(BaseException):
    pass


class ManualClock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def operation(index: int = 0, *, risk: Risk = Risk.LOW) -> Operation:
    return Operation(
        capability="files",
        action="replace",
        resource=f"/etc/managed/service-{index}.conf",
        parameters={"content": f"enabled={index}\n"},
        model_risk=risk,
        verify={"sha256": "a" * 64},
        undo={"restore": True},
    )


def plan(
    *,
    count: int = 1,
    risk: Risk = Risk.LOW,
    target_id: str = "node-a",
    fingerprint: str = "identity-a",
) -> Plan:
    return Plan(
        target_id=target_id,
        target_fingerprint=fingerprint,
        operations=tuple(operation(index, risk=risk) for index in range(count)),
    )


def registry_at(root: Path) -> PluginRegistry:
    artifact_dir = root / "plugins"
    artifact_dir.mkdir(parents=True)
    artifact = artifact_dir / "files.whl"
    artifact.write_bytes(b"acceptance fixture artifact")
    manifest_path = root / "capability-files.json"
    manifest_path.write_bytes(
        json.dumps(
            {
                "name": "capability-files",
                "plugin_type": "capability",
                "version": "1.0.0",
                "api_min": "1.0",
                "api_max": "1.0",
                "executable": "a4diag_plugins.files:main",
                "socket": "/run/a4diag/files.sock",
                "config_schema": "schemas/files.json",
                "operations": [
                    {
                        "name": "files.replace",
                        "risk_floor": "low",
                        "reversible": True,
                        "supports_prepare": True,
                        "supports_verify": True,
                        "supports_reconcile": True,
                        "supports_undo": True,
                        "parameters_schema": {
                            "type": "object",
                            "properties": {"content": {"type": "string"}},
                            "required": ["content"],
                            "additionalProperties": False,
                        },
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    pin = PluginPin(
        name="capability-files",
        version="1.0.0",
        api_version="1.0",
        artifact_path="plugins/files.whl",
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        enabled=True,
    )
    return PluginRegistry.load((pin,), root, core_api="1.0")


class FakeCollector:
    def __init__(self) -> None:
        self.fingerprint = "identity-a"
        self.views = 0

    def verify_identity(self, target: TargetConfig) -> str:
        return self.fingerprint

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str:
        if fingerprint != self.fingerprint:
            raise PermissionError("identity changed")
        self.views += 1
        return f"view-{self.views}"

    def collect(self, target: TargetConfig, read_view: str) -> list[dict[str, object]]:
        return [{"view": read_view, "healthy": self.views > 1}]

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, object]],
    ) -> StepResult:
        return StepResult(ok=True, status="healthy")


class FakeModel:
    def __init__(self) -> None:
        self.plan_result = plan()
        self.critic_result = Risk.LOW
        self.failure: Exception | None = None

    def diagnose(
        self, target: TargetConfig, evidence: list[dict[str, object]]
    ) -> dict[str, object]:
        if self.failure is not None:
            raise self.failure
        return {"cause": "configuration drift", "confidence": 90}

    def plan(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        diagnosis: dict[str, object],
    ) -> Plan:
        return self.plan_result

    def critic(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        candidate: Plan,
    ) -> Risk:
        return self.critic_result


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.apply_timeout = False
        self.crash_after_apply = False
        self.reconcile_outcome = "unknown"
        self.verify_failure: str | None = None
        self.undo_failure: str | None = None
        self.undo_unknown: str | None = None
        self._verify_lock_probe: tuple[TransactionStore, str, str] | None = None
        self.verify_lock_probe_attempts: list[str] = []
        self.verify_lock_probe_busy: list[str] = []

    def arm_verify_lock_probe(
        self,
        store: TransactionStore,
        *,
        transaction_id: str,
        target_id: str,
    ) -> None:
        self._verify_lock_probe = (store, transaction_id, target_id)

    @property
    def prepare_count(self) -> int:
        return sum(call.startswith("prepare:") for call in self.calls)

    @property
    def apply_count(self) -> int:
        return sum(call.startswith("apply:") for call in self.calls)

    @property
    def undo_count(self) -> int:
        return sum(call.startswith("undo:") for call in self.calls)

    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        requested: Operation,
        ticket: str,
    ) -> PreparedEffect:
        self.calls.append(f"prepare:{step_id}")
        return PreparedEffect(
            pre_state={"content": "before"}, marker={"id": f"marker-{step_id}"}
        )

    def apply(
        self,
        target: TargetConfig,
        step_id: str,
        requested: Operation,
        marker: dict[str, object],
        ticket: str,
    ) -> StepResult:
        self.calls.append(f"apply:{step_id}")
        if self.crash_after_apply:
            self.crash_after_apply = False
            raise SimulatedProcessCrash("effect completed before response")
        if self.apply_timeout:
            self.apply_timeout = False
            raise TimeoutError("unknown effect result")
        return StepResult(ok=True, status="succeeded")

    def verify(
        self,
        target: TargetConfig,
        step_id: str,
        requested: Operation,
        marker: dict[str, object],
    ) -> StepResult:
        self.calls.append(f"verify:{step_id}")
        if self._verify_lock_probe is not None:
            store, transaction_id, target_id = self._verify_lock_probe
            self.verify_lock_probe_attempts.append(step_id)
            try:
                store.begin(
                    transaction_id,
                    target_id,
                    "d" * 64,
                    now=1_001,
                )
            except TargetBusyError:
                self.verify_lock_probe_busy.append(step_id)
            else:
                raise AssertionError(
                    "same-target write lock was not held during recovered verify"
                )
        if self.verify_failure == step_id:
            return StepResult(ok=False, status="failed")
        return StepResult(ok=True, status="succeeded")

    def undo(
        self,
        target: TargetConfig,
        step_id: str,
        requested: Operation,
        marker: dict[str, object],
        undo: dict[str, object] | None,
        ticket: str,
    ) -> StepResult:
        self.calls.append(f"undo:{step_id}")
        if self.undo_unknown == step_id:
            return StepResult(ok=False, status="unknown")
        if self.undo_failure == step_id:
            return StepResult(ok=False, status="failed")
        return StepResult(ok=True, status="succeeded")

    def reconcile(
        self,
        target: TargetConfig,
        step_id: str,
        requested: Operation,
        phase: OperationPhase,
        dispatch_id: str,
        marker: dict[str, object] | None,
    ) -> ReconcileEffect:
        self.calls.append(f"reconcile:{phase.value}:{step_id}")
        return ReconcileEffect(outcome=self.reconcile_outcome)

    def verify_restored(
        self,
        target: TargetConfig,
        step_id: str,
        requested: Operation,
        marker: dict[str, object],
        pre_state: dict[str, object],
    ) -> StepResult:
        self.calls.append(f"restoration:{step_id}")
        if self.undo_failure == step_id:
            return StepResult(ok=False, status="not_restored")
        return StepResult(ok=True, status="restored")


class FakeNotifier:
    def __init__(self) -> None:
        self.acknowledgement: object = True

    def send_approval(
        self,
        target: TargetConfig,
        transaction_id: str,
        digest: str,
        candidate: Plan,
        risk: Risk,
    ) -> bool:
        return self.acknowledgement  # type: ignore[return-value]


class CountingTicketIssuer(TicketIssuer):
    def __init__(self, clock: ManualClock) -> None:
        self.issue_count = 0
        self._counter = 0
        super().__init__(
            TICKET_KEY,
            authorization_key=POLICY_KEY,
            clock=clock,
            ticket_id_factory=self._next_ticket_id,
        )

    def _next_ticket_id(self) -> str:
        self._counter += 1
        return f"ticket-{self._counter}"

    def issue(
        self,
        request: OperationTicketRequest,
        authorization: PolicyAuthorization | None,
    ) -> str:
        self.issue_count += 1
        return super().issue(request, authorization)


class CoreHarness:
    def __init__(
        self,
        root: Path,
        *,
        settings: AgentSettings | None = None,
        notification_required: bool = False,
    ) -> None:
        self.root = root
        self.clock = ManualClock()
        self.collector = FakeCollector()
        self.model = FakeModel()
        self.executor = FakeExecutor()
        self.notifier = FakeNotifier()
        self.registry = registry_at(root / "registry")
        if settings is None:
            target = TargetConfig(
                id="node-a",
                mode="local",
                identity_ref="target/node-a",
                write_enabled=True,
                auto_execute_low=True,
                notification_required=notification_required,
                capabilities=(
                    CapabilityGrant(
                        name="files",
                        actions=("replace",),
                        resources=("/etc/managed/**",),
                    ),
                ),
            )
            settings = AgentSettings(
                global_mode="read_write",
                targets=(target,),
                auto_execute_low=True,
                max_write_targets=2,
            )
        self.settings = settings
        self.connection = sqlite3.connect(
            root / "checkpoints.sqlite3", check_same_thread=False
        )
        self.approvals = ApprovalStore(
            root / "approvals.sqlite3", request_id_factory=lambda: "approval-a"
        )
        self.transactions = TransactionStore(
            root / "transactions.sqlite3",
            max_concurrent_targets=settings.max_write_targets,
        )
        self.tickets = CountingTicketIssuer(self.clock)
        self._set_dependencies(settings)

    def _set_dependencies(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.deps = WorkflowDependencies(
            settings=settings,
            registry=self.registry,
            policy=PolicyEngine(settings, self.registry, authorization_key=POLICY_KEY),
            approvals=self.approvals,
            transactions=self.transactions,
            tickets=self.tickets,
            plugins=PluginPorts(
                model=self.model,
                collector=self.collector,
                executor=self.executor,
                notifier=self.notifier,
            ),
            checkpointer=SqliteSaver(self.connection),
            clock=self.clock,
            approval_ttl_seconds=60,
        )
        self.graph = build_graph(self.deps)

    def reconfigure(self, settings: AgentSettings) -> None:
        self._set_dependencies(settings)

    def run(self, *, event_id: str = "event-a", target_id: str = "node-a") -> dict[str, object]:
        return run_event(
            self.graph,
            {"event_id": event_id, "target_id": target_id, "request": "repair"},
        )

    def resume(self, event_id: str = "event-a") -> dict[str, object]:
        return run_event(
            self.graph, {"transaction_id": event_id, "resume": True}
        )

    def approve(self, state: dict[str, object]) -> None:
        approval = self.approvals.get(str(state["approval_id"]))
        self.approvals.approve(
            approval.id,
            approved_digest=approval.plan_digest,
            actor="local-cli:operator",
            now=self.clock.value + 1,
        )

    def assert_no_effects(self) -> None:
        assert self.executor.prepare_count == 0
        assert self.executor.apply_count == 0
        assert self.executor.undo_count == 0

    def close(self) -> None:
        self.connection.close()


@pytest.fixture
def harness(tmp_path: Path) -> CoreHarness:
    value = CoreHarness(tmp_path)
    yield value
    value.close()


def test_safe_empty_defaults_expose_no_target_and_no_write(tmp_path: Path) -> None:
    settings = AgentSettings()
    empty = CoreHarness(tmp_path, settings=settings)
    try:
        state = empty.run(target_id="unregistered")
        assert settings.global_mode == "read_only"
        assert settings.targets == ()
        assert settings.auto_execute_low is False
        assert state["status"] == "policy_denied"
        empty.assert_no_effects()
        # Catches a workflow that creates a transaction/lock before target policy.
        with sqlite3.connect(tmp_path / "transactions.sqlite3") as connection:
            transaction_count = connection.execute(
                "SELECT COUNT(*) FROM transactions WHERE transaction_id = ?",
                ("event-a",),
            ).fetchone()[0]
            lock_count = connection.execute(
                "SELECT COUNT(*) FROM target_write_locks"
            ).fetchone()[0]
        assert transaction_count == 0
        assert lock_count == 0
    finally:
        empty.close()


def test_unknown_target_denial_has_zero_effects(harness: CoreHarness) -> None:
    state = harness.run(target_id="unregistered")
    assert state["status"] == "policy_denied"
    assert str(state["error"]).startswith("target_resolution_failed")
    harness.assert_no_effects()


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        pytest.param("identity", "target_fingerprint_mismatch", id="identity-mismatch"),
        pytest.param("capability", "capability_not_allowed", id="missing-capability"),
        pytest.param("action", "action_not_allowed", id="missing-action"),
        pytest.param("resource", "resource_not_allowed", id="resource-escape"),
        pytest.param("target-read-only", "target_read_only", id="target-read-only"),
        pytest.param("global-read-only", "global_read_only", id="global-read-only"),
    ],
)
def test_policy_denials_never_reach_state_changing_executor(
    harness: CoreHarness, case: str, expected: str
) -> None:
    target = harness.settings.targets[0]
    if case == "identity":
        harness.model.plan_result = plan(fingerprint="identity-b")
    elif case == "capability":
        changed = target.model_copy(update={"capabilities": ()})
        harness.reconfigure(harness.settings.model_copy(update={"targets": (changed,)}))
    elif case == "action":
        grant = target.capabilities[0].model_copy(update={"actions": ()})
        changed = target.model_copy(update={"capabilities": (grant,)})
        harness.reconfigure(harness.settings.model_copy(update={"targets": (changed,)}))
    elif case == "resource":
        harness.model.plan_result = Plan(
            target_id="node-a",
            target_fingerprint="identity-a",
            operations=(operation().model_copy(update={"resource": "/etc/outside.conf"}),),
        )
    elif case == "target-read-only":
        changed = target.model_copy(update={"write_enabled": False})
        harness.reconfigure(harness.settings.model_copy(update={"targets": (changed,)}))
    else:
        harness.reconfigure(harness.settings.model_copy(update={"global_mode": "read_only"}))

    state = harness.run()

    assert state["status"] == "policy_denied"
    assert state["error"] == expected
    harness.assert_no_effects()


def test_lexical_resource_traversal_is_rejected_before_workflow(harness: CoreHarness) -> None:
    with pytest.raises(ValidationError):
        Operation.model_validate(
            operation().model_dump() | {"resource": "/etc/managed/../outside"}
        )
    harness.assert_no_effects()


def test_high_without_approval_has_no_ticket_and_no_effects(harness: CoreHarness) -> None:
    harness.model.plan_result = plan(risk=Risk.HIGH)
    state = harness.run()
    assert state["status"] == "pending_approval"
    assert harness.tickets.issue_count == 0
    harness.assert_no_effects()


def test_changed_frozen_digest_is_denied_on_full_high_resume(harness: CoreHarness) -> None:
    harness.model.plan_result = plan(risk=Risk.HIGH)
    pending = harness.run()
    harness.approve(pending)
    changed = plan(count=2, risk=Risk.HIGH).model_dump(mode="json")
    harness.graph.update_state(
        {"configurable": {"thread_id": "event-a"}},
        {"plan": changed},
        as_node="freeze_plan",
    )
    state = harness.resume()
    if state["status"] == "pending_approval":
        state = harness.resume()
    assert state["status"] == "policy_denied"
    assert state["error"] == "approval_mismatch"
    harness.assert_no_effects()


def test_expired_approval_is_rejected_on_full_resume(harness: CoreHarness) -> None:
    harness.model.plan_result = plan(risk=Risk.HIGH)
    pending = harness.run()
    harness.approve(pending)
    harness.clock.value += 61
    state = harness.resume()
    assert state["status"] == "approval_expired"
    harness.assert_no_effects()


class MemoryReplayStore:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def consume(self, ticket_id: str) -> bool:
        if ticket_id in self.seen:
            return False
        self.seen.add(ticket_id)
        return True


def ticket_fixture(
    harness: CoreHarness, *, phase: OperationPhase = OperationPhase.APPLY
) -> tuple[str, OperationTicketExpectation]:
    candidate = plan()
    target = harness.settings.targets[0]
    decision = harness.deps.policy.evaluate(
        target,
        candidate,
        critic_risk=Risk.LOW,
        approval_digest=None,
    )
    assert decision.authorization is not None
    request = OperationTicketRequest(
        transaction_id="ticket-tx",
        step_id="0",
        target_id=target.id,
        target_fingerprint=candidate.target_fingerprint,
        operation=candidate.operations[0],
        phase=phase,
        plan_digest=decision.digest,
        risk=Risk.LOW,
        approval_id=None,
        ttl_seconds=30,
    )
    token = harness.tickets.issue(request, decision.authorization)
    expected = OperationTicketExpectation(
        transaction_id=request.transaction_id,
        step_id=request.step_id,
        target_id=request.target_id,
        target_fingerprint=request.target_fingerprint,
        operation=request.operation,
        phase=request.phase,
        plan_digest=request.plan_digest,
        risk=request.risk,
        approval_id=request.approval_id,
    )
    return token, expected


@pytest.mark.parametrize(
    "case",
    [
        pytest.param("expired", id="expired"),
        pytest.param("replayed", id="replayed"),
        pytest.param("wrong-phase", id="wrong-phase"),
    ],
)
def test_operation_ticket_boundary_rejects_invalid_use(
    harness: CoreHarness, case: str
) -> None:
    token, expected = ticket_fixture(harness)
    replay = MemoryReplayStore()
    verifier = TicketVerifier(TICKET_KEY, replay, clock=harness.clock)
    if case == "expired":
        harness.clock.value += 30
        code = "expired"
    elif case == "wrong-phase":
        expected = expected.model_copy(update={"phase": OperationPhase.UNDO})
        code = "phase_mismatch"
    else:
        verifier.verify(token, expected)
        code = "replay"
    with pytest.raises(TicketError) as caught:
        verifier.verify(token, expected)
    assert caught.value.code == code
    harness.assert_no_effects()


def test_transaction_locks_enforce_same_target_and_cross_target_cap(tmp_path: Path) -> None:
    store = TransactionStore(tmp_path / "locks.sqlite3", max_concurrent_targets=2)
    store.begin("tx-a", "node-a", "a" * 64, now=1)
    with pytest.raises(TargetBusyError):
        store.begin("tx-a2", "node-a", "b" * 64, now=2)
    store.begin("tx-b", "node-b", "b" * 64, now=2)
    with pytest.raises(GlobalWriteLimitError):
        store.begin("tx-c", "node-c", "c" * 64, now=3)


def test_unknown_apply_restart_reconciles_without_second_apply(harness: CoreHarness) -> None:
    harness.executor.apply_timeout = True
    harness.executor.arm_verify_lock_probe(
        harness.transactions, transaction_id="probe-timeout", target_id="node-a"
    )
    first = harness.run()
    assert first["status"] == "execution_unknown"
    assert harness.executor.apply_count == 1
    # Catches premature release while the apply outcome is still ambiguous.
    with pytest.raises(TargetBusyError):
        harness.transactions.begin("event-b", "node-a", "b" * 64, now=1_001)
    harness.executor.reconcile_outcome = "applied"
    harness.graph = build_graph(harness.deps)
    resumed = harness.resume()
    assert resumed["status"] == "succeeded"
    # Catches blind replay, phase/step-free reconcile, or assumed success without verify.
    assert [call for call in harness.executor.calls if call.startswith("apply:")] == [
        "apply:0"
    ]
    assert [
        call for call in harness.executor.calls if call.startswith("reconcile:")
    ] == ["reconcile:apply:0"]
    assert [call for call in harness.executor.calls if call.startswith("verify:")] == [
        "verify:0"
    ]
    # Catches release in the narrow reconcile-to-verify window.
    assert harness.executor.verify_lock_probe_attempts == ["0"]
    assert harness.executor.verify_lock_probe_busy == ["0"]
    assert harness.executor.apply_count == 1
    # Catches failure to release only after reconciliation, verification, and close.
    harness.transactions.begin("event-b", "node-a", "b" * 64, now=1_002)


def test_completed_apply_crash_reconstructs_without_replay(harness: CoreHarness) -> None:
    harness.executor.crash_after_apply = True
    harness.executor.arm_verify_lock_probe(
        harness.transactions, transaction_id="probe-crash", target_id="node-a"
    )
    with pytest.raises(SimulatedProcessCrash):
        harness.run()
    assert harness.executor.apply_count == 1
    with pytest.raises(TargetBusyError):
        harness.transactions.begin("event-b", "node-a", "b" * 64, now=1_001)
    harness.executor.reconcile_outcome = "applied"
    harness.graph = build_graph(harness.deps)
    assert harness.resume()["status"] == "succeeded"
    # Catches a checkpoint recovery path that replays or skips independent verify.
    assert [call for call in harness.executor.calls if call.startswith("apply:")] == [
        "apply:0"
    ]
    assert [
        call for call in harness.executor.calls if call.startswith("reconcile:")
    ] == ["reconcile:apply:0"]
    assert [call for call in harness.executor.calls if call.startswith("verify:")] == [
        "verify:0"
    ]
    # Catches release after dispatch reconciliation but before recovered verify.
    assert harness.executor.verify_lock_probe_attempts == ["0"]
    assert harness.executor.verify_lock_probe_busy == ["0"]
    assert harness.executor.apply_count == 1
    harness.transactions.begin("event-b", "node-a", "b" * 64, now=1_002)


def test_rollback_is_exact_reverse_order(harness: CoreHarness) -> None:
    harness.model.plan_result = plan(count=3)
    harness.executor.verify_failure = "2"
    state = harness.run()
    assert state["status"] == "rollback_succeeded"
    # Catches skipped/reordered apply and rollback that is not strict LIFO.
    assert [call for call in harness.executor.calls if call.startswith("apply:")] == [
        "apply:0",
        "apply:1",
        "apply:2",
    ]
    assert [call for call in harness.executor.calls if call.startswith("undo:")] == [
        "undo:2",
        "undo:1",
        "undo:0",
    ]
    assert [
        call for call in harness.executor.calls if call.startswith("restoration:")
    ] == ["restoration:2", "restoration:1", "restoration:0"]
    assert [
        call
        for call in harness.executor.calls
        if call.startswith(("apply:", "verify:", "undo:", "restoration:"))
    ] == [
        "apply:0",
        "apply:1",
        "apply:2",
        "verify:0",
        "verify:1",
        "verify:2",
        "undo:2",
        "restoration:2",
        "undo:1",
        "restoration:1",
        "undo:0",
        "restoration:0",
    ]


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        pytest.param("partial", "rollback_partial", id="partial"),
        pytest.param("unknown", "rollback_unknown", id="unknown"),
    ],
)
def test_rollback_failure_is_truthful_and_lock_safe(
    harness: CoreHarness, case: str, expected: str
) -> None:
    harness.model.plan_result = plan(count=2)
    harness.executor.verify_failure = "1"
    if case == "partial":
        harness.executor.undo_failure = "0"
    else:
        harness.executor.undo_unknown = "0"
    state = harness.run()
    if state["status"] == "execution_unknown":
        state = harness.resume()
    assert state["status"] == expected
    # Catches synthesized rollback labels that do not reflect durable phase results.
    assert [call for call in harness.executor.calls if call.startswith("apply:")] == [
        "apply:0",
        "apply:1",
    ]
    assert [call for call in harness.executor.calls if call.startswith("undo:")] == [
        "undo:1",
        "undo:0",
    ]
    results = {
        (result.phase, result.step_id): result.status
        for result in harness.transactions.get_results("event-a")
    }
    assert results[("undo", "1")] == "succeeded"
    assert results[("undo", "0")] == (
        "unknown" if case == "unknown" else "failed"
    )
    assert harness.transactions.get("event-a").status is TransactionStatus(expected)
    if case == "unknown":
        # Catches automatic replay of an ambiguous undo instead of one reconcile.
        assert [
            call for call in harness.executor.calls if call.startswith("restoration:")
        ] == ["restoration:1"]
        assert [
            call for call in harness.executor.calls if call.startswith("reconcile:")
        ] == ["reconcile:undo:0"]
        assert harness.executor.calls.count("undo:0") == 1
        with pytest.raises(TargetBusyError):
            harness.transactions.begin("event-b", "node-a", "b" * 64, now=2_000)
    else:
        assert [
            call for call in harness.executor.calls if call.startswith("restoration:")
        ] == ["restoration:1", "restoration:0"]
        assert not [
            call for call in harness.executor.calls if call.startswith("reconcile:")
        ]
        harness.transactions.begin("event-b", "node-a", "b" * 64, now=2_000)


def test_model_failure_is_read_only_and_has_zero_effects(harness: CoreHarness) -> None:
    harness.model.failure = RuntimeError("model unavailable")
    state = harness.run()
    assert state["status"] == "read_only_no_model"
    harness.assert_no_effects()


def test_optional_notification_failure_is_audited_and_locally_approvable(
    harness: CoreHarness,
) -> None:
    harness.model.plan_result = plan(risk=Risk.HIGH)
    harness.notifier.acknowledgement = False
    pending = harness.run()
    assert pending["status"] == "pending_approval"
    assert "notification_failed" in {
        event["kind"] for event in pending["audit_events"]  # type: ignore[index]
    }
    harness.assert_no_effects()
    harness.approve(pending)
    assert harness.resume()["status"] == "succeeded"


@pytest.mark.parametrize(
    "acknowledgement",
    [pytest.param(False, id="false"), pytest.param("true", id="malformed-truthy")],
)
def test_required_notification_failure_is_blocked_and_non_approvable(
    tmp_path: Path, acknowledgement: object
) -> None:
    harness = CoreHarness(tmp_path, notification_required=True)
    try:
        harness.model.plan_result = plan(risk=Risk.HIGH)
        harness.notifier.acknowledgement = acknowledgement
        state = harness.run()
        assert state["status"] == "notification_blocked"
        harness.assert_no_effects()
        approval = harness.approvals.for_transaction("event-a")
        assert approval is not None
        with pytest.raises(ApprovalStateError):
            harness.approvals.approve(
                approval.id,
                approved_digest=approval.plan_digest,
                actor="local-cli:operator",
                now=harness.clock.value + 1,
            )
    finally:
        harness.close()


@pytest.mark.parametrize(
    "revocation",
    [pytest.param("configuration", id="configuration"), pytest.param("identity", id="identity")],
)
def test_current_boundary_revocation_on_high_resume_has_zero_effects(
    harness: CoreHarness, revocation: str
) -> None:
    harness.model.plan_result = plan(risk=Risk.HIGH)
    pending = harness.run()
    harness.approve(pending)
    if revocation == "configuration":
        harness.reconfigure(
            harness.settings.model_copy(update={"global_mode": "read_only"})
        )
    else:
        harness.collector.fingerprint = "identity-b"
    state = harness.resume()
    assert state["status"] == "policy_denied"
    harness.assert_no_effects()

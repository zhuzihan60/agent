"""Disposable fake-lab fixtures for the acceptance suite.

Every "machine" in the lab is a fake: the collector/executor/model ports are
injected fakes that record every attempted connection in a ledger, and the
runtime never contacts a real host, SSH daemon, mail server, model API, or
FlashDuty endpoint. The optional live_t11 scenario requires
``A4DIAG_ACCEPTANCE=1`` and is skipped otherwise.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from a4diag.approvals import ApprovalStore
from a4diag.audit import AuditWriter
from a4diag.domain import (
    CapabilityGrant,
    Operation,
    Plan,
    Risk,
    StepResult,
    TargetConfig,
    TargetMode,
)
from a4diag.plugin_api.ticket import TicketIssuer
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.policy_engine import PolicyEngine
from a4diag.runtime import Runtime, RuntimeResult
from a4diag.settings import AgentSettings
from a4diag.transaction_store import TransactionStore
from a4diag.workflow import (
    PluginPorts,
    PreparedEffect,
    ReconcileEffect,
)

POLICY_KEY = b"runtime-policy-key-32bytes-long!"
TICKET_KEY = b"runtime-ticket-key-32bytes-long!"


@dataclass
class NetworkLedger:
    connections: list[tuple[str, str]] = field(default_factory=list)

    def record(self, kind: str, destination: str) -> None:
        self.connections.append((kind, destination))

    def connections_to(self, *destinations: str) -> int:
        return sum(1 for _kind, destination in self.connections if destination in destinations)

    @property
    def total_connections(self) -> int:
        return len(self.connections)


class FakeCollector:
    def __init__(
        self,
        ledger: NetworkLedger,
        *,
        identity_error: Exception | None = None,
        identity_drift: bool = False,
        collect_error: Exception | None = None,
    ) -> None:
        self.ledger = ledger
        self.identity_error = identity_error
        self.identity_drift = identity_drift
        self.collect_error = collect_error
        self.fingerprint = "machine-1"
        self.verify_count = 0

    def verify_identity(self, target: TargetConfig) -> str:
        self.verify_count += 1
        self.ledger.record("identity", target.id)
        if self.identity_error is not None:
            raise self.identity_error
        if self.identity_drift and self.verify_count > 1:
            return "machine-1-drifted"
        return self.fingerprint

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str:
        self.ledger.record("read_view", target.id)
        return "read-view-1"

    def collect(self, target: TargetConfig, read_view: str) -> list[dict[str, object]]:
        self.ledger.record("collect", target.id)
        if self.collect_error is not None:
            raise self.collect_error
        return [{"symptom": "example service down"}]

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, object]],
    ) -> StepResult:
        self.ledger.record("final_verify", "target")
        return StepResult(ok=True, status="healthy")


class FakeModel:
    def __init__(
        self,
        *,
        risk: Risk = Risk.LOW,
        error: Exception | None = None,
        plan_risk: Risk | None = None,
    ) -> None:
        self.risk = risk
        self.error = error
        self.plan_risk = plan_risk or risk

    def diagnose(
        self, target: TargetConfig, evidence: list[dict[str, object]]
    ) -> dict[str, object]:
        if self.error is not None:
            raise self.error
        return {"cause": "stale unit file", "confidence": 0.9}

    def plan(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        diagnosis: dict[str, object],
    ) -> Plan:
        if self.error is not None:
            raise self.error
        return Plan(
            target_id=target.id,
            target_fingerprint="machine-1",
            operations=(
                Operation(
                    capability="files",
                    action="replace",
                    resource="/etc/example/app-0.conf",
                    parameters={"content": "value=0\n"},
                    model_risk=self.plan_risk,
                    verify={"content_sha256": "a" * 64},
                    undo={"restore_backup": True},
                ),
            ),
        )

    def critic(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        plan: Plan,
    ) -> Risk:
        if self.error is not None:
            raise self.error
        return self.risk


class FakeExecutor:
    def __init__(self, ledger: NetworkLedger) -> None:
        self.ledger = ledger
        self.apply_count = 0
        self.prepare_count = 0
        self.reconcile_count = 0
        self.undo_order: list[int] = []
        self.break_on_apply: Exception | None = None
        self.crash_after_apply: Exception | None = None
        self.prepare_crash: Exception | None = None
        self.undo_fail: Exception | None = None
        self.verify_fail_step: str | None = None
        self.reconcile_outcome: str = "not_applied"

    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        ticket: str,
    ) -> PreparedEffect:
        self.prepare_count += 1
        if self.prepare_crash is not None:
            raise self.prepare_crash
        return PreparedEffect(
            pre_state={"content": "before"},
            marker={"path": operation.resource, "pre": "before"},
        )

    def apply(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        ticket: str,
    ) -> StepResult:
        self.ledger.record("apply", target.id)
        self.apply_count += 1
        if self.break_on_apply is not None:
            raise self.break_on_apply
        if self.crash_after_apply is not None:
            raise self.crash_after_apply
        return StepResult(ok=True, status="succeeded")

    def verify(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
    ) -> StepResult:
        self.ledger.record("verify", target.id)
        if self.verify_fail_step == step_id:
            return StepResult(ok=False, status="failed", data={"reason": "verification failed"})
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
        self.ledger.record("undo", target.id)
        self.undo_order.append(int(step_id))
        if self.undo_fail is not None:
            raise self.undo_fail
        return StepResult(ok=True, status="succeeded")

    def reconcile(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        phase: object,
        dispatch_id: str,
        marker: dict[str, object] | None,
    ) -> ReconcileEffect:
        self.reconcile_count += 1
        return ReconcileEffect(outcome=self.reconcile_outcome, prepared=None)

    def verify_restored(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
        pre_state: dict[str, object],
    ) -> StepResult:
        return StepResult(ok=True, status="succeeded")


class FakeNotifier:
    def __init__(self) -> None:
        self.send_count = 0
        self.delivered = True

    def send_approval(
        self,
        target: TargetConfig,
        transaction_id: str,
        digest: str,
        plan: Plan,
        risk: Risk,
    ) -> bool:
        self.send_count += 1
        return self.delivered


@dataclass
class Lab:
    runtime: Runtime
    ledger: NetworkLedger
    collector: FakeCollector
    model: FakeModel
    executor: FakeExecutor
    notifier: FakeNotifier
    approvals: ApprovalStore
    ticket_key: bytes
    target_id: str = "target-1"

    def event(self, target_id: str | None = None, event_id: str = "evt-1") -> dict[str, object]:
        return {
            "event_id": event_id,
            "target_hint": target_id if target_id is not None else self.target_id,
            "request": "repair",
        }

    def run_agent(self, **event_kwargs: object) -> RuntimeResult:
        return self.runtime.handle(self.event(**event_kwargs))  # type: ignore[arg-type]

    def resume(self, transaction_id: str) -> RuntimeResult:
        return self.runtime.resume(transaction_id)

    def service_is_healthy(self) -> bool:
        return self.executor.apply_count == 1

    def outside_canary_unchanged(self) -> bool:
        return self.ledger.connections_to("unregistered", "10.0.0.99", "unknown") == 0


def write_registry(
    root: Path, *, operation_risk_floor: str = "low", supports_undo: bool = True
) -> PluginRegistry:
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
                "risk_floor": operation_risk_floor,
                "reversible": supports_undo,
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


def make_target(*, risk_floor: str = "low") -> TargetConfig:
    return TargetConfig(
        id="target-1",
        mode=TargetMode.LOCAL,
        identity_ref="target/target-1",
        write_enabled=True,
        auto_execute_low=True,
        capabilities=(
            CapabilityGrant(
                name="files",
                actions=("replace",),
                resources=("/etc/example/**",),
            ),
        ),
    )


@pytest.fixture
def lab_factory(tmp_path: Path):
    created: list[Lab] = []

    def make(
        *,
        operation_risk_floor: str = "low",
        model_risk: Risk = Risk.LOW,
        model_error: Exception | None = None,
        identity_error: Exception | None = None,
        identity_drift: bool = False,
        collect_error: Exception | None = None,
        supports_undo: bool = True,
    ) -> Lab:
        registry = write_registry(
            tmp_path, operation_risk_floor=operation_risk_floor, supports_undo=supports_undo
        )
        ledger = NetworkLedger()
        collector = FakeCollector(
            ledger,
            identity_error=identity_error,
            identity_drift=identity_drift,
            collect_error=collect_error,
        )
        model = FakeModel(risk=model_risk, error=model_error)
        executor = FakeExecutor(ledger)
        notifier = FakeNotifier()
        settings = AgentSettings(
            global_mode="read_write",
            targets=(make_target(),),
            auto_execute_low=True,
        )
        approvals = ApprovalStore(tmp_path / "approvals.sqlite3")
        connection = sqlite3.connect(tmp_path / "checkpoints.sqlite3", check_same_thread=False)
        runtime = Runtime(
            settings=settings,
            registry=registry,
            policy=PolicyEngine(settings, registry, authorization_key=POLICY_KEY),
            approvals=approvals,
            transactions=TransactionStore(tmp_path / "transactions.sqlite3"),
            tickets=TicketIssuer(
                TICKET_KEY,
                authorization_key=POLICY_KEY,
                clock=lambda: 1_700_000_000,
                ticket_id_factory=lambda: "ticket-acceptance",
            ),
            checkpointer=SqliteSaver(connection),
            plugins=PluginPorts(
                model=model,
                collector=collector,
                executor=executor,
                notifier=notifier,
            ),
            audit=AuditWriter(tmp_path / "audit.jsonl", clock=lambda: 1_700_000_000.0),
            clock=lambda: 1_700_000_000,
        )
        lab = Lab(
            runtime=runtime,
            ledger=ledger,
            collector=collector,
            model=model,
            executor=executor,
            notifier=notifier,
            approvals=approvals,
            ticket_key=TICKET_KEY,
        )
        created.append(lab)
        return lab

    yield make
    # Close audit fds and checkpointer connections so temporary directories
    # can be removed on Windows.
    for lab in created:
        lab.runtime.close()

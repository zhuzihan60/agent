from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import yaml
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
from a4diag.models import Alert
from a4diag.orchestrator import Orchestrator
from a4diag.plugin_api.ticket import TicketIssuer
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.policy_engine import PolicyEngine
from a4diag.report import ReportWriter, classify_report
from a4diag.runtime import Runtime
from a4diag.settings import AgentSettings
from a4diag.transaction_store import TransactionStore
from a4diag.workflow import PluginPorts, PreparedEffect, ReconcileEffect

POLICY_KEY = b"runtime-policy-key-32bytes-long!"
TICKET_KEY = b"runtime-ticket-key-32bytes-long!"


def make_target() -> TargetConfig:
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


def configured_settings() -> AgentSettings:
    return AgentSettings(
        global_mode="read_write",
        targets=(make_target(),),
        auto_execute_low=True,
    )


def write_registry(root: Path) -> PluginRegistry:
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
                "supports_undo": True,
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
        self.calls = 0

    def verify_identity(self, target: TargetConfig) -> str:
        return "machine-1"

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str:
        self.calls += 1
        return "read-view-1"

    def collect(self, target: TargetConfig, read_view: str) -> list[dict[str, object]]:
        return [{"symptom": "example service down"}]

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, object]],
    ) -> StepResult:
        return StepResult(ok=True, status="healthy")


class FakeModel:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error

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
                    model_risk=Risk.LOW,
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
        return Risk.LOW


class FakeExecutor:
    def __init__(self) -> None:
        self.apply_count = 0

    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        ticket: str,
    ) -> PreparedEffect:
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
        self.apply_count += 1
        return StepResult(ok=True, status="succeeded")

    def verify(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        marker: dict[str, object],
    ) -> StepResult:
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
        return ReconcileEffect(outcome="not_applied", prepared=None)

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
    def send_approval(self, *args, **kwargs) -> bool:
        return True


def build_runtime(root: Path, *, model_error: Exception | None = None) -> Runtime:
    registry = write_registry(root)
    connection = sqlite3.connect(root / "checkpoints.sqlite3", check_same_thread=False)
    return Runtime(
        settings=configured_settings(),
        registry=registry,
        policy=PolicyEngine(configured_settings(), registry, authorization_key=POLICY_KEY),
        approvals=ApprovalStore(root / "approvals.sqlite3"),
        transactions=TransactionStore(root / "transactions.sqlite3"),
        tickets=TicketIssuer(
            TICKET_KEY,
            authorization_key=POLICY_KEY,
            clock=lambda: 1_700_000_000,
            ticket_id_factory=lambda: "ticket-1",
        ),
        checkpointer=SqliteSaver(connection),
        plugins=PluginPorts(
            model=FakeModel(error=model_error),
            collector=FakeCollector(),
            executor=FakeExecutor(),
            notifier=FakeNotifier(),
        ),
        audit=AuditWriter(root / "audit.jsonl", clock=lambda: 1_700_000_000.0),
        clock=lambda: 1_700_000_000,
    )


ALERT = Alert(
    fingerprint="fp-001",
    starts_at="2026-08-24T09:00:00+08:00",
    name="HostHighCpu",
    severity="warning",
    target="target-1",
    labels={
        "alertname": "HostHighCpu",
        "instance": "10.3.12.131:9100",
        "severity": "warning",
    },
    annotations={"summary": "CPU usage is high"},
)


class OrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        runtime = getattr(self, "runtime", None)
        if runtime is not None:
            runtime.close()
        self.temp_dir.cleanup()

    def test_orchestrator_writes_v3_report_from_runtime_run(self) -> None:
        self.runtime = build_runtime(self.root)
        writer = ReportWriter(self.root)
        orchestrator = Orchestrator(runtime=self.runtime, writer=writer)

        report_path = Path(orchestrator.run_alert(ALERT))
        report = yaml.safe_load(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["status"], "succeeded")
        self.assertEqual(report["target_id"], "target-1")
        self.assertEqual(report["trigger"], "alertmanager")
        self.assertEqual(report["alert"]["fingerprint"], "fp-001")
        self.assertEqual(report["alert"]["name"], "HostHighCpu")
        self.assertIn("task_id", report)
        self.assertIn("finished_at", report)
        self.assertIn("equivalent_commands", report)
        if os.name != "nt":
            self.assertEqual(os.stat(report_path).st_mode & 0o777, 0o640)

    def test_orchestrator_records_model_failure_as_read_only_report(self) -> None:
        self.runtime = build_runtime(
            self.root, model_error=TimeoutError("model timeout")
        )
        executor = self.runtime.plugins.executor
        orchestrator = Orchestrator(
            runtime=self.runtime, writer=ReportWriter(self.root)
        )

        report_path = Path(orchestrator.run_alert(ALERT))
        report = yaml.safe_load(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["status"], "read_only_no_model")
        self.assertEqual(executor.apply_count, 0)
        self.assertNotIn("model timeout", json.dumps(report))

    def test_orchestrator_records_unregistered_alert_target_as_policy_denied(self) -> None:
        self.runtime = build_runtime(self.root)
        orchestrator = Orchestrator(
            runtime=self.runtime, writer=ReportWriter(self.root)
        )
        unregistered = Alert(
            fingerprint="fp-002",
            starts_at="2026-08-24T09:00:00+08:00",
            name="HostHighCpu",
            severity="warning",
            target="unknown",
            labels={"alertname": "HostHighCpu", "severity": "warning"},
            annotations={"summary": "CPU usage is high"},
        )

        report_path = Path(orchestrator.run_alert(unregistered))
        report = yaml.safe_load(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["status"], "policy_denied")
        self.assertEqual(report["target_id"], "")
        self.assertEqual(self.runtime.plugins.collector.calls, 0)


if __name__ == "__main__":
    unittest.main()

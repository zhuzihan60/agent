"""Integration tests for the generic plugin runtime.

Only fake plugin ports, fake identity probes, temporary SQLite stores, and
temporary configs are used; no server, real plugin, mail, or systemd is
touched.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from langgraph.checkpoint.sqlite import SqliteSaver

from a4diag.alertmanager import resolve_target_id
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
from a4diag.runtime import Runtime, RuntimeFailure, build_runtime
from a4diag.settings import AgentSettings
from a4diag.transaction_store import TransactionStore, TransactionStatus
from a4diag.workflow import (
    PluginPorts,
    PreparedEffect,
    ReconcileEffect,
)

POLICY_KEY = b"runtime-policy-key-32bytes-long!"
TICKET_KEY = b"runtime-ticket-key-32bytes-long!"


class FakeClock:
    def __init__(self, value: int = 1000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def make_target(
    *, write_enabled: bool = True, auto_execute_low: bool = True
) -> TargetConfig:
    return TargetConfig(
        id="target-1",
        mode=TargetMode.LOCAL,
        identity_ref="target/target-1",
        write_enabled=write_enabled,
        auto_execute_low=auto_execute_low,
        capabilities=(
            CapabilityGrant(
                name="files",
                actions=("replace",),
                resources=("/etc/example/**",),
            ),
        ),
    )


def empty_settings() -> AgentSettings:
    return AgentSettings(global_mode="read_only", targets=())


def configured_settings(
    *, write_enabled: bool = True, auto_execute_low: bool = True
) -> AgentSettings:
    return AgentSettings(
        global_mode="read_write" if write_enabled else "read_only",
        targets=(make_target(write_enabled=write_enabled, auto_execute_low=auto_execute_low),),
        auto_execute_low=auto_execute_low,
    )


def write_registry_files(root: Path) -> tuple[Path, PluginPin]:
    """Write the capability wheel, manifest, and matching pin; return (root, pin)."""
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
    return root, pin


def write_registry(root: Path) -> PluginRegistry:
    root, pin = write_registry_files(root)
    return PluginRegistry.load((pin,), root, core_api="1.0")


class FakeCollector:
    def __init__(self, *, identity_error: Exception | None = None) -> None:
        self.call_count = 0
        self.fingerprint = "machine-1"
        self.identity_error = identity_error

    def verify_identity(self, target: TargetConfig) -> str:
        self.call_count += 1
        if self.identity_error is not None:
            raise self.identity_error
        return self.fingerprint

    def acquire_read_view(self, target: TargetConfig, fingerprint: str) -> str:
        self.call_count += 1
        return "read-view-1"

    def collect(self, target: TargetConfig, read_view: str) -> list[dict[str, object]]:
        self.call_count += 1
        return [{"symptom": "example service down"}]

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, object]],
    ) -> StepResult:
        self.call_count += 1
        return StepResult(ok=True, status="healthy")


class FakeModel:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.call_count = 0
        self.error = error
        self.risk = Risk.LOW

    def diagnose(
        self, target: TargetConfig, evidence: list[dict[str, object]]
    ) -> dict[str, object]:
        self.call_count += 1
        if self.error is not None:
            raise self.error
        return {"cause": "stale unit file", "confidence": 0.9}

    def plan(
        self,
        target: TargetConfig,
        evidence: list[dict[str, object]],
        diagnosis: dict[str, object],
    ) -> Plan:
        self.call_count += 1
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
                    model_risk=self.risk,
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
        self.call_count += 1
        if self.error is not None:
            raise self.error
        return self.risk


class FakeExecutor:
    def __init__(self) -> None:
        self.apply_count = 0
        self.prepare_count = 0
        self.apply_error: Exception | None = None
        self.reconcile_calls: list[str] = []

    def prepare(
        self,
        target: TargetConfig,
        step_id: str,
        operation: Operation,
        ticket: str,
    ) -> PreparedEffect:
        self.prepare_count += 1
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
        if self.apply_error is not None:
            raise self.apply_error
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
        self.reconcile_calls.append(dispatch_id)
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
    def __init__(self) -> None:
        self.call_count = 0

    def send_approval(
        self,
        target: TargetConfig,
        transaction_id: str,
        digest: str,
        plan: Plan,
        risk: Risk,
    ) -> bool:
        self.call_count += 1
        return True


def build_ports(
    *,
    model_error: Exception | None = None,
    identity_error: Exception | None = None,
) -> tuple[PluginPorts, FakeCollector, FakeModel, FakeExecutor, FakeNotifier]:
    collector = FakeCollector(identity_error=identity_error)
    model = FakeModel(error=model_error)
    executor = FakeExecutor()
    notifier = FakeNotifier()
    return (
        PluginPorts(model=model, collector=collector, executor=executor, notifier=notifier),
        collector,
        model,
        executor,
        notifier,
    )


@pytest.fixture
def runtime_factory(tmp_path: Path):
    def make(
        settings: AgentSettings,
        *,
        model_error: Exception | None = None,
        identity_error: Exception | None = None,
        audit_chain_broken: bool = False,
        executor: FakeExecutor | None = None,
    ) -> Runtime:
        registry_root = tmp_path / f"registry-{make.counter}"
        make.counter += 1
        registry_root.mkdir()
        registry = write_registry(registry_root)
        ports, collector, model, fake_executor, notifier = build_ports(
            model_error=model_error, identity_error=identity_error
        )
        used_executor = executor or fake_executor
        ports = PluginPorts(
            model=model, collector=collector, executor=used_executor, notifier=notifier
        )
        clock = FakeClock()
        audit = AuditWriter(
            tmp_path / f"audit-{make.counter}.jsonl", clock=lambda: 1_700_000_000.0
        )
        if audit_chain_broken:
            audit.append({"event": "seed"})
            path = tmp_path / f"audit-{make.counter}.jsonl"
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text[:-2] + ("1" if text[-2] != "1" else "2") + "\n", encoding="utf-8"
            )
        connection = sqlite3.connect(
            tmp_path / f"checkpoints-{make.counter}.sqlite3",
            check_same_thread=False,
        )
        ticket_counter = iter(range(100))
        return Runtime(
            settings=settings,
            registry=registry,
            policy=PolicyEngine(settings, registry, authorization_key=POLICY_KEY),
            approvals=ApprovalStore(
                tmp_path / f"approvals-{make.counter}.sqlite3",
                request_id_factory=lambda: "approval-1",
            ),
            transactions=TransactionStore(
                tmp_path / f"transactions-{make.counter}.sqlite3"
            ),
            tickets=TicketIssuer(
                TICKET_KEY,
                authorization_key=POLICY_KEY,
                clock=clock,
                ticket_id_factory=lambda: f"ticket-{next(ticket_counter)}",
            ),
            checkpointer=SqliteSaver(connection),
            plugins=ports,
            audit=audit,
            clock=clock,
        )

    make.counter = 0
    return make


def event(*, target_hint: str | None = None, event_id: str = "evt-1") -> dict[str, object]:
    value: dict[str, object] = {"event_id": event_id, "request": "repair"}
    if target_hint is not None:
        value["target_hint"] = target_hint
    return value


# ---------------------------------------------------------------------------
# Empty install and target resolution
# ---------------------------------------------------------------------------


def test_empty_install_reports_policy_denied_without_plugin_calls(runtime_factory: Any) -> None:
    runtime = runtime_factory(empty_settings())

    result = runtime.handle(event(target_hint="unknown"))

    assert result.status == "policy_denied"
    assert runtime.plugins.model.call_count == 0
    assert runtime.plugins.collector.call_count == 0
    assert runtime.plugins.executor.apply_count == 0


def test_empty_install_without_hint_reports_read_only(runtime_factory: Any) -> None:
    runtime = runtime_factory(empty_settings())

    result = runtime.handle(event(target_hint=None))

    assert result.status == "read_only"
    assert runtime.plugins.collector.call_count == 0


def test_broken_audit_chain_forces_read_only(runtime_factory: Any) -> None:
    runtime = runtime_factory(empty_settings(), audit_chain_broken=True)

    result = runtime.handle(event(target_hint="unknown"))

    assert result.status == "read_only"
    assert "audit_chain_broken" in result.report["error"]
    assert runtime.plugins.collector.call_count == 0


def test_unregistered_target_hint_denied_without_ip_fallback(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings())

    result = runtime.handle(event(target_hint="192.0.2.10"))

    assert result.status == "policy_denied"
    assert runtime.plugins.collector.call_count == 0


# ---------------------------------------------------------------------------
# Model failure and execution
# ---------------------------------------------------------------------------


def test_model_failure_produces_read_only_report(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings(), model_error=TimeoutError("model timeout"))

    result = runtime.handle(event(target_hint="target-1"))

    assert result.status == "read_only_no_model"
    assert runtime.plugins.executor.apply_count == 0
    assert "read_only_no_model" in result.report["status"]


def test_low_plan_executes_and_succeeds(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings())

    result = runtime.handle(event(target_hint="target-1"))

    assert result.status == "succeeded"
    assert runtime.plugins.executor.apply_count == 1


def test_high_plan_enters_pending_approval(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings())
    runtime.plugins.model.risk = Risk.HIGH

    result = runtime.handle(event(target_hint="target-1"))

    assert result.status == "pending_approval"
    assert runtime.plugins.executor.apply_count == 0
    assert runtime.plugins.notifier.call_count == 1


# ---------------------------------------------------------------------------
# Unknown executions are never replayed
# ---------------------------------------------------------------------------


def test_unknown_execution_not_replayed(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings())
    runtime.plugins.executor.apply_error = RuntimeError("executor crash")

    first = runtime.handle(event(target_hint="target-1"))

    assert first.status == "execution_unknown"
    assert runtime.plugins.executor.apply_count == 1

    second = runtime.resume("evt-1")

    assert runtime.plugins.executor.apply_count == 1  # never re-applied
    assert second.status in {"execution_unknown", "failed", "rollback_running"}


# ---------------------------------------------------------------------------
# Startup verification
# ---------------------------------------------------------------------------


def test_build_runtime_verifies_audit_chain(
    tmp_path: Path, runtime_factory: Any
) -> None:
    settings_path = tmp_path / "config.yaml"
    settings_path.write_text("global_mode: read_only\ntargets: []\n", encoding="utf-8")
    audit = AuditWriter(tmp_path / "audit.jsonl", clock=lambda: 1_700_000_000.0)
    audit.append({"event": "seed"})
    path = tmp_path / "audit.jsonl"
    text = path.read_text(encoding="utf-8")
    path.write_text(text[:-2] + ("1" if text[-2] != "1" else "2") + "\n", encoding="utf-8")

    with pytest.raises(RuntimeFailure, match="audit_chain_broken"):
        build_runtime(
            settings_path,
            audit_path=tmp_path / "audit.jsonl",
            checkpoints_path=tmp_path / "checkpoints.sqlite3",
            transactions_path=tmp_path / "transactions.sqlite3",
            approvals_path=tmp_path / "approvals.sqlite3",
            registry_pins=(),
            manifest_root=tmp_path / "manifests",
            plugin_ports_factory=lambda settings, registry: build_ports()[0],
            ticket_key=TICKET_KEY,
            policy_key=POLICY_KEY,
            clock=FakeClock(),
        )


def test_build_runtime_uses_system_clock_when_clock_is_omitted(tmp_path: Path) -> None:
    settings_path = tmp_path / "config.yaml"
    settings_path.write_text(
        "global_mode: read_only\ntargets: []\nplugins: []\n",
        encoding="utf-8",
    )
    manifests = tmp_path / "manifests"
    manifests.mkdir()

    runtime = build_runtime(
        settings_path,
        audit_path=tmp_path / "audit.jsonl",
        checkpoints_path=tmp_path / "checkpoints.sqlite3",
        transactions_path=tmp_path / "transactions.sqlite3",
        approvals_path=tmp_path / "approvals.sqlite3",
        registry_pins=(),
        manifest_root=manifests,
        plugin_ports_factory=lambda settings, registry: build_ports()[0],
        ticket_key=TICKET_KEY,
        policy_key=POLICY_KEY,
    )
    try:
        result = runtime.handle({"event_id": "evt-clock", "request": "diagnose"})
        assert result.status == "read_only"
    finally:
        runtime.close()


def _write_target_config(tmp_path: Path) -> Path:
    settings_path = tmp_path / "config.yaml"
    settings_path.write_text(
        "global_mode: read_only\ntargets:\n  - id: target-1\n    mode: local\n"
        "    identity_ref: target/target-1\n    write_enabled: false\n"
        "    auto_execute_low: false\n    capabilities: []\n"
        "    notification_required: false\n",
        encoding="utf-8",
    )
    return settings_path


def _build_kwargs(tmp_path: Path, registry_root: Path, pins: tuple[PluginPin, ...], settings_path: Path) -> dict[str, object]:
    return {
        "settings_path": settings_path,
        "audit_path": tmp_path / "audit.jsonl",
        "checkpoints_path": tmp_path / "checkpoints.sqlite3",
        "transactions_path": tmp_path / "transactions.sqlite3",
        "approvals_path": tmp_path / "approvals.sqlite3",
        "registry_pins": pins,
        "manifest_root": registry_root,
        "plugin_ports_factory": lambda settings, registry: build_ports()[0],
        "ticket_key": TICKET_KEY,
        "policy_key": POLICY_KEY,
        "clock": FakeClock(),
    }


def test_build_runtime_rejects_bad_registry_pins(tmp_path: Path) -> None:
    settings_path = _write_target_config(tmp_path)
    registry_root = tmp_path / "registry"
    registry_root.mkdir()
    _registry, pin = write_registry_files(registry_root)
    wrong = PluginPin(
        name=pin.name,
        version=pin.version,
        api_version=pin.api_version,
        artifact_path=pin.artifact_path,
        artifact_sha256="a" * 64,
        manifest_sha256=pin.manifest_sha256,
        enabled=True,
    )

    with pytest.raises(RuntimeFailure, match="registry"):
        build_runtime(
            **_build_kwargs(tmp_path, registry_root, (wrong,), settings_path)  # type: ignore[arg-type]
        )


def test_build_runtime_probes_target_identity(tmp_path: Path) -> None:
    settings_path = _write_target_config(tmp_path)
    registry_root = tmp_path / "registry"
    registry_root.mkdir()
    _registry, pin = write_registry_files(registry_root)

    def failing_ports(settings: object, registry: object) -> PluginPorts:
        return build_ports(identity_error=RuntimeError("host key mismatch"))[0]

    kwargs = _build_kwargs(tmp_path, registry_root, (pin,), settings_path)
    kwargs["plugin_ports_factory"] = failing_ports

    with pytest.raises(RuntimeFailure, match="target_identity_unavailable"):
        build_runtime(**kwargs)  # type: ignore[arg-type]


def test_build_runtime_recovers_incomplete_transactions(tmp_path: Path) -> None:
    settings_path = _write_target_config(tmp_path)
    registry_root = tmp_path / "registry"
    registry_root.mkdir()
    _registry, pin = write_registry_files(registry_root)
    transactions = TransactionStore(tmp_path / "transactions.sqlite3")
    transactions.begin(
        "tx-incomplete", "target-1", "a" * 64, now=1
    )
    transactions.transition("tx-incomplete", TransactionStatus.PREPARING, now=2)
    transactions.mark_unknown("tx-incomplete", now=3)
    assert transactions.get("tx-incomplete").status is TransactionStatus.EXECUTION_UNKNOWN

    runtime = build_runtime(
        **_build_kwargs(tmp_path, registry_root, (pin,), settings_path)  # type: ignore[arg-type]
    )

    assert runtime.recoverable == ("tx-incomplete",)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_report_contains_required_fields(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings())

    result = runtime.handle(event(target_hint="target-1"))

    report = result.report
    assert report["event_id"] == "evt-1"
    assert report["transaction_id"] == "evt-1"
    assert report["target_id"] == "target-1"
    assert report["target_fingerprint"] == "machine-1"
    assert report["evidence"] == [{"symptom": "example service down"}]
    assert report["operations"][0]["capability"] == "files"
    assert "files replace /etc/example/app-0.conf" in report["equivalent_commands"][0]
    assert report["risk"] == "low"
    assert report["approval_status"] == "none"
    assert "results" in report
    assert report["residual_risk"]
    assert report["manual_commands"]


def test_report_never_leaks_secret(runtime_factory: Any) -> None:
    runtime = runtime_factory(configured_settings())
    runtime.plugins.collector.collect = lambda target, view: [
        {"log": "password=super-secret-token"}
    ]

    result = runtime.handle(event(target_hint="target-1"))

    dumped = json.dumps(result.report)
    assert "super-secret-token" not in dumped


# ---------------------------------------------------------------------------
# Alertmanager routing
# ---------------------------------------------------------------------------


def test_alertmanager_routes_only_by_registered_target_id() -> None:
    registered = {"target-1", "target-2"}

    assert resolve_target_id({"target_id": "target-1"}, registered) == "target-1"
    assert resolve_target_id({"target_id": "unknown"}, registered) is None
    # IP/instance labels never select a target.
    assert resolve_target_id({"ip": "192.0.2.10"}, registered) is None
    assert resolve_target_id({"instance": "target-1"}, registered) is None
    assert resolve_target_id({}, registered) is None

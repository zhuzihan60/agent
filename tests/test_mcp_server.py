from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import unittest
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver
from mcp import Client

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
from a4diag.mcp_server import build_server
from a4diag.plugin_api.ticket import TicketIssuer
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.policy_engine import PolicyEngine
from a4diag.runtime import Runtime
from a4diag.settings import AgentSettings
from a4diag.transaction_store import TransactionStore
from a4diag.workflow import PluginPorts

POLICY_KEY = b"runtime-policy-key-32bytes-long!"
TICKET_KEY = b"runtime-ticket-key-32bytes-long!"


def make_target() -> TargetConfig:
    return TargetConfig(
        id="target-1",
        mode=TargetMode.LOCAL,
        identity_ref="target/target-1",
        write_enabled=False,
        auto_execute_low=False,
        capabilities=(
            CapabilityGrant(
                name="files",
                actions=("replace",),
                resources=("/etc/example/**",),
            ),
        ),
    )


def settings() -> AgentSettings:
    return AgentSettings(
        global_mode="read_only",
        targets=(make_target(),),
        auto_execute_low=False,
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
        self.calls += 1
        return [{"symptom": "example service down"}]

    def final_verify(
        self,
        target: TargetConfig,
        read_view: str,
        evidence: list[dict[str, object]],
    ) -> StepResult:
        return StepResult(ok=True, status="healthy")


class FakeModel:
    def diagnose(self, target, evidence) -> dict[str, object]:
        return {"cause": "stale unit file", "confidence": 0.9}

    def plan(self, target, evidence, diagnosis) -> Plan:
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

    def critic(self, target, evidence, plan) -> Risk:
        return Risk.LOW


class FakeExecutor:
    def prepare(self, *args, **kwargs) -> object:
        raise AssertionError("MCP surface must never execute")

    def apply(self, *args, **kwargs) -> object:
        raise AssertionError("MCP surface must never execute")

    def verify(self, *args, **kwargs) -> object:
        raise AssertionError("MCP surface must never execute")

    def undo(self, *args, **kwargs) -> object:
        raise AssertionError("MCP surface must never execute")

    def reconcile(self, *args, **kwargs) -> object:
        raise AssertionError("MCP surface must never execute")

    def verify_restored(self, *args, **kwargs) -> object:
        raise AssertionError("MCP surface must never execute")


class FakeNotifier:
    def send_approval(self, *args, **kwargs) -> bool:
        raise AssertionError("MCP surface must never notify")


def build_runtime(root: Path) -> tuple[Runtime, PluginRegistry, FakeCollector]:
    registry = write_registry(root)
    collector = FakeCollector()
    connection = sqlite3.connect(root / "checkpoints.sqlite3", check_same_thread=False)
    runtime = Runtime(
        settings=settings(),
        registry=registry,
        policy=PolicyEngine(settings(), registry, authorization_key=POLICY_KEY),
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
            model=FakeModel(),
            collector=collector,
            executor=FakeExecutor(),
            notifier=FakeNotifier(),
        ),
        audit=AuditWriter(root / "audit.jsonl", clock=lambda: 1_700_000_000.0),
        clock=lambda: 1_700_000_000,
    )
    return runtime, registry, collector


class McpServerTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.runtime, self.registry, self.collector = build_runtime(self.root)
        self.server = build_server(runtime=self.runtime, registry=self.registry)

    def tearDown(self) -> None:
        self.runtime.close()
        self.temp_dir.cleanup()

    def test_tool_surface_is_the_registered_read_only_diagnose(self) -> None:
        async def scenario() -> None:
            async with Client(self.server) as client:
                result = await client.list_tools()
                self.assertEqual({tool.name for tool in result.tools}, {"diagnose"})
                properties = set(result.tools[0].input_schema.get("properties", {}))
                self.assertEqual(properties, {"target", "capability", "action"})

        asyncio.run(scenario())

    def test_unregistered_target_is_policy_denied(self) -> None:
        async def scenario() -> None:
            async with Client(self.server) as client:
                result = await client.call_tool(
                    "diagnose",
                    {"target": "unknown", "capability": "files", "action": "replace"},
                )
                self.assertTrue(result.is_error)
                self.assertIn("POLICY_DENIED", result.content[0].text)

        asyncio.run(scenario())

    def test_ip_never_matches_a_target(self) -> None:
        async def scenario() -> None:
            async with Client(self.server) as client:
                result = await client.call_tool(
                    "diagnose",
                    {"target": "10.3.12.131", "capability": "files", "action": "replace"},
                )
                self.assertTrue(result.is_error)
                self.assertIn("POLICY_DENIED", result.content[0].text)

        asyncio.run(scenario())

    def test_unregistered_operation_is_policy_denied(self) -> None:
        async def scenario() -> None:
            async with Client(self.server) as client:
                result = await client.call_tool(
                    "diagnose",
                    {"target": "target-1", "capability": "files", "action": "remove"},
                )
                self.assertTrue(result.is_error)
                self.assertIn("POLICY_DENIED", result.content[0].text)

        asyncio.run(scenario())

    def test_registered_operation_collects_redacted_evidence(self) -> None:
        async def scenario() -> None:
            async with Client(self.server) as client:
                result = await client.call_tool(
                    "diagnose",
                    {"target": "target-1", "capability": "files", "action": "replace"},
                )
                self.assertFalse(result.is_error)
                self.assertEqual(result.structured_content["target"], "target-1")
                self.assertEqual(result.structured_content["fingerprint"], "machine-1")
                self.assertEqual(
                    result.structured_content["evidence"],
                    [{"symptom": "example service down"}],
                )

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()

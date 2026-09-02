"""Tests for the serve controller, the plugin supervisor, and the RPC ports.

No real AF_UNIX socket, server, mail, model, or FlashDuty endpoint is used:
the RPC executor fails closed on an unreachable socket path, the serve loop is
driven with an already-set stop event, and the plugin host is tested for
config loading and plugin construction only.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from a4diag.runtime import RuntimeFailure
from a4diag.settings import AgentSettings
from a4diag.workflow import PluginPorts

POLICY_KEY = b"runtime-policy-key-32bytes-long!"
TICKET_KEY = b"runtime-ticket-key-32bytes-long!"


def write_registry(root: Path) -> object:
    import sqlite3

    from a4diag.plugin_registry import PluginPin, PluginRegistry

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


def test_host_loads_instance_config(tmp_path: Path) -> None:
    from a4diag_builtin_plugins.host import load_instance_config

    config = tmp_path / "instance.yaml"
    config.write_text(
        "manifest: capability-files\n"
        "socket: /run/a4diag/capability-files.sock\n"
        "ticket_key_ref: file:plugin-ticket.key\n",
        encoding="utf-8",
    )
    parsed = load_instance_config(config)
    assert parsed == {
        "manifest": "capability-files",
        "socket": "/run/a4diag/capability-files.sock",
        "ticket_key_ref": "file:plugin-ticket.key",
        "config": {},
    }


def test_host_rejects_malformed_instance_config(tmp_path: Path) -> None:
    from a4diag_builtin_plugins.host import load_instance_config

    bad = tmp_path / "bad.yaml"
    bad.write_text("manifest: ../../escape\nsocket: x\n", encoding="utf-8")
    with pytest.raises(RuntimeFailure, match="instance_config_invalid"):
        load_instance_config(bad)

    missing = tmp_path / "missing.yaml"
    missing.write_text("manifest: capability-files\n", encoding="utf-8")
    with pytest.raises(RuntimeFailure, match="instance_config_invalid"):
        load_instance_config(missing)


def test_host_rejects_socket_not_bound_to_cli_instance() -> None:
    from a4diag_builtin_plugins.host import serve_instance

    with pytest.raises(RuntimeFailure, match="socket does not match instance identity"):
        serve_instance(
            {
                "manifest": "capability-files",
                "socket": "/run/a4diag/a-different-instance.sock",
                "ticket_key_ref": "file:plugin-ticket.key",
                "config": {},
            },
            instance_name="capability-lab-node-1",
        )


def test_host_wires_capability_and_transport_hosts_with_strict_config() -> None:
    from a4diag_builtin_plugins.host import build_plugin

    files = build_plugin("capability-files")
    assert hasattr(files, "prepare") and hasattr(files, "apply")
    assert hasattr(build_plugin("capability-services"), "undo")
    assert hasattr(build_plugin("capability-packages"), "verify")
    assert hasattr(build_plugin("transport-local"), "verify_identity")
    with pytest.raises(RuntimeFailure, match="instance_config_invalid"):
        build_plugin("transport-ssh")


def test_rpc_ports_compose_and_runtime_builds_with_zero_targets(tmp_path: Path) -> None:
    from a4diag.approvals import ApprovalStore
    from a4diag.audit import AuditWriter
    from a4diag.plugin_api.ticket import TicketIssuer
    from a4diag.plugin_ports import build_rpc_plugin_ports
    from a4diag.plugin_registry import PluginRegistry
    from a4diag.policy_engine import PolicyEngine
    from a4diag.runtime import build_runtime
    from a4diag.transaction_store import TransactionStore

    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    empty = PluginRegistry.load((), empty_root, core_api="1.0")
    settings = AgentSettings(global_mode="read_only", targets=())
    ports = build_rpc_plugin_ports(settings, empty)
    assert isinstance(ports, PluginPorts)

    settings_path = tmp_path / "config.yaml"
    settings_path.write_text(
        "global_mode: read_only\ntargets: []\nplugins: []\n", encoding="utf-8"
    )
    runtime = build_runtime(
        settings_path,
        audit_path=tmp_path / "audit.jsonl",
        checkpoints_path=tmp_path / "checkpoints.sqlite3",
        transactions_path=tmp_path / "transactions.sqlite3",
        approvals_path=tmp_path / "approvals.sqlite3",
        registry_pins=(),
        manifest_root=empty_root,
        plugin_ports_factory=build_rpc_plugin_ports,
        ticket_key=TICKET_KEY,
        policy_key=POLICY_KEY,
        clock=lambda: 1_700_000_000,
    )
    runtime.close()
    assert runtime.registered_target_ids == frozenset()


def test_rpc_executor_fails_closed_on_unreachable_socket(tmp_path: Path) -> None:
    from a4diag.domain import Operation, Risk
    from a4diag.plugin_ports import build_rpc_plugin_ports

    registry = write_registry(tmp_path)
    settings = AgentSettings(global_mode="read_only", targets=())
    ports = build_rpc_plugin_ports(settings, registry)
    operation = Operation(
        capability="files",
        action="replace",
        resource="/etc/example/app-0.conf",
        parameters={"content": "value=0\n"},
        model_risk=Risk.LOW,
        verify={"content_sha256": "a" * 64},
        undo={"restore_backup": True},
    )
    with pytest.raises(RuntimeFailure, match="plugin_rpc_failed|plugin_unavailable"):
        ports.executor.prepare(None, "0", operation, "ticket-1")  # type: ignore[arg-type]


def test_serve_loop_stops_on_stop_event() -> None:
    from a4diag.cli import run_serve_loop

    class CountingPoller:
        def __init__(self) -> None:
            self.polls = 0
            self.stop = threading.Event()

        def poll_once(self) -> int:
            self.polls += 1
            self.stop.set()
            return 1

    poller = CountingPoller()
    code = run_serve_loop(None, poller.stop, poller=poller, poll_interval_seconds=0.01)
    assert code == 0
    assert poller.polls == 1

    # An already-set stop event exits immediately without polling.
    stop = threading.Event()
    stop.set()
    code = run_serve_loop(None, stop, poller=poller, poll_interval_seconds=0.01)
    assert code == 0


def test_cli_parser_accepts_serve() -> None:
    from a4diag.cli import _parser

    assert _parser().parse_args(["serve"]).command == "serve"
    assert _parser().parse_args(["serve", "--once"]).once is True

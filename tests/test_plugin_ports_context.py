from __future__ import annotations

from a4diag.domain import Operation, Plan, Risk, TargetConfig, TargetMode
from a4diag.plugin_api.manifest import PluginType
from a4diag.plugin_ports import (
    _RpcCollectorPort,
    _RpcExecutorPort,
    _RpcModelPort,
    _RpcNotificationPort,
)
from a4diag.plugin_registry import PluginRegistry


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object], str | None]] = []

    async def call(
        self, method: str, params: dict[str, object], *, ticket: str | None = None
    ) -> dict[str, object]:
        self.calls.append((method, params, ticket))
        return {"ok": True, "status": "undone", "data": {}}


class ScriptedClient:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def call(
        self, method: str, params: dict[str, object], *, ticket: str | None = None
    ) -> dict[str, object]:
        assert ticket is None
        self.calls.append((method, params))
        return self.responses[method]


class TransportRegistry(PluginRegistry):
    def require(self, name: str, plugin_type: PluginType):  # type: ignore[override]
        assert name == "transport-local"
        assert plugin_type is PluginType.TRANSPORT
        return object()


def operation() -> Operation:
    return Operation(
        capability="files",
        action="replace_managed_file",
        resource="/etc/example.conf",
        parameters={"content": "new"},
        model_risk=Risk.LOW,
        verify={"sha256": "0" * 64},
        undo={"restore": True},
    )


def test_rpc_undo_binds_real_transaction_and_complete_effect_payload() -> None:
    client = RecordingClient()
    port = _RpcExecutorPort({"files": client})  # type: ignore[arg-type]
    port.bind_transaction("txn-123")

    result = port.undo(
        TargetConfig(id="lab", mode=TargetMode.LOCAL, identity_ref="target/lab"),
        "4",
        operation(),
        {"before_sha256": "1" * 64},
        {"restore": True},
        "ticket",
    )

    assert result.ok is True
    method, params, ticket = client.calls[0]
    assert method == "undo"
    assert ticket == "ticket"
    assert params["transaction_id"] == "txn-123"
    assert params["step_id"] == "4"
    assert params["marker"] == {"before_sha256": "1" * 64}
    assert params["undo"] == {"restore": True}


def test_rpc_collector_uses_registered_transport_and_preserves_read_view() -> None:
    fingerprint = "f" * 64
    client = ScriptedClient(
        {
            "verify_identity": {
                "ok": True,
                "data": {"fingerprint": fingerprint},
            },
            "read": {
                "ok": True,
                "stdout": "value",
                "data": {"truncated": False},
            },
        }
    )
    registry = object.__new__(TransportRegistry)
    collector = _RpcCollectorPort(registry, lambda _instance: client)  # type: ignore[arg-type]
    target = TargetConfig(
        id="lab", mode=TargetMode.LOCAL, identity_ref="target/lab"
    )

    view = collector.acquire_read_view(target, fingerprint)
    evidence = collector.collect(target, view)

    assert evidence[0] == {
        "kind": "target_fingerprint",
        "content": fingerprint,
        "truncated": False,
    }
    assert [item[1]["kind"] for item in client.calls if item[0] == "read"] == [
        "machine_id",
        "os_release",
        "systemd_version",
    ]


def test_rpc_model_builds_core_plan_from_strict_typed_result() -> None:
    fingerprint = "e" * 64
    client = ScriptedClient(
        {
            "plan": {
                "reasoning": "typed repair",
                "operations": [
                    {
                        "capability": "services",
                        "action": "restart",
                        "resource": "demo.service",
                        "parameters": {},
                        "model_risk": "low",
                        "verify": {"active": True},
                        "undo": {"restore": True},
                    }
                ],
            }
        }
    )
    port = _RpcModelPort(client)  # type: ignore[arg-type]
    target = TargetConfig(
        id="lab", mode=TargetMode.LOCAL, identity_ref="target/lab"
    )

    plan = port.plan(
        target,
        [{"kind": "target_fingerprint", "content": fingerprint}],
        {"cause": "stopped"},
    )

    assert plan.target_fingerprint == fingerprint
    assert plan.operations[0].model_risk is Risk.LOW
    assert client.calls[0][0] == "plan"


def test_rpc_notification_requires_receipts_from_every_configured_channel() -> None:
    first = ScriptedClient({"send": {"external_id": "one"}})
    second = ScriptedClient({"send": {"external_id": "two"}})
    notifier = _RpcNotificationPort((first, second))  # type: ignore[arg-type]
    target = TargetConfig(
        id="lab", mode=TargetMode.LOCAL, identity_ref="target/lab"
    )
    plan = Plan(
        target_id="lab", target_fingerprint="f" * 64, operations=(operation(),)
    )

    assert notifier.send_approval(target, "txn-1", "a" * 64, plan, Risk.HIGH)
    assert first.calls[0][1]["event"]["target_id"] == "lab"

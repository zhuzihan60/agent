from __future__ import annotations

from pathlib import Path

import pytest

from a4diag.runtime import RuntimeFailure
from a4diag_builtin_plugins.host import (
    build_bindings,
    build_plugin,
    load_instance_config,
)


def test_transport_ssh_host_uses_strict_instance_configuration() -> None:
    plugin = build_plugin(
        "transport-ssh",
        {
            "host": "sandbox.example",
            "port": 22,
            "user": "a4diag",
            "identity_file": "/etc/a4diag/ssh/id_ed25519",
            "known_hosts": "/etc/a4diag/ssh/known_hosts",
            "host_key_sha256": "a" * 64,
        },
    )

    assert set(build_bindings("transport-ssh", plugin)) == {
        "health",
        "describe",
        "capability_probe",
        "verify_identity",
        "read",
        "execute_typed",
        "prepare_typed",
        "apply_typed",
        "verify_typed",
        "undo_typed",
        "reconcile_typed",
    }


def test_model_and_notification_hosts_have_real_rpc_bindings() -> None:
    model = build_plugin(
        "model-openai-compatible",
        {
            "base_url": "https://model.example/v1",
            "api_key_ref": "file:model.key",
            "model": "deepseek-chat",
        },
    )
    notification = build_plugin(
        "notification-flashduty",
        {
            "url": "https://api.flashcat.cloud/event/push/alert/standard",
            "integration_key_ref": "file:flashduty.key",
        },
    )

    assert {"diagnose", "plan", "critic"} <= set(
        build_bindings("model-openai-compatible", model)
    )
    assert "send" in build_bindings("notification-flashduty", notification)


def test_instance_config_rejects_unknown_or_untyped_plugin_config(
    tmp_path: Path,
) -> None:
    config = tmp_path / "plugin.yaml"
    config.write_text(
        "manifest: transport-local\n"
        "socket: /run/a4diag/transport-local.sock\n"
        "ticket_key_ref: file:core-ticket.key\n"
        "config: nope\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeFailure, match="config must be a mapping"):
        load_instance_config(config)


def test_local_capability_cannot_receive_hidden_instance_fields() -> None:
    with pytest.raises(RuntimeFailure, match="instance_config_invalid"):
        build_plugin("capability-files", {"target": "other-server"})


def test_model_host_starts_without_controller_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from a4diag_builtin_plugins import host

    served = []

    async def serve(plugin_host, socket):
        served.append(socket)

    monkeypatch.setattr(host, "_serve_forever", serve)
    assert host.serve_instance({
        "manifest": "model-openai-compatible",
        "socket": "/run/a4diag/model-openai-compatible.sock",
        "ticket_key_ref": "file:unavailable-ticket.key",
        "config": {"base_url": "https://model.example/v1", "api_key_ref": "file:model.key", "model": "test"},
    }) == 0
    assert served == ["/run/a4diag/model-openai-compatible.sock"]


def test_effectful_host_keeps_replay_database_in_systemd_state_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from a4diag_builtin_plugins import host

    async def serve(plugin_host, socket):
        pass

    monkeypatch.setenv("STATE_DIRECTORY", str(tmp_path))
    monkeypatch.setattr(host, "_resolve_ticket_key", lambda ref: b"t" * 32)
    monkeypatch.setattr(host, "_serve_forever", serve)
    host.serve_instance({"manifest": "transport-local", "socket": "/run/a4diag/transport-local.sock",
                         "ticket_key_ref": "file:test.key", "config": {}}, instance_name="transport-local")
    assert (tmp_path / "replay-transport-local.sqlite3").is_file()

"""Production lifecycle tests for isolated built-in plugin instances."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from a4diag.plugin_instances import (
    InstanceActivationError,
    InstanceValidationError,
    PluginInstanceManager,
    PluginInstanceSpec,
)


class FakeSystemd:
    def __init__(self, *, enabled: bool = False, active: bool = False) -> None:
        self.enabled = enabled
        self.active = active
        self.healthy = True
        self.calls: list[tuple[str, str]] = []

    def is_enabled(self, unit: str) -> bool:
        self.calls.append(("is_enabled", unit))
        return self.enabled

    def is_active(self, unit: str) -> bool:
        self.calls.append(("is_active", unit))
        return self.active

    def enable(self, unit: str) -> None:
        self.calls.append(("enable", unit))
        self.enabled = True

    def disable(self, unit: str) -> None:
        self.calls.append(("disable", unit))
        self.enabled = False

    def start(self, unit: str) -> None:
        self.calls.append(("start", unit))
        self.active = True

    def stop(self, unit: str) -> None:
        self.calls.append(("stop", unit))
        self.active = False

    def health(self, instance: str, socket: str) -> bool:
        self.calls.append(("health", f"{instance}:{socket}"))
        return self.healthy


def _manager(tmp_path: Path, systemd: FakeSystemd) -> PluginInstanceManager:
    manifests = tmp_path / "manifests"
    secrets = tmp_path / "secrets"
    configs = tmp_path / "configs"
    manifests.mkdir()
    secrets.mkdir()
    (manifests / "transport-ssh.json").write_text(
        json.dumps(
            {
                "name": "transport-ssh",
                "plugin_type": "transport",
                "version": "0.4.2",
                "api_min": "1.0",
                "api_max": "1.0",
                "executable": "a4diag_builtin_plugins.transport_ssh:main",
                "socket": "/run/a4diag/transport-ssh.sock",
                "config_schema": "schemas/transport-ssh.json",
                "operations": [],
                "permissions": ["exec:ssh"],
                "network_access": ["target-ssh"],
                "secret_refs": ["target:ssh-key"],
                "target_compatibility": ["linux:systemd"],
                "read_risk_floor": "low",
                "write_risk_floor": "high",
            }
        ),
        encoding="utf-8",
    )
    key = secrets / "target.key"
    key.write_text("test-only-key\n", encoding="utf-8")
    key.chmod(0o600)
    return PluginInstanceManager(
        config_root=configs,
        manifest_root=manifests,
        secrets_root=secrets,
        systemd=systemd,
    )


def _spec() -> PluginInstanceSpec:
    return PluginInstanceSpec(
        instance="transport-lab-node-1",
        manifest="transport-ssh",
        socket="/run/a4diag/transport-lab-node-1.sock",
        ticket_key_ref="file:target.key",
        config={"target_id": "lab-node-1", "port": 22, "user": "operator"},
    )


def test_stage_then_activate_writes_config_and_starts_only_instance_socket(
    tmp_path: Path,
) -> None:
    systemd = FakeSystemd()
    manager = _manager(tmp_path, systemd)

    staged = manager.stage(_spec())

    assert not (tmp_path / "configs" / "transport-lab-node-1.yaml").exists()
    receipt = manager.activate(staged)
    payload = (tmp_path / "configs" / "transport-lab-node-1.yaml").read_text(
        encoding="utf-8"
    )
    assert "transport-lab-node-1" in payload
    assert "file:target.key" in payload
    assert receipt.instance == "transport-lab-node-1"
    assert systemd.enabled is True
    assert systemd.active is True
    assert ("enable", "a4diag-plugin@transport-lab-node-1.socket") in systemd.calls
    assert not any(call[1].endswith(".service") for call in systemd.calls)


def test_failed_health_restores_previous_config_and_systemd_state(tmp_path: Path) -> None:
    systemd = FakeSystemd(enabled=True, active=True)
    manager = _manager(tmp_path, systemd)
    final = tmp_path / "configs" / "transport-lab-node-1.yaml"
    final.parent.mkdir(exist_ok=True)
    original = b"previous: exact-bytes\n"
    final.write_bytes(original)
    staged = manager.stage(_spec())
    systemd.healthy = False

    with pytest.raises(InstanceActivationError, match="plugin_health_failed"):
        manager.activate(staged)

    assert final.read_bytes() == original
    assert systemd.enabled is True
    assert systemd.active is True


def test_explicit_rollback_restores_absent_config_and_disabled_socket(tmp_path: Path) -> None:
    systemd = FakeSystemd()
    manager = _manager(tmp_path, systemd)
    receipt = manager.activate(manager.stage(_spec()))

    manager.rollback(receipt)

    assert not (tmp_path / "configs" / "transport-lab-node-1.yaml").exists()
    assert systemd.enabled is False
    assert systemd.active is False


@pytest.mark.parametrize(
    "changes",
    (
        {"instance": "../escape"},
        {"socket": "/run/a4diag/other.sock"},
        {"manifest": "not-installed"},
        {"ticket_key_ref": "env:KEY"},
        {"config": {"command": "rm -rf /"}},
    ),
)
def test_invalid_instance_fails_before_config_or_systemd_change(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    systemd = FakeSystemd()
    manager = _manager(tmp_path, systemd)
    values = _spec().model_dump()
    values.update(changes)

    with pytest.raises((InstanceValidationError, ValueError)):
        manager.stage(PluginInstanceSpec.model_validate(values))

    assert list((tmp_path / "configs").glob("*")) == []
    assert systemd.calls == []


def test_symlink_ticket_secret_is_rejected_before_systemd(tmp_path: Path) -> None:
    systemd = FakeSystemd()
    manager = _manager(tmp_path, systemd)
    real = tmp_path / "secrets" / "real.key"
    real.write_text("test-only-key\n", encoding="utf-8")
    real.chmod(0o600)
    link = tmp_path / "secrets" / "link.key"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    values = _spec().model_dump()
    values["ticket_key_ref"] = "file:link.key"

    with pytest.raises(InstanceValidationError, match="ticket_key_invalid"):
        manager.stage(PluginInstanceSpec.model_validate(values))

    assert systemd.calls == []

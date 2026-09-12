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
        self.service_active = active
        self.healthy = True
        self.available_groups = {"a4diag-target"}
        self.calls: list[tuple[str, str]] = []

    def is_enabled(self, unit: str) -> bool:
        self.calls.append(("is_enabled", unit))
        return self.enabled

    def is_active(self, unit: str) -> bool:
        self.calls.append(("is_active", unit))
        return self.service_active if unit.endswith(".service") else self.active

    def enable(self, unit: str) -> None:
        self.calls.append(("enable", unit))
        self.enabled = True

    def disable(self, unit: str) -> None:
        self.calls.append(("disable", unit))
        self.enabled = False

    def start(self, unit: str) -> None:
        self.calls.append(("start", unit))
        if unit.endswith(".service"):
            self.service_active = True
        else:
            self.active = True

    def stop(self, unit: str) -> None:
        self.calls.append(("stop", unit))
        if unit.endswith(".service"):
            self.service_active = False
        else:
            self.active = False

    def daemon_reload(self) -> None:
        self.calls.append(("daemon_reload", ""))

    def require_group(self, name: str) -> None:
        if name not in self.available_groups:
            raise KeyError(name)

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
                "version": "0.5.0",
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
    assert not any(call[0] == "start" and call[1].endswith(".service") for call in systemd.calls)


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


def test_reconfigure_reloads_running_plugin_and_rollback_reloads_prior_config(tmp_path: Path) -> None:
    systemd = FakeSystemd(enabled=True, active=True)
    manager = _manager(tmp_path, systemd)
    final = tmp_path / "configs" / "transport-lab-node-1.yaml"
    final.parent.mkdir(exist_ok=True)
    final.write_bytes(b"previous: exact-bytes\n")
    receipt = manager.activate(manager.stage(_spec()))
    unit = "a4diag-plugin@transport-lab-node-1.service"
    assert ("stop", unit) in systemd.calls
    assert ("start", unit) in systemd.calls
    systemd.calls.clear()
    manager.rollback(receipt)
    assert final.read_bytes() == b"previous: exact-bytes\n"
    assert ("stop", unit) in systemd.calls
    assert ("start", unit) in systemd.calls


def test_model_credentials_exclude_ticket_and_restore_previous_dropin(tmp_path: Path) -> None:
    import shutil
    from a4diag.secrets import credential_name

    systemd = FakeSystemd()
    manager = _manager(tmp_path, systemd)
    manifest = Path(__file__).resolve().parents[1] / "packages/a4diag-builtin-plugins/manifests/model-openai-compatible.json"
    shutil.copyfile(manifest, tmp_path / "manifests/model-openai-compatible.json")
    key = tmp_path / "secrets/model.key"
    key.write_text("model-secret", encoding="utf-8")
    key.chmod(0o600)
    manager = PluginInstanceManager(config_root=tmp_path / "configs", manifest_root=tmp_path / "manifests",
        secrets_root=tmp_path / "secrets", systemd=systemd, systemd_root=tmp_path / "units")
    spec = PluginInstanceSpec(instance="model-openai-compatible", manifest="model-openai-compatible",
        socket="/run/a4diag/model-openai-compatible.sock", ticket_key_ref="file:unavailable.key",
        config={"api_key_ref": "file:model.key"})
    staged = manager.stage(spec)
    dropin = tmp_path / "units/a4diag-plugin@model-openai-compatible.service.d/credentials.conf"
    assert not dropin.exists()
    receipt = manager.activate(staged)
    payload = dropin.read_text(encoding="utf-8")
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in payload
    assert credential_name("file:model.key") in payload
    assert "unavailable.key" not in payload
    assert "model-secret" not in payload
    manager.rollback(receipt)
    assert not dropin.exists()


def test_ssh_instance_receives_only_its_own_credentials(tmp_path: Path) -> None:
    import yaml
    from a4diag.secrets import credential_name

    systemd = FakeSystemd()
    _manager(tmp_path, systemd)
    for name in ("id_ed25519", "known_hosts"):
        key = tmp_path / "secrets" / name
        key.write_text("test-only-material", encoding="utf-8")
        key.chmod(0o600)
    manager = PluginInstanceManager(config_root=tmp_path / "configs", manifest_root=tmp_path / "manifests",
        secrets_root=tmp_path / "secrets", systemd=systemd, systemd_root=tmp_path / "units")
    spec = _spec().model_copy(update={"config": {
        "identity_file": str(tmp_path / "secrets/id_ed25519"),
        "known_hosts": str(tmp_path / "secrets/known_hosts"),
    }})
    receipt = manager.activate(manager.stage(spec))
    config = yaml.safe_load(receipt.final_path.read_text(encoding="utf-8"))
    assert config["config"]["identity_file"] == "/run/credentials/a4diag-plugin@transport-lab-node-1.service/" + credential_name("file:id_ed25519")
    assert config["config"]["known_hosts"] == "/run/credentials/a4diag-plugin@transport-lab-node-1.service/" + credential_name("file:known_hosts")
    dropin = receipt.credential_path.read_text(encoding="utf-8")
    assert sum(line.startswith("LoadCredential=") and line != "LoadCredential="
               for line in dropin.splitlines()) == 3
    assert "core-policy.key" not in dropin


def test_only_local_transport_gets_executor_socket_group(tmp_path: Path) -> None:
    import shutil

    systemd = FakeSystemd()
    _manager(tmp_path, systemd)
    manifest = Path(__file__).resolve().parents[1] / "packages/a4diag-builtin-plugins/manifests/transport-local.json"
    shutil.copyfile(manifest, tmp_path / "manifests/transport-local.json")
    manager = PluginInstanceManager(config_root=tmp_path / "configs", manifest_root=tmp_path / "manifests",
        secrets_root=tmp_path / "secrets", systemd=systemd, systemd_root=tmp_path / "units")
    spec = PluginInstanceSpec(instance="transport-local", manifest="transport-local",
        socket="/run/a4diag/transport-local.sock", ticket_key_ref="file:target.key", config={})
    staged = manager.stage(spec)
    assert b"SupplementaryGroups=a4diag-target" in staged.credentials
    assert b"AF_INET" not in staged.credentials
    ssh = manager.stage(_spec())
    assert b"SupplementaryGroups=a4diag-target" not in ssh.credentials
    staged.staged_path.unlink()
    systemd.available_groups.clear()
    with pytest.raises(InstanceValidationError, match="target_runtime_group_missing"):
        manager.stage(spec)


def test_loadcredential_parser_receives_literal_id_and_source(tmp_path: Path) -> None:
    from a4diag.secrets import credential_name

    systemd = FakeSystemd()
    _manager(tmp_path, systemd)
    secrets = tmp_path / "secrets with %i"
    secrets.mkdir()
    source = secrets / "target.key"
    source.write_text("parser-boundary-secret", encoding="utf-8")
    source.chmod(0o600)
    manager = PluginInstanceManager(config_root=tmp_path / "configs", manifest_root=tmp_path / "manifests",
        secrets_root=secrets, systemd=systemd, systemd_root=tmp_path / "units")
    staged = manager.stage(_spec())
    directive = next(line for line in staged.credentials.decode().splitlines()
                     if line.startswith("LoadCredential=") and line != "LoadCredential=")
    # systemd v255 config_parse_load_credential splits on ':' without
    # EXTRACT_UNQUOTE, then expands unit specifiers in the literal source path.
    # https://github.com/systemd/systemd/blob/v255/src/core/load-fragment.c#L4511-L4541
    identifier, raw_source = directive.removeprefix("LoadCredential=").split(":", 1)
    assert identifier == credential_name("file:target.key")
    assert raw_source.replace("%%", "%") == str(source)
    assert Path(raw_source.replace("%%", "%")).read_text(encoding="utf-8") == "parser-boundary-secret"


def test_dynamic_accounts_fit_linux_limit_and_remain_instance_specific(tmp_path: Path) -> None:
    systemd = FakeSystemd()
    _manager(tmp_path, systemd)
    manager = PluginInstanceManager(config_root=tmp_path / "configs", manifest_root=tmp_path / "manifests",
        secrets_root=tmp_path / "secrets", systemd=systemd, systemd_root=tmp_path / "units")
    accounts = []
    for instance in ("model-openai-compatible", "transport-ssh-target-1", "x" * 63 + "a", "x" * 63 + "b"):
        spec = _spec().model_copy(update={"instance": instance, "socket": f"/run/a4diag/{instance}.sock"})
        staged = manager.stage(spec)
        lines = staged.credentials.decode().splitlines()
        user = next(line.removeprefix("User=") for line in lines if line.startswith("User="))
        assert 1 <= len(user) <= 31
        assert user.startswith("a4diag-") and user.isascii()
        assert f"Group={user}" in lines
        accounts.append(user)
        staged.staged_path.unlink()
        again = manager.stage(spec)
        assert again.credentials == staged.credentials
        again.staged_path.unlink()
    assert len(set(accounts)) == len(accounts)

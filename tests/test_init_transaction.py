"""Transactional production initialization contract.

All collaborators are fakes.  The Linux production implementations are
exercised later by the Task 10 systemd E2E gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ValidationError

from a4diag.domain import TargetMode
from a4diag.init_config import InitRequest, InitService, NotificationInit, TargetInit
from a4diag.init_transaction import (
    InitTransaction,
    InitTransactionError,
    build_builtin_instance_specs,
)
from a4diag.plugin_instances import PluginInstanceSpec
from a4diag.settings import load_settings


class IdentityProbe:
    def probe(self, target: TargetInit) -> str:
        return "sha256:" + ("a" if target.id == "lab" else "b") * 64


class ModelProbe:
    def probe(self, _config: object) -> None:
        return None


@dataclass
class Receipt:
    instance: str


class InstanceManager:
    def __init__(self, fail_on: str | None = None) -> None:
        self.fail_on = fail_on
        self.live: list[str] = ["prior"]
        self.staged: list[str] = []
        self.rolled_back: list[str] = []

    def stage(self, spec: PluginInstanceSpec) -> PluginInstanceSpec:
        self.staged.append(spec.instance)
        if self.fail_on == f"stage:{spec.instance}":
            raise RuntimeError("stage failed")
        return spec

    def activate(self, staged: PluginInstanceSpec) -> Receipt:
        if self.fail_on == f"activate:{staged.instance}":
            raise RuntimeError("activation failed")
        self.live.append(staged.instance)
        return Receipt(staged.instance)

    def rollback(self, receipt: Receipt) -> None:
        self.live.remove(receipt.instance)
        self.rolled_back.append(receipt.instance)


class NotificationProbe:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def probe(self, _notification: NotificationInit) -> None:
        if self.fail:
            raise RuntimeError("notification failed")


class WriteProbe:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def probe(self, target: TargetInit, fingerprint: str) -> None:
        self.calls.append((target.id, fingerprint))
        if self.fail:
            raise RuntimeError("target helper failed")


class Core:
    def __init__(self, fail_restart: bool = False) -> None:
        self.enabled = True
        self.active = True
        self.fail_restart = fail_restart
        self.restores: list[tuple[bool, bool]] = []

    def snapshot(self) -> tuple[bool, bool]:
        return self.enabled, self.active

    def restart(self) -> None:
        if self.fail_restart:
            raise RuntimeError("restart failed")

    def restore(self, enabled: bool, active: bool) -> None:
        self.enabled, self.active = enabled, active
        self.restores.append((enabled, active))


def request(*, write: bool = False, notification: bool = False) -> InitRequest:
    return InitRequest(
        global_mode="read_write" if write else "read_only",
        targets=(
            TargetInit(
                id="lab",
                mode=TargetMode.SSH,
                host="sandbox.invalid",
                port=22,
                user="a4diag-target",
                transport="transport-lab",
                identity_file_ref="file:targets/lab/id_ed25519",
                known_hosts_ref="file:targets/lab/known_hosts",
                operation_signing_key_ref="file:targets/lab/operation-ed25519.pem",
                host_key_sha256="c" * 64,
                write_enabled=write,
            ),
        ),
        notifications=(NotificationInit(channel="cli"),) if notification else (),
        write_confirmation="ENABLE" if write else None,
    )


def specs(_request: InitRequest) -> tuple[PluginInstanceSpec, ...]:
    return (
        PluginInstanceSpec(
            instance="transport-lab",
            manifest="transport-ssh",
            socket="/run/a4diag/transport-lab.sock",
            ticket_key_ref="file:core-ticket.key",
            config={"host": "sandbox.invalid"},
        ),
    )


def transaction(
    *, manager: InstanceManager | None = None,
    notification: NotificationProbe | None = None,
    write_probe: WriteProbe | None = None,
    core: Core | None = None,
    self_check=lambda _path: True,
) -> InitTransaction:
    return InitTransaction(
        service=InitService(transport=IdentityProbe(), model=ModelProbe()),
        instances=manager or InstanceManager(),
        notification=notification or NotificationProbe(),
        target_write=write_probe or WriteProbe(),
        core=core or Core(),
        self_check=self_check,
        instance_specs=specs,
    )


def test_noninteractive_global_write_requires_literal_enable() -> None:
    with pytest.raises(ValidationError):
        InitRequest.model_validate({"global_mode": "read_write"})
    with pytest.raises(ValidationError):
        InitRequest.model_validate(
            {"global_mode": "read_write", "write_confirmation": "yes"}
        )
    assert InitRequest.model_validate(
        {"global_mode": "read_write", "write_confirmation": "ENABLE"}
    ).global_mode == "read_write"


def test_success_persists_full_target_connection_and_pinned_identity(tmp_path: Path) -> None:
    destination = tmp_path / "config.yaml"
    write_probe = WriteProbe()
    result = transaction(write_probe=write_probe).execute(request(write=True), destination)

    configured = load_settings(destination).targets[0]
    assert configured.host == "sandbox.invalid"
    assert configured.port == 22
    assert configured.user == "a4diag-target"
    assert configured.transport == "transport-lab"
    assert configured.identity_fingerprint == "sha256:" + "a" * 64
    assert configured.identity_file_ref == "file:targets/lab/id_ed25519"
    assert configured.known_hosts_ref == "file:targets/lab/known_hosts"
    assert configured.operation_signing_key_ref == "file:targets/lab/operation-ed25519.pem"
    assert configured.host_key_sha256 == "c" * 64
    assert result.settings.global_mode == "read_write"
    assert write_probe.calls == [("lab", "sha256:" + "a" * 64)]


@pytest.mark.parametrize(
    "failure",
    ["socket", "notification", "target_helper", "core_restart", "self_check"],
)
def test_any_activation_failure_restores_config_instances_and_core(
    tmp_path: Path, failure: str
) -> None:
    destination = tmp_path / "config.yaml"
    destination.write_bytes(b"prior-config\n")
    manager = InstanceManager(
        fail_on="activate:transport-lab" if failure == "socket" else None
    )
    core = Core(fail_restart=failure == "core_restart")
    tx = transaction(
        manager=manager,
        notification=NotificationProbe(fail=failure == "notification"),
        write_probe=WriteProbe(fail=failure == "target_helper"),
        core=core,
        self_check=lambda _path: failure != "self_check",
    )

    with pytest.raises(InitTransactionError):
        tx.execute(request(write=True, notification=True), destination)

    assert destination.read_bytes() == b"prior-config\n"
    assert manager.live == ["prior"]
    assert core.enabled is True
    assert core.active is True


def test_builtin_specs_start_transport_but_no_controller_capability_service() -> None:
    built = build_builtin_instance_specs(
        request(write=True), secrets_root=Path("/secure")
    )

    assert [item.instance for item in built] == ["transport-lab"]
    assert all(not item.instance.startswith("capability-") for item in built)
    assert built[0].manifest == "transport-ssh"
    assert built[0].config["identity_file"] == "/secure/targets/lab/id_ed25519"
    assert built[0].config["known_hosts"] == "/secure/targets/lab/known_hosts"

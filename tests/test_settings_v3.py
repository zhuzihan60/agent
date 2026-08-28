from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from a4diag.settings import load_settings
from a4diag.domain import CapabilityGrant, StepResult, TargetConfig, TargetMode


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_empty_config_is_read_only(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        "global_mode: read_only\ntargets: []\nplugins: []\n",
    )

    settings = load_settings(path)

    assert settings.global_mode == "read_only"
    assert settings.targets == ()
    assert settings.auto_execute_low is False


def test_unknown_target_key_is_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        "global_mode: read_only\ntargets:\n  - id: lab\n    mode: local\n"
        "    surprise: true\nplugins: []\n",
    )

    with pytest.raises(ValueError, match="surprise"):
        load_settings(path)


def test_defaults_are_safe_when_optional_values_are_absent(tmp_path: Path) -> None:
    settings = load_settings(write_config(tmp_path, "{}\n"))

    assert settings.global_mode == "read_only"
    assert settings.targets == ()
    assert settings.plugins == ()
    assert settings.auto_execute_low is False
    assert settings.max_write_targets == 2


def test_valid_target_uses_its_canonical_identity_reference(tmp_path: Path) -> None:
    settings = load_settings(
        write_config(
            tmp_path,
            "targets:\n  - id: lab_01\n    mode: local\n"
            "    identity_ref: target/lab_01\n    capabilities:\n"
            "      - name: filesystem\n        actions: [read]\n"
            "        resources: [/var/log/**]\n",
        )
    )

    assert settings.targets[0].id == "lab_01"
    assert settings.targets[0].mode is TargetMode.LOCAL
    assert settings.targets[0].capabilities[0].actions == ("read",)
    assert settings.targets[0].capabilities[0].resources == ("/var/log/**",)


def test_capability_grant_defaults_to_no_authorized_actions() -> None:
    grant = CapabilityGrant(name="filesystem", resources=("/var/log/**",))

    assert grant.actions == ()


@pytest.mark.parametrize("action", ["", " ", "replace/file", "replace.action", "bad\nname"])
def test_capability_actions_reject_unsafe_names(action: str) -> None:
    with pytest.raises(ValidationError, match="action"):
        CapabilityGrant(
            name="filesystem",
            actions=(action,),
            resources=("/var/log/**",),
        )


def test_capability_actions_reject_duplicates() -> None:
    with pytest.raises(ValidationError, match="duplicate capability action"):
        CapabilityGrant(
            name="filesystem",
            actions=("replace", "replace"),
            resources=("/var/log/**",),
        )


@pytest.mark.parametrize("target_id", ["", "-lab", ".lab", "lab name", "a" * 65])
def test_target_id_must_match_the_safe_identifier_format(target_id: str) -> None:
    with pytest.raises(ValidationError, match="id"):
        TargetConfig(id=target_id, mode="local", identity_ref=f"target/{target_id}")


@pytest.mark.parametrize("mode", ["local", "ssh"])
def test_each_target_mode_requires_the_canonical_identity_reference(mode: str) -> None:
    with pytest.raises(ValidationError, match="identity_ref"):
        TargetConfig(id="lab", mode=mode, identity_ref="other/lab")


def test_duplicate_target_ids_are_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        "targets:\n  - id: lab\n    mode: local\n    identity_ref: target/lab\n"
        "  - id: lab\n    mode: ssh\n    identity_ref: target/lab\n",
    )

    with pytest.raises(ValueError, match="duplicate target id"):
        load_settings(path)


def test_duplicate_plugin_names_are_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "plugins: [audit, audit]\n")

    with pytest.raises(ValueError, match="duplicate plugin"):
        load_settings(path)


def test_duplicate_capability_names_and_resources_are_rejected() -> None:
    duplicate_name = (
        CapabilityGrant(name="network", resources=("/etc/hosts",)),
        CapabilityGrant(name="network", resources=("/etc/resolv.conf",)),
    )
    duplicate_resource = (
        CapabilityGrant(name="network", resources=("/etc/hosts",)),
        CapabilityGrant(name="filesystem", resources=("/etc/hosts",)),
    )

    with pytest.raises(ValidationError, match="duplicate capability name"):
        TargetConfig(
            id="lab",
            mode="local",
            identity_ref="target/lab",
            capabilities=duplicate_name,
        )
    with pytest.raises(ValidationError, match="duplicate capability resource"):
        TargetConfig(
            id="lab",
            mode="local",
            identity_ref="target/lab",
            capabilities=duplicate_resource,
        )


@pytest.mark.parametrize("resource", ["", " \t", "/", "**", "../etc", "/var/../etc", "/var/\x00log"])
def test_capability_resources_reject_unsafe_patterns(resource: str) -> None:
    with pytest.raises(ValidationError, match="resource"):
        CapabilityGrant(name="filesystem", resources=(resource,))


@pytest.mark.parametrize(
    ("value", "yaml_value"),
    [("", "''"), (" \t", '" \\t"'), ("net\nwork", '"net\\nwork"')],
)
def test_capability_and_plugin_names_reject_blank_or_control_values(
    tmp_path: Path, value: str, yaml_value: str
) -> None:
    with pytest.raises(ValidationError, match="name"):
        CapabilityGrant(name=value, resources=("/var/log/**",))

    with pytest.raises(ValueError, match="plugin"):
        load_settings(write_config(tmp_path, f"plugins: [{yaml_value}]\n"))


def test_high_capability_with_low_auto_execution_is_valid(tmp_path: Path) -> None:
    settings = load_settings(
        write_config(
            tmp_path,
            "auto_execute_low: true\ntargets:\n  - id: lab\n    mode: ssh\n"
            "    identity_ref: target/lab\n    auto_execute_low: true\n"
            "    capabilities:\n      - name: network\n        resources: [/etc/hosts]\n",
        )
    )

    assert settings.auto_execute_low is True
    assert settings.targets[0].auto_execute_low is True
    assert settings.targets[0].capabilities[0].name == "network"


def test_unknown_risk_or_approval_bypass_fields_are_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        "targets:\n  - id: lab\n    mode: local\n    identity_ref: target/lab\n"
        "    capabilities:\n      - name: network\n        resources: [/etc/hosts]\n"
        "        risk: low\n    approval_required: false\n",
    )

    with pytest.raises(ValueError, match="risk|approval_required"):
        load_settings(path)


def test_step_result_is_immutable_and_rejects_unknown_fields() -> None:
    result = StepResult(ok=True, status="complete", data={"count": 1})

    with pytest.raises(ValidationError):
        result.status = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="surprise"):
        StepResult(ok=True, status="complete", surprise=True)

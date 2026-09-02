"""Exact-inventory and sandbox contract tests for the generic hardened units.

Units must be generic templates (no fixed target id, IP, or SSH username),
fail closed by default (no configuration writes, no ambient capability, no
network without a declared drop-in), and give every plugin instance its own
identity and socket.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"

EXPECTED_UNITS = frozenset(
    {
        "a4diag-cleanup.service",
        "a4diag-cleanup.timer",
        "a4diag-core.service",
        "a4diag-plugin@.service",
        "a4diag-plugin@.socket",
    }
)
EXPECTED_SUPPORT_FILES = frozenset(
    {"a4diag.conf"}  # tmpfiles.d and sysusers.d each carry one a4diag.conf
)
REMOVED_LEGACY_UNITS = frozenset(
    {
        "a4diag-controller.service",
        "a4diag-executor.service",
        "a4diag-executor.socket",
        "a4diag-poller.service",
        "a4diag-poller.timer",
    }
)
FORBIDDEN_TARGET_IP = re.compile(
    r"(?<![0-9])(?:10|192\.168)(?:\.[0-9]{1,3}){3}(?![0-9])"
)
FORBIDDEN_SSH_USER = re.compile(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+")


def parse_unit(text: str) -> dict[str, dict[str, str]]:
    """Minimal systemd unit parser (INI-like, no continuation lines)."""
    result: dict[str, dict[str, str]] = {}
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            result.setdefault(section, {})
            continue
        if section is None or "=" not in line:
            raise AssertionError(f"invalid unit line: {raw_line!r}")
        key, value = line.split("=", 1)
        result[section][key.strip()] = value.strip()
    return result


def read_deploy_units() -> dict[str, dict[str, dict[str, str]]]:
    return {
        path.name: parse_unit(path.read_text(encoding="utf-8"))
        for path in DEPLOY.iterdir()
        if path.is_file() and path.suffix in {".service", ".socket"}
    }


def test_deploy_has_exact_generic_unit_inventory() -> None:
    units = {path.name for path in DEPLOY.iterdir() if path.is_file()}
    assert units == EXPECTED_UNITS
    assert not REMOVED_LEGACY_UNITS.intersection(units)


def test_support_files_exist_with_exact_names() -> None:
    tmpfiles = DEPLOY / "tmpfiles.d" / "a4diag.conf"
    sysusers = DEPLOY / "sysusers.d" / "a4diag.conf"
    assert tmpfiles.is_file()
    assert sysusers.is_file()


def test_units_contain_no_fixed_target_literals() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in DEPLOY.rglob("*")
        if path.is_file()
    )
    assert "t_11" not in combined
    assert "t_01" not in combined
    assert FORBIDDEN_TARGET_IP.search(combined) is None
    assert FORBIDDEN_SSH_USER.search(combined) is None


def test_core_cannot_write_configuration() -> None:
    units = read_deploy_units()
    service = units["a4diag-core.service"]["Service"]
    assert service["ProtectSystem"] == "strict"
    read_write = service.get("ReadWritePaths", "")
    assert "/etc/a4diag" not in read_write
    assert "NoNewPrivileges" in service and service["NoNewPrivileges"] == "yes"
    assert "PrivateTmp" in service and service["PrivateTmp"] == "yes"
    assert "ProtectHome" in service and service["ProtectHome"] == "yes"
    # The core may only write its own state, checkpoints, reports, audit, and
    # the plugin socket directory.
    assert "/var/lib/a4diag" in read_write
    assert "/run/a4diag" in read_write


def test_core_restricts_capabilities_and_services() -> None:
    service = read_deploy_units()["a4diag-core.service"]["Service"]
    assert service["CapabilityBoundingSet"] == ""
    assert service["NoNewPrivileges"] == "yes"
    assert "RestrictAddressFamilies" in service
    assert "SystemCallArchitectures" in service
    assert "MemoryDenyWriteExecute" in service
    assert "RestrictRealtime" in service


def test_plugin_template_uses_instance_specific_user_and_socket() -> None:
    units = read_deploy_units()
    service = units["a4diag-plugin@.service"]["Service"]
    assert service["User"] == "a4diag-plugin-%i"
    socket = units["a4diag-plugin@.socket"]["Socket"]
    assert "%i.sock" in socket["ListenStream"]
    assert socket["RemoveOnStop"] == "yes"


def test_plugin_template_cannot_write_configuration() -> None:
    service = read_deploy_units()["a4diag-plugin@.service"]["Service"]
    read_write = service.get("ReadWritePaths", "")
    assert "/etc/a4diag" not in read_write
    assert service["ProtectSystem"] == "strict"
    assert service["ReadOnlyPaths"].count("/etc/a4diag") >= 1


def test_plugin_template_fails_closed_without_declared_network() -> None:
    service = read_deploy_units()["a4diag-plugin@.service"]["Service"]
    assert service["RestrictAddressFamilies"] == "AF_UNIX"
    assert service["CapabilityBoundingSet"] == ""
    assert service["NoNewPrivileges"] == "yes"
    assert service["PrivateTmp"] == "yes"
    assert service["ProtectHome"] == "yes"
    assert "MemoryMax" in service
    assert "TasksMax" in service
    assert "%i.yaml" in service["ReadOnlyPaths"] or "/etc/a4diag/plugins" in service.get(
        "ReadOnlyPaths", ""
    )


def test_units_execstart_match_installed_layout() -> None:
    """ExecStart must point at the real venv layout created by the installer."""
    units = read_deploy_units()
    assert (
        units["a4diag-core.service"]["Service"]["ExecStart"]
        == "/opt/a4diag/current/venv/bin/a4diag serve"
    )
    assert (
        units["a4diag-plugin@.service"]["Service"]["ExecStart"]
        == "/opt/a4diag/plugins/current/venv/bin/a4diag-plugin --instance %i"
    )
    assert "/opt/a4diag/plugins/current" in units["a4diag-plugin@.service"]["Service"]["ReadOnlyPaths"]
    cleanup = parse_unit((DEPLOY / "a4diag-cleanup.service").read_text(encoding="utf-8"))
    assert (
        cleanup["Service"]["ExecStart"]
        == "/opt/a4diag/current/venv/bin/a4diag cleanup"
    )


def test_tmpfiles_creates_state_dirs_with_core_owner() -> None:
    text = (DEPLOY / "tmpfiles.d" / "a4diag.conf").read_text(encoding="utf-8")
    assert "d /run/a4diag 0750 a4diag a4diag -" in text
    assert "d /var/lib/a4diag 0750 a4diag a4diag -" in text


def test_sysusers_defines_only_the_core_identity() -> None:
    text = (DEPLOY / "sysusers.d" / "a4diag.conf").read_text(encoding="utf-8")
    assert "u a4diag" in text
    assert "g a4diag" in text
    assert "a4diag-plugin" not in text.replace("a4diag-plugin-%i", "")
    assert "t_11" not in text

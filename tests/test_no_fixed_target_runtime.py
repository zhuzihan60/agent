"""Source and behavior guards: no fixed-target runtime remains.

Scans every module under ``src/a4diag`` plus the default configuration for
forbidden fixed-target literals (fixed target ids, fixed private IPs, a
hardcoded SSH username, "fixed-target executor"), asserts the MCP/collector
path routes through the generic v3 runtime, asserts v3 settings never
auto-import legacy permissions, and behaviorally asserts that targets resolve
only by registered id — never by IP, never by falling back to the first
configured target.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_RUNTIME_LITERALS = (
    "t_11",
    "targets must contain exactly",
    "fixed-target executor",
    "a4diag-ro",
)
FORBIDDEN_FIXED_IP = re.compile(
    r"(?<![0-9])(?:10|192\.168)(?:\.[0-9]{1,3}){3}(?![0-9])"
)
FORBIDDEN_SSH_DESTINATION = re.compile(
    r"[A-Za-z0-9_.-]+@[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
)


def source_files() -> list[Path]:
    files = sorted((ROOT / "src" / "a4diag").rglob("*.py"))
    example = ROOT / "config" / "config.example.yaml"
    assert example.is_file()
    return files + [example]


def test_runtime_and_default_config_have_no_fixed_target_literals() -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_files())
    for literal in FORBIDDEN_RUNTIME_LITERALS:
        assert literal not in combined, f"forbidden literal: {literal}"
    assert FORBIDDEN_FIXED_IP.search(combined) is None, (
        "fixed private IP present in source or default config"
    )
    assert FORBIDDEN_SSH_DESTINATION.search(combined) is None, (
        "hardcoded SSH user@host present in source or default config"
    )


def test_mcp_server_routes_through_generic_v3_runtime() -> None:
    source = (ROOT / "src" / "a4diag" / "mcp_server.py").read_text(encoding="utf-8")
    assert "from .runtime import" in source or "from a4diag.runtime import" in source


def test_v3_settings_never_import_legacy_permissions() -> None:
    settings = (ROOT / "src" / "a4diag" / "settings.py").read_text(encoding="utf-8")
    assert "from .config import" not in settings
    assert "from a4diag.config import" not in settings


LEGACY_CONFIG_TEXT = """
alertmanager_url: http://alertmanager.example:9093
prometheus_url: http://prometheus.example:9090
poll_interval_seconds: 600
max_concurrency: 2
normal_report_days: 1
abnormal_report_days: 14
audit_days: 90
ssh_private_key: /var/lib/a4diag/.ssh/id_ed25519
ssh_known_hosts: /var/lib/a4diag/.ssh/known_hosts
ssh_user: a4diag-ro
targets:
  t_01:
    ip: 10.0.0.1
    ssh_port: 22122
    allowed_units:
      - node_exporter.service
  t_02:
    ip: 10.0.0.2
    ssh_port: 22122
    allowed_units:
      - sshd.service
""".lstrip()


def test_policy_never_authorizes_target_by_ip(tmp_path: Path) -> None:
    from a4diag.config import Config
    from a4diag.policy import PolicyError, authorize_target

    path = tmp_path / "legacy.yaml"
    path.write_text(LEGACY_CONFIG_TEXT, encoding="utf-8")
    config = Config.load(path)

    # Even a registered target's own IP must never authorize by IP.
    registered_ip = config.targets["t_01"].ip
    with pytest.raises(PolicyError):
        authorize_target(config, registered_ip)
    # Registered ids still authorize.
    assert authorize_target(config, "t_02").name == "t_02"


def test_alert_routing_never_matches_ip_or_falls_back_to_first_target() -> None:
    from a4diag.alertmanager import resolve_target_id

    registered = {"t_01", "t_02"}
    assert resolve_target_id({"target_id": "t_02"}, registered) == "t_02"
    assert resolve_target_id({"target_id": "unknown"}, registered) is None
    assert resolve_target_id({"ip": "10.0.0.1"}, registered) is None
    assert resolve_target_id({"instance": "t_01:9100"}, registered) is None
    assert resolve_target_id({}, registered) is None

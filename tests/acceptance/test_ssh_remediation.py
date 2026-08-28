"""SSH remediation acceptance: host-key/identity changes and registered-only
contact, exercised through injected fakes (no real SSH connection)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from a4diag.config import Config
from a4diag.policy import PolicyError, authorize_target


def test_host_key_change_blocks_everything(lab_factory) -> None:
    lab = lab_factory(identity_error=RuntimeError("host key mismatch"))

    result = lab.run_agent()

    assert result.status != "succeeded"
    assert lab.executor.apply_count == 0
    assert lab.ledger.connections_to("apply", "undo") == 0


def test_ssh_username_comes_from_config_not_hardcoded(tmp_path: Path) -> None:
    config_path = tmp_path / "legacy.yaml"
    config_path.write_text(
        "\n".join(
            [
                "alertmanager_url: http://alertmanager.example:9093",
                "prometheus_url: http://prometheus.example:9090",
                "poll_interval_seconds: 600",
                "max_concurrency: 2",
                "normal_report_days: 1",
                "abnormal_report_days: 14",
                "audit_days: 90",
                "ssh_private_key: /var/lib/a4diag/.ssh/id_ed25519",
                "ssh_known_hosts: /var/lib/a4diag/.ssh/known_hosts",
                "ssh_user: ops-readonly",
                "targets:",
                "  target-1:",
                "    ip: 10.0.0.1",
                "    ssh_port: 22122",
                "    allowed_units:",
                "      - sshd.service",
            ]
        ),
        encoding="utf-8",
    )
    from a4diag.ssh_collector import build_ssh_argv

    config = Config.load(config_path)
    argv = build_ssh_argv(config, config.targets["target-1"])
    assert argv[-1] == "ops-readonly@10.0.0.1"
    assert "a4diag-ro" not in argv[-1]


def test_unregistered_ssh_destination_is_never_contacted(lab_factory) -> None:
    lab = lab_factory()

    for candidate in ("10.0.0.99", "other-host", "target-2"):
        result = lab.run_agent(target_id=candidate)
        assert result.status == "policy_denied"
    assert lab.executor.apply_count == 0
    assert lab.ledger.total_connections == 0


def test_ssh_authorization_is_by_registered_name_only(tmp_path: Path) -> None:
    config_path = tmp_path / "legacy.yaml"
    config_path.write_text(
        "\n".join(
            [
                "alertmanager_url: http://alertmanager.example:9093",
                "prometheus_url: http://prometheus.example:9090",
                "poll_interval_seconds: 600",
                "max_concurrency: 2",
                "normal_report_days: 1",
                "abnormal_report_days: 14",
                "audit_days: 90",
                "ssh_private_key: /var/lib/a4diag/.ssh/id_ed25519",
                "ssh_known_hosts: /var/lib/a4diag/.ssh/known_hosts",
                "ssh_user: ops-readonly",
                "targets:",
                "  target-1:",
                "    ip: 10.0.0.1",
                "    ssh_port: 22122",
                "    allowed_units:",
                "      - sshd.service",
            ]
        ),
        encoding="utf-8",
    )
    config = Config.load(config_path)
    # The registered target's own IP must never authorize.
    try:
        authorize_target(config, "10.0.0.1")
        raise AssertionError("authorize_target matched by IP")
    except PolicyError:
        pass
    assert authorize_target(config, "target-1").name == "target-1"


def test_ssh_transport_never_contains_hardcoded_user_in_source() -> None:
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parents[2]
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "src" / "a4diag").rglob("*.py")
    )
    assert "a4diag-ro" not in combined

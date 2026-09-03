"""Assertions over evidence emitted by the Linux production wiring harness."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def test_signed_controller_to_target_production_path() -> None:
    if os.environ.get("A4DIAG_E2E") != "1":
        pytest.skip("production wiring runs in the dedicated Linux E2E job")
    evidence_path = Path(
        os.environ.get("A4DIAG_E2E_EVIDENCE", "/tmp/a4diag-e2e/evidence.json")
    )
    assert evidence_path.is_file(), "production harness is not installed"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert evidence["execution_path"] == [
        "runtime",
        "plugin-rpc",
        "transport-ssh",
        "openssh",
        "forced-command-helper",
        "systemd-socket",
        "target-executor",
    ]
    assert evidence["plugin_list"]["count"] == 10
    assert evidence["plugin_list"]["source"] == "installed-registry"
    assert evidence["plugin_list"]["private_key_reads"] == 0
    assert evidence["target"]["identity_verified"] is True
    assert evidence["low_change"]["applied_on_target"] is True
    assert evidence["low_change"]["controller_file_unchanged"] is True
    assert evidence["rollback"]["exact"] is True
    assert evidence["high_before_approval"]["effect_count"] == 0
    assert evidence["high_after_resume"]["effect_count"] == 1
    assert evidence["high_after_resume"]["source"] == "approval-store-resume"
    assert evidence["protected_ssh_change"]["effect_count"] == 0
    assert evidence["wrong_target"]["ssh_spawn_count"] == 0
    assert evidence["replay"]["effect_count"] == 1
    assert evidence["faults"]["transport_restart_reconciled"] is True
    assert evidence["faults"]["ssh_host_key_drift_zero_dispatch"] is True
    assert evidence["faults"]["machine_id_drift_zero_dispatch"] is True
    assert evidence["faults"]["audit_corruption_read_only"] is True
    assert evidence["model"]["http_calls"] >= 3
    assert evidence["notification"]["http_calls"] >= 1

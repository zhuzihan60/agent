"""Offline, public-only target bootstrap bundle tests."""

from __future__ import annotations

import json
import os
import stat
import contextlib
import io
from pathlib import Path

from a4diag.target_bootstrap import TargetBootstrapRequest, build_target_bootstrap


def test_bootstrap_generates_public_bundle_and_keeps_private_keys_in_secret_root(
    tmp_path: Path,
) -> None:
    output = tmp_path / "bundle"
    secrets = tmp_path / "controller-secrets"
    receipt = build_target_bootstrap(
        TargetBootstrapRequest(
            target_id="lab-node-1", allowed_source_cidrs=("192.0.2.10/32",)
        ),
        output,
        secret_root=secrets,
    )

    assert receipt.install_document == output / "target-install.json"
    assert {path.name for path in output.iterdir()} == {"target-install.json"}
    document = json.loads(receipt.install_document.read_text(encoding="utf-8"))
    assert document["target_id"] == "lab-node-1"
    assert document["allowed_source_cidrs"] == ["192.0.2.10/32"]
    assert document["managed_resources"] == []
    assert document["confirm_managed_resources"] == "DISABLED"
    assert document["ssh_public_key"].startswith("ssh-ed25519 ")
    assert "BEGIN PUBLIC KEY" in document["operation_public_key"]
    assert document["controller_key_fingerprint"].startswith("sha256:")
    assert "PRIVATE KEY" not in receipt.install_document.read_text(encoding="utf-8")
    assert receipt.ssh_private_key.parent == secrets / "lab-node-1"
    assert receipt.operation_private_key.parent == secrets / "lab-node-1"
    if os.name == "posix":
        assert stat.S_IMODE(receipt.ssh_private_key.stat().st_mode) == 0o600
        assert stat.S_IMODE(receipt.operation_private_key.stat().st_mode) == 0o600


def test_bootstrap_rejects_existing_output_without_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    output.mkdir()
    sentinel = output / "keep"
    sentinel.write_text("unchanged", encoding="utf-8")

    try:
        build_target_bootstrap(
            TargetBootstrapRequest(target_id="lab-node-1", allowed_source_cidrs=()),
            output,
            secret_root=tmp_path / "secrets",
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing output must fail closed")

    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert not (tmp_path / "secrets").exists()


def test_bootstrap_request_rejects_invalid_target_and_network() -> None:
    for values in (
        {"target_id": "../escape", "allowed_source_cidrs": ()},
        {"target_id": "lab", "allowed_source_cidrs": ("not-a-network",)},
        {"target_id": "lab", "allowed_source_cidrs": ("0.0.0.0/0",)},
    ):
        try:
            TargetBootstrapRequest.model_validate(values)
        except ValueError:
            continue
        raise AssertionError(f"unsafe request accepted: {values}")


def test_cli_target_bootstrap_uses_controller_secret_root(
    tmp_path: Path, monkeypatch
) -> None:
    from a4diag.cli import main

    output = tmp_path / "bundle"
    secrets = tmp_path / "secrets"
    monkeypatch.setenv("A4DIAG_TARGET_SECRET_ROOT", str(secrets))
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(
            [
                "target",
                "bootstrap",
                "lab-node-1",
                "--output",
                str(output),
                "--source-cidr",
                "192.0.2.10/32",
            ]
        )
    assert code == 0
    result = json.loads(stdout.getvalue())
    assert result["target_id"] == "lab-node-1"
    assert result["private_keys"] == "stored_in_controller_secret_root"
    assert (output / "target-install.json").is_file()
    assert (secrets / "lab-node-1" / "operation-ed25519.pem").is_file()

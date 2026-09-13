"""Offline, public-only target bootstrap bundle tests."""

from __future__ import annotations

import json
import os
import stat
import contextlib
import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

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


def test_production_bootstrap_assigns_only_new_target_secrets_to_service_user(tmp_path: Path, monkeypatch) -> None:
    from a4diag import target_bootstrap as bootstrap

    secret_root = tmp_path / "production-secrets"
    monkeypatch.setattr(bootstrap, "DEFAULT_TARGET_SECRET_ROOT", secret_root, raising=False)
    owned = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid, **kwargs: owned.append((Path(path), uid, gid)), raising=False)
    receipt = build_target_bootstrap(
        TargetBootstrapRequest(target_id="lab", allowed_source_cidrs=()), tmp_path / "bundle",
        secret_root=secret_root, secret_owner=(1234, 4321),
    )
    assert set(owned) == {
        (receipt.ssh_private_key, 1234, 4321),
        (receipt.operation_private_key, 1234, 4321),
        (secret_root / "lab", 1234, 4321),
    }
    assert receipt.install_document not in {path for path, _, _ in owned}


def test_bootstrap_refuses_ownership_changes_outside_production_secret_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="production secret root"):
        build_target_bootstrap(
            TargetBootstrapRequest(target_id="lab", allowed_source_cidrs=()), tmp_path / "bundle",
            secret_root=tmp_path / "custom", secret_owner=(1234, 4321),
        )
    assert not (tmp_path / "bundle").exists()


def test_cli_default_secret_root_uses_a4diag_account(tmp_path: Path, monkeypatch) -> None:
    from a4diag import target_bootstrap as bootstrap
    from a4diag.cli import main

    secret_root = tmp_path / "production-secrets"
    monkeypatch.setattr(bootstrap, "DEFAULT_TARGET_SECRET_ROOT", secret_root, raising=False)
    monkeypatch.delenv("A4DIAG_TARGET_SECRET_ROOT", raising=False)
    lookups = []
    def account(name):
        lookups.append(name)
        return SimpleNamespace(pw_uid=1234, pw_gid=4321)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=account))
    owned = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid, **kwargs: owned.append((Path(path), uid, gid)), raising=False)
    assert main(["target", "bootstrap", "lab", "--output", str(tmp_path / "bundle")]) == 0
    assert lookups == ["a4diag"]
    assert len(owned) == 3
    assert {uid for _, uid, _ in owned} == {1234}

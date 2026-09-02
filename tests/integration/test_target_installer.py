from __future__ import annotations

import json
import hashlib
import os
import stat
import subprocess
import sys
import sqlite3
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "tools" / "install_target_lib.sh"
POSIX = pytest.mark.skipif(os.name == "nt", reason="target installer is Linux-only")


def configuration(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "protocol_version": "1.0",
        "target_id": "disposable-sandbox",
        "allowed_source_cidrs": ["192.0.2.10/32"],
        "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyController controller",
        "operation_public_key": "-----BEGIN PUBLIC KEY-----\nTEST-ONLY\n-----END PUBLIC KEY-----\n",
        "controller_key_fingerprint": "sha256:" + "a" * 64,
        "managed_resources": [],
        "confirm_managed_resources": "DISABLED",
    }
    value.update(overrides)
    return value


def run_validate(tmp_path: Path, payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    config = tmp_path / "target-install.json"
    config.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        ["bash", str(INSTALLER), "validate", str(config)],
        check=False,
        capture_output=True,
        text=True,
    )


@POSIX
@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        ({"allowed_source_cidrs": ["192.0.2.10"]}, "source_cidr"),
        ({"allowed_source_cidrs": ["0.0.0.0/0"]}, "source_cidr"),
        ({"operation_public_key": "-----BEGIN PRIVATE KEY-----\nNO\n-----END PRIVATE KEY-----"}, "private"),
        ({"managed_resources": [{"capability": "files", "resource": "/srv/app/config"}]}, "ENABLE"),
    ),
)
def test_target_configuration_fails_closed(
    tmp_path: Path, overrides: dict[str, object], message: str
) -> None:
    result = run_validate(tmp_path, configuration(**overrides))
    assert result.returncode != 0
    assert message.lower() in result.stderr.lower()


@POSIX
def test_target_configuration_accepts_explicit_managed_resource_confirmation(tmp_path: Path) -> None:
    result = run_validate(
        tmp_path,
        configuration(
            managed_resources=[{"capability": "files", "resource": "/srv/app/config"}],
            confirm_managed_resources="ENABLE",
        ),
    )
    assert result.returncode == 0, result.stderr


@POSIX
def test_target_install_is_restricted_idempotent_and_rolls_back(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    python = fake_bin / "python3.11"
    python.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [ \"${1:-}\" = \"-\" ]; then exec \"$A4DIAG_TEST_REAL_PYTHON\" \"$@\"; fi
if [ \"${1:-}\" = \"-m\" ] && [ \"${2:-}\" = \"venv\" ]; then
  mkdir -p \"$3/bin\"
  printf '#!/usr/bin/env bash\\nexec \"$A4DIAG_TEST_REAL_PYTHON\" \"$@\"\\n' > \"$3/bin/python\"
  printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$3/bin/a4diag-target-executor\"
  printf '#!/usr/bin/env bash\\nexit 0\\n' > \"$3/bin/a4diag-transport-helper\"
  chmod 755 \"$3/bin/\"*
fi
exit 0
""",
        encoding="utf-8",
    )
    python.chmod(0o755)
    for command in ("systemctl", "systemd-sysusers", "systemd-tmpfiles", "chown"):
        shim = fake_bin / command
        shim.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        shim.chmod(0o755)

    release = tmp_path / "release"
    (release / "wheelhouse").mkdir(parents=True)
    (release / "systemd" / "sysusers.d").mkdir(parents=True)
    (release / "systemd" / "tmpfiles.d").mkdir(parents=True)
    for name in ("a4diag-target-executor.service", "a4diag-target-executor.socket"):
        (release / "systemd" / name).write_text("[Unit]\n", encoding="utf-8")
    (release / "systemd" / "sysusers.d" / "a4diag-target.conf").write_text("u a4diag-target\n", encoding="utf-8")
    (release / "systemd" / "tmpfiles.d" / "a4diag-target.conf").write_text("d /run/a4diag-target\n", encoding="utf-8")
    (release / "VERSION").write_text("0.4.1\n", encoding="utf-8")
    for name in (
        "a4diag-0.4.1-py3-none-any.whl",
        "a4diag_builtin_plugins-0.4.1-py3-none-any.whl",
        "a4diag_target_runtime-0.4.1-py3-none-any.whl",
    ):
        (release / "wheelhouse" / name).write_bytes(b"wheel")
    artifacts = sorted(path for path in release.rglob("*") if path.is_file())
    manifest = {
        "version": "0.4.1",
        "artifacts": {
            path.relative_to(release).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in artifacts
        },
    }
    (release / "MANIFEST.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    lines = []
    for path in sorted((p for p in release.rglob("*") if p.is_file()), key=lambda p: p.relative_to(release).as_posix()):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(release).as_posix()}")
    (release / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    config = tmp_path / "target-install.json"
    config.write_text(json.dumps(configuration()), encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "A4DIAG_TARGET_ROOT": str(tmp_path / "root") + os.sep,
            "A4DIAG_TARGET_SKIP_ROOT": "1",
            "A4DIAG_TARGET_SKIP_SYSTEMD": "1",
            "A4DIAG_TARGET_ALLOW_UNSIGNED": "1",
            "A4DIAG_TARGET_TEST_REAL_PYTHON": sys.executable,
            "A4DIAG_TEST_REAL_PYTHON": sys.executable,
            "A4DIAG_TARGET_MACHINE_ID": "0123456789abcdef0123456789abcdef",
            "A4DIAG_TARGET_OS_RELEASE": str(tmp_path / "os-release"),
            "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
        }
    )
    (tmp_path / "os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8")
    command = ["bash", str(INSTALLER), "install", str(release), str(config)]
    first = subprocess.run(command, env=environment, check=False, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    second = subprocess.run(command, env=environment, check=False, capture_output=True, text=True)
    assert second.returncode == 0, second.stderr

    target_root = tmp_path / "root"
    helper = target_root / "usr" / "libexec" / "a4diag" / "a4diag-transport-helper"
    public_key = target_root / "etc" / "a4diag-target" / "operation-public.pem"
    authorized_keys = target_root / "var" / "lib" / "a4diag-target" / ".ssh" / "authorized_keys"
    assert stat.S_IMODE(helper.stat().st_mode) == 0o755
    assert stat.S_IMODE(public_key.stat().st_mode) == 0o644
    assert not any(path.name.endswith("private.pem") for path in target_root.rglob("*"))
    assert 'restrict,command="/usr/libexec/a4diag/a4diag-transport-helper"' in authorized_keys.read_text("utf-8")
    assert (target_root / "var" / "lib" / "a4diag-target" / "executor").stat().st_mode & 0o777 == 0o700

    before = os.readlink(target_root / "opt" / "a4diag-target" / "current")
    environment["A4DIAG_TARGET_INJECT_FAILURE"] = "before_switch"
    failed = subprocess.run(command, env=environment, check=False, capture_output=True, text=True)
    assert failed.returncode != 0
    assert os.readlink(target_root / "opt" / "a4diag-target" / "current") == before

    ledger = target_root / "var" / "lib" / "a4diag-target" / "executor" / "replay.sqlite3"
    connection = sqlite3.connect(ledger)
    connection.execute("CREATE TABLE replay (completed_at INTEGER)")
    connection.execute("INSERT INTO replay VALUES (NULL)")
    connection.commit()
    connection.close()
    environment["A4DIAG_TARGET_CONFIRM_UNINSTALL"] = "REMOVE"
    uninstall = subprocess.run(
        ["bash", str(INSTALLER), "uninstall"],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert uninstall.returncode != 0
    assert "incomplete" in uninstall.stderr

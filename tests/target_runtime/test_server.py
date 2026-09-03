from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from unittest.mock import patch

from a4diag_builtin_plugins.transport_common import identity_fingerprint
from a4diag_target.server import probe_identity, read_identity, target_fingerprint


def test_target_systemd_version_uses_fixed_cross_distro_systemctl() -> None:
    completed = type("Completed", (), {"stdout": b"systemd 255 (255.4-1)\n"})()
    with patch("a4diag_target.server.subprocess.run", return_value=completed) as execute:
        from a4diag_target.server import _systemd_version

        assert _systemd_version() == completed.stdout
    execute.assert_called_once_with(
        ["/usr/bin/systemctl", "--version"],
        check=True,
        capture_output=True,
        timeout=10,
    )


def test_target_identity_uses_machine_os_systemd_and_host_key(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/machine-id").write_text("machine-1\n", encoding="utf-8")
    (root / "etc/os-release").write_text(
        'ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8"
    )
    raw_key = b"test-host-public-key"
    (root / "etc/ssh/ssh_host_ed25519_key.pub").write_text(
        "ssh-ed25519 " + base64.b64encode(raw_key).decode("ascii") + " host\n",
        encoding="ascii",
    )

    identity = probe_identity(root)

    assert identity.machine_id == "machine-1"
    assert identity.os_id == "ubuntu"
    assert identity.os_version_id == "24.04"
    assert identity.host_key_sha256 == hashlib.sha256(raw_key).hexdigest()
    assert target_fingerprint(root) == identity_fingerprint(identity)


def test_target_read_surface_is_fixed_to_identity_fields(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/machine-id").write_text("machine-1\n", encoding="utf-8")
    (root / "etc/os-release").write_text(
        'ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8"
    )

    machine = read_identity(root, {"method": "read", "kind": "machine_id", "limit": 65536})
    release = read_identity(root, {"method": "read", "kind": "os_release", "limit": 65536})

    assert machine == {"content": "machine-1\n", "truncated": False}
    assert 'ID="ubuntu"' in release["content"]
    assert read_identity(root, {"method": "read", "kind": "file", "path": "/etc/shadow", "limit": 65536}) == {
        "ok": False,
        "reason": "read_kind_not_allowed",
    }

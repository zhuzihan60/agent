from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from a4diag_builtin_plugins.transport_common import identity_fingerprint
from a4diag_target.server import probe_identity, target_fingerprint


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


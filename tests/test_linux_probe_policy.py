from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from a4diag_target.policy import PolicyDenied, TargetPolicy


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools/install_target_lib.sh"


def policy_data(**changes: object) -> dict[str, object]:
    return {
        "target_id": "node-1",
        "target_fingerprint": "sha256:" + "a" * 64,
        "controller_key_fingerprint": "sha256:" + "b" * 64,
        **changes,
    }


def probe(kind: str = "memory", resource: str = "host", id: str = "health") -> dict[str, object]:
    return {"id": id, "kind": kind, "resource": resource}


def installer_script(function: str, marker: str = "") -> str:
    # Exercise the installer's actual Python validation/rendering on Windows too.
    body = INSTALLER.read_text(encoding="utf-8").split(function + "() {", 1)[1]
    if marker:
        body = body.split(marker, 1)[1]
    return body.split("<<'PY'", 1)[1].split("\n", 1)[1].split("\nPY", 1)[0]


def installation_config(**changes: object) -> dict[str, object]:
    return {
        "protocol_version": "1.0",
        "target_id": "node-1",
        "ssh_public_key": "ssh-ed25519 AAAATestOnly test",
        "operation_public_key": "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----",
        "controller_key_fingerprint": "sha256:" + "b" * 64,
        "allowed_source_cidrs": ["192.0.2.10/32"],
        "managed_resources": [],
        **changes,
    }


def test_default_policy_has_no_implicit_diagnostics() -> None:
    policy = TargetPolicy.model_validate(policy_data())
    assert policy.diagnostic_probes == ()
    with pytest.raises(PolicyDenied, match="probe_not_granted"):
        policy.authorize_probe("health")


@pytest.mark.parametrize("requested", ["HEALTH", "health*", "health/child", "", "other"])
def test_probe_authorization_requires_exact_registered_id(requested: str) -> None:
    policy = TargetPolicy.model_validate(policy_data(diagnostic_probes=[probe()]))
    assert policy.authorize_probe("health") == policy.diagnostic_probes[0]
    with pytest.raises(PolicyDenied, match="probe_not_granted"):
        policy.authorize_probe(requested)


@pytest.mark.parametrize("probes", [[probe(), probe()], [probe(id=f"p{i}") for i in range(9)]])
def test_policy_rejects_duplicate_or_excessive_probes(probes: list[dict[str, object]]) -> None:
    with pytest.raises(ValueError):
        TargetPolicy.model_validate(policy_data(diagnostic_probes=probes))


@pytest.mark.parametrize("resource", ["/srv/other/config", "/etc/ssh/sshd_config", "/etc/resolv.conf"])
def test_file_probes_cannot_escape_existing_read_policy(resource: str) -> None:
    with pytest.raises(ValueError):
        TargetPolicy.model_validate(policy_data(
            managed_roots=["/srv/app", "/etc"], diagnostic_probes=[probe("file", resource)],
        ))


def test_file_probe_uses_managed_root_read_authorization() -> None:
    policy = TargetPolicy.model_validate(policy_data(
        managed_roots=["/srv/app"], diagnostic_probes=[probe("file", "/srv/app/config")],
    ))
    assert policy.authorize_probe("health").resource == "/srv/app/config"


@pytest.mark.parametrize(("kind", "resource"), [
    ("filesystem", "/"), ("memory", "host"), ("load", "host"),
    ("package", "openssh-server"), ("tcp", "tcp://127.0.0.1:8080"), ("dns", "example.com"),
])
def test_registered_read_only_probes_do_not_create_mutation_grants(kind: str, resource: str) -> None:
    policy = TargetPolicy.model_validate(policy_data(diagnostic_probes=[probe(kind, resource)]))
    assert policy.authorize_probe("health").resource == resource
    assert policy.allowed_packages == ()
    assert policy.allowed_units == ()
    assert policy.managed_roots == ()


@pytest.mark.parametrize("probes", [None, {}, [probe()] * 9, [probe(), probe()],
    [{**probe(), "command": "uname"}], [{**probe(), "max_bytes": True}],
    [{**probe(), "max_bytes": 0}], [{**probe(), "max_bytes": 1048577}],
    [{**probe(), "kind": "shell"}], [{**probe(), "resource": ["host"]}],
])
def test_installer_preliminary_validation_rejects_unbounded_shapes(tmp_path: Path, probes: object) -> None:
    config = tmp_path / "install.json"
    config.write_text(json.dumps(installation_config(diagnostic_probes=probes)), encoding="utf-8")
    result = subprocess.run([sys.executable, "-c", installer_script("validate_config"), str(config)], capture_output=True, text=True)
    assert result.returncode != 0


@pytest.mark.parametrize("changes", [{}, {"diagnostic_probes": [probe()]}])
def test_installer_accepts_legacy_and_explicit_probes(tmp_path: Path, changes: dict[str, object]) -> None:
    config = tmp_path / "install.json"
    config.write_text(json.dumps(installation_config(**changes)), encoding="utf-8")
    result = subprocess.run([sys.executable, "-c", installer_script("validate_config"), str(config)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("registered", [[], [probe()], [probe("tcp", "tcp://127.0.0.1:8080")], [probe("dns", "example.com")]])
def test_installer_renders_only_explicit_network_access(tmp_path: Path, registered: list[dict[str, object]]) -> None:
    config, policy, drop_in = (tmp_path / name for name in ("install.json", "policy.json", "managed-roots.conf"))
    config.write_text(json.dumps(installation_config(diagnostic_probes=registered)), encoding="utf-8")
    result = subprocess.run([
        sys.executable, "-c", installer_script("write_configuration", '"$drop_in_dir/managed-roots.conf.tmp"'),
        str(config), str(policy), str(drop_in), "sha256:" + "a" * 64,
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    parsed = TargetPolicy.model_validate_json(policy.read_text(encoding="utf-8"))
    assert len(parsed.diagnostic_probes) == len(registered)
    rendered = drop_in.read_text(encoding="utf-8")
    network = any(item["kind"] in {"tcp", "dns"} for item in registered)
    assert ("RestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n" in rendered) == network
    # Resolve additive systemd address-family lines, including empty resets.
    families: set[str] = set()
    for line in (ROOT / "deploy/a4diag-target-executor.service").read_text(encoding="utf-8").splitlines() + rendered.splitlines():
        if line.startswith("RestrictAddressFamilies="):
            values = line.split("=", 1)[1].split()
            if not values:
                families.clear()
            families.update(values)
    assert families == ({"AF_UNIX", "AF_INET", "AF_INET6"} if network else {"AF_UNIX"})


@pytest.mark.parametrize("registered", [[probe("memory", "wrong")], [probe("file", "/etc/shadow")]])
def test_installer_full_validation_prevents_any_policy_write(tmp_path: Path, registered: list[dict[str, object]]) -> None:
    config, policy, drop_in = (tmp_path / name for name in ("install.json", "policy.json", "managed-roots.conf"))
    config.write_text(json.dumps(installation_config(diagnostic_probes=registered)), encoding="utf-8")
    result = subprocess.run([
        sys.executable, "-c", installer_script("write_configuration", '"$drop_in_dir/managed-roots.conf.tmp"'),
        str(config), str(policy), str(drop_in), "sha256:" + "a" * 64,
    ], capture_output=True, text=True)
    assert result.returncode != 0
    assert not policy.exists()
    assert not drop_in.exists()


def test_installer_validates_with_runtime_before_publishing_current() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    assert '"$runtime_python" - "$config" "$TARGET_ETC/policy.json.tmp"' in source
    assert source.index('write_configuration "$config" "$destination/venv/bin/python"') < source.index('ln -sfn "$destination"')

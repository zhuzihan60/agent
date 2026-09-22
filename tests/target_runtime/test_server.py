from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import Operation, RepairBinding, Risk, canonical_json_bytes
from a4diag.plugin_api.target_protocol import (
    TargetLifecycleV11,
    TargetRequestV11,
    TargetSigner,
)
from a4diag.plugin_api.ticket import effect_payload_digest
from a4diag.repair_profiles import RepairProfile, profile_digest
from a4diag_builtin_plugins.capability_common import CommandOutcome, LocalFileAdapter
from a4diag_builtin_plugins.transport_common import identity_fingerprint
from a4diag_target.policy import TargetPolicy
from a4diag_target.server import (
    TargetSocketServer,
    probe_identity,
    read_identity,
    target_fingerprint,
)


FINGERPRINT = "sha256:" + "a" * 64


def _profile(*, expires_at: int) -> RepairProfile:
    return RepairProfile(
        id="web",
        target_id="demo",
        capability="services",
        resource="demo.service",
        actions=("restart",),
        constraints={},
        recovery_check_ids=("health",),
        expires_at=expires_at,
        standing_authorization=True,
    )


def _operation() -> Operation:
    return Operation(
        capability="services",
        action="restart",
        resource="demo.service",
        parameters={"unit": "demo.service"},
        model_risk=Risk.HIGH,
        verify={"recovery_check_ids": ["health"]},
        undo={"restore": True},
    )


def _key_fingerprint(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _policy(
    key: Ed25519PrivateKey,
    profile: RepairProfile | None,
    *,
    allowed_units: tuple[str, ...] = ("demo.service",),
) -> TargetPolicy:
    return TargetPolicy(
        target_id="demo",
        target_fingerprint=FINGERPRINT,
        controller_key_fingerprint=_key_fingerprint(key),
        allowed_units=allowed_units,
        repair_profiles=() if profile is None else (profile,),
    )


def _request(
    profile: RepairProfile,
    lifecycle: TargetLifecycleV11,
    nonce: str,
    now: int,
    *,
    marker: dict[str, object] | None = None,
) -> TargetRequestV11:
    preconditions = None
    if marker is not None:
        preconditions = hashlib.sha256(canonical_json_bytes(marker)).hexdigest()
    effect = {} if lifecycle is TargetLifecycleV11.PREPARE else {"marker": marker}
    return TargetRequestV11(
        controller_id="controller-1",
        target_id="demo",
        target_fingerprint=FINGERPRINT,
        transaction_id="txn-1",
        step_id="0",
        lifecycle=lifecycle,
        operation=_operation(),
        marker=marker,
        undo=None,
        plan_digest="d" * 64,
        effect_payload_digest=effect_payload_digest(effect),
        risk=Risk.HIGH,
        binding=RepairBinding(
            profile_id="web",
            profile_digest=profile_digest(profile),
            preconditions_digest=preconditions,
        ),
        authorization_kind="standing",
        authorization_id="web",
        issued_at=now - 1,
        expires_at=now + 120,
        nonce=nonce,
    )


def _write_policy(path: Path, policy: TargetPolicy) -> None:
    replacement = path.with_suffix(".replacement")
    replacement.write_text(policy.model_dump_json(), encoding="utf-8")
    replacement.replace(path)


def _server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    key: Ed25519PrivateKey,
    policy: TargetPolicy,
    effect_calls: list[tuple[str, ...]],
) -> tuple[TargetSocketServer, Path]:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(policy.model_dump_json(), encoding="utf-8")
    public_key_path = tmp_path / "operation-public.pem"
    public_key_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    async def run_command(
        _adapter: LocalFileAdapter,
        argv: list[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandOutcome:
        del timeout_seconds, output_limit_bytes
        if argv[1] == "show":
            return CommandOutcome(
                returncode=0,
                stdout=(
                    "ActiveState=active\nSubState=running\n"
                    "UnitFileState=enabled\nInvocationID=before\n"
                ),
            )
        effect_calls.append(tuple(argv))
        return CommandOutcome(returncode=0)

    monkeypatch.setattr(LocalFileAdapter, "run_command", run_command)
    monkeypatch.setattr(
        "a4diag_target.server.target_fingerprint", lambda _root: FINGERPRINT
    )
    server = TargetSocketServer(
        policy_path=policy_path,
        public_key_path=public_key_path,
        replay_path=tmp_path / "replay.sqlite3",
    )
    return server, policy_path


def _handle_signed(
    server: TargetSocketServer,
    signer: TargetSigner,
    request: TargetRequestV11,
) -> dict[str, object]:
    envelope = signer.sign(request)
    raw = asyncio.run(
        server.handle(canonical_json_bytes(envelope.model_dump(mode="json")))
    )
    value = json.loads(raw)
    assert isinstance(value, dict)
    return value


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


def test_target_identity_uses_machine_os_systemd_and_host_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("a4diag_target.server._systemd_version", lambda: b"systemd 255\n")
    root = tmp_path / "root"
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/machine-id").write_bytes(b"machine-1\n")
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
    (root / "etc/machine-id").write_bytes(b"machine-1\n")
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


def test_socket_server_reloads_policy_and_denies_apply_after_atomic_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = int(time.time())
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    profile = _profile(expires_at=now + 600)
    effects: list[tuple[str, ...]] = []
    server, policy_path = _server(
        tmp_path,
        monkeypatch,
        key=key,
        policy=_policy(key, profile),
        effect_calls=effects,
    )

    prepared = _handle_signed(
        server,
        signer,
        _request(profile, TargetLifecycleV11.PREPARE, "nonce-prepare-live", now),
    )
    marker = prepared["marker"]
    assert isinstance(marker, dict)
    _write_policy(policy_path, _policy(key, None))

    result = _handle_signed(
        server,
        signer,
        _request(
            profile,
            TargetLifecycleV11.APPLY,
            "nonce-apply-revoked",
            now,
            marker=marker,
        ),
    )

    assert result == {"ok": False, "reason": "profile_revoked"}
    assert effects == []


@pytest.mark.parametrize("mutation", ("missing", "invalid", "symlink"))
def test_socket_server_policy_reload_failure_denies_signed_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    now = int(time.time())
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    profile = _profile(expires_at=now + 600)
    effects: list[tuple[str, ...]] = []
    server, policy_path = _server(
        tmp_path,
        monkeypatch,
        key=key,
        policy=_policy(key, profile),
        effect_calls=effects,
    )
    if mutation == "missing":
        policy_path.unlink()
    elif mutation == "symlink":
        alternate = policy_path.with_suffix(".alternate")
        alternate.write_text(_policy(key, profile).model_dump_json(), encoding="utf-8")
        policy_path.unlink()
        policy_path.symlink_to(alternate)
    else:
        policy_path.write_text("{invalid", encoding="utf-8")

    result = _handle_signed(
        server,
        signer,
        _request(profile, TargetLifecycleV11.PREPARE, f"nonce-{mutation}-policy", now),
    )

    assert result == {"ok": False, "reason": "target_policy_unavailable"}
    assert effects == []


def test_socket_server_diagnostic_read_uses_current_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = int(time.time())
    key = Ed25519PrivateKey.generate()
    profile = _profile(expires_at=now + 600)
    server, policy_path = _server(
        tmp_path,
        monkeypatch,
        key=key,
        policy=_policy(key, profile),
        effect_calls=[],
    )
    _write_policy(policy_path, _policy(key, profile, allowed_units=()))

    raw = asyncio.run(
        server.handle(
            canonical_json_bytes(
                {
                    "method": "read",
                    "kind": "service_state",
                    "unit": "demo.service",
                    "limit": 8192,
                }
            )
        )
    )

    assert json.loads(raw) == {"ok": False, "reason": "unit_not_granted"}

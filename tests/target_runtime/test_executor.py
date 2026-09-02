from __future__ import annotations

import asyncio
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import Operation, Risk
from a4diag.plugin_api.target_protocol import TargetLifecycle, TargetRequest, TargetSigner, TargetVerifier
from a4diag.plugin_api.ticket import effect_payload_digest
from a4diag_target.executor import ExecutorError, TargetExecutor
from a4diag_target.policy import TargetPolicy
from a4diag_target.replay import SqliteReplayLedger
from a4diag_builtin_plugins.capability_common import LocalFileAdapter


class TrackingAdapter(LocalFileAdapter):
    def __init__(self) -> None:
        self.effects = 0

    async def write_file(self, path: str, content: bytes, mode: int | None) -> None:
        self.effects += 1
        await super().write_file(path, content, mode)

    async def set_mode(self, path: str, mode: int) -> None:
        self.effects += 1
        await super().set_mode(path, mode)


def test_file_lifecycle_and_invalid_identity_zero_effects(tmp_path) -> None:
    target = tmp_path / "managed" / "app.conf"
    target.parent.mkdir()
    target.write_bytes(b"before\n")
    target.chmod(0o640)
    fingerprint = "sha256:" + "a" * 64
    key = Ed25519PrivateKey.generate()
    ledger = SqliteReplayLedger(tmp_path / "replay.sqlite3")
    verifier = TargetVerifier(key.public_key(), replay_store=ledger, clock=lambda: 110)
    adapter = TrackingAdapter()
    policy = TargetPolicy(
        target_id="lab-node-1", target_fingerprint=fingerprint,
        controller_key_fingerprint=TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.PREPARE, "n" * 16)).key_fingerprint,
        managed_roots=(str(target.parent),), allowed_units=(), allowed_packages=(),
    )
    executor = TargetExecutor(verifier=verifier, policy=policy, identity_probe=lambda: fingerprint, adapter=adapter)

    prepare = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.PREPARE, "a" * 16))))
    marker = prepare["marker"]
    assert marker["prior_content_sha256"] == hashlib.sha256(b"before\n").hexdigest()
    apply = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.APPLY, "b" * 16, marker=marker))))
    assert apply["ok"] is True and target.read_bytes() == b"after\n"
    verify = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.VERIFY, "c" * 16, marker=marker))))
    assert verify["ok"] is True
    states = {}
    states["applied"] = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.RECONCILE, "d" * 16, marker=marker))))["state"]
    target.write_bytes(b"partial\n")
    states["partial"] = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.RECONCILE, "e" * 16, marker=marker))))["state"]
    target.write_bytes(b"before\n")
    states["not_applied"] = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.RECONCILE, "f" * 16, marker=marker))))["state"]
    assert states == {"applied": "applied", "partial": "partial", "not_applied": "not_applied"}
    asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.APPLY, "g" * 16, marker=marker))))
    undo = asyncio.run(executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.UNDO, "h" * 16, marker=marker))))
    assert undo["ok"] is True and target.read_bytes() == b"before\n"

    effects = adapter.effects
    bad_executor = TargetExecutor(verifier=verifier, policy=policy, identity_probe=lambda: "sha256:" + "f" * 64, adapter=adapter)
    with pytest.raises(ExecutorError, match="target_identity_mismatch"):
        asyncio.run(bad_executor.execute(TargetSigner(key).sign(_request(target, fingerprint, TargetLifecycle.APPLY, "i" * 16, marker=marker))))
    assert adapter.effects == effects


def _request(path, fingerprint, lifecycle, nonce, marker=None):
    operation = Operation(
        capability="files", action="replace_managed_file", resource=str(path),
        parameters={"content": base64.b64encode(b"after\n").decode(), "mode": 0o640},
        model_risk=Risk.LOW, verify={}, undo={"restore": True},
    )
    effect = {}
    if lifecycle in {TargetLifecycle.APPLY, TargetLifecycle.VERIFY, TargetLifecycle.RECONCILE}:
        effect = {"marker": marker}
    elif lifecycle is TargetLifecycle.UNDO:
        effect = {"marker": marker, "undo": operation.undo}
    return TargetRequest(
        controller_id="controller-1", target_id="lab-node-1", target_fingerprint=fingerprint,
        transaction_id="txn-1", step_id="0", lifecycle=lifecycle, operation=operation,
        marker=marker, undo=operation.undo if lifecycle is TargetLifecycle.UNDO else None,
        plan_digest="d" * 64, effect_payload_digest=effect_payload_digest(effect), risk=Risk.LOW,
        approval_id=None, issued_at=100, expires_at=200, nonce=nonce,
    )

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from a4diag.domain import Operation, RepairBinding, Risk, canonical_json_bytes
from a4diag.plugin_api.target_protocol import (
    SignedTargetRequest,
    TargetLifecycleV11,
    TargetProtocolError,
    TargetRequestV11,
    TargetSigner,
    TargetVerifier,
)
from a4diag.plugin_api.ticket import effect_payload_digest
from a4diag.repair_profiles import RepairProfile, profile_digest
from a4diag_target.executor import ExecutorError, TargetExecutor
from a4diag_target.policy import TargetPolicy
from a4diag_builtin_plugins.capability_common import CommandOutcome


FINGERPRINT = "sha256:" + "a" * 64


class ReplayStore:
    def __init__(self) -> None:
        self.nonces: set[str] = set()

    def consume(self, nonce: str, expires_at: int) -> bool:
        del expires_at
        if nonce in self.nonces:
            return False
        self.nonces.add(nonce)
        return True


class RecordingServicesAdapter:
    def __init__(self) -> None:
        self.effect_calls: list[tuple[str, ...]] = []

    async def run_command(
        self,
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
        self.effect_calls.append(tuple(argv))
        return CommandOutcome(returncode=0)


def _profile(**changes: object) -> RepairProfile:
    values: dict[str, object] = {
        "id": "web",
        "target_id": "demo",
        "capability": "services",
        "resource": "demo.service",
        "actions": ("restart",),
        "constraints": {},
        "recovery_check_ids": ("health",),
        "expires_at": 200,
        "standing_authorization": True,
    }
    values.update(changes)
    return RepairProfile.model_validate(values)


def _operation(**changes: object) -> Operation:
    values: dict[str, object] = {
        "capability": "services",
        "action": "restart",
        "resource": "demo.service",
        "parameters": {"unit": "demo.service"},
        "model_risk": Risk.HIGH,
        "verify": {"recovery_check_ids": ["health"]},
        "undo": {"restore": True},
    }
    values.update(changes)
    return Operation.model_validate(values)


def _binding(profile: RepairProfile, marker: dict[str, object] | None = None) -> RepairBinding:
    digest = None
    if marker is not None:
        digest = hashlib.sha256(canonical_json_bytes(marker)).hexdigest()
    return RepairBinding(
        profile_id=profile.id,
        profile_digest=profile_digest(profile),
        preconditions_digest=digest,
    )


def _request(
    profile: RepairProfile,
    lifecycle: TargetLifecycleV11,
    nonce: str,
    *,
    marker: dict[str, object] | None = None,
    binding: RepairBinding | None = None,
    authorization_kind: str = "standing",
    authorization_id: str = "web",
    operation: Operation | None = None,
    target_id: str = "demo",
    job_id: str | None = None,
) -> TargetRequestV11:
    selected = operation or _operation()
    effect: dict[str, object] = {}
    if lifecycle in {
        TargetLifecycleV11.APPLY,
        TargetLifecycleV11.VERIFY,
        TargetLifecycleV11.RECONCILE,
    }:
        effect = {"marker": marker}
    elif lifecycle is TargetLifecycleV11.UNDO:
        effect = {"marker": marker, "undo": selected.undo}
    return TargetRequestV11(
        controller_id="controller-1",
        target_id=target_id,
        target_fingerprint=FINGERPRINT,
        transaction_id="txn-1",
        step_id="0",
        lifecycle=lifecycle,
        operation=selected,
        marker=marker,
        undo=selected.undo if lifecycle is TargetLifecycleV11.UNDO else None,
        plan_digest="d" * 64,
        effect_payload_digest=effect_payload_digest(effect),
        risk=Risk.HIGH,
        binding=binding or _binding(profile, marker),
        authorization_kind=authorization_kind,
        authorization_id=authorization_id,
        issued_at=100,
        expires_at=190,
        nonce=nonce,
        **({"job_id": job_id} if job_id is not None else {}),
    )


@dataclass
class MutableTarget:
    profile: RepairProfile | None

    def policy(self, key_fingerprint: str) -> TargetPolicy:
        return TargetPolicy(
            target_id="demo",
            target_fingerprint=FINGERPRINT,
            controller_key_fingerprint=key_fingerprint,
            repair_profiles=() if self.profile is None else (self.profile,),
        )

    def revoke(self, profile_id: str) -> None:
        assert self.profile is not None and self.profile.id == profile_id
        self.profile = None


@dataclass
class PreparedRepair:
    target: MutableTarget
    executor: TargetExecutor
    signer: TargetSigner
    profile: RepairProfile
    marker: dict[str, object]
    effect_calls: list[tuple[str, ...]]

    def apply_signed(self) -> ExecutorError | None:
        request = _request(
            self.profile,
            TargetLifecycleV11.APPLY,
            "nonce-apply-00001",
            marker=self.marker,
        )
        try:
            asyncio.run(self.executor.execute(self.signer.sign(request)))
        except ExecutorError as error:
            return error
        return None


@pytest.fixture
def prepared_repair() -> PreparedRepair:
    profile = _profile()
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    key_fingerprint = signer.sign(
        _request(profile, TargetLifecycleV11.PREPARE, "nonce-probe-00001")
    ).key_fingerprint
    target = MutableTarget(profile)
    adapter = RecordingServicesAdapter()
    verifier = TargetVerifier(
        key.public_key(), replay_store=ReplayStore(), clock=lambda: 150
    )
    executor = TargetExecutor(
        verifier=verifier,
        policy=lambda: target.policy(key_fingerprint),
        identity_probe=lambda: FINGERPRINT,
        adapter=adapter,
    )
    result = asyncio.run(
        executor.execute(
            signer.sign(
                _request(profile, TargetLifecycleV11.PREPARE, "nonce-prepare-0001")
            )
        )
    )
    return PreparedRepair(
        target=target,
        executor=executor,
        signer=signer,
        profile=profile,
        marker=result["marker"],
        effect_calls=adapter.effect_calls,
    )


def test_revoked_profile_cannot_apply(prepared_repair: PreparedRepair) -> None:
    prepared_repair.target.revoke("web")
    result = prepared_repair.apply_signed()
    assert result is not None and str(result) == "profile_revoked"
    assert prepared_repair.effect_calls == []


def test_v11_signature_binds_complete_authorization_and_replays_once() -> None:
    profile = _profile()
    key = Ed25519PrivateKey.generate()
    request = _request(profile, TargetLifecycleV11.PREPARE, "nonce-signed-00001")
    envelope = TargetSigner(key).sign(request)
    verifier = TargetVerifier(key.public_key(), replay_store=ReplayStore(), clock=lambda: 150)

    assert verifier.verify(envelope, expected_target="demo") == request
    with pytest.raises(TargetProtocolError, match="replay"):
        verifier.verify(envelope, expected_target="demo")


def test_v11_authorization_fields_are_covered_by_ed25519_signature() -> None:
    profile = _profile()
    key = Ed25519PrivateKey.generate()
    envelope = TargetSigner(key).sign(
        _request(profile, TargetLifecycleV11.PREPARE, "nonce-tamper-00001")
    )
    payload = json.loads(envelope.payload)
    payload["authorization_id"] = "forged"
    tampered = envelope.model_copy(
        update={"payload": canonical_json_bytes(payload).decode("utf-8")}
    )
    with pytest.raises(TargetProtocolError, match="invalid_signature"):
        TargetVerifier(
            key.public_key(), replay_store=ReplayStore(), clock=lambda: 150
        ).verify(tampered, expected_target="demo")


def test_legacy_target_rejects_v11_explicitly() -> None:
    profile = _profile()
    key = Ed25519PrivateKey.generate()
    envelope = TargetSigner(key).sign(
        _request(profile, TargetLifecycleV11.PREPARE, "nonce-legacy-00001")
    )
    verifier = TargetVerifier(
        key.public_key(),
        replay_store=ReplayStore(),
        clock=lambda: 150,
        supported_versions=("1.0",),
    )
    with pytest.raises(TargetProtocolError) as caught:
        verifier.verify(envelope, expected_target="demo")
    assert caught.value.code == "unsupported_protocol_version"


def test_v11_cannot_downgrade_repair_risk() -> None:
    profile = _profile()
    raw = _request(
        profile, TargetLifecycleV11.PREPARE, "nonce-risk-0000001"
    ).model_dump(mode="python")
    raw["risk"] = Risk.LOW
    raw["operation"] = _operation(model_risk=Risk.LOW)
    with pytest.raises(ValidationError, match="HIGH"):
        TargetRequestV11.model_validate(raw)


@pytest.mark.parametrize(
    ("changes", "code"),
    (
        ({"authorization_id": "forged"}, "standing_authorization_mismatch"),
        ({"target_id": "other"}, "target_mismatch"),
        ({"binding": RepairBinding(profile_id="other", profile_digest="0" * 64)}, "profile_revoked"),
    ),
)
def test_v11_rejects_forged_standing_cross_target_and_cross_profile(
    changes: dict[str, object], code: str
) -> None:
    profile = _profile()
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    request = _request(
        profile,
        TargetLifecycleV11.PREPARE,
        "nonce-cross-000001",
        **changes,
    )
    key_fingerprint = signer.sign(request).key_fingerprint
    target = MutableTarget(profile)
    executor = TargetExecutor(
        verifier=TargetVerifier(
            key.public_key(), replay_store=ReplayStore(), clock=lambda: 150
        ),
        policy=lambda: target.policy(key_fingerprint),
        identity_probe=lambda: FINGERPRINT,
        adapter=RecordingServicesAdapter(),
    )
    with pytest.raises(ExecutorError) as caught:
        asyncio.run(executor.execute(signer.sign(request)))
    assert str(caught.value) == code


def test_apply_rejects_replaced_prepare_marker_before_effect(prepared_repair: PreparedRepair) -> None:
    replaced = {**prepared_repair.marker, "unit": "other.service"}
    request = _request(
        prepared_repair.profile,
        TargetLifecycleV11.APPLY,
        "nonce-marker-00001",
        marker=replaced,
        binding=_binding(prepared_repair.profile, prepared_repair.marker),
    )
    with pytest.raises(ExecutorError, match="preconditions_digest_mismatch"):
        asyncio.run(
            prepared_repair.executor.execute(prepared_repair.signer.sign(request))
        )
    assert prepared_repair.effect_calls == []


@pytest.mark.parametrize("lifecycle", (TargetLifecycleV11.QUERY_JOB, TargetLifecycleV11.CONFIRM_JOB))
def test_job_lifecycles_fail_closed_until_job_handlers_exist(
    prepared_repair: PreparedRepair, lifecycle: TargetLifecycleV11
) -> None:
    request = _request(
        prepared_repair.profile,
        lifecycle,
        f"nonce-{lifecycle.value}-0001",
        job_id="job-1",
    )
    with pytest.raises(ExecutorError, match="lifecycle_not_wired"):
        asyncio.run(
            prepared_repair.executor.execute(prepared_repair.signer.sign(request))
        )
    assert prepared_repair.effect_calls == []


def test_job_lifecycle_requires_a_bound_job_id() -> None:
    profile = _profile()
    with pytest.raises(ValidationError, match="job_id"):
        _request(
            profile,
            TargetLifecycleV11.QUERY_JOB,
            "nonce-job-id-00001",
        )


def test_profile_expiry_boundary_denies_execution_before_effect() -> None:
    profile = _profile(expires_at=150)
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    request = _request(profile, TargetLifecycleV11.PREPARE, "nonce-expire-00001")
    key_fingerprint = signer.sign(request).key_fingerprint
    adapter = RecordingServicesAdapter()
    executor = TargetExecutor(
        verifier=TargetVerifier(
            key.public_key(), replay_store=ReplayStore(), clock=lambda: 150
        ),
        policy=lambda: MutableTarget(profile).policy(key_fingerprint),
        identity_probe=lambda: FINGERPRINT,
        adapter=adapter,
    )
    with pytest.raises(ExecutorError, match="profile_expired"):
        asyncio.run(executor.execute(signer.sign(request)))
    assert adapter.effect_calls == []


def test_revoked_profile_cannot_confirm_job(prepared_repair: PreparedRepair) -> None:
    prepared_repair.target.revoke("web")
    request = _request(
        prepared_repair.profile,
        TargetLifecycleV11.CONFIRM_JOB,
        "nonce-confirm-revoked",
        job_id="job-1",
    )
    with pytest.raises(ExecutorError, match="profile_revoked"):
        asyncio.run(
            prepared_repair.executor.execute(prepared_repair.signer.sign(request))
        )
    assert prepared_repair.effect_calls == []

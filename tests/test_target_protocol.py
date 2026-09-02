"""Signed controller-to-target request protocol security contracts."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import Operation, Risk, canonical_json_bytes
from a4diag.plugin_api.target_protocol import (
    SignedTargetRequest,
    TargetLifecycle,
    TargetProtocolError,
    TargetRequest,
    TargetSigner,
    TargetVerifier,
)


class ReplayStore:
    def __init__(self) -> None:
        self.nonces: set[str] = set()

    def consume(self, nonce: str, expires_at: int) -> bool:
        del expires_at
        if nonce in self.nonces:
            return False
        self.nonces.add(nonce)
        return True


def _request(**changes: object) -> TargetRequest:
    values: dict[str, object] = {
        "controller_id": "controller-1",
        "target_id": "lab-node-1",
        "target_fingerprint": "sha256:" + "a" * 64,
        "transaction_id": "txn-1",
        "step_id": "0",
        "lifecycle": "apply",
        "operation": Operation(
            capability="files",
            action="replace_managed_file",
            resource="/opt/lab/app.conf",
            parameters={"content": "enabled=true\n"},
            model_risk=Risk.LOW,
            verify={"sha256": "b" * 64},
            undo={"restore_marker": True},
        ),
        "marker": {"before_sha256": "c" * 64},
        "undo": {"restore_marker": True},
        "plan_digest": "d" * 64,
        "effect_payload_digest": "e" * 64,
        "risk": "low",
        "approval_id": None,
        "issued_at": 1_700_000_000,
        "expires_at": 1_700_000_120,
        "nonce": "nonce-000000000001",
    }
    values.update(changes)
    return TargetRequest.model_validate(values)


def _verifier(private: Ed25519PrivateKey, store: ReplayStore | None = None) -> TargetVerifier:
    return TargetVerifier(
        private.public_key(),
        replay_store=store or ReplayStore(),
        clock=lambda: 1_700_000_010,
    )


def test_valid_request_verifies_once_and_replay_is_rejected() -> None:
    private = Ed25519PrivateKey.generate()
    request = _request()
    envelope = TargetSigner(private).sign(request)
    verifier = _verifier(private)

    assert verifier.verify(envelope, expected_target="lab-node-1") == request
    with pytest.raises(TargetProtocolError, match="replay"):
        verifier.verify(envelope, expected_target="lab-node-1")


def test_wrong_key_and_wrong_expected_target_are_rejected() -> None:
    signer_key = Ed25519PrivateKey.generate()
    envelope = TargetSigner(signer_key).sign(_request())
    with pytest.raises(TargetProtocolError, match="key_mismatch"):
        _verifier(Ed25519PrivateKey.generate()).verify(
            envelope, expected_target="lab-node-1"
        )
    with pytest.raises(TargetProtocolError, match="target_mismatch"):
        _verifier(signer_key).verify(envelope, expected_target="lab-node-2")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_id", "lab-node-2"),
        ("target_fingerprint", "sha256:" + "f" * 64),
        ("lifecycle", "undo"),
        ("marker", {"changed": True}),
        ("undo", {"changed": True}),
        ("effect_payload_digest", "0" * 64),
    ),
)
def test_every_effect_binding_is_covered_by_signature(field: str, value: object) -> None:
    private = Ed25519PrivateKey.generate()
    envelope = TargetSigner(private).sign(_request())
    payload = json.loads(envelope.payload)
    payload[field] = value
    tampered = envelope.model_copy(
        update={"payload": canonical_json_bytes(payload, max_bytes=1_048_576).decode()}
    )
    with pytest.raises(TargetProtocolError, match="invalid_signature"):
        _verifier(private).verify(tampered, expected_target="lab-node-1")


def test_operation_mutation_is_covered_by_signature() -> None:
    private = Ed25519PrivateKey.generate()
    envelope = TargetSigner(private).sign(_request())
    payload = json.loads(envelope.payload)
    payload["operation"]["resource"] = "/opt/lab/other.conf"
    tampered = envelope.model_copy(
        update={"payload": canonical_json_bytes(payload, max_bytes=1_048_576).decode()}
    )
    with pytest.raises(TargetProtocolError, match="invalid_signature"):
        _verifier(private).verify(tampered, expected_target="lab-node-1")


def test_expired_and_future_requests_are_rejected_before_replay_consumption() -> None:
    private = Ed25519PrivateKey.generate()
    store = ReplayStore()
    verifier = TargetVerifier(private.public_key(), replay_store=store, clock=lambda: 200)
    with pytest.raises(TargetProtocolError, match="expired"):
        verifier.verify(
            TargetSigner(private).sign(_request(issued_at=50, expires_at=100)),
            expected_target="lab-node-1",
        )
    with pytest.raises(TargetProtocolError, match="issued_in_future"):
        verifier.verify(
            TargetSigner(private).sign(_request(issued_at=300, expires_at=400)),
            expected_target="lab-node-1",
        )
    assert store.nonces == set()


def _signed_raw(private: Ed25519PrivateKey, payload: bytes) -> SignedTargetRequest:
    signature = base64.urlsafe_b64encode(private.sign(payload)).rstrip(b"=").decode()
    good = TargetSigner(private).sign(_request())
    return SignedTargetRequest(
        payload=payload.decode(),
        signature=signature,
        key_fingerprint=good.key_fingerprint,
    )


def test_duplicate_json_unknown_field_and_noncanonical_body_are_rejected() -> None:
    private = Ed25519PrivateKey.generate()
    duplicate = b'{"target_id":"a","target_id":"b"}'
    unknown = json.loads(TargetSigner(private).sign(_request()).payload)
    unknown["unexpected"] = True
    noncanonical = json.dumps(
        _request().model_dump(mode="json"), ensure_ascii=False, indent=2
    ).encode()
    for payload, code in (
        (duplicate, "duplicate_json_key"),
        (canonical_json_bytes(unknown, max_bytes=1_048_576), "request_invalid"),
        (noncanonical, "noncanonical_payload"),
    ):
        with pytest.raises(TargetProtocolError, match=code):
            _verifier(private).verify(
                _signed_raw(private, payload), expected_target="lab-node-1"
            )


def test_oversized_body_and_high_without_approval_are_rejected() -> None:
    private = Ed25519PrivateKey.generate()
    oversized = SignedTargetRequest(
        payload="x" * 1_048_577,
        signature="AA",
        key_fingerprint=TargetSigner(private).sign(_request()).key_fingerprint,
    )
    with pytest.raises(TargetProtocolError, match="payload_too_large"):
        _verifier(private).verify(oversized, expected_target="lab-node-1")

    raw = _request().model_dump(mode="json")
    raw["risk"] = "high"
    payload = canonical_json_bytes(raw, max_bytes=1_048_576)
    with pytest.raises(TargetProtocolError, match="request_invalid"):
        _verifier(private).verify(
            _signed_raw(private, payload), expected_target="lab-node-1"
        )


def test_lifecycle_and_digest_models_are_strict() -> None:
    assert {item.value for item in TargetLifecycle} == {
        "prepare",
        "apply",
        "verify",
        "undo",
        "reconcile",
    }
    with pytest.raises(ValueError):
        _request(plan_digest="not-a-digest")
    with pytest.raises(ValueError):
        _request(unknown=True)

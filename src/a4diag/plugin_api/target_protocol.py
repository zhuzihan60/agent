"""Canonical Ed25519 controller-to-target execution request protocol."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from enum import StrEnum
from typing import Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, JsonValue, field_validator, model_validator

from a4diag.domain import Operation, Risk, canonical_json_bytes

MAX_TARGET_REQUEST_BYTES = 1_048_576
MAX_CLOCK_SKEW_SECONDS = 30
MAX_REQUEST_LIFETIME_SECONDS = 300
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class TargetProtocolError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TargetLifecycle(StrEnum):
    PREPARE = "prepare"
    APPLY = "apply"
    VERIFY = "verify"
    UNDO = "undo"
    RECONCILE = "reconcile"


class TargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal["1.0"] = "1.0"
    controller_id: str
    target_id: str
    target_fingerprint: str
    transaction_id: str
    step_id: str
    lifecycle: TargetLifecycle
    operation: Operation
    marker: dict[str, JsonValue] | None
    undo: dict[str, JsonValue] | None
    plan_digest: str
    effect_payload_digest: str
    risk: Risk
    approval_id: str | None
    issued_at: int
    expires_at: int
    nonce: str

    @field_validator("controller_id", "transaction_id", "step_id")
    @classmethod
    def safe_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise ValueError("unsafe request identifier")
        return value

    @field_validator("target_id")
    @classmethod
    def safe_target(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_TARGET.fullmatch(value):
            raise ValueError("unsafe target identifier")
        return value

    @field_validator("target_fingerprint")
    @classmethod
    def safe_fingerprint(cls, value: str) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("invalid target fingerprint")
        return value

    @field_validator("plan_digest", "effect_payload_digest")
    @classmethod
    def digest(cls, value: str) -> str:
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise ValueError("invalid digest")
        return value

    @field_validator("nonce")
    @classmethod
    def nonce_value(cls, value: str) -> str:
        if not isinstance(value, str) or not _NONCE.fullmatch(value):
            raise ValueError("invalid nonce")
        return value

    @field_validator("marker", "undo")
    @classmethod
    def bounded_json_object(
        cls, value: dict[str, JsonValue] | None
    ) -> dict[str, JsonValue] | None:
        if value is not None:
            canonical_json_bytes(value, max_bytes=262_144)
        return value

    @field_validator("approval_id")
    @classmethod
    def approval_value(cls, value: str | None) -> str | None:
        if value is not None and not _SAFE_ID.fullmatch(value):
            raise ValueError("invalid approval identifier")
        return value

    @model_validator(mode="after")
    def validate_window_and_approval(self) -> TargetRequest:
        if self.expires_at <= self.issued_at:
            raise ValueError("expiry must follow issue time")
        if self.expires_at - self.issued_at > MAX_REQUEST_LIFETIME_SECONDS:
            raise ValueError("request lifetime exceeds limit")
        if self.risk is Risk.HIGH and self.approval_id is None:
            raise ValueError("HIGH request requires approval")
        if self.operation.model_risk is not self.risk:
            raise ValueError("operation risk mismatch")
        return self


class SignedTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: str
    signature: str
    key_fingerprint: str


class NonceReplayStore(Protocol):
    def consume(self, nonce: str, expires_at: int) -> bool: ...


def _public_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise TargetProtocolError("signature_invalid_encoding")
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, UnicodeError) as exc:
        raise TargetProtocolError("signature_invalid_encoding") from exc


class TargetSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Ed25519 private key required")
        self._private_key = private_key

    def sign(self, request: TargetRequest) -> SignedTargetRequest:
        if not isinstance(request, TargetRequest):
            raise TypeError("TargetRequest required")
        payload = canonical_json_bytes(
            request.model_dump(mode="json"), max_bytes=MAX_TARGET_REQUEST_BYTES
        )
        return SignedTargetRequest(
            payload=payload.decode("utf-8"),
            signature=_b64url_encode(self._private_key.sign(payload)),
            key_fingerprint=_public_fingerprint(self._private_key.public_key()),
        )


class TargetVerifier:
    def __init__(
        self,
        public_key: Ed25519PublicKey,
        *,
        replay_store: NonceReplayStore,
        clock: Callable[[], int],
    ) -> None:
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("Ed25519 public key required")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._public_key = public_key
        self._replay_store = replay_store
        self._clock = clock

    def verify(
        self, envelope: SignedTargetRequest, *, expected_target: str
    ) -> TargetRequest:
        if not isinstance(envelope, SignedTargetRequest):
            raise TargetProtocolError("envelope_invalid")
        try:
            payload = envelope.payload.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise TargetProtocolError("payload_invalid_encoding") from exc
        if len(payload) > MAX_TARGET_REQUEST_BYTES:
            raise TargetProtocolError("payload_too_large")
        if envelope.key_fingerprint != _public_fingerprint(self._public_key):
            raise TargetProtocolError("key_mismatch")
        signature = _b64url_decode(envelope.signature)
        if len(signature) != 64:
            raise TargetProtocolError("signature_invalid_encoding")
        try:
            self._public_key.verify(signature, payload)
        except InvalidSignature as exc:
            raise TargetProtocolError("invalid_signature") from exc

        decoded = self._parse_unique_json(payload)
        try:
            request = TargetRequest.model_validate(decoded)
        except ValueError as exc:
            raise TargetProtocolError("request_invalid") from exc
        canonical = canonical_json_bytes(
            request.model_dump(mode="json"), max_bytes=MAX_TARGET_REQUEST_BYTES
        )
        if canonical != payload:
            raise TargetProtocolError("noncanonical_payload")
        if not _SAFE_TARGET.fullmatch(expected_target) or request.target_id != expected_target:
            raise TargetProtocolError("target_mismatch")
        now = int(self._clock())
        if request.issued_at > now + MAX_CLOCK_SKEW_SECONDS:
            raise TargetProtocolError("issued_in_future")
        if request.expires_at < now:
            raise TargetProtocolError("expired")
        consume_request = getattr(self._replay_store, "consume_request", None)
        if callable(consume_request):
            consumed = consume_request(
                nonce=request.nonce,
                expires_at=request.expires_at,
                transaction_id=request.transaction_id,
                step_id=request.step_id,
                lifecycle=request.lifecycle.value,
                request_digest=hashlib.sha256(payload).hexdigest(),
                now=now,
            )
        else:
            consumed = self._replay_store.consume(request.nonce, request.expires_at)
        if not consumed:
            raise TargetProtocolError("replay")
        return request

    def record_result(self, nonce: str, result: object) -> None:
        recorder = getattr(self._replay_store, "record_result", None)
        if not callable(recorder):
            return
        digest = hashlib.sha256(
            canonical_json_bytes(result, max_bytes=MAX_TARGET_REQUEST_BYTES)
        ).hexdigest()
        recorder(nonce, digest, now=int(self._clock()))

    @staticmethod
    def _parse_unique_json(payload: bytes) -> object:
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise TargetProtocolError("duplicate_json_key")
                result[key] = value
            return result

        try:
            return json.loads(payload, object_pairs_hook=unique)
        except TargetProtocolError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TargetProtocolError("request_invalid") from exc


__all__ = [
    "MAX_TARGET_REQUEST_BYTES",
    "NonceReplayStore",
    "SignedTargetRequest",
    "TargetLifecycle",
    "TargetProtocolError",
    "TargetRequest",
    "TargetSigner",
    "TargetVerifier",
]

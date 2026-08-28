from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
import uuid
from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from a4diag.domain import (
    CanonicalPlanError,
    Operation,
    Risk,
    canonical_json_bytes,
)
from a4diag.policy_engine import (
    PolicyAuthorization,
    canonical_operation_digest,
    policy_authorization_is_authentic,
)


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TOKEN_SEGMENT_LENGTH = 400_000


class ReplayStore(Protocol):
    def consume(self, ticket_id: str) -> bool: ...


class TicketError(ValueError):
    """Stable, typed failure raised by ticket issuance and verification."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


class OperationPhase(StrEnum):
    PREPARE = "prepare"
    APPLY = "apply"
    UNDO = "undo"


def _validate_safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{label} must be a safe nonblank identifier")
    return value


def _validate_target_id(value: str) -> str:
    if not isinstance(value, str) or not _TARGET_ID.fullmatch(value):
        raise ValueError("target_id must be a safe identifier")
    return value


def _validate_fingerprint(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target_fingerprint must not be blank")
    if len(value) > 512:
        raise ValueError("target_fingerprint must not exceed 512 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("target_fingerprint must not contain control characters")
    return value


def _validate_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA256 digest")
    return value


def _validate_approval(value: str | None) -> str | None:
    if value is None:
        return None
    return _validate_safe_id(value, "approval_id")


def effect_payload_digest(payload: Mapping[str, JsonValue]) -> str:
    """Return the canonical digest of phase-specific validated effect fields."""

    if not isinstance(payload, Mapping):
        raise TicketError("invalid_effect_payload")
    try:
        value = dict(payload)
        if any(type(key) is not str for key in value):
            raise ValueError("effect payload keys must be strings")
        return hashlib.sha256(
            canonical_json_bytes(value, max_bytes=1_048_576)
        ).hexdigest()
    except (CanonicalPlanError, ValueError, TypeError) as error:
        raise TicketError("invalid_effect_payload", str(error)) from error


EMPTY_EFFECT_PAYLOAD_DIGEST = effect_payload_digest({})


class OperationTicketEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str
    step_id: str
    target_id: str
    target_fingerprint: str
    operation: Operation
    plan_digest: str
    risk: Risk
    approval_id: str | None

    @field_validator("transaction_id")
    @classmethod
    def validate_transaction_id(cls, value: str) -> str:
        return _validate_safe_id(value, "transaction_id")

    @field_validator("step_id")
    @classmethod
    def validate_step_id(cls, value: str) -> str:
        return _validate_safe_id(value, "step_id")

    @field_validator("target_id")
    @classmethod
    def validate_target_id(cls, value: str) -> str:
        return _validate_target_id(value)

    @field_validator("target_fingerprint")
    @classmethod
    def validate_target_fingerprint(cls, value: str) -> str:
        return _validate_fingerprint(value)

    @field_validator("plan_digest")
    @classmethod
    def validate_plan_digest(cls, value: str) -> str:
        return _validate_digest(value, "plan_digest")

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str | None) -> str | None:
        return _validate_approval(value)

    @model_validator(mode="after")
    def validate_high_approval(self) -> OperationTicketEnvelope:
        if self.risk is Risk.HIGH and self.approval_id is None:
            raise ValueError("approval_id is required for HIGH risk")
        return self


class OperationTicketRequest(OperationTicketEnvelope):
    phase: OperationPhase = OperationPhase.APPLY
    effect_payload_digest: str = EMPTY_EFFECT_PAYLOAD_DIGEST
    ttl_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("effect_payload_digest")
    @classmethod
    def validate_effect_payload_digest(cls, value: str) -> str:
        return _validate_digest(value, "effect_payload_digest")


class OperationTicketExpectation(OperationTicketEnvelope):
    phase: OperationPhase = OperationPhase.APPLY
    effect_payload_digest: str = EMPTY_EFFECT_PAYLOAD_DIGEST

    @field_validator("effect_payload_digest")
    @classmethod
    def validate_effect_payload_digest(cls, value: str) -> str:
        return _validate_digest(value, "effect_payload_digest")


class OperationTicket(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ticket_id: str
    transaction_id: str
    step_id: str
    target_id: str
    target_fingerprint: str
    capability: str
    action: str
    resource: str
    phase: OperationPhase
    parameters_digest: str
    operation_digest: str
    effect_payload_digest: str
    plan_digest: str
    risk: Risk
    approval_id: str | None
    issued_at: int
    expires_at: int

    @field_validator("ticket_id", "transaction_id", "step_id")
    @classmethod
    def validate_safe_ids(cls, value: str, info: object) -> str:
        return _validate_safe_id(value, getattr(info, "field_name", "identifier"))

    @field_validator("target_id")
    @classmethod
    def validate_target_id(cls, value: str) -> str:
        return _validate_target_id(value)

    @field_validator("target_fingerprint")
    @classmethod
    def validate_target_fingerprint(cls, value: str) -> str:
        return _validate_fingerprint(value)

    @field_validator(
        "parameters_digest", "operation_digest", "effect_payload_digest", "plan_digest"
    )
    @classmethod
    def validate_digests(cls, value: str, info: object) -> str:
        return _validate_digest(value, getattr(info, "field_name", "digest"))

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str | None) -> str | None:
        return _validate_approval(value)

    @model_validator(mode="after")
    def validate_claims(self) -> OperationTicket:
        ttl = self.expires_at - self.issued_at
        if not 1 <= ttl <= 300:
            raise ValueError("ticket lifetime must be between 1 and 300 seconds")
        if self.risk is Risk.HIGH and self.approval_id is None:
            raise ValueError("approval_id is required for HIGH risk")
        return self


class TicketIssuer:
    def __init__(
        self,
        key: bytes,
        *,
        authorization_key: bytes,
        clock: Callable[[], int] | None = None,
        ticket_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._key = _validate_key(key)
        self._authorization_key = _validate_key(authorization_key)
        self._clock = clock or _system_clock
        self._ticket_id_factory = ticket_id_factory or (lambda: uuid.uuid4().hex)

    def issue(
        self,
        request: OperationTicketRequest,
        authorization: PolicyAuthorization | None,
    ) -> str:
        if not isinstance(request, OperationTicketRequest):
            raise TypeError("request must be OperationTicketRequest")
        if not isinstance(
            authorization, PolicyAuthorization
        ) or not policy_authorization_is_authentic(
            authorization, self._authorization_key
        ):
            raise TicketError("invalid_authorization")
        _verify_policy_authorization_bindings(request, authorization)
        issued_at = _read_clock(self._clock)
        try:
            parameters_digest = hashlib.sha256(
                canonical_json_bytes(request.operation.parameters)
            ).hexdigest()
            claims = OperationTicket(
                ticket_id=self._ticket_id_factory(),
                transaction_id=request.transaction_id,
                step_id=request.step_id,
                target_id=request.target_id,
                target_fingerprint=request.target_fingerprint,
                capability=request.operation.capability,
                action=request.operation.action,
                resource=request.operation.resource,
                phase=request.phase,
                parameters_digest=parameters_digest,
                operation_digest=canonical_operation_digest(request.operation),
                effect_payload_digest=request.effect_payload_digest,
                plan_digest=request.plan_digest,
                risk=request.risk,
                approval_id=request.approval_id,
                issued_at=issued_at,
                expires_at=issued_at + request.ttl_seconds,
            )
            payload = canonical_json_bytes(claims.model_dump(mode="json"))
        except (CanonicalPlanError, ValueError, TypeError) as error:
            raise TicketError("invalid_request", str(error)) from error
        signature = hmac.new(self._key, payload, hashlib.sha256).digest()
        return f"{_base64url_encode(payload)}.{_base64url_encode(signature)}"


class TicketVerifier:
    def __init__(
        self,
        key: bytes,
        replay_store: ReplayStore,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._key = _validate_key(key)
        consume = getattr(replay_store, "consume", None)
        if not callable(consume):
            raise TypeError("replay_store must implement consume(ticket_id)")
        self._replay_store = replay_store
        self._clock = clock or _system_clock

    def verify(
        self,
        token: str,
        expected: OperationTicketExpectation,
    ) -> OperationTicket:
        if not isinstance(expected, OperationTicketExpectation):
            raise TypeError("expected must be OperationTicketExpectation")
        payload, signature = _decode_token(token)
        expected_signature = hmac.new(self._key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise TicketError("invalid_signature")

        claims = _parse_canonical_claims(payload)
        now = _read_clock(self._clock)
        if claims.issued_at > now:
            raise TicketError("not_yet_valid")
        if now >= claims.expires_at:
            raise TicketError("expired")

        _verify_bindings(claims, expected)

        if not self._replay_store.consume(claims.ticket_id):
            raise TicketError("replay")
        return claims


def _validate_key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) < 32:
        raise TicketError("invalid_key", "HMAC key must be at least 32 bytes")
    return key


def _system_clock() -> int:
    return int(time.time())


def _read_clock(clock: Callable[[], int]) -> int:
    value = clock()
    if type(value) is not int or value < 0:
        raise TicketError("invalid_clock", "clock must return a non-negative integer")
    return value


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if (
        not value
        or "=" in value
        or len(value) > _MAX_TOKEN_SEGMENT_LENGTH
        or any(ord(character) > 127 for character in value)
    ):
        raise TicketError("malformed_token")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(
            (value + padding).encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error, UnicodeEncodeError) as error:
        raise TicketError("malformed_token") from error
    if _base64url_encode(decoded) != value:
        raise TicketError("malformed_token")
    return decoded


def _decode_token(token: str) -> tuple[bytes, bytes]:
    if not isinstance(token, str) or token.count(".") != 1:
        raise TicketError("malformed_token")
    payload_segment, signature_segment = token.split(".")
    payload = _base64url_decode(payload_segment)
    signature = _base64url_decode(signature_segment)
    if len(signature) != hashlib.sha256().digest_size:
        raise TicketError("malformed_token")
    return payload, signature


def _reject_float(value: str) -> object:
    raise ValueError(f"floating-point JSON value is forbidden: {value}")


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _parse_canonical_claims(payload: bytes) -> OperationTicket:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
        if type(value) is not dict:
            raise ValueError("ticket payload must be an object")
        claims = OperationTicket.model_validate(value)
        canonical = canonical_json_bytes(claims.model_dump(mode="json"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, CanonicalPlanError) as error:
        raise TicketError("invalid_claims", str(error)) from error
    if not hmac.compare_digest(payload, canonical):
        raise TicketError("invalid_claims", "payload is not canonical JSON")
    return claims


def _verify_bindings(
    claims: OperationTicket, expected: OperationTicketExpectation
) -> None:
    if claims.transaction_id != expected.transaction_id:
        raise TicketError("transaction_mismatch")
    if claims.step_id != expected.step_id:
        raise TicketError("step_mismatch")
    if (
        claims.target_id != expected.target_id
        or claims.target_fingerprint != expected.target_fingerprint
    ):
        raise TicketError("target_mismatch")
    try:
        operation_digest = canonical_operation_digest(expected.operation)
    except CanonicalPlanError as error:
        raise TicketError("operation_mismatch", str(error)) from error
    if (
        claims.capability != expected.operation.capability
        or claims.action != expected.operation.action
        or claims.resource != expected.operation.resource
        or not hmac.compare_digest(claims.operation_digest, operation_digest)
    ):
        raise TicketError("operation_mismatch")
    if not hmac.compare_digest(
        claims.effect_payload_digest, expected.effect_payload_digest
    ):
        raise TicketError("effect_payload_mismatch")
    if claims.phase is not expected.phase:
        raise TicketError("phase_mismatch")
    if not hmac.compare_digest(claims.plan_digest, expected.plan_digest):
        raise TicketError("plan_mismatch")
    if claims.risk is not expected.risk:
        raise TicketError("risk_mismatch")
    if claims.approval_id != expected.approval_id:
        raise TicketError("approval_mismatch")


def _verify_policy_authorization_bindings(
    request: OperationTicketRequest,
    authorization: PolicyAuthorization,
) -> None:
    if (
        authorization.target_id != request.target_id
        or authorization.target_fingerprint != request.target_fingerprint
    ):
        raise TicketError("authorization_target_mismatch")
    if not hmac.compare_digest(authorization.plan_digest, request.plan_digest):
        raise TicketError("authorization_plan_mismatch")
    if authorization.risk is not request.risk:
        raise TicketError("authorization_risk_mismatch")
    if authorization.approval_id != request.approval_id:
        raise TicketError("authorization_approval_mismatch")
    try:
        digest = canonical_operation_digest(request.operation)
    except CanonicalPlanError as error:
        raise TicketError("invalid_request", str(error)) from error
    if not any(
        hmac.compare_digest(digest, authorized_digest)
        for authorized_digest in authorization.operation_digests
    ):
        raise TicketError("operation_not_authorized")

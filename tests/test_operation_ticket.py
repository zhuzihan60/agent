from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest
from pydantic import ValidationError

from a4diag.domain import Operation, Risk
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketExpectation,
    OperationTicketRequest,
    TicketError,
    TicketIssuer,
    TicketVerifier,
    effect_payload_digest,
)
from a4diag.policy_engine import PolicyAuthorization


KEY = b"k" * 32
POLICY_KEY = b"p" * 32
POLICY_AUTHORIZATION_PREFIX = b"a4diag-policy-authorization-v1\x00"


class MemoryReplayStore:
    def __init__(self) -> None:
        self.consumed: set[str] = set()
        self.calls: list[str] = []

    def consume(self, ticket_id: str) -> bool:
        self.calls.append(ticket_id)
        if ticket_id in self.consumed:
            return False
        self.consumed.add(ticket_id)
        return True


def make_operation(**overrides: object) -> Operation:
    values: dict[str, object] = {
        "capability": "files",
        "action": "replace",
        "resource": "/etc/example/app.conf",
        "parameters": {"content": "ok"},
        "model_risk": Risk.LOW,
        "verify": {"content_sha256": "a" * 64},
        "undo": {"restore_backup": True},
    }
    values.update(overrides)
    return Operation.model_validate(values)


def make_request(**overrides: object) -> OperationTicketRequest:
    values: dict[str, object] = {
        "transaction_id": "tx-1",
        "step_id": "step-1",
        "target_id": "lab",
        "target_fingerprint": "machine-1",
        "operation": make_operation(),
        "phase": OperationPhase.APPLY,
        "plan_digest": "a" * 64,
        "risk": Risk.LOW,
        "approval_id": None,
        "ttl_seconds": 30,
    }
    values.update(overrides)
    return OperationTicketRequest.model_validate(values)


def expectation_for(
    request: OperationTicketRequest, **overrides: object
) -> OperationTicketExpectation:
    values: dict[str, object] = {
        "transaction_id": request.transaction_id,
        "step_id": request.step_id,
        "target_id": request.target_id,
        "target_fingerprint": request.target_fingerprint,
        "operation": request.operation,
        "phase": request.phase,
        "plan_digest": request.plan_digest,
        "risk": request.risk,
        "approval_id": request.approval_id,
        "effect_payload_digest": request.effect_payload_digest,
    }
    values.update(overrides)
    return OperationTicketExpectation.model_validate(values)


def make_issuer(*, now: int = 100) -> TicketIssuer:
    return TicketIssuer(
        KEY,
        authorization_key=POLICY_KEY,
        clock=lambda: now,
        ticket_id_factory=lambda: "ticket-1",
    )


def operation_digest(operation: Operation) -> str:
    encoded = json.dumps(
        operation.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def authorization_for(
    request: OperationTicketRequest,
    *,
    operation_digests: tuple[str, ...] | None = None,
    **overrides: object,
) -> PolicyAuthorization:
    values: dict[str, object] = {
        "target_id": request.target_id,
        "target_fingerprint": request.target_fingerprint,
        "plan_digest": request.plan_digest,
        "risk": request.risk,
        "approval_id": request.approval_id,
        "operation_digests": operation_digests
        or (operation_digest(request.operation),),
    }
    values.update(overrides)
    payload = json.dumps(
        {
            **values,
            "risk": Risk(values["risk"]).value,
            "operation_digests": list(values["operation_digests"]),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    values["mac"] = hmac.new(
        POLICY_KEY,
        POLICY_AUTHORIZATION_PREFIX + payload,
        hashlib.sha256,
    ).hexdigest()
    return PolicyAuthorization.model_validate(values)


def issue_request(
    request: OperationTicketRequest,
    *,
    authorization: PolicyAuthorization | None = None,
    now: int = 100,
) -> str:
    return make_issuer(now=now).issue(
        request,
        authorization or authorization_for(request),
    )


def make_verifier(
    replay: MemoryReplayStore, *, now: int = 110
) -> TicketVerifier:
    return TicketVerifier(KEY, replay, clock=lambda: now)


def test_ticket_contains_full_canonical_operation_bound_claims() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request)

    claims = make_verifier(replay).verify(token, expectation_for(request))

    expected_parameters_digest = hashlib.sha256(b'{"content":"ok"}').hexdigest()
    assert claims.ticket_id == "ticket-1"
    assert claims.transaction_id == "tx-1"
    assert claims.step_id == "step-1"
    assert claims.target_id == "lab"
    assert claims.target_fingerprint == "machine-1"
    assert claims.capability == "files"
    assert claims.action == "replace"
    assert claims.resource == "/etc/example/app.conf"
    assert claims.phase is OperationPhase.APPLY
    assert claims.parameters_digest == expected_parameters_digest
    assert claims.operation_digest == operation_digest(request.operation)
    assert claims.effect_payload_digest == effect_payload_digest({})
    assert claims.plan_digest == "a" * 64
    assert claims.risk is Risk.LOW
    assert claims.approval_id is None
    assert claims.issued_at == 100
    assert claims.expires_at == 130

    payload_segment, signature_segment = token.split(".")
    assert "=" not in payload_segment
    assert "=" not in signature_segment
    payload = base64.urlsafe_b64decode(payload_segment + "==")
    assert payload == json.dumps(
        json.loads(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_ticket_is_single_use() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    verifier = make_verifier(replay)
    token = issue_request(request)
    expected = expectation_for(request)

    verifier.verify(token, expected)

    with pytest.raises(TicketError, match="replay") as caught:
        verifier.verify(token, expected)
    assert caught.value.code == "replay"


@pytest.mark.parametrize("phase", [OperationPhase.PREPARE, OperationPhase.UNDO])
def test_ticket_is_bound_to_effect_phase(phase: OperationPhase) -> None:
    request = make_request(phase=phase)
    token = issue_request(request)
    replay = MemoryReplayStore()

    with pytest.raises(TicketError) as caught:
        make_verifier(replay).verify(
            token,
            expectation_for(request, phase=OperationPhase.APPLY),
        )

    assert caught.value.code == "phase_mismatch"
    assert replay.calls == []


def test_replay_store_false_has_a_stable_replay_error() -> None:
    class RejectingReplayStore:
        def consume(self, ticket_id: str) -> bool:
            return False

    request = make_request()
    token = issue_request(request)
    verifier = TicketVerifier(KEY, RejectingReplayStore(), clock=lambda: 110)

    with pytest.raises(TicketError, match="replay") as caught:
        verifier.verify(token, expectation_for(request))

    assert caught.value.code == "replay"


def test_expired_ticket_does_not_burn_an_otherwise_valid_ticket() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request)
    expected = expectation_for(request)

    with pytest.raises(TicketError, match="expired") as caught:
        make_verifier(replay, now=130).verify(token, expected)

    assert caught.value.code == "expired"
    assert replay.calls == []
    claims = make_verifier(replay, now=129).verify(token, expected)
    assert claims.ticket_id == "ticket-1"


def test_future_ticket_is_rejected_without_replay_consumption() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request, now=100)

    with pytest.raises(TicketError, match="not_yet_valid") as caught:
        make_verifier(replay, now=99).verify(token, expectation_for(request))

    assert caught.value.code == "not_yet_valid"
    assert replay.calls == []


def test_invalid_signature_does_not_consume_ticket() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request)
    payload, signature = token.split(".")
    replacement = "A" if signature[-1] != "A" else "B"
    tampered = f"{payload}.{signature[:-1]}{replacement}"

    with pytest.raises(TicketError, match="signature") as caught:
        make_verifier(replay).verify(tampered, expectation_for(request))

    assert caught.value.code == "invalid_signature"
    assert replay.calls == []
    make_verifier(replay).verify(token, expectation_for(request))


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"transaction_id": "tx-2"}, "transaction_mismatch"),
        ({"step_id": "step-2"}, "step_mismatch"),
        ({"target_id": "other"}, "target_mismatch"),
        ({"target_fingerprint": "machine-2"}, "target_mismatch"),
        ({"operation": make_operation(resource="/etc/example/other.conf")}, "operation_mismatch"),
        ({"operation": make_operation(parameters={"content": "changed"})}, "operation_mismatch"),
        ({"operation": make_operation(capability="services")}, "operation_mismatch"),
        ({"operation": make_operation(action="remove")}, "operation_mismatch"),
        ({"operation": make_operation(model_risk=Risk.HIGH)}, "operation_mismatch"),
        ({"operation": make_operation(verify={"different": True})}, "operation_mismatch"),
        ({"operation": make_operation(undo={"different": True})}, "operation_mismatch"),
        ({"operation": make_operation(timeout_seconds=21)}, "operation_mismatch"),
        ({"operation": make_operation(output_limit_bytes=1024)}, "operation_mismatch"),
        ({"effect_payload_digest": effect_payload_digest({"marker": {"id": "changed"}})}, "effect_payload_mismatch"),
        ({"plan_digest": "b" * 64}, "plan_mismatch"),
        ({"risk": Risk.HIGH, "approval_id": "approval-2"}, "risk_mismatch"),
        ({"approval_id": "approval-2"}, "approval_mismatch"),
    ],
)
def test_binding_mismatch_is_rejected_before_replay_consumption(
    override: dict[str, object], code: str
) -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request)
    expected = expectation_for(request, **override)

    with pytest.raises(TicketError) as caught:
        make_verifier(replay).verify(token, expected)

    assert caught.value.code == code
    assert replay.calls == []
    make_verifier(replay).verify(token, expectation_for(request))


def test_noncanonical_base64url_is_rejected_without_consuming_ticket() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request)
    payload, signature = token.split(".")

    with pytest.raises(TicketError, match="malformed") as caught:
        make_verifier(replay).verify(
            f"{payload}=.{signature}", expectation_for(request)
        )

    assert caught.value.code == "malformed_token"
    assert replay.calls == []


def test_signed_noncanonical_payload_is_rejected_without_consuming_ticket() -> None:
    request = make_request()
    replay = MemoryReplayStore()
    token = issue_request(request)
    payload_segment, _signature_segment = token.split(".")
    payload = base64.urlsafe_b64decode(payload_segment + "==")
    noncanonical_payload = b" " + payload
    signature = hmac.new(KEY, noncanonical_payload, hashlib.sha256).digest()
    forged = (
        base64.urlsafe_b64encode(noncanonical_payload).rstrip(b"=").decode("ascii")
        + "."
        + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    )

    with pytest.raises(TicketError, match="invalid_claims") as caught:
        make_verifier(replay).verify(forged, expectation_for(request))

    assert caught.value.code == "invalid_claims"
    assert replay.calls == []


def test_high_ticket_requires_nonblank_approval_id() -> None:
    with pytest.raises(ValidationError, match="approval_id"):
        make_request(risk=Risk.HIGH, approval_id="   ")


def test_high_ticket_with_nonblank_approval_is_issued_and_verified() -> None:
    request = make_request(risk=Risk.HIGH, approval_id="approval-1")
    replay = MemoryReplayStore()

    claims = make_verifier(replay).verify(
        issue_request(request), expectation_for(request)
    )

    assert claims.risk is Risk.HIGH
    assert claims.approval_id == "approval-1"


def test_forged_policy_authorization_is_rejected_before_ticket_signing() -> None:
    request = make_request()
    forged = authorization_for(request).model_copy(update={"mac": "0" * 64})

    with pytest.raises(TicketError, match="authorization") as caught:
        make_issuer().issue(request, forged)

    assert caught.value.code == "invalid_authorization"


def test_missing_policy_authorization_mac_is_rejected_before_ticket_signing() -> None:
    request = make_request()
    missing_mac = authorization_for(request).model_copy(update={"mac": ""})

    with pytest.raises(TicketError, match="authorization") as caught:
        make_issuer().issue(request, missing_mac)

    assert caught.value.code == "invalid_authorization"


@pytest.mark.parametrize(
    ("authorization_override", "code"),
    [
        ({"target_id": "other"}, "authorization_target_mismatch"),
        ({"target_fingerprint": "machine-2"}, "authorization_target_mismatch"),
        ({"plan_digest": "b" * 64}, "authorization_plan_mismatch"),
        (
            {"risk": Risk.HIGH, "approval_id": "approval-1"},
            "authorization_risk_mismatch",
        ),
        ({"operation_digests": ("b" * 64,)}, "operation_not_authorized"),
    ],
)
def test_ticket_issuer_rejects_policy_authorization_binding_mismatch(
    authorization_override: dict[str, object], code: str
) -> None:
    request = make_request()
    authorization = authorization_for(request, **authorization_override)

    with pytest.raises(TicketError) as caught:
        make_issuer().issue(request, authorization)

    assert caught.value.code == code


@pytest.mark.parametrize("ttl", [0, 301])
def test_ticket_ttl_is_limited_to_one_through_three_hundred_seconds(ttl: int) -> None:
    with pytest.raises(ValidationError, match="ttl_seconds"):
        make_request(ttl_seconds=ttl)


def test_hmac_key_must_be_at_least_thirty_two_bytes() -> None:
    replay = MemoryReplayStore()

    with pytest.raises(TicketError, match="key") as issuer_error:
        TicketIssuer(b"short", authorization_key=POLICY_KEY)
    with pytest.raises(TicketError, match="key") as authorization_error:
        TicketIssuer(KEY, authorization_key=b"short")
    with pytest.raises(TicketError, match="key") as verifier_error:
        TicketVerifier(b"short", replay)

    assert issuer_error.value.code == "invalid_key"
    assert authorization_error.value.code == "invalid_key"
    assert verifier_error.value.code == "invalid_key"


def test_ticket_models_are_frozen_and_reject_unknown_fields() -> None:
    request = make_request()
    token = issue_request(request)
    claims = make_verifier(MemoryReplayStore()).verify(token, expectation_for(request))

    with pytest.raises(ValidationError):
        request.target_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        claims.target_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="surprise"):
        OperationTicketRequest.model_validate(
            {**request.model_dump(), "surprise": True}
        )

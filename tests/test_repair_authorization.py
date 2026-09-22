from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import (
    Operation,
    RepairBinding,
    Risk,
    TargetConfig,
    TargetMode,
    canonical_json_bytes,
)
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketExpectationV11,
    OperationTicketRequestV11,
    TicketError,
    TicketIssuer,
    TicketVerifier,
)
from a4diag.policy_engine import (
    bind_repair_preconditions,
    issue_repair_policy_authorization,
    repair_policy_authorization_is_authentic,
)
from a4diag.plugin_api.target_protocol import TargetRequestV11, TargetSigner
from a4diag.plugin_ports import _RpcExecutorPort
from a4diag.recovery import RecoveryCheck
from a4diag.repair_profiles import (
    RepairAuthorizationError,
    RepairProfile,
    authorize_profile,
    profile_digest,
)


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


def test_authorize_profile_returns_exact_unprepared_binding() -> None:
    profile = _profile()

    binding = authorize_profile(
        profile,
        _operation(),
        now=199,
        presented_digest=profile_digest(profile),
    )

    assert binding == RepairBinding(
        profile_id="web",
        profile_digest=profile_digest(profile),
        preconditions_digest=None,
    )


@pytest.mark.parametrize(
    ("profile_changes", "operation_changes", "now", "digest", "code"),
    (
        ({}, {}, 200, None, "profile_expired"),
        ({}, {}, 100, "0" * 64, "profile_digest_mismatch"),
        ({}, {"capability": "files"}, 100, None, "profile_capability_mismatch"),
        ({}, {"resource": "other.service"}, 100, None, "profile_resource_mismatch"),
        ({}, {"action": "start"}, 100, None, "profile_action_not_allowed"),
        ({}, {"model_risk": Risk.LOW}, 100, None, "risk_downgrade"),
        ({}, {"parameters": {}}, 100, None, "profile_parameters_mismatch"),
        (
            {},
            {"parameters": {"unit": "demo.service", "authorization_id": "web"}},
            100,
            None,
            "profile_parameters_mismatch",
        ),
        (
            {},
            {"verify": {"recovery_check_ids": ["other"]}},
            100,
            None,
            "recovery_checks_mismatch",
        ),
    ),
)
def test_authorize_profile_fails_closed(
    profile_changes: dict[str, object],
    operation_changes: dict[str, object],
    now: int,
    digest: str | None,
    code: str,
) -> None:
    profile = _profile(**profile_changes)
    with pytest.raises(RepairAuthorizationError) as caught:
        authorize_profile(
            profile,
            _operation(**operation_changes),
            now=now,
            presented_digest=digest or profile_digest(profile),
        )
    assert caught.value.code == code


@pytest.mark.parametrize("now", (True, -1))
def test_authorize_profile_requires_a_nonnegative_strict_integer_clock(now: object) -> None:
    profile = _profile()
    with pytest.raises(RepairAuthorizationError) as caught:
        authorize_profile(
            profile,
            _operation(),
            now=now,  # type: ignore[arg-type]
            presented_digest=profile_digest(profile),
        )
    assert caught.value.code == "invalid_clock"


class _Replay:
    def __init__(self) -> None:
        self.values: set[str] = set()

    def consume(self, ticket_id: str) -> bool:
        if ticket_id in self.values:
            return False
        self.values.add(ticket_id)
        return True


def test_v11_ticket_binds_profile_and_standing_authorization_end_to_end() -> None:
    profile = _profile()
    operation = _operation()
    authorization = issue_repair_policy_authorization(
        profile,
        operation,
        target_fingerprint="sha256:" + "a" * 64,
        plan_digest="b" * 64,
        authorization_kind="standing",
        authorization_id="web",
        now=100,
        key=b"p" * 32,
    )
    request = OperationTicketRequestV11(
        transaction_id="tx-1",
        step_id="0",
        target_id="demo",
        target_fingerprint="sha256:" + "a" * 64,
        operation=operation,
        phase=OperationPhase.PREPARE,
        plan_digest="b" * 64,
        risk=Risk.HIGH,
        binding=authorization.binding,
        authorization_kind="standing",
        authorization_id="web",
    )
    token = TicketIssuer(
        b"t" * 32,
        authorization_key=b"p" * 32,
        clock=lambda: 100,
        ticket_id_factory=lambda: "ticket-1",
    ).issue(request, authorization)

    verifier = TicketVerifier(b"t" * 32, _Replay(), clock=lambda: 110)
    expected = OperationTicketExpectationV11(
        **request.model_dump(mode="python", exclude={"ttl_seconds"})
    )
    claims = verifier.verify(token, expected)

    assert claims.protocol_version == "1.1"
    assert claims.binding == authorization.binding
    assert claims.authorization_kind == "standing"
    assert claims.authorization_id == "web"
    assert claims.risk is Risk.HIGH
    with pytest.raises(TicketError, match="replay"):
        verifier.verify(token, expected)


def test_v11_ticket_rejects_cross_profile_authorization_before_signing() -> None:
    profile = _profile()
    operation = _operation()
    authorization = issue_repair_policy_authorization(
        profile,
        operation,
        target_fingerprint="sha256:" + "a" * 64,
        plan_digest="b" * 64,
        authorization_kind="standing",
        authorization_id="web",
        now=100,
        key=b"p" * 32,
    )
    request = OperationTicketRequestV11(
        transaction_id="tx-1",
        step_id="0",
        target_id="demo",
        target_fingerprint="sha256:" + "a" * 64,
        operation=operation,
        phase=OperationPhase.PREPARE,
        plan_digest="b" * 64,
        risk=Risk.HIGH,
        binding=RepairBinding(
            profile_id="other",
            profile_digest="0" * 64,
            preconditions_digest=None,
        ),
        authorization_kind="standing",
        authorization_id="web",
    )
    with pytest.raises(TicketError) as caught:
        TicketIssuer(
            b"t" * 32,
            authorization_key=b"p" * 32,
            clock=lambda: 100,
        ).issue(request, authorization)
    assert caught.value.code == "authorization_profile_mismatch"


class _RecordingTarget:
    def __init__(self) -> None:
        self.params: dict[str, object] | None = None

    async def call(
        self, method: str, params: dict[str, object], *, ticket: str | None = None
    ) -> dict[str, object]:
        assert method == "prepare_typed"
        assert ticket is not None
        self.params = params
        return {
            "ok": True,
            "data": {"result": {"marker": {"unit": "demo.service"}}},
        }


def test_rpc_port_dispatches_v11_from_ticket_without_hiding_metadata_in_parameters() -> None:
    profile = _profile()
    operation = _operation()
    authorization = issue_repair_policy_authorization(
        profile,
        operation,
        target_fingerprint="sha256:" + "a" * 64,
        plan_digest="b" * 64,
        authorization_kind="standing",
        authorization_id="web",
        now=100,
        key=b"p" * 32,
    )
    request = OperationTicketRequestV11(
        transaction_id="tx-1",
        step_id="0",
        target_id="demo",
        target_fingerprint="sha256:" + "a" * 64,
        operation=operation,
        phase=OperationPhase.PREPARE,
        plan_digest="b" * 64,
        risk=Risk.HIGH,
        binding=authorization.binding,
        authorization_kind="standing",
        authorization_id="web",
    )
    ticket = TicketIssuer(
        b"t" * 32,
        authorization_key=b"p" * 32,
        clock=lambda: 100,
        ticket_id_factory=lambda: "ticket-1",
    ).issue(request, authorization)
    target_client = _RecordingTarget()
    signer = TargetSigner(Ed25519PrivateKey.generate())
    port = _RpcExecutorPort(
        {"demo": target_client},
        signer_resolver=lambda _target: signer,
        clock=lambda: 100,
        nonce_factory=lambda: "nonce-rpc-port-001",
    )
    port.bind_transaction("tx-1")
    target = TargetConfig(
        id="demo",
        mode=TargetMode.LOCAL,
        identity_ref="target/demo",
        identity_fingerprint="sha256:" + "a" * 64,
        repair_profiles=(profile,),
        recovery_checks=(
            RecoveryCheck(
                id="health", kind="service_active", resource="demo.service"
            ),
        ),
    )

    port.prepare(target, "0", operation, ticket)

    assert target_client.params is not None
    envelope = target_client.params["envelope"]
    assert isinstance(envelope, dict)
    target_request = TargetRequestV11.model_validate_json(envelope["payload"])
    assert target_request.binding == authorization.binding
    assert target_request.authorization_id == "web"
    assert target_request.operation.parameters == {"unit": "demo.service"}


def test_prepare_marker_is_digest_bound_before_apply_ticket_issuance() -> None:
    profile = _profile()
    operation = _operation()
    authorization = issue_repair_policy_authorization(
        profile,
        operation,
        target_fingerprint="sha256:" + "a" * 64,
        plan_digest="b" * 64,
        authorization_kind="standing",
        authorization_id="web",
        now=100,
        key=b"p" * 32,
    )
    marker = {"unit": "demo.service", "invocation_id": "before"}

    bound = bind_repair_preconditions(authorization, marker, key=b"p" * 32)

    assert bound.binding.preconditions_digest == hashlib.sha256(
        canonical_json_bytes(marker)
    ).hexdigest()
    assert repair_policy_authorization_is_authentic(bound, b"p" * 32)
    assert authorization.binding.preconditions_digest is None

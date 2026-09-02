from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import Operation, Risk, TargetConfig, TargetMode, canonical_json_bytes
from a4diag.plugin_api.target_protocol import TargetRequest, TargetSigner
from a4diag.plugin_api.ticket import OperationPhase, OperationTicket, effect_payload_digest
from a4diag.plugin_ports import _RpcExecutorPort


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object], str | None]] = []

    async def call(self, method: str, params: dict[str, object], *, ticket: str | None = None) -> dict[str, object]:
        self.calls.append((method, params, ticket))
        if method == "prepare_typed":
            result: dict[str, object] = {"marker": {"before_sha256": "b" * 64}}
        elif method == "reconcile_typed":
            result = {"state": "applied", "data": {}}
        else:
            result = {"ok": True, "changed": method in {"apply_typed", "undo_typed"}, "data": {}}
        return {"ok": True, "status": "applied", "data": {"result": result}}


def operation(risk: Risk = Risk.LOW) -> Operation:
    return Operation(
        capability="files", action="replace_managed_file", resource="/srv/lab/config",
        parameters={"content": "new"}, model_risk=risk,
        verify={"sha256": "0" * 64}, undo={"restore": True},
    )


def ticket(operation: Operation, *, phase: OperationPhase, effect: dict[str, object], approval_id: str | None = None) -> str:
    claims = OperationTicket(
        ticket_id=f"ticket-{phase.value}", transaction_id="tx-1", step_id="0",
        target_id="lab", target_fingerprint="sha256:" + "a" * 64,
        capability=operation.capability, action=operation.action, resource=operation.resource,
        phase=phase, parameters_digest=__import__("hashlib").sha256(canonical_json_bytes(operation.parameters)).hexdigest(),
        operation_digest=__import__("a4diag.policy_engine", fromlist=["canonical_operation_digest"]).canonical_operation_digest(operation),
        effect_payload_digest=effect_payload_digest(effect), plan_digest="c" * 64,
        risk=operation.model_risk, approval_id=approval_id, issued_at=100, expires_at=130,
    )
    payload = canonical_json_bytes(claims.model_dump(mode="json"))
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    return encoded + "." + base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode("ascii")


def target(target_id: str = "lab") -> TargetConfig:
    return TargetConfig(
        id=target_id, mode=TargetMode.SSH, identity_ref=f"target/{target_id}",
        transport=f"transport-{target_id}", host="sandbox.invalid", port=22,
        user="a4diag-target", write_enabled=True,
    )


def test_ssh_target_routes_complete_lifecycle_to_its_transport() -> None:
    transport = RecordingTransport()
    signer = TargetSigner(Ed25519PrivateKey.generate())
    port = _RpcExecutorPort(
        {"lab": transport}, signer_resolver=lambda selected: signer,
        clock=lambda: 100, nonce_factory=iter((f"nonce-{index:011d}" for index in range(10))).__next__,
    )
    port.bind_transaction("tx-1")
    op = operation()
    prepared = port.prepare(target(), "0", op, ticket(op, phase=OperationPhase.PREPARE, effect={}))
    marker = prepared.marker
    port.apply(target(), "0", op, marker, ticket(op, phase=OperationPhase.APPLY, effect={"marker": marker}))
    port.verify(target(), "0", op, marker)
    port.reconcile(target(), "0", op, OperationPhase.APPLY, "dispatch-1", marker)
    port.undo(target(), "0", op, marker, op.undo, ticket(op, phase=OperationPhase.UNDO, effect={"marker": marker, "undo": op.undo}))

    assert [call[0] for call in transport.calls] == [
        "prepare_typed", "apply_typed", "verify_typed", "reconcile_typed", "undo_typed"
    ]
    for method, params, _ticket in transport.calls:
        request = TargetRequest.model_validate_json(params["envelope"]["payload"])
        assert request.target_id == "lab"
        assert request.transaction_id == "tx-1"
        assert request.step_id == "0"
        assert request.lifecycle.value == method.removesuffix("_typed")
    undo_request = TargetRequest.model_validate_json(transport.calls[-1][1]["envelope"]["payload"])
    assert undo_request.effect_payload_digest == effect_payload_digest({"marker": marker, "undo": op.undo})


def test_transport_is_target_bound_and_unknown_target_has_zero_dispatch() -> None:
    transport = RecordingTransport()
    port = _RpcExecutorPort(
        {"lab": transport}, signer_resolver=lambda selected: TargetSigner(Ed25519PrivateKey.generate()),
        clock=lambda: 100, nonce_factory=lambda: "nonce-00000000001",
    )
    port.bind_transaction("tx-1")
    op = operation()
    try:
        port.prepare(target("other"), "0", op, ticket(op, phase=OperationPhase.PREPARE, effect={}))
    except Exception as error:
        assert "transport" in str(error) or "target" in str(error)
    else:
        raise AssertionError("unregistered target transport must fail closed")
    assert transport.calls == []

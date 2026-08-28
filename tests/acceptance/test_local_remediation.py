"""Local remediation acceptance: LOW auto-repair, isolation, fail-closed.

No real server, SSH, mail, model, or FlashDuty connection is made; every
"machine" is an injected fake whose connections are recorded in the ledger.
"""

from __future__ import annotations

import os

import pytest

from a4diag.domain import Risk


def test_low_service_fault_is_repaired_and_verified(lab_factory) -> None:
    lab = lab_factory()

    result = lab.run_agent()

    assert result.status == "succeeded"
    assert lab.service_is_healthy()
    assert lab.outside_canary_unchanged()


def test_outside_target_is_never_contacted(lab_factory) -> None:
    lab = lab_factory()

    result = lab.run_agent(target_id="unregistered")

    assert result.status == "policy_denied"
    assert lab.executor.apply_count == 0
    assert lab.ledger.connections_to("unregistered", "10.0.0.99") == 0
    assert lab.ledger.total_connections == 0


def test_identity_drift_blocks_write_revalidation(lab_factory) -> None:
    lab = lab_factory(identity_drift=True)

    result = lab.run_agent()

    # The write path re-probes identity and must refuse when it drifted.
    assert result.status != "succeeded"
    assert lab.executor.apply_count == 0


def test_unknown_execution_is_never_replayed(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.break_on_apply = RuntimeError("executor crashed")

    first = lab.run_agent()
    assert first.status == "execution_unknown"
    assert lab.executor.apply_count == 1

    resumed = lab.resume(first.transaction_id or "evt-1")
    assert lab.executor.apply_count == 1  # never re-applied
    assert resumed.status in {"execution_unknown", "failed", "rollback_running"}


def test_model_timeout_fails_closed_without_executor(lab_factory) -> None:
    lab = lab_factory(model_error=TimeoutError("model timeout"))

    result = lab.run_agent()

    assert result.status == "read_only_no_model"
    assert lab.executor.apply_count == 0
    assert lab.ledger.connections_to("apply") == 0


def test_network_drop_fails_closed_without_executor(lab_factory) -> None:
    lab = lab_factory(collect_error=ConnectionError("network dropped"))

    result = lab.run_agent()

    assert result.status == "failed"
    assert lab.executor.apply_count == 0


def test_consumed_ticket_cannot_be_reused(lab_factory) -> None:
    """Replay protection: a ticket is consumed exactly once (fail-closed)."""
    import tempfile
    from pathlib import Path

    from a4diag.domain import Plan
    from a4diag.plugin_api.ticket import (
        OperationPhase,
        OperationTicketExpectation,
        OperationTicketRequest,
        TicketIssuer,
        TicketVerifier,
        effect_payload_digest,
    )
    from a4diag.transaction_store import TransactionStore

    lab = lab_factory()
    target = lab.runtime.settings.targets[0]
    operation = lab.runtime.plugins.model.plan(target, [], {}).operations[0]
    policy = lab.runtime._deps.policy
    candidate = Plan(
        target_id=lab.target_id,
        target_fingerprint="machine-1",
        operations=(operation,),
    )
    authorization = policy.evaluate(
        target, candidate, critic_risk=Risk.LOW, approval_digest=None, approval_id=None
    ).authorization
    assert authorization is not None

    issuer = TicketIssuer(
        lab.ticket_key,
        authorization_key=lab.runtime._deps.policy._authorization_key,
        clock=lambda: 1_700_000_000,
    )
    request = OperationTicketRequest(
        transaction_id="tx-1",
        step_id="0",
        target_id=lab.target_id,
        target_fingerprint="machine-1",
        operation=operation,
        phase=OperationPhase.APPLY,
        plan_digest=authorization.plan_digest,
        risk=Risk.LOW,
        approval_id=None,
        effect_payload_digest=effect_payload_digest({}),
        ttl_seconds=30,
    )
    token = issuer.issue(request, authorization)

    ticket_store = TransactionStore(Path(tempfile.mkdtemp()) / "replay.sqlite3")
    verifier = TicketVerifier(
        lab.ticket_key, replay_store=ticket_store, clock=lambda: 1_700_000_000
    )
    expectation = OperationTicketExpectation(
        transaction_id="tx-1",
        step_id="0",
        target_id=lab.target_id,
        target_fingerprint="machine-1",
        operation=operation,
        phase=OperationPhase.APPLY,
        plan_digest=authorization.plan_digest,
        risk=Risk.LOW,
        approval_id=None,
        effect_payload_digest=effect_payload_digest({}),
    )
    assert verifier.verify(token, expectation) is not None
    # Replaying the same ticket must be refused.
    with pytest.raises(Exception):
        verifier.verify(token, expectation)


@pytest.mark.live_t11
def test_live_t11_sandbox_scenario_is_staged_but_not_executed(lab_factory) -> None:
    """The isolated t_11 sandbox scenario runs only with explicit opt-in.

    This environment never connects to the real t_11 sandbox; with
    A4DIAG_ACCEPTANCE=1 a real disposable environment would be provisioned.
    """
    if os.environ.get("A4DIAG_ACCEPTANCE") != "1":
        pytest.skip("live t_11 sandbox scenario requires A4DIAG_ACCEPTANCE=1")
    lab = lab_factory()
    result = lab.run_agent()
    assert result.status == "succeeded"

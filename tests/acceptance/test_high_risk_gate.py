"""High-risk gate acceptance: HIGH never executes without CLI approval, wrong
or stale digests stay blocked, and a high-risk operation stays HIGH even when
the model claims LOW."""

from __future__ import annotations

from a4diag.approvals import ApprovalDigestMismatchError
from a4diag.domain import Risk


def _approve(lab, transaction_id: str, *, digest: str | None = None) -> None:
    record = lab.approvals.for_transaction(transaction_id)
    assert record is not None, "approval record missing"
    lab.approvals.approve(
        record.id,
        approved_digest=digest if digest is not None else record.plan_digest,
        actor="acceptance:operator",
        now=1_700_000_001,
    )


def test_high_without_approval_has_zero_dispatch(lab_factory) -> None:
    lab = lab_factory(model_risk=Risk.HIGH)

    result = lab.run_agent()

    assert result.status == "pending_approval"
    assert lab.executor.apply_count == 0
    assert lab.notifier.send_count == 1


def test_wrong_digest_approval_remains_blocked(lab_factory) -> None:
    lab = lab_factory(model_risk=Risk.HIGH)

    result = lab.run_agent()
    assert result.status == "pending_approval"

    record = lab.approvals.for_transaction("evt-1")
    assert record is not None
    try:
        lab.approvals.approve(
            record.id,
            approved_digest="0" * 64,
            actor="acceptance:operator",
            now=1_700_000_001,
        )
        raise AssertionError("wrong digest was accepted")
    except ApprovalDigestMismatchError:
        pass

    resumed = lab.resume("evt-1")
    assert resumed.status == "pending_approval"
    assert lab.executor.apply_count == 0


def test_correct_local_cli_approval_dispatches_once(lab_factory) -> None:
    lab = lab_factory(model_risk=Risk.HIGH)

    first = lab.run_agent()
    assert first.status == "pending_approval"

    _approve(lab, "evt-1")
    resumed = lab.resume("evt-1")

    assert resumed.status == "succeeded"
    assert lab.executor.apply_count == 1


def test_changed_target_identity_after_approval_invalidates_it(lab_factory) -> None:
    lab = lab_factory(model_risk=Risk.HIGH)

    first = lab.run_agent()
    assert first.status == "pending_approval"

    _approve(lab, "evt-1")
    lab.collector.identity_drift = True  # target identity changed after approval
    resumed = lab.resume("evt-1")

    assert resumed.status == "policy_denied"
    assert lab.executor.apply_count == 0


def test_high_floor_operation_stays_high_when_model_says_low(lab_factory) -> None:
    lab = lab_factory(operation_risk_floor="high", model_risk=Risk.LOW)

    result = lab.run_agent()

    # The plugin's risk floor keeps the operation HIGH regardless of the model.
    assert result.status == "pending_approval"
    assert lab.executor.apply_count == 0

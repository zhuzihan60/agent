"""Plugin chaos acceptance: crash at every phase fails closed, reconciles from
the dispatch intent, and never replays an unknown effect."""

from __future__ import annotations


def test_crash_before_dispatch_reconciles_without_replay(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.break_on_apply = ConnectionError("dispatch lost")

    first = lab.run_agent()
    assert first.status == "execution_unknown"
    assert lab.executor.apply_count == 1

    lab.executor.break_on_apply = None
    lab.executor.reconcile_outcome = "not_applied"
    resumed = lab.resume(first.transaction_id or "evt-1")

    assert lab.executor.apply_count == 1  # never re-applied
    assert lab.executor.reconcile_count == 1
    assert resumed.status == "failed"


def test_crash_after_apply_effect_reconciles_to_applied(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.crash_after_apply = RuntimeError("crashed after effect")

    first = lab.run_agent()
    assert first.status == "execution_unknown"
    assert lab.executor.apply_count == 1

    lab.executor.crash_after_apply = None
    lab.executor.reconcile_outcome = "applied"
    resumed = lab.resume(first.transaction_id or "evt-1")

    assert lab.executor.apply_count == 1
    assert resumed.status == "succeeded"


def test_crash_during_prepare_never_reprepares(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.prepare_crash = RuntimeError("crashed during prepare")

    first = lab.run_agent()
    assert first.status == "execution_unknown"
    assert lab.executor.prepare_count == 1

    lab.executor.prepare_crash = None
    lab.executor.reconcile_outcome = "not_applied"
    resumed = lab.resume(first.transaction_id or "evt-1")

    assert lab.executor.prepare_count == 1
    assert lab.executor.apply_count == 0
    assert resumed.status == "failed"


def test_verify_failure_triggers_reverse_rollback(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.verify_fail_step = "0"

    result = lab.run_agent()

    assert result.status == "rollback_succeeded"
    assert lab.executor.undo_order == [0]
    assert lab.outside_canary_unchanged()


def test_undo_crash_reports_rollback_unknown_truthfully(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.verify_fail_step = "0"
    lab.executor.undo_fail = RuntimeError("undo crashed")

    result = lab.run_agent()

    assert result.status in {"rollback_unknown", "execution_unknown"}
    assert lab.executor.undo_order == [0]
    assert lab.outside_canary_unchanged()


def test_network_loss_during_apply_fails_closed(lab_factory) -> None:
    lab = lab_factory()
    lab.executor.break_on_apply = TimeoutError("ssh timed out")

    first = lab.run_agent()
    assert first.status == "execution_unknown"
    assert lab.executor.apply_count == 1

    lab.executor.break_on_apply = None
    lab.executor.reconcile_outcome = "unknown"
    resumed = lab.resume(first.transaction_id or "evt-1")

    # An unknowable outcome stops; it is never retried automatically.
    assert lab.executor.apply_count == 1
    assert resumed.status == "execution_unknown"

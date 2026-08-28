from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from a4diag.transaction_store import (
    ALLOWED_TRANSITIONS,
    DispatchStatus,
    EffectPhase,
    GlobalWriteLimitError,
    InvalidTransitionError,
    PreparedStep,
    RecoveryAction,
    TargetBusyError,
    TransactionStatus,
    TransactionStore,
    UnknownTransactionError,
)


DIGEST = "a" * 64


def make_store(path: object, *, limit: int = 2) -> TransactionStore:
    return TransactionStore(
        path, max_concurrent_targets=limit  # type: ignore[arg-type]
    )


def prepared_step(step_id: str = "0") -> PreparedStep:
    return PreparedStep(
        step_id=step_id,
        operation_json='{"action":"replace","resource":"/etc/app.conf"}',
        pre_state_json='{"content":"old"}',
        plugin_marker_json='{"marker":"marker-' + step_id + '"}',
    )


def plan_step(step_id: str) -> PreparedStep:
    return PreparedStep(
        step_id=step_id,
        operation_json=(
            '{"action":"replace","resource":"/etc/app-'
            + step_id
            + '.conf"}'
        ),
        pre_state_json='{"content":"old-' + step_id + '"}',
        plugin_marker_json='{"marker":"marker-' + step_id + '"}',
    )


def setup_bound_executing(path: object, *, count: int = 2) -> TransactionStore:
    store = make_store(path)
    steps = tuple(plan_step(str(index)) for index in range(count))
    store.begin(
        "tx-1",
        "target-1",
        DIGEST,
        expected_operations=tuple(step.operation_json for step in steps),
        now=10,
    )
    store.transition("tx-1", TransactionStatus.PREPARING, now=11)
    for index, step in enumerate(steps):
        dispatch = store.begin_dispatch(
            "tx-1",
            step.step_id,
            phase=EffectPhase.PREPARE,
            dispatch_id=f"prepare-{index}",
            ticket=f"ticket-{index}",
            now=12 + index * 2,
        )
        store.complete_prepare_dispatch(
            dispatch.dispatch_id, step, now=13 + index * 2
        )
    store.finish_prepared("tx-1", expected_steps=count, now=30)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=31)
    return store


def test_second_write_for_same_target_is_rejected(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)

    with pytest.raises(TargetBusyError):
        make_store(path).begin("tx-2", "target-1", "b" * 64, now=11)


def test_independent_store_objects_racing_same_target_have_one_winner(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    make_store(path)
    barrier = Barrier(2)

    def compete(transaction_id: str) -> str:
        contender = make_store(path)
        barrier.wait()
        try:
            contender.begin(transaction_id, "target-1", DIGEST, now=10)
        except TargetBusyError:
            return "busy"
        return "acquired"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(compete, ("tx-1", "tx-2")))

    assert sorted(outcomes) == ["acquired", "busy"]


def test_independent_store_objects_racing_global_limit_do_not_exceed_it(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    make_store(path, limit=2).begin("tx-existing", "target-existing", DIGEST, now=5)
    barrier = Barrier(2)

    def compete(index: int) -> str:
        contender = make_store(path, limit=2)
        barrier.wait()
        try:
            contender.begin(f"tx-{index}", f"target-{index}", DIGEST, now=10)
        except GlobalWriteLimitError:
            return "limited"
        return "acquired"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(compete, (1, 2)))

    assert sorted(outcomes) == ["acquired", "limited"]
    with sqlite3.connect(path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM target_write_locks"
        ).fetchone()[0]
    assert count == 2


def test_record_prepared_persists_all_steps_and_markers_atomically(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    steps = (prepared_step("0"), prepared_step("1"))

    prepared = store.record_prepared("tx-1", steps, now=20)

    assert prepared.status is TransactionStatus.PREPARED
    assert make_store(path).get_steps("tx-1") == steps


def test_incremental_prepare_persists_each_marker_before_next_dispatch(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.transition("tx-1", TransactionStatus.PREPARING, now=11)
    first = store.begin_dispatch(
        "tx-1", "0", phase=EffectPhase.PREPARE, dispatch_id="prepare-0", ticket="t0", now=12
    )
    store.record_prepared_step("tx-1", prepared_step("0"), now=13)
    store.complete_dispatch(first.dispatch_id, now=14)

    assert store.get_steps("tx-1") == (prepared_step("0"),)
    assert store.pending_dispatch("tx-1") is None

    second = store.begin_dispatch(
        "tx-1", "1", phase=EffectPhase.PREPARE, dispatch_id="prepare-1", ticket="t1", now=15
    )
    store.record_prepared_step("tx-1", prepared_step("1"), now=16)
    store.complete_dispatch(second.dispatch_id, now=17)
    store.finish_prepared("tx-1", expected_steps=2, now=18)

    assert store.get("tx-1").status is TransactionStatus.PREPARED
    assert store.get_steps("tx-1") == (prepared_step("0"), prepared_step("1"))


def test_complete_prepare_dispatch_atomically_persists_marker_and_is_idempotent(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.transition("tx-1", TransactionStatus.PREPARING, now=11)
    dispatch = store.begin_dispatch(
        "tx-1",
        "0",
        phase=EffectPhase.PREPARE,
        dispatch_id="prepare-0",
        ticket="t0",
        now=12,
    )

    completed = store.complete_prepare_dispatch(
        dispatch.dispatch_id, prepared_step("0"), now=13
    )
    reread = make_store(path).complete_prepare_dispatch(
        dispatch.dispatch_id, prepared_step("0"), now=99
    )

    assert completed.status is DispatchStatus.COMPLETED
    assert reread == completed
    assert make_store(path).get_steps("tx-1") == (prepared_step("0"),)
    assert make_store(path).pending_dispatch("tx-1") is None


@pytest.mark.parametrize(
    ("effect_phase", "result_phase"),
    [(EffectPhase.APPLY, "apply"), (EffectPhase.UNDO, "undo")],
)
def test_complete_result_dispatch_atomically_persists_result_and_is_idempotent(
    tmp_path: object, effect_phase: EffectPhase, result_phase: str
) -> None:
    path = tmp_path / f"{result_phase}.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=11)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=12)
    if effect_phase is EffectPhase.UNDO:
        store.transition("tx-1", TransactionStatus.ROLLBACK_RUNNING, now=13)
    dispatch = store.begin_dispatch(
        "tx-1",
        "0",
        phase=effect_phase,
        dispatch_id=f"{result_phase}-0",
        ticket="token",
        now=20,
    )

    completed = store.complete_result_dispatch(
        dispatch.dispatch_id,
        phase=result_phase,
        status="succeeded",
        payload={"ok": True},
        now=21,
    )
    reread = make_store(path).complete_result_dispatch(
        dispatch.dispatch_id,
        phase=result_phase,
        status="succeeded",
        payload={"ok": True},
        now=99,
    )

    assert completed.status is DispatchStatus.COMPLETED
    assert reread == completed
    assert make_store(path).get_results("tx-1")[0].phase == result_phase
    assert make_store(path).pending_dispatch("tx-1") is None


def test_completed_apply_without_pending_dispatch_resumes_instead_of_becoming_unknown(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=11)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=12)
    dispatch = store.begin_dispatch(
        "tx-1",
        "0",
        phase=EffectPhase.APPLY,
        dispatch_id="apply-0",
        ticket="token",
        now=20,
    )
    store.complete_result_dispatch(
        dispatch.dispatch_id,
        phase="apply",
        status="succeeded",
        payload={"ok": True},
        now=21,
    )

    action = make_store(path).next_recovery_action("tx-1", now=30)

    assert action is RecoveryAction.RESUME
    assert make_store(path).get("tx-1").status is TransactionStatus.EXECUTING


def test_executing_after_all_completed_prepares_resumes_before_first_apply(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = setup_bound_executing(path)

    action = make_store(path).next_recovery_action("tx-1", now=30)

    assert action is RecoveryAction.RESUME
    assert make_store(path).get("tx-1").status is TransactionStatus.EXECUTING


@pytest.mark.parametrize(
    "damage",
    ["deleted_tail", "extra", "extra_marker", "tampered", "reordered"],
)
def test_pre_first_apply_resume_is_bound_to_complete_frozen_plan(
    tmp_path: object, damage: str
) -> None:
    path = tmp_path / f"{damage}.sqlite3"  # type: ignore[operator]
    setup_bound_executing(path)
    with sqlite3.connect(path) as connection:
        if damage == "deleted_tail":
            connection.execute(
                "DELETE FROM effect_dispatches WHERE step_id = '1'"
            )
            connection.execute("DELETE FROM plugin_markers WHERE step_id = '1'")
            connection.execute("DELETE FROM transaction_steps WHERE step_id = '1'")
        elif damage == "extra":
            extra = plan_step("2")
            connection.execute(
                """
                INSERT INTO transaction_steps (
                    transaction_id, step_id, step_index,
                    operation_json, pre_state_json
                ) VALUES ('tx-1', '2', 2, ?, ?)
                """,
                (extra.operation_json, extra.pre_state_json),
            )
            connection.execute(
                """
                INSERT INTO plugin_markers VALUES ('tx-1', '2', ?)
                """,
                (extra.plugin_marker_json,),
            )
            connection.execute(
                """
                INSERT INTO effect_dispatches VALUES (
                    'prepare-2', 'tx-1', '2', 'prepare', 'ticket-2',
                    'completed', 40, 41
                )
                """
            )
        elif damage == "extra_marker":
            connection.execute(
                """
                INSERT INTO plugin_markers VALUES (
                    'tx-1', '9', '{"marker":"extra"}'
                )
                """
            )
        elif damage == "tampered":
            connection.execute(
                """
                UPDATE transaction_steps
                SET operation_json = '{"action":"replace","resource":"/etc/evil.conf"}'
                WHERE step_id = '0'
                """
            )
        else:
            connection.execute(
                "UPDATE transaction_steps SET step_index = 99 WHERE step_id = '0'"
            )
            connection.execute(
                "UPDATE transaction_steps SET step_index = 0 WHERE step_id = '1'"
            )
            connection.execute(
                "UPDATE transaction_steps SET step_index = 1 WHERE step_id = '0'"
            )

    action = make_store(path).next_recovery_action("tx-1", now=50)

    assert action is RecoveryAction.RECONCILE
    assert make_store(path).get("tx-1").status is TransactionStatus.EXECUTION_UNKNOWN


@pytest.mark.parametrize("field", ["pre_state", "marker"])
@pytest.mark.parametrize(
    "invalid_json",
    [
        pytest.param("{", id="malformed"),
        pytest.param('{"a": 1}', id="whitespace"),
        pytest.param('{"b":1,"a":2}', id="key-order"),
        pytest.param('{"a":1,"a":2}', id="duplicate-key"),
        pytest.param("1", id="scalar"),
        pytest.param("[]", id="list"),
        pytest.param("null", id="null"),
        pytest.param(sqlite3.Binary(b"\xff"), id="invalid-utf8"),
        pytest.param('{"blob":"' + ("x" * 262_144) + '"}', id="oversized"),
    ],
)
def test_pre_first_apply_resume_rejects_invalid_pre_state_or_marker_json(
    tmp_path: object, field: str, invalid_json: object
) -> None:
    path = tmp_path / f"{field}.sqlite3"  # type: ignore[operator]
    setup_bound_executing(path)
    with sqlite3.connect(path) as connection:
        if field == "pre_state":
            connection.execute(
                """
                UPDATE transaction_steps SET pre_state_json = ?
                WHERE transaction_id = 'tx-1' AND step_id = '0'
                """,
                (invalid_json,),
            )
        else:
            connection.execute(
                """
                UPDATE plugin_markers SET marker_json = ?
                WHERE transaction_id = 'tx-1' AND step_id = '0'
                """,
                (invalid_json,),
            )

    action = make_store(path).next_recovery_action("tx-1", now=50)

    assert action is RecoveryAction.RECONCILE
    assert make_store(path).get("tx-1").status is TransactionStatus.EXECUTION_UNKNOWN


@pytest.mark.parametrize("damage", ["missing", "mismatched"])
def test_executing_before_first_apply_requires_complete_matching_prepare_evidence(
    tmp_path: object, damage: str
) -> None:
    path = tmp_path / f"{damage}.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.transition("tx-1", TransactionStatus.PREPARING, now=11)
    dispatch = store.begin_dispatch(
        "tx-1",
        "0",
        phase=EffectPhase.PREPARE,
        dispatch_id="prepare-0",
        ticket="ticket-0",
        now=12,
    )
    store.complete_prepare_dispatch(
        dispatch.dispatch_id, prepared_step(), now=13
    )
    store.finish_prepared("tx-1", expected_steps=1, now=14)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=15)
    with sqlite3.connect(path) as connection:
        if damage == "missing":
            connection.execute(
                "DELETE FROM effect_dispatches WHERE dispatch_id = 'prepare-0'"
            )
        else:
            connection.execute(
                """
                UPDATE effect_dispatches SET step_id = '9'
                WHERE dispatch_id = 'prepare-0'
                """
            )

    action = make_store(path).next_recovery_action("tx-1", now=30)

    assert action is RecoveryAction.RECONCILE
    assert make_store(path).get("tx-1").status is TransactionStatus.EXECUTION_UNKNOWN


def test_completed_apply_dispatch_without_atomic_result_is_not_resumable(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=11)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=12)
    dispatch = store.begin_dispatch(
        "tx-1",
        "0",
        phase=EffectPhase.APPLY,
        dispatch_id="apply-0",
        ticket="token",
        now=20,
    )
    store.complete_dispatch(dispatch.dispatch_id, now=21)

    action = make_store(path).next_recovery_action("tx-1", now=30)

    assert action is RecoveryAction.RECONCILE
    assert make_store(path).get("tx-1").status is TransactionStatus.EXECUTION_UNKNOWN


@pytest.mark.parametrize(
    ("status", "phase"),
    [
        (TransactionStatus.PREPARING, EffectPhase.PREPARE),
        (TransactionStatus.EXECUTING, EffectPhase.APPLY),
        (TransactionStatus.ROLLBACK_RUNNING, EffectPhase.UNDO),
    ],
)
def test_pending_effect_dispatch_drives_reconcile_recovery(
    tmp_path: object, status: TransactionStatus, phase: EffectPhase
) -> None:
    path = tmp_path / f"{phase}.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    if status is TransactionStatus.PREPARING:
        store.transition("tx-1", status, now=11)
    else:
        store.record_prepared("tx-1", (prepared_step(),), now=11)
        store.transition("tx-1", TransactionStatus.EXECUTING, now=12)
        if status is TransactionStatus.ROLLBACK_RUNNING:
            store.transition("tx-1", status, now=13)
    dispatch = store.begin_dispatch(
        "tx-1", "0", phase=phase, dispatch_id=f"{phase}-0", ticket="token", now=20
    )

    action = make_store(path).next_recovery_action("tx-1", now=30)

    assert action is RecoveryAction.RECONCILE
    assert store.get("tx-1").status is TransactionStatus.EXECUTION_UNKNOWN
    assert store.pending_dispatch("tx-1") == dispatch


@pytest.mark.parametrize(
    "steps",
    [
        (prepared_step("0"), prepared_step("0")),
        (prepared_step("0"), prepared_step("2")),
        (),
    ],
)
def test_invalid_step_sequences_leave_created_transaction_empty(
    tmp_path: object, steps: tuple[PreparedStep, ...]
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)

    with pytest.raises(ValueError, match="step"):
        store.record_prepared("tx-1", steps, now=20)

    assert store.get("tx-1").status is TransactionStatus.CREATED
    assert store.get_steps("tx-1") == ()


def test_prepared_step_requires_bounded_canonical_json() -> None:
    with pytest.raises(ValueError, match="canonical"):
        PreparedStep(
            step_id="0",
            operation_json='{ "action": "replace" }',
            pre_state_json="{}",
            plugin_marker_json="{}",
        )
    with pytest.raises(ValueError, match="JSON"):
        PreparedStep(
            step_id="0",
            operation_json="{}",
            pre_state_json="not-json",
            plugin_marker_json="{}",
        )


def test_result_and_marker_persistence_does_not_declare_transaction_success(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=20)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=30)

    result = store.record_result(
        "tx-1",
        "0",
        phase="apply",
        status="succeeded",
        payload={"changed": True},
        now=40,
    )

    reopened = make_store(path)
    assert result.payload_json == '{"changed":true}'
    assert reopened.get_results("tx-1") == (result,)
    assert reopened.get_steps("tx-1")[0].plugin_marker_json == '{"marker":"marker-0"}'
    assert reopened.get("tx-1").status is TransactionStatus.EXECUTING


@pytest.mark.parametrize(
    ("phase", "status"),
    [
        ("retry", "succeeded"),
        ("apply", "applied"),
        ("reconcile", "succeeded"),
        ("verify", "not_applied"),
    ],
)
def test_record_result_rejects_unknown_or_phase_incompatible_statuses(
    tmp_path: object, phase: str, status: str
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=20)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=30)

    with pytest.raises(ValueError):
        store.record_result(
            "tx-1", "0", phase=phase, status=status, payload={}, now=40
        )


def test_allowed_transitions_are_compare_and_swap_guarded(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    first = make_store(path)
    second = make_store(path)
    first.begin("tx-1", "target-1", DIGEST, now=10)
    first.record_prepared("tx-1", (prepared_step(),), now=20)

    assert ALLOWED_TRANSITIONS[TransactionStatus.CREATED] == {
        TransactionStatus.PREPARING,
        TransactionStatus.PREPARED,
        TransactionStatus.FAILED,
    }
    first.transition("tx-1", TransactionStatus.EXECUTING, now=30)
    with pytest.raises(InvalidTransitionError):
        second.transition("tx-1", TransactionStatus.SUCCEEDED, now=31)
    assert second.get("tx-1").status is TransactionStatus.EXECUTING


def test_public_transition_cannot_bypass_atomic_preparation(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)

    with pytest.raises(InvalidTransitionError):
        store.transition("tx-1", TransactionStatus.PREPARED, now=20)

    assert store.get("tx-1").status is TransactionStatus.CREATED
    assert store.get_steps("tx-1") == ()


def test_startup_recovery_never_replays_apply(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=20)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=30)

    action = make_store(path).next_recovery_action("tx-1", now=40)

    assert action is RecoveryAction.RECONCILE
    assert store.get("tx-1").status is TransactionStatus.EXECUTION_UNKNOWN
    assert store.next_recovery_action("tx-1", now=41) is RecoveryAction.RECONCILE


def test_unsupported_persisted_status_requires_manual_recovery(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE transactions SET status = 'legacy_paused' "
            "WHERE transaction_id = 'tx-1'"
        )

    assert store.next_recovery_action("tx-1", now=20) is RecoveryAction.MANUAL


@pytest.mark.parametrize(
    ("status", "action"),
    [
        (TransactionStatus.CREATED, RecoveryAction.MANUAL),
        (TransactionStatus.PREPARED, RecoveryAction.MANUAL),
        (TransactionStatus.VERIFYING, RecoveryAction.VERIFY),
        (TransactionStatus.ROLLBACK_RUNNING, RecoveryAction.ROLLBACK),
        (TransactionStatus.SUCCEEDED, RecoveryAction.MANUAL),
        (TransactionStatus.ROLLBACK_UNKNOWN, RecoveryAction.MANUAL),
    ],
)
def test_recovery_action_is_safe_for_persisted_status(
    tmp_path: object, status: TransactionStatus, action: RecoveryAction
) -> None:
    path = tmp_path / f"{status.value}.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    if status is not TransactionStatus.CREATED:
        store.record_prepared("tx-1", (prepared_step(),), now=20)
    route = {
        TransactionStatus.PREPARED: (),
        TransactionStatus.VERIFYING: (
            TransactionStatus.EXECUTING,
            TransactionStatus.VERIFYING,
        ),
        TransactionStatus.ROLLBACK_RUNNING: (
            TransactionStatus.EXECUTING,
            TransactionStatus.ROLLBACK_RUNNING,
        ),
        TransactionStatus.SUCCEEDED: (
            TransactionStatus.EXECUTING,
            TransactionStatus.VERIFYING,
            TransactionStatus.SUCCEEDED,
        ),
        TransactionStatus.ROLLBACK_UNKNOWN: (
            TransactionStatus.EXECUTING,
            TransactionStatus.ROLLBACK_RUNNING,
            TransactionStatus.ROLLBACK_UNKNOWN,
        ),
    }.get(status, ())
    for index, next_status in enumerate(route, start=30):
        store.transition("tx-1", next_status, now=index)

    assert store.next_recovery_action("tx-1", now=100) is action


def test_target_lock_is_released_only_for_terminal_status(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    store = make_store(path)
    store.begin("tx-1", "target-1", DIGEST, now=10)
    store.record_prepared("tx-1", (prepared_step(),), now=20)
    store.transition("tx-1", TransactionStatus.EXECUTING, now=30)
    store.mark_unknown("tx-1", now=40)

    with pytest.raises(InvalidTransitionError):
        store.release_target("tx-1")
    with pytest.raises(TargetBusyError):
        make_store(path).begin("tx-2", "target-1", "b" * 64, now=50)

    store.transition("tx-1", TransactionStatus.FAILED, now=60)
    assert store.release_target("tx-1") is True
    make_store(path).begin("tx-2", "target-1", "b" * 64, now=70)


def test_unknown_transaction_errors_are_stable(tmp_path: object) -> None:
    store = make_store(tmp_path / "state.sqlite3")  # type: ignore[operator]

    with pytest.raises(UnknownTransactionError):
        store.get("missing")
    with pytest.raises(UnknownTransactionError):
        store.next_recovery_action("missing", now=10)


def test_consume_is_atomic_across_independent_store_objects(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    make_store(path)
    barrier = Barrier(2)

    def consume_once(_: int) -> bool:
        contender = make_store(path)
        barrier.wait()
        return contender.consume("ticket-1")

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(consume_once, (1, 2)))

    assert sorted(outcomes) == [False, True]


def test_schema_has_required_tables_and_foreign_keys_enabled(tmp_path: object) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    make_store(path)

    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    assert {
        "transactions",
        "transaction_plan_operations",
        "transaction_steps",
        "plugin_markers",
        "target_write_locks",
        "consumed_tickets",
    } <= tables
    assert journal_mode == "wal"


def test_max_concurrent_targets_must_be_positive(tmp_path: object) -> None:
    with pytest.raises(ValueError, match="max_concurrent_targets"):
        make_store(tmp_path / "state.sqlite3", limit=0)  # type: ignore[operator]

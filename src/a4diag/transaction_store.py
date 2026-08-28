from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from a4diag.domain import CanonicalPlanError, canonical_json_bytes


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STEP_ID = re.compile(r"^(?:0|[1-9][0-9]{0,5})$")
_MAX_JSON_BYTES = 262_144
_MAX_STEPS = 20


class TransactionStatus(StrEnum):
    CREATED = "created"
    PREPARING = "preparing"
    PREPARED = "prepared"
    EXECUTING = "executing"
    EXECUTION_UNKNOWN = "execution_unknown"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLBACK_RUNNING = "rollback_running"
    ROLLBACK_SUCCEEDED = "rollback_succeeded"
    ROLLBACK_PARTIAL = "rollback_partial"
    ROLLBACK_UNKNOWN = "rollback_unknown"


ALLOWED_TRANSITIONS: dict[TransactionStatus, set[TransactionStatus]] = {
    TransactionStatus.CREATED: {
        TransactionStatus.PREPARING,
        TransactionStatus.PREPARED,
        TransactionStatus.FAILED,
    },
    TransactionStatus.PREPARING: {
        TransactionStatus.PREPARED,
        TransactionStatus.EXECUTION_UNKNOWN,
        TransactionStatus.FAILED,
    },
    TransactionStatus.PREPARED: {
        TransactionStatus.EXECUTING,
        TransactionStatus.FAILED,
    },
    TransactionStatus.EXECUTING: {
        TransactionStatus.VERIFYING,
        TransactionStatus.EXECUTION_UNKNOWN,
        TransactionStatus.ROLLBACK_RUNNING,
    },
    TransactionStatus.EXECUTION_UNKNOWN: {
        TransactionStatus.VERIFYING,
        TransactionStatus.ROLLBACK_RUNNING,
        TransactionStatus.FAILED,
    },
    TransactionStatus.VERIFYING: {
        TransactionStatus.SUCCEEDED,
        TransactionStatus.ROLLBACK_RUNNING,
    },
    TransactionStatus.ROLLBACK_RUNNING: {
        TransactionStatus.EXECUTION_UNKNOWN,
        TransactionStatus.ROLLBACK_SUCCEEDED,
        TransactionStatus.ROLLBACK_PARTIAL,
        TransactionStatus.ROLLBACK_UNKNOWN,
    },
    TransactionStatus.SUCCEEDED: set(),
    TransactionStatus.FAILED: set(),
    TransactionStatus.ROLLBACK_SUCCEEDED: set(),
    TransactionStatus.ROLLBACK_PARTIAL: set(),
    TransactionStatus.ROLLBACK_UNKNOWN: set(),
}


class RecoveryAction(StrEnum):
    RECONCILE = "reconcile"
    RESUME = "resume"
    VERIFY = "verify"
    ROLLBACK = "rollback"
    MANUAL = "manual"


class EffectPhase(StrEnum):
    PREPARE = "prepare"
    APPLY = "apply"
    UNDO = "undo"


class DispatchStatus(StrEnum):
    DISPATCHED = "dispatched"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class PreparedStep:
    step_id: str
    operation_json: str
    pre_state_json: str
    plugin_marker_json: str

    def __post_init__(self) -> None:
        _validate_step_id(self.step_id)
        _validate_canonical_json_text(
            self.operation_json, "operation_json", require_object=True
        )
        _validate_canonical_json_text(
            self.pre_state_json, "pre_state_json", require_object=True
        )
        _validate_canonical_json_text(
            self.plugin_marker_json, "plugin_marker_json", require_object=True
        )


@dataclass(frozen=True, slots=True)
class TransactionRecord:
    transaction_id: str
    target_id: str
    plan_digest: str
    status: TransactionStatus
    created_at: int
    updated_at: int


@dataclass(frozen=True, slots=True)
class TransactionResultRecord:
    transaction_id: str
    step_id: str
    phase: str
    status: str
    payload_json: str
    recorded_at: int


@dataclass(frozen=True, slots=True)
class EffectDispatchRecord:
    dispatch_id: str
    transaction_id: str
    step_id: str
    phase: EffectPhase
    ticket: str
    status: DispatchStatus
    dispatched_at: int
    completed_at: int | None


class TransactionStoreError(RuntimeError):
    """Base class for stable durable transaction-state failures."""


class TargetBusyError(TransactionStoreError):
    pass


class GlobalWriteLimitError(TransactionStoreError):
    pass


class InvalidTransitionError(TransactionStoreError):
    pass


class UnknownTransactionError(TransactionStoreError):
    pass


_RESULT_STATUSES: dict[str, frozenset[str]] = {
    "apply": frozenset({"succeeded", "failed", "unknown"}),
    "verify": frozenset({"succeeded", "failed", "unknown"}),
    "undo": frozenset({"succeeded", "failed", "unknown"}),
    "reconcile": frozenset({"not_applied", "applied", "partial", "unknown"}),
}
_RESULT_TRANSACTION_STATES: dict[str, frozenset[TransactionStatus]] = {
    "apply": frozenset(
        {TransactionStatus.EXECUTING, TransactionStatus.EXECUTION_UNKNOWN}
    ),
    "verify": frozenset({TransactionStatus.VERIFYING}),
    "undo": frozenset({TransactionStatus.ROLLBACK_RUNNING}),
    "reconcile": frozenset({TransactionStatus.EXECUTION_UNKNOWN}),
}
_TERMINAL_RELEASE_STATES = frozenset(
    {
        TransactionStatus.SUCCEEDED,
        TransactionStatus.FAILED,
        TransactionStatus.ROLLBACK_SUCCEEDED,
        TransactionStatus.ROLLBACK_PARTIAL,
    }
)
_PHASE_ORDER = ("apply", "verify", "undo", "reconcile")


class TransactionStore:
    """Durable write-transaction journal and cross-process target lock manager."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_concurrent_targets: int = 2,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self._path = _validate_path(path)
        self._max_concurrent_targets = _validate_positive_int(
            max_concurrent_targets, "max_concurrent_targets"
        )
        self._busy_timeout_ms = _validate_positive_int(
            busy_timeout_ms, "busy_timeout_ms"
        )
        self._initialize()

    def begin(
        self,
        transaction_id: str,
        target_id: str,
        digest: str,
        *,
        expected_operations: Sequence[str] | None = None,
        now: int,
    ) -> TransactionRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        target_id = _validate_target_id(target_id)
        digest = _validate_digest(digest, "digest")
        frozen_operations = _validate_expected_operations(expected_operations)
        now = _validate_time(now, "now")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            lock = connection.execute(
                "SELECT transaction_id FROM target_write_locks WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            if lock is not None:
                raise TargetBusyError(
                    f"target already has an active write transaction: {target_id}"
                )
            lock_count = connection.execute(
                "SELECT COUNT(*) FROM target_write_locks"
            ).fetchone()[0]
            if lock_count >= self._max_concurrent_targets:
                raise GlobalWriteLimitError("global target write limit reached")
            try:
                connection.execute(
                    """
                    INSERT INTO transactions (
                        transaction_id, target_id, plan_digest, status,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, 'created', ?, ?)
                    """,
                    (transaction_id, target_id, digest, now, now),
                )
                for step_index, operation_json in enumerate(frozen_operations):
                    connection.execute(
                        """
                        INSERT INTO transaction_plan_operations (
                            transaction_id, step_id, step_index, operation_json
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            transaction_id,
                            str(step_index),
                            step_index,
                            operation_json,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO target_write_locks (
                        target_id, transaction_id, acquired_at
                    ) VALUES (?, ?, ?)
                    """,
                    (target_id, transaction_id, now),
                )
            except sqlite3.IntegrityError as error:
                raise InvalidTransitionError(
                    f"transaction already exists: {transaction_id}"
                ) from error
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(transaction_id)

    def record_prepared(
        self,
        transaction_id: str,
        steps: Sequence[PreparedStep],
        *,
        now: int,
    ) -> TransactionRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        now = _validate_time(now, "now")
        prepared_steps = _validate_prepared_steps(steps)

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            status = self._status_in_connection(connection, transaction_id)
            if status is not TransactionStatus.CREATED:
                raise InvalidTransitionError(
                    f"cannot prepare transaction from {status.value}"
                )
            for step_index, step in enumerate(prepared_steps):
                connection.execute(
                    """
                    INSERT INTO transaction_steps (
                        transaction_id, step_id, step_index,
                        operation_json, pre_state_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        transaction_id,
                        step.step_id,
                        step_index,
                        step.operation_json,
                        step.pre_state_json,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO plugin_markers (
                        transaction_id, step_id, marker_json
                    ) VALUES (?, ?, ?)
                    """,
                    (transaction_id, step.step_id, step.plugin_marker_json),
                )
            changed = connection.execute(
                """
                UPDATE transactions SET status = 'prepared', updated_at = ?
                WHERE transaction_id = ? AND status = 'created'
                """,
                (now, transaction_id),
            ).rowcount
            if changed != 1:
                raise InvalidTransitionError("transaction state changed concurrently")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(transaction_id)

    def record_prepared_step(
        self, transaction_id: str, step: PreparedStep, *, now: int
    ) -> TransactionRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        if not isinstance(step, PreparedStep):
            raise TypeError("step must be PreparedStep")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            status = self._status_in_connection(connection, transaction_id)
            if status is not TransactionStatus.PREPARING:
                raise InvalidTransitionError(
                    f"cannot persist prepared step while transaction is {status.value}"
                )
            expected_index = connection.execute(
                "SELECT COUNT(*) FROM transaction_steps WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()[0]
            if step.step_id != str(expected_index):
                raise ValueError("prepared step IDs must be contiguous from 0")
            connection.execute(
                """
                INSERT INTO transaction_steps (
                    transaction_id, step_id, step_index, operation_json, pre_state_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    transaction_id,
                    step.step_id,
                    expected_index,
                    step.operation_json,
                    step.pre_state_json,
                ),
            )
            connection.execute(
                """
                INSERT INTO plugin_markers (transaction_id, step_id, marker_json)
                VALUES (?, ?, ?)
                """,
                (transaction_id, step.step_id, step.plugin_marker_json),
            )
            connection.execute(
                "UPDATE transactions SET updated_at = ? WHERE transaction_id = ?",
                (now, transaction_id),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(transaction_id)

    def finish_prepared(
        self, transaction_id: str, *, expected_steps: int, now: int
    ) -> TransactionRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        expected_steps = _validate_positive_int(expected_steps, "expected_steps")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            status = self._status_in_connection(connection, transaction_id)
            if status is not TransactionStatus.PREPARING:
                raise InvalidTransitionError(
                    f"cannot finish prepare while transaction is {status.value}"
                )
            count = connection.execute(
                "SELECT COUNT(*) FROM transaction_steps WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()[0]
            if count != expected_steps:
                raise ValueError("prepared step count does not match plan")
            changed = connection.execute(
                """
                UPDATE transactions SET status = 'prepared', updated_at = ?
                WHERE transaction_id = ? AND status = 'preparing'
                """,
                (now, transaction_id),
            ).rowcount
            if changed != 1:
                raise InvalidTransitionError("transaction state changed concurrently")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(transaction_id)

    def begin_dispatch(
        self,
        transaction_id: str,
        step_id: str,
        *,
        phase: EffectPhase | str,
        dispatch_id: str,
        ticket: str,
        now: int,
    ) -> EffectDispatchRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        step_id = _validate_step_id(step_id)
        dispatch_id = _validate_safe_id(dispatch_id, "dispatch_id")
        try:
            effect_phase = EffectPhase(phase)
        except (TypeError, ValueError) as error:
            raise ValueError("invalid effect phase") from error
        if not isinstance(ticket, str) or not ticket:
            raise ValueError("ticket must be a non-empty string")
        now = _validate_time(now, "now")
        expected_state = {
            EffectPhase.PREPARE: TransactionStatus.PREPARING,
            EffectPhase.APPLY: TransactionStatus.EXECUTING,
            EffectPhase.UNDO: TransactionStatus.ROLLBACK_RUNNING,
        }[effect_phase]
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            status = self._status_in_connection(connection, transaction_id)
            if status is not expected_state:
                raise InvalidTransitionError(
                    f"cannot dispatch {effect_phase.value} while transaction is {status.value}"
                )
            pending = connection.execute(
                """
                SELECT 1 FROM effect_dispatches
                WHERE transaction_id = ? AND status = 'dispatched'
                """,
                (transaction_id,),
            ).fetchone()
            if pending is not None:
                raise InvalidTransitionError("transaction already has a pending dispatch")
            connection.execute(
                """
                INSERT INTO effect_dispatches (
                    dispatch_id, transaction_id, step_id, phase, ticket,
                    status, dispatched_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, 'dispatched', ?, NULL)
                """,
                (
                    dispatch_id,
                    transaction_id,
                    step_id,
                    effect_phase.value,
                    ticket,
                    now,
                ),
            )
            connection.commit()
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise InvalidTransitionError("duplicate effect dispatch") from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        record = self.dispatch(dispatch_id)
        return record

    def complete_dispatch(self, dispatch_id: str, *, now: int) -> EffectDispatchRecord:
        dispatch_id = _validate_safe_id(dispatch_id, "dispatch_id")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """
                UPDATE effect_dispatches
                SET status = 'completed', completed_at = ?
                WHERE dispatch_id = ? AND status = 'dispatched'
                """,
                (now, dispatch_id),
            ).rowcount
            if changed != 1:
                raise InvalidTransitionError("dispatch is not pending")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.dispatch(dispatch_id)

    def complete_prepare_dispatch(
        self, dispatch_id: str, step: PreparedStep, *, now: int
    ) -> EffectDispatchRecord:
        """Atomically persist one prepare outcome and complete its dispatch.

        Re-reading an already completed dispatch with the identical prepared
        value is idempotent. A different value is rejected rather than
        rewriting durable recovery evidence.
        """

        dispatch_id = _validate_safe_id(dispatch_id, "dispatch_id")
        if not isinstance(step, PreparedStep):
            raise TypeError("step must be PreparedStep")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            dispatch = connection.execute(
                "SELECT * FROM effect_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            if dispatch is None:
                raise ValueError(f"unknown dispatch: {dispatch_id}")
            if (
                EffectPhase(dispatch["phase"]) is not EffectPhase.PREPARE
                or dispatch["step_id"] != step.step_id
            ):
                raise InvalidTransitionError(
                    "prepare outcome does not match dispatch binding"
                )
            status = self._status_in_connection(
                connection, dispatch["transaction_id"]
            )
            if status not in {
                TransactionStatus.PREPARING,
                TransactionStatus.EXECUTION_UNKNOWN,
            }:
                raise InvalidTransitionError(
                    f"cannot complete prepare while transaction is {status.value}"
                )

            existing = connection.execute(
                """
                SELECT s.operation_json, s.pre_state_json, m.marker_json
                FROM transaction_steps AS s
                JOIN plugin_markers AS m
                  ON m.transaction_id = s.transaction_id
                 AND m.step_id = s.step_id
                WHERE s.transaction_id = ? AND s.step_id = ?
                """,
                (dispatch["transaction_id"], step.step_id),
            ).fetchone()
            if existing is not None:
                if (
                    existing["operation_json"] != step.operation_json
                    or existing["pre_state_json"] != step.pre_state_json
                    or existing["marker_json"] != step.plugin_marker_json
                ):
                    raise InvalidTransitionError(
                        "completed prepare outcome does not match durable step"
                    )
            elif DispatchStatus(dispatch["status"]) is DispatchStatus.COMPLETED:
                raise InvalidTransitionError(
                    "completed prepare dispatch is missing durable step"
                )
            else:
                expected_index = connection.execute(
                    """
                    SELECT COUNT(*) FROM transaction_steps
                    WHERE transaction_id = ?
                    """,
                    (dispatch["transaction_id"],),
                ).fetchone()[0]
                if step.step_id != str(expected_index):
                    raise ValueError("prepared step IDs must be contiguous from 0")
                connection.execute(
                    """
                    INSERT INTO transaction_steps (
                        transaction_id, step_id, step_index,
                        operation_json, pre_state_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        dispatch["transaction_id"],
                        step.step_id,
                        expected_index,
                        step.operation_json,
                        step.pre_state_json,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO plugin_markers (
                        transaction_id, step_id, marker_json
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        dispatch["transaction_id"],
                        step.step_id,
                        step.plugin_marker_json,
                    ),
                )

            if DispatchStatus(dispatch["status"]) is DispatchStatus.DISPATCHED:
                changed = connection.execute(
                    """
                    UPDATE effect_dispatches
                    SET status = 'completed', completed_at = ?
                    WHERE dispatch_id = ? AND status = 'dispatched'
                    """,
                    (now, dispatch_id),
                ).rowcount
                if changed != 1:
                    raise InvalidTransitionError("dispatch changed concurrently")
                if status is TransactionStatus.EXECUTION_UNKNOWN:
                    connection.execute(
                        """
                        UPDATE transactions
                        SET status = 'preparing', updated_at = ?
                        WHERE transaction_id = ?
                          AND status = 'execution_unknown'
                        """,
                        (now, dispatch["transaction_id"]),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE transactions SET updated_at = ?
                        WHERE transaction_id = ?
                        """,
                        (now, dispatch["transaction_id"]),
                    )
            completed = connection.execute(
                "SELECT * FROM effect_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return _effect_dispatch_record(completed)

    def complete_result_dispatch(
        self,
        dispatch_id: str,
        *,
        phase: str,
        status: str,
        payload: object,
        now: int,
    ) -> EffectDispatchRecord:
        """Atomically persist an apply/undo result and complete its dispatch."""

        dispatch_id = _validate_safe_id(dispatch_id, "dispatch_id")
        phase, status = _validate_result(phase, status)
        if phase not in {EffectPhase.APPLY.value, EffectPhase.UNDO.value}:
            raise ValueError("dispatch result phase must be apply or undo")
        payload_json = _canonicalize_json(payload, "payload")
        now = _validate_time(now, "now")
        status_column = f"{phase}_status"
        payload_column = f"{phase}_payload_json"
        recorded_column = f"{phase}_recorded_at"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            dispatch = connection.execute(
                "SELECT * FROM effect_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            if dispatch is None:
                raise ValueError(f"unknown dispatch: {dispatch_id}")
            if dispatch["phase"] != phase:
                raise InvalidTransitionError(
                    "result phase does not match dispatch binding"
                )
            transaction_status = self._status_in_connection(
                connection, dispatch["transaction_id"]
            )
            allowed_states = set(_RESULT_TRANSACTION_STATES[phase])
            if phase == EffectPhase.UNDO.value:
                allowed_states.add(TransactionStatus.EXECUTION_UNKNOWN)
            if transaction_status not in allowed_states:
                raise InvalidTransitionError(
                    f"cannot record {phase} result while transaction is "
                    f"{transaction_status.value}"
                )
            step = connection.execute(
                """
                SELECT * FROM transaction_steps
                WHERE transaction_id = ? AND step_id = ?
                """,
                (dispatch["transaction_id"], dispatch["step_id"]),
            ).fetchone()
            if step is None:
                raise ValueError(f"unknown transaction step: {dispatch['step_id']}")
            if step[status_column] is not None:
                if (
                    step[status_column] == "unknown"
                    and status != "unknown"
                    and DispatchStatus(dispatch["status"])
                    is DispatchStatus.DISPATCHED
                ):
                    changed = connection.execute(
                        f"""
                        UPDATE transaction_steps
                        SET {status_column} = ?, {payload_column} = ?,
                            {recorded_column} = ?
                        WHERE transaction_id = ? AND step_id = ?
                          AND {status_column} = 'unknown'
                        """,
                        (
                            status,
                            payload_json,
                            now,
                            dispatch["transaction_id"],
                            dispatch["step_id"],
                        ),
                    ).rowcount
                    if changed != 1:
                        raise InvalidTransitionError(
                            "unknown result changed concurrently"
                        )
                elif (
                    step[status_column] != status
                    or step[payload_column] != payload_json
                ):
                    raise InvalidTransitionError(
                        "completed dispatch result does not match durable result"
                    )
            elif DispatchStatus(dispatch["status"]) is DispatchStatus.COMPLETED:
                raise InvalidTransitionError(
                    "completed dispatch is missing durable result"
                )
            else:
                changed = connection.execute(
                    f"""
                    UPDATE transaction_steps
                    SET {status_column} = ?, {payload_column} = ?,
                        {recorded_column} = ?
                    WHERE transaction_id = ? AND step_id = ?
                      AND {status_column} IS NULL
                    """,
                    (
                        status,
                        payload_json,
                        now,
                        dispatch["transaction_id"],
                        dispatch["step_id"],
                    ),
                ).rowcount
                if changed != 1:
                    raise InvalidTransitionError("step result changed concurrently")
            if DispatchStatus(dispatch["status"]) is DispatchStatus.DISPATCHED:
                changed = connection.execute(
                    """
                    UPDATE effect_dispatches
                    SET status = 'completed', completed_at = ?
                    WHERE dispatch_id = ? AND status = 'dispatched'
                    """,
                    (now, dispatch_id),
                ).rowcount
                if changed != 1:
                    raise InvalidTransitionError("dispatch changed concurrently")
                connection.execute(
                    """
                    UPDATE transactions SET updated_at = ?
                    WHERE transaction_id = ?
                    """,
                    (now, dispatch["transaction_id"]),
                )
            completed = connection.execute(
                "SELECT * FROM effect_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return _effect_dispatch_record(completed)

    def dispatch(self, dispatch_id: str) -> EffectDispatchRecord:
        dispatch_id = _validate_safe_id(dispatch_id, "dispatch_id")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM effect_dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ValueError(f"unknown dispatch: {dispatch_id}")
        return _effect_dispatch_record(row)

    def pending_dispatch(self, transaction_id: str) -> EffectDispatchRecord | None:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT * FROM effect_dispatches
                WHERE transaction_id = ? AND status = 'dispatched'
                ORDER BY dispatched_at, dispatch_id LIMIT 1
                """,
                (transaction_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else _effect_dispatch_record(row)

    def get_dispatches(
        self, transaction_id: str
    ) -> tuple[EffectDispatchRecord, ...]:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if exists is None:
                raise UnknownTransactionError(
                    f"unknown transaction: {transaction_id}"
                )
            rows = connection.execute(
                """
                SELECT * FROM effect_dispatches
                WHERE transaction_id = ?
                ORDER BY dispatched_at, dispatch_id
                """,
                (transaction_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(_effect_dispatch_record(row) for row in rows)

    def record_result(
        self,
        transaction_id: str,
        step_id: str,
        *,
        phase: str,
        status: str,
        payload: object,
        now: int,
    ) -> TransactionResultRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        step_id = _validate_step_id(step_id)
        phase, status = _validate_result(phase, status)
        payload_json = _canonicalize_json(payload, "payload")
        now = _validate_time(now, "now")
        status_column = f"{phase}_status"
        payload_column = f"{phase}_payload_json"
        recorded_column = f"{phase}_recorded_at"

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_status = self._status_in_connection(
                connection, transaction_id
            )
            if transaction_status not in _RESULT_TRANSACTION_STATES[phase]:
                raise InvalidTransitionError(
                    f"cannot record {phase} result while transaction is "
                    f"{transaction_status.value}"
                )
            step = connection.execute(
                """
                SELECT * FROM transaction_steps
                WHERE transaction_id = ? AND step_id = ?
                """,
                (transaction_id, step_id),
            ).fetchone()
            if step is None:
                raise ValueError(f"unknown transaction step: {step_id}")
            if step[status_column] is not None:
                raise ValueError(f"{phase} result already recorded for step {step_id}")
            changed = connection.execute(
                f"""
                UPDATE transaction_steps
                SET {status_column} = ?, {payload_column} = ?, {recorded_column} = ?
                WHERE transaction_id = ? AND step_id = ?
                  AND {status_column} IS NULL
                """,
                (status, payload_json, now, transaction_id, step_id),
            ).rowcount
            if changed != 1:
                raise InvalidTransitionError("step result changed concurrently")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return TransactionResultRecord(
            transaction_id=transaction_id,
            step_id=step_id,
            phase=phase,
            status=status,
            payload_json=payload_json,
            recorded_at=now,
        )

    def transition(
        self,
        transaction_id: str,
        new_status: TransactionStatus | str,
        *,
        now: int,
    ) -> TransactionRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        try:
            destination = TransactionStatus(new_status)
        except (TypeError, ValueError) as error:
            raise InvalidTransitionError(
                f"unknown transaction status: {new_status}"
            ) from error
        if destination is TransactionStatus.PREPARED:
            raise InvalidTransitionError(
                "prepared status can only be entered by record_prepared"
            )
        now = _validate_time(now, "now")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            source = self._status_in_connection(connection, transaction_id)
            if destination not in ALLOWED_TRANSITIONS[source]:
                raise InvalidTransitionError(
                    "invalid transaction transition: "
                    f"{source.value} -> {destination.value}"
                )
            changed = connection.execute(
                """
                UPDATE transactions SET status = ?, updated_at = ?
                WHERE transaction_id = ? AND status = ?
                """,
                (destination.value, now, transaction_id, source.value),
            ).rowcount
            if changed != 1:
                raise InvalidTransitionError("transaction state changed concurrently")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(transaction_id)

    def mark_unknown(self, transaction_id: str, *, now: int) -> TransactionRecord:
        return self.transition(
            transaction_id, TransactionStatus.EXECUTION_UNKNOWN, now=now
        )

    def next_recovery_action(
        self, transaction_id: str, *, now: int
    ) -> RecoveryAction:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            raw_status = self._raw_status_in_connection(connection, transaction_id)
            try:
                status = TransactionStatus(raw_status)
            except ValueError:
                connection.commit()
                return RecoveryAction.MANUAL
            pending = connection.execute(
                """
                SELECT 1 FROM effect_dispatches
                WHERE transaction_id = ? AND status = 'dispatched'
                """,
                (transaction_id,),
            ).fetchone()
            if pending is not None and status in {
                TransactionStatus.PREPARING,
                TransactionStatus.EXECUTING,
                TransactionStatus.ROLLBACK_RUNNING,
            }:
                changed = connection.execute(
                    """
                    UPDATE transactions
                    SET status = 'execution_unknown', updated_at = ?
                    WHERE transaction_id = ? AND status = ?
                    """,
                    (now, transaction_id, status.value),
                ).rowcount
                if changed != 1:
                    raise InvalidTransitionError(
                        "transaction state changed concurrently"
                    )
                status = TransactionStatus.EXECUTION_UNKNOWN
            elif status is TransactionStatus.EXECUTING:
                apply_dispatches = connection.execute(
                    """
                    SELECT d.status, s.apply_status
                    FROM effect_dispatches AS d
                    LEFT JOIN transaction_steps AS s
                      ON s.transaction_id = d.transaction_id
                     AND s.step_id = d.step_id
                    WHERE d.transaction_id = ? AND d.phase = 'apply'
                    """,
                    (transaction_id,),
                ).fetchall()
                apply_evidence_complete = bool(apply_dispatches) and all(
                    row["status"] == DispatchStatus.COMPLETED.value
                    and row["apply_status"] is not None
                    for row in apply_dispatches
                )
                before_first_apply = not apply_dispatches
                if apply_evidence_complete or (
                    before_first_apply
                    and self._pre_first_apply_evidence_matches_in_connection(
                        connection, transaction_id
                    )
                ):
                    connection.commit()
                    return RecoveryAction.RESUME
                changed = connection.execute(
                    """
                    UPDATE transactions
                    SET status = 'execution_unknown', updated_at = ?
                    WHERE transaction_id = ? AND status = 'executing'
                    """,
                    (now, transaction_id),
                ).rowcount
                if changed != 1:
                    raise InvalidTransitionError(
                        "transaction state changed concurrently"
                    )
                status = TransactionStatus.EXECUTION_UNKNOWN
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

        if status is TransactionStatus.EXECUTION_UNKNOWN:
            return RecoveryAction.RECONCILE
        if status in {TransactionStatus.PREPARING, TransactionStatus.EXECUTING}:
            return RecoveryAction.RESUME
        if status is TransactionStatus.VERIFYING:
            return RecoveryAction.VERIFY
        if status is TransactionStatus.ROLLBACK_RUNNING:
            return RecoveryAction.ROLLBACK
        return RecoveryAction.MANUAL

    def pre_first_apply_evidence_matches(
        self,
        transaction_id: str,
        expected_operations: Sequence[str],
    ) -> bool:
        """Verify a zero-apply recovery snapshot against the frozen plan."""

        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        operations = _validate_expected_operations(expected_operations)
        if not operations:
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            matches = self._pre_first_apply_evidence_matches_in_connection(
                connection,
                transaction_id,
                expected_operations=operations,
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return matches

    def _pre_first_apply_evidence_matches_in_connection(
        self,
        connection: sqlite3.Connection,
        transaction_id: str,
        *,
        expected_operations: tuple[str, ...] | None = None,
    ) -> bool:
        expected_rows = connection.execute(
            """
            SELECT step_id, step_index, operation_json
            FROM transaction_plan_operations
            WHERE transaction_id = ? ORDER BY step_index
            """,
            (transaction_id,),
        ).fetchall()
        if not expected_rows:
            return False
        persisted_operations = tuple(
            str(row["operation_json"]) for row in expected_rows
        )
        if expected_operations is not None and persisted_operations != expected_operations:
            return False
        expected_count = len(expected_rows)
        if any(
            row["step_id"] != str(index) or row["step_index"] != index
            for index, row in enumerate(expected_rows)
        ):
            return False

        step_rows = connection.execute(
            """
            SELECT s.step_id, s.step_index, s.operation_json,
                   s.pre_state_json, m.marker_json
            FROM transaction_steps AS s
            LEFT JOIN plugin_markers AS m
              ON m.transaction_id = s.transaction_id
             AND m.step_id = s.step_id
            WHERE s.transaction_id = ? ORDER BY s.step_index
            """,
            (transaction_id,),
        ).fetchall()
        prepare_rows = connection.execute(
            """
            SELECT step_id, status FROM effect_dispatches
            WHERE transaction_id = ? AND phase = 'prepare'
            ORDER BY CAST(step_id AS INTEGER)
            """,
            (transaction_id,),
        ).fetchall()
        marker_count = connection.execute(
            """
            SELECT COUNT(*) FROM plugin_markers
            WHERE transaction_id = ?
            """,
            (transaction_id,),
        ).fetchone()[0]
        apply_count = connection.execute(
            """
            SELECT COUNT(*) FROM effect_dispatches
            WHERE transaction_id = ? AND phase = 'apply'
            """,
            (transaction_id,),
        ).fetchone()[0]
        if (
            len(step_rows) != expected_count
            or len(prepare_rows) != expected_count
            or marker_count != expected_count
            or apply_count != 0
        ):
            return False
        for index, (expected, step, dispatch) in enumerate(
            zip(expected_rows, step_rows, prepare_rows, strict=True)
        ):
            step_id = str(index)
            try:
                _validate_canonical_json_text(
                    step["pre_state_json"],
                    "pre_state_json",
                    require_object=True,
                )
                _validate_canonical_json_text(
                    step["marker_json"],
                    "plugin_marker_json",
                    require_object=True,
                )
            except (TypeError, ValueError):
                return False
            if (
                expected["step_id"] != step_id
                or step["step_id"] != step_id
                or step["step_index"] != index
                or step["operation_json"] != expected["operation_json"]
                or step["marker_json"] is None
                or dispatch["step_id"] != step_id
                or dispatch["status"] != DispatchStatus.COMPLETED.value
            ):
                return False
        return True

    def release_target(self, transaction_id: str) -> bool:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            status = self._status_in_connection(connection, transaction_id)
            if status not in _TERMINAL_RELEASE_STATES:
                raise InvalidTransitionError(
                    f"cannot release target while transaction is {status.value}"
                )
            changed = connection.execute(
                "DELETE FROM target_write_locks WHERE transaction_id = ?",
                (transaction_id,),
            ).rowcount
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return changed == 1

    def incomplete_transaction_ids(self) -> tuple[str, ...]:
        """Return every non-terminal transaction id, for startup recovery."""
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT transaction_id FROM transactions
                WHERE status NOT IN ('succeeded', 'failed', 'rollback_succeeded',
                                     'rollback_partial')
                ORDER BY created_at, transaction_id
                """
            ).fetchall()
        finally:
            connection.close()
        return tuple(str(row["transaction_id"]) for row in rows)

    def consume(self, ticket_id: str) -> bool:
        ticket_id = _validate_safe_id(ticket_id, "ticket_id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "INSERT OR IGNORE INTO consumed_tickets (ticket_id) VALUES (?)",
                (ticket_id,),
            ).rowcount
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return changed == 1

    def get(self, transaction_id: str) -> TransactionRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise UnknownTransactionError(f"unknown transaction: {transaction_id}")
        return _transaction_record(row)

    def get_steps(self, transaction_id: str) -> tuple[PreparedStep, ...]:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if exists is None:
                raise UnknownTransactionError(f"unknown transaction: {transaction_id}")
            rows = connection.execute(
                """
                SELECT s.step_id, s.operation_json, s.pre_state_json, m.marker_json
                FROM transaction_steps AS s
                JOIN plugin_markers AS m
                  ON m.transaction_id = s.transaction_id AND m.step_id = s.step_id
                WHERE s.transaction_id = ?
                ORDER BY s.step_index
                """,
                (transaction_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(
            PreparedStep(
                step_id=row["step_id"],
                operation_json=row["operation_json"],
                pre_state_json=row["pre_state_json"],
                plugin_marker_json=row["marker_json"],
            )
            for row in rows
        )

    def get_results(
        self, transaction_id: str
    ) -> tuple[TransactionResultRecord, ...]:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if exists is None:
                raise UnknownTransactionError(f"unknown transaction: {transaction_id}")
            rows = connection.execute(
                """
                SELECT * FROM transaction_steps
                WHERE transaction_id = ? ORDER BY step_index
                """,
                (transaction_id,),
            ).fetchall()
        finally:
            connection.close()
        results: list[TransactionResultRecord] = []
        for row in rows:
            for phase in _PHASE_ORDER:
                status = row[f"{phase}_status"]
                if status is not None:
                    results.append(
                        TransactionResultRecord(
                            transaction_id=transaction_id,
                            step_id=row["step_id"],
                            phase=phase,
                            status=status,
                            payload_json=row[f"{phase}_payload_json"],
                            recorded_at=row[f"{phase}_recorded_at"],
                        )
                    )
        return tuple(results)

    def _status_in_connection(
        self, connection: sqlite3.Connection, transaction_id: str
    ) -> TransactionStatus:
        return TransactionStatus(
            self._raw_status_in_connection(connection, transaction_id)
        )

    def _raw_status_in_connection(
        self, connection: sqlite3.Connection, transaction_id: str
    ) -> str:
        row = connection.execute(
            "SELECT status FROM transactions WHERE transaction_id = ?",
            (transaction_id,),
        ).fetchone()
        if row is None:
            raise UnknownTransactionError(f"unknown transaction: {transaction_id}")
        return str(row["status"])

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA:
                connection.execute(statement)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        return connection


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS transactions (
        transaction_id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 64),
        status TEXT NOT NULL CHECK (status IN (
            'created', 'preparing', 'prepared', 'executing', 'execution_unknown',
            'verifying', 'succeeded', 'failed', 'rollback_running',
            'rollback_succeeded', 'rollback_partial', 'rollback_unknown'
        )),
        created_at INTEGER NOT NULL CHECK (created_at >= 0),
        updated_at INTEGER NOT NULL CHECK (updated_at >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS transaction_plan_operations (
        transaction_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        step_index INTEGER NOT NULL CHECK (step_index >= 0),
        operation_json TEXT NOT NULL,
        PRIMARY KEY (transaction_id, step_id),
        UNIQUE (transaction_id, step_index),
        FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS effect_dispatches (
        dispatch_id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('prepare', 'apply', 'undo')),
        ticket TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('dispatched', 'completed')),
        dispatched_at INTEGER NOT NULL CHECK (dispatched_at >= 0),
        completed_at INTEGER,
        UNIQUE (transaction_id, step_id, phase),
        FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS transaction_steps (
        transaction_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        step_index INTEGER NOT NULL CHECK (step_index >= 0),
        operation_json TEXT NOT NULL,
        pre_state_json TEXT NOT NULL,
        apply_status TEXT CHECK (apply_status IN ('succeeded', 'failed', 'unknown')),
        apply_payload_json TEXT,
        apply_recorded_at INTEGER,
        verify_status TEXT CHECK (verify_status IN ('succeeded', 'failed', 'unknown')),
        verify_payload_json TEXT,
        verify_recorded_at INTEGER,
        undo_status TEXT CHECK (undo_status IN ('succeeded', 'failed', 'unknown')),
        undo_payload_json TEXT,
        undo_recorded_at INTEGER,
        reconcile_status TEXT CHECK (
            reconcile_status IN ('not_applied', 'applied', 'partial', 'unknown')
        ),
        reconcile_payload_json TEXT,
        reconcile_recorded_at INTEGER,
        PRIMARY KEY (transaction_id, step_id),
        UNIQUE (transaction_id, step_index),
        FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS plugin_markers (
        transaction_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        marker_json TEXT NOT NULL,
        PRIMARY KEY (transaction_id, step_id),
        FOREIGN KEY (transaction_id, step_id)
            REFERENCES transaction_steps(transaction_id, step_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS target_write_locks (
        target_id TEXT PRIMARY KEY,
        transaction_id TEXT NOT NULL UNIQUE,
        acquired_at INTEGER NOT NULL CHECK (acquired_at >= 0),
        FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
            ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS consumed_tickets (
        ticket_id TEXT PRIMARY KEY
    )
    """,
)


def _transaction_record(row: sqlite3.Row) -> TransactionRecord:
    return TransactionRecord(
        transaction_id=row["transaction_id"],
        target_id=row["target_id"],
        plan_digest=row["plan_digest"],
        status=TransactionStatus(row["status"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _effect_dispatch_record(row: sqlite3.Row) -> EffectDispatchRecord:
    return EffectDispatchRecord(
        dispatch_id=row["dispatch_id"],
        transaction_id=row["transaction_id"],
        step_id=row["step_id"],
        phase=EffectPhase(row["phase"]),
        ticket=row["ticket"],
        status=DispatchStatus(row["status"]),
        dispatched_at=row["dispatched_at"],
        completed_at=row["completed_at"],
    )


def _validate_prepared_steps(
    steps: Sequence[PreparedStep],
) -> tuple[PreparedStep, ...]:
    if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
        raise ValueError("steps must be a sequence of PreparedStep values")
    values = tuple(steps)
    if not 1 <= len(values) <= _MAX_STEPS:
        raise ValueError(f"step count must be between 1 and {_MAX_STEPS}")
    if any(not isinstance(step, PreparedStep) for step in values):
        raise ValueError("steps must contain only PreparedStep values")
    expected_ids = tuple(str(index) for index in range(len(values)))
    actual_ids = tuple(step.step_id for step in values)
    if actual_ids != expected_ids:
        raise ValueError("step IDs must be unique, ordered, and contiguous from 0")
    return values


def _validate_expected_operations(
    operations: Sequence[str] | None,
) -> tuple[str, ...]:
    if operations is None:
        return ()
    if isinstance(operations, (str, bytes)) or not isinstance(operations, Sequence):
        raise ValueError("expected_operations must be a sequence of canonical JSON")
    values = tuple(operations)
    if not 1 <= len(values) <= _MAX_STEPS:
        raise ValueError(
            f"expected operation count must be between 1 and {_MAX_STEPS}"
        )
    return tuple(
        _validate_canonical_json_text(
            operation, "expected operation", require_object=True
        )
        for operation in values
    )


def _validate_result(phase: str, status: str) -> tuple[str, str]:
    if not isinstance(phase, str) or phase not in _RESULT_STATUSES:
        raise ValueError("result phase must be apply, verify, undo, or reconcile")
    if not isinstance(status, str) or status not in _RESULT_STATUSES[phase]:
        raise ValueError(f"invalid {phase} result status")
    return phase, status


def _canonicalize_json(value: object, label: str) -> str:
    if isinstance(value, str):
        return _validate_canonical_json_text(value, label)
    try:
        return canonical_json_bytes(value, max_bytes=_MAX_JSON_BYTES).decode("utf-8")
    except (CanonicalPlanError, UnicodeError) as error:
        raise ValueError(f"{label} must be bounded canonical JSON") from error


def _validate_canonical_json_text(
    value: str, label: str, *, require_object: bool = False
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical JSON string")
    try:
        parsed = json.loads(
            value,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
            object_pairs_hook=_unique_object,
        )
        if require_object and type(parsed) is not dict:
            raise ValueError(f"{label} must contain a JSON object")
        canonical = canonical_json_bytes(parsed, max_bytes=_MAX_JSON_BYTES).decode(
            "utf-8"
        )
    except (
        json.JSONDecodeError,
        CanonicalPlanError,
        UnicodeError,
        ValueError,
    ) as error:
        raise ValueError(f"{label} must be bounded canonical JSON") from error
    if canonical != value:
        raise ValueError(f"{label} must use canonical JSON encoding")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_json_number(value: str) -> object:
    raise ValueError(f"unsupported JSON number: {value}")


def _validate_path(path: str | Path) -> str:
    if not isinstance(path, (str, Path)) or not str(path).strip():
        raise ValueError("path must be a filesystem path")
    if str(path) == ":memory:":
        raise ValueError("path must be durable; :memory: is not supported")
    return str(path)


def _validate_safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{label} must be a safe nonblank identifier")
    return value


def _validate_target_id(value: str) -> str:
    if not isinstance(value, str) or not _TARGET_ID.fullmatch(value):
        raise ValueError("target_id must be a safe identifier")
    return value


def _validate_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA256 digest")
    return value


def _validate_step_id(value: str) -> str:
    if not isinstance(value, str) or not _STEP_ID.fullmatch(value):
        raise ValueError("step_id must be a canonical non-negative integer string")
    return value


def _validate_time(value: int, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer Unix timestamp")
    return value


def _validate_positive_int(value: int, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be an integer of at least 1")
    return value

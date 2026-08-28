from __future__ import annotations

import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ACTOR_LENGTH = 256


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class NotificationStatus(StrEnum):
    NOT_STARTED = "not_started"
    DISPATCHED = "dispatched"
    DELIVERED = "delivered"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    id: str
    transaction_id: str
    target_id: str
    plan_digest: str
    notification_required: bool
    expires_at: int
    status: ApprovalStatus
    actor: str | None
    created_at: int
    decided_at: int | None
    updated_at: int


class ApprovalError(ValueError):
    """Base class for stable approval-state failures."""


class UnknownApprovalError(ApprovalError):
    pass


class ApprovalStateError(ApprovalError):
    pass


class ApprovalDigestMismatchError(ApprovalError):
    pass


class ApprovalExpiredError(ApprovalStateError):
    pass


class ApprovalStore:
    """SQLite-backed approval state with digest-bound compare-and-swap decisions."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        request_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._path = _validate_path(path)
        self._busy_timeout_ms = _validate_positive_int(
            busy_timeout_ms, "busy_timeout_ms"
        )
        self._request_id_factory = request_id_factory or (lambda: uuid.uuid4().hex)
        if not callable(self._request_id_factory):
            raise TypeError("request_id_factory must be callable")
        self._initialize()

    def request(
        self,
        transaction_id: str,
        target_id: str,
        digest: str,
        *,
        expires_at: int,
        now: int,
        notification_required: bool = False,
    ) -> ApprovalRecord:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        target_id = _validate_target_id(target_id)
        digest = _validate_digest(digest, "digest")
        expires_at = _validate_time(expires_at, "expires_at")
        now = _validate_time(now, "now")
        if type(notification_required) is not bool:
            raise ValueError("notification_required must be a boolean")
        if expires_at <= now:
            raise ValueError("expires_at must be later than now")
        approval_id = _validate_safe_id(self._request_id_factory(), "approval_id")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO approvals (
                    approval_id, transaction_id, target_id, plan_digest,
                    notification_required, expires_at, status, actor,
                    created_at, decided_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, ?, NULL, ?)
                """,
                (
                    approval_id,
                    transaction_id,
                    target_id,
                    digest,
                    int(notification_required),
                    expires_at,
                    now,
                    now,
                ),
            )
            connection.commit()
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ApprovalStateError(
                "approval_id or transaction_id already exists"
            ) from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(approval_id)

    def approve(
        self,
        approval_id: str,
        *,
        approved_digest: str,
        actor: str,
        now: int,
    ) -> ApprovalRecord:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        approved_digest = _validate_digest(approved_digest, "approved_digest")
        actor = _validate_actor(actor)
        now = _validate_time(now, "now")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                raise UnknownApprovalError(f"unknown approval: {approval_id}")
            if ApprovalStatus(row["status"]) is not ApprovalStatus.PENDING:
                raise ApprovalStateError("approval is not pending")
            if row["plan_digest"] != approved_digest:
                raise ApprovalDigestMismatchError(
                    "approved digest does not match request"
                )
            if row["notification_required"]:
                notification = connection.execute(
                    """
                    SELECT status FROM approval_notifications
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                ).fetchone()
                if notification is None or notification["status"] != "delivered":
                    raise ApprovalStateError(
                        "required notification has not been delivered"
                    )
            if now >= row["expires_at"]:
                changed = connection.execute(
                    """
                    UPDATE approvals
                    SET status = 'expired', updated_at = ?
                    WHERE approval_id = ? AND status = 'pending' AND expires_at <= ?
                    """,
                    (now, approval_id, now),
                ).rowcount
                if changed != 1:
                    raise ApprovalStateError("approval state changed concurrently")
                connection.commit()
                raise ApprovalExpiredError("approval has expired")
            changed = connection.execute(
                """
                UPDATE approvals
                SET status = 'approved', actor = ?, decided_at = ?, updated_at = ?
                WHERE approval_id = ? AND status = 'pending'
                  AND plan_digest = ? AND expires_at > ?
                """,
                (actor, now, now, approval_id, approved_digest, now),
            ).rowcount
            if changed != 1:
                raise ApprovalStateError("approval state changed concurrently")
            connection.commit()
        except ApprovalExpiredError:
            raise
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(approval_id)

    def reject(self, approval_id: str, *, actor: str, now: int) -> ApprovalRecord:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        actor = _validate_actor(actor)
        now = _validate_time(now, "now")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, expires_at FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise UnknownApprovalError(f"unknown approval: {approval_id}")
            if ApprovalStatus(row["status"]) is not ApprovalStatus.PENDING:
                raise ApprovalStateError("approval is not pending")
            if now >= row["expires_at"]:
                connection.execute(
                    """
                    UPDATE approvals SET status = 'expired', updated_at = ?
                    WHERE approval_id = ? AND status = 'pending' AND expires_at <= ?
                    """,
                    (now, approval_id, now),
                )
                connection.commit()
                raise ApprovalExpiredError("approval has expired")
            changed = connection.execute(
                """
                UPDATE approvals
                SET status = 'rejected', actor = ?, decided_at = ?, updated_at = ?
                WHERE approval_id = ? AND status = 'pending' AND expires_at > ?
                """,
                (actor, now, now, approval_id, now),
            ).rowcount
            if changed != 1:
                raise ApprovalStateError("approval state changed concurrently")
            connection.commit()
        except ApprovalExpiredError:
            raise
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(approval_id)

    def expire(self, approval_id: str, *, now: int) -> ApprovalRecord:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT expires_at FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise UnknownApprovalError(f"unknown approval: {approval_id}")
            if now >= row["expires_at"]:
                connection.execute(
                    """
                    UPDATE approvals SET status = 'expired', updated_at = ?
                    WHERE approval_id = ? AND status IN ('pending', 'approved')
                      AND expires_at <= ?
                    """,
                    (now, approval_id, now),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get(approval_id)

    def valid_digest(
        self,
        transaction_id: str,
        *,
        expected_digest: str | None = None,
        expected_target: str | None = None,
        now: int,
    ) -> str | None:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        if expected_digest is not None:
            expected_digest = _validate_digest(expected_digest, "expected_digest")
        if expected_target is not None:
            expected_target = _validate_target_id(expected_target)
        now = _validate_time(now, "now")
        record = self._find_valid(
            transaction_id,
            expected_digest=expected_digest,
            expected_target=expected_target,
            now=now,
        )
        return None if record is None else record.plan_digest

    def valid_approval(
        self,
        transaction_id: str,
        *,
        expected_digest: str,
        expected_target: str,
        now: int,
    ) -> ApprovalRecord | None:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        expected_digest = _validate_digest(expected_digest, "expected_digest")
        expected_target = _validate_target_id(expected_target)
        now = _validate_time(now, "now")
        return self._find_valid(
            transaction_id,
            expected_digest=expected_digest,
            expected_target=expected_target,
            now=now,
        )

    def get(self, approval_id: str) -> ApprovalRecord:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise UnknownApprovalError(f"unknown approval: {approval_id}")
        return _approval_record(row)

    def for_transaction(self, transaction_id: str) -> ApprovalRecord | None:
        transaction_id = _validate_safe_id(transaction_id, "transaction_id")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM approvals WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else _approval_record(row)

    def list_approvals(self, *, limit: int = 100) -> tuple[ApprovalRecord, ...]:
        """Return the most recent approval records, newest first."""
        limit = _validate_positive_int(limit, "limit")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(_approval_record(row) for row in rows)

    def begin_notification(self, approval_id: str, *, now: int) -> bool:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        now = _validate_time(now, "now")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """
                INSERT OR IGNORE INTO approval_notifications (
                    approval_id, status, dispatched_at, completed_at
                ) VALUES (?, 'dispatched', ?, NULL)
                """,
                (approval_id, now),
            ).rowcount
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return changed == 1

    def complete_notification(
        self, approval_id: str, *, delivered: bool, now: int
    ) -> NotificationStatus:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        if type(delivered) is not bool:
            raise ValueError("delivered must be a boolean")
        now = _validate_time(now, "now")
        status = (
            NotificationStatus.DELIVERED if delivered else NotificationStatus.FAILED
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """
                UPDATE approval_notifications SET status = ?, completed_at = ?
                WHERE approval_id = ? AND status = 'dispatched'
                """,
                (status.value, now, approval_id),
            ).rowcount
            if changed != 1:
                raise ApprovalStateError("notification is not pending")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return status

    def notification_status(self, approval_id: str) -> NotificationStatus:
        approval_id = _validate_safe_id(approval_id, "approval_id")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT status FROM approval_notifications WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return NotificationStatus.NOT_STARTED
        return NotificationStatus(row["status"])

    def _find_valid(
        self,
        transaction_id: str,
        *,
        expected_digest: str | None,
        expected_target: str | None,
        now: int,
    ) -> ApprovalRecord | None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE approvals SET status = 'expired', updated_at = ?
                WHERE transaction_id = ? AND status IN ('pending', 'approved')
                  AND expires_at <= ?
                """,
                (now, transaction_id, now),
            )
            row = connection.execute(
                """
                SELECT * FROM approvals
                WHERE transaction_id = ? AND status = 'approved' AND expires_at > ?
                  AND (? IS NULL OR plan_digest = ?)
                  AND (? IS NULL OR target_id = ?)
                """,
                (
                    transaction_id,
                    now,
                    expected_digest,
                    expected_digest,
                    expected_target,
                    expected_target,
                ),
            ).fetchone()
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return None if row is None else _approval_record(row)

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    transaction_id TEXT NOT NULL UNIQUE,
                    target_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    notification_required INTEGER NOT NULL DEFAULT 0 CHECK (
                        notification_required IN (0, 1)
                    ),
                    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'approved', 'rejected', 'expired')
                    ),
                    actor TEXT,
                    created_at INTEGER NOT NULL CHECK (created_at >= 0),
                    decided_at INTEGER,
                    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
                    CHECK (length(plan_digest) = 64),
                    CHECK (
                        (status = 'pending' AND actor IS NULL AND decided_at IS NULL)
                        OR status IN ('approved', 'rejected', 'expired')
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_notifications (
                    approval_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL CHECK (
                        status IN ('dispatched', 'delivered', 'failed')
                    ),
                    dispatched_at INTEGER NOT NULL CHECK (dispatched_at >= 0),
                    completed_at INTEGER,
                    FOREIGN KEY (approval_id) REFERENCES approvals(approval_id)
                        ON DELETE CASCADE
                )
                """
            )
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


def _approval_record(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        id=row["approval_id"],
        transaction_id=row["transaction_id"],
        target_id=row["target_id"],
        plan_digest=row["plan_digest"],
        notification_required=bool(row["notification_required"]),
        expires_at=row["expires_at"],
        status=ApprovalStatus(row["status"]),
        actor=row["actor"],
        created_at=row["created_at"],
        decided_at=row["decided_at"],
        updated_at=row["updated_at"],
    )


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


def _validate_actor(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("actor must not be blank")
    if len(value) > _MAX_ACTOR_LENGTH:
        raise ValueError(f"actor must not exceed {_MAX_ACTOR_LENGTH} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("actor must not contain control characters")
    return value


def _validate_time(value: int, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer Unix timestamp")
    return value


def _validate_positive_int(value: int, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be an integer of at least 1")
    return value

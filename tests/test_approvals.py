from __future__ import annotations

import sqlite3

import pytest

from a4diag.approvals import (
    ApprovalDigestMismatchError,
    ApprovalExpiredError,
    ApprovalStateError,
    ApprovalStatus,
    ApprovalStore,
    NotificationStatus,
)


DIGEST = "a" * 64


@pytest.fixture
def store(tmp_path: object) -> ApprovalStore:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    return ApprovalStore(path, request_id_factory=lambda: "approval-1")


def test_changed_digest_or_target_invalidates_approval(store: ApprovalStore) -> None:
    request = store.request("tx-1", "target-1", DIGEST, expires_at=200, now=50)
    approved = store.approve(
        request.id, approved_digest=DIGEST, actor="uid:1000", now=100
    )

    assert store.valid_digest("tx-1", now=101) == DIGEST
    assert (
        store.valid_digest("tx-1", expected_digest="b" * 64, now=101) is None
    )
    assert (
        store.valid_approval(
            "tx-1",
            expected_digest=DIGEST,
            expected_target="target-2",
            now=101,
        )
        is None
    )
    assert approved.id == "approval-1"
    assert approved.plan_digest == DIGEST
    assert approved.actor == "uid:1000"


def test_approval_request_is_recoverable_by_transaction(store: ApprovalStore) -> None:
    requested = store.request("tx-1", "target-1", DIGEST, expires_at=200, now=50)

    assert store.for_transaction("tx-1") == requested
    assert store.for_transaction("missing") is None


def test_notification_dispatch_intent_is_single_and_crash_detectable(
    store: ApprovalStore,
) -> None:
    requested = store.request("tx-1", "target-1", DIGEST, expires_at=200, now=50)

    assert store.begin_notification(requested.id, now=60) is True
    assert store.begin_notification(requested.id, now=61) is False
    assert store.notification_status(requested.id) is NotificationStatus.DISPATCHED

    store.complete_notification(requested.id, delivered=False, now=62)
    assert store.notification_status(requested.id) is NotificationStatus.FAILED


def test_required_notification_must_be_delivered_before_approval(
    store: ApprovalStore,
) -> None:
    requested = store.request(
        "tx-1",
        "target-1",
        DIGEST,
        expires_at=200,
        now=50,
        notification_required=True,
    )
    store.begin_notification(requested.id, now=60)

    with pytest.raises(ApprovalStateError, match="notification"):
        store.approve(
            requested.id, approved_digest=DIGEST, actor="uid:1000", now=70
        )

    store.complete_notification(requested.id, delivered=True, now=80)
    assert store.approve(
        requested.id, approved_digest=DIGEST, actor="uid:1000", now=90
    ).status is ApprovalStatus.APPROVED


def test_approval_expires_at_exact_boundary_and_cannot_be_revived(
    store: ApprovalStore,
) -> None:
    request = store.request("tx-1", "target-1", DIGEST, expires_at=101, now=50)
    store.approve(request.id, approved_digest=DIGEST, actor="uid:1000", now=100)

    assert (
        store.valid_approval(
            "tx-1",
            expected_digest=DIGEST,
            expected_target="target-1",
            now=101,
        )
        is None
    )
    assert store.get(request.id).status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalStateError):
        store.approve(
            request.id, approved_digest=DIGEST, actor="uid:1001", now=100
        )


def test_expired_pending_request_is_terminal(store: ApprovalStore) -> None:
    request = store.request("tx-1", "target-1", DIGEST, expires_at=100, now=50)

    with pytest.raises(ApprovalExpiredError):
        store.approve(request.id, approved_digest=DIGEST, actor="uid:1000", now=100)

    assert store.get(request.id).status is ApprovalStatus.EXPIRED


def test_digest_mismatch_and_blank_actor_leave_request_pending(
    store: ApprovalStore,
) -> None:
    request = store.request("tx-1", "target-1", DIGEST, expires_at=200, now=50)

    with pytest.raises(ApprovalDigestMismatchError):
        store.approve(
            request.id, approved_digest="b" * 64, actor="uid:1000", now=100
        )
    with pytest.raises(ValueError, match="actor"):
        store.approve(request.id, approved_digest=DIGEST, actor="   ", now=100)

    assert store.get(request.id).status is ApprovalStatus.PENDING
    assert store.get(request.id).plan_digest == DIGEST


def test_rejection_is_terminal_and_preserves_digest(store: ApprovalStore) -> None:
    request = store.request("tx-1", "target-1", DIGEST, expires_at=200, now=50)

    rejected = store.reject(request.id, actor="uid:1000", now=80)

    assert rejected.status is ApprovalStatus.REJECTED
    assert rejected.plan_digest == DIGEST
    assert rejected.actor == "uid:1000"
    with pytest.raises(ApprovalStateError):
        store.approve(request.id, approved_digest=DIGEST, actor="uid:1001", now=90)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("transaction_id", ""),
        ("target_id", "bad target"),
        ("digest", "A" * 64),
        ("expires_at", True),
        ("now", -1),
    ],
)
def test_request_rejects_invalid_identifiers_digest_and_times(
    store: ApprovalStore, field: str, value: object
) -> None:
    values: dict[str, object] = {
        "transaction_id": "tx-1",
        "target_id": "target-1",
        "digest": DIGEST,
        "expires_at": 200,
        "now": 50,
    }
    values[field] = value

    with pytest.raises(ValueError):
        store.request(**values)  # type: ignore[arg-type]


def test_schema_uses_wal_foreign_keys_and_coexists_with_legacy_table(
    tmp_path: object,
) -> None:
    path = tmp_path / "state.sqlite3"  # type: ignore[operator]
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE legacy_state (value TEXT NOT NULL)")
        connection.execute("INSERT INTO legacy_state VALUES ('kept')")

    ApprovalStore(path)

    with sqlite3.connect(path) as connection:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        legacy = connection.execute("SELECT value FROM legacy_state").fetchone()[0]
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(approvals)")
        }
    assert journal_mode == "wal"
    assert legacy == "kept"
    assert {"approval_id", "transaction_id", "target_id", "plan_digest"} <= columns

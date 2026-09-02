from __future__ import annotations

import sqlite3

import pytest

from a4diag_target.replay import ReplayLedgerError, SqliteReplayLedger


def test_nonce_is_consumed_once_and_durable_with_request_record(tmp_path) -> None:
    path = tmp_path / "replay.sqlite3"
    ledger = SqliteReplayLedger(path)
    assert ledger.consume_request(
        nonce="nonce-000000000001", expires_at=200, transaction_id="txn-1",
        step_id="0", lifecycle="apply", request_digest="a" * 64, now=100,
    ) is True
    assert ledger.consume_request(
        nonce="nonce-000000000001", expires_at=200, transaction_id="txn-1",
        step_id="0", lifecycle="apply", request_digest="a" * 64, now=101,
    ) is False
    ledger.close()
    reopened = SqliteReplayLedger(path)
    record = reopened.record("nonce-000000000001")
    assert record.transaction_id == "txn-1"
    assert record.request_digest == "a" * 64
    reopened.record_result("nonce-000000000001", "b" * 64, now=110)
    assert reopened.record("nonce-000000000001").result_digest == "b" * 64


def test_inconsistent_schema_fails_closed(tmp_path) -> None:
    path = tmp_path / "bad.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE replay (nonce TEXT)")
    connection.commit()
    connection.close()
    with pytest.raises(ReplayLedgerError, match="schema_invalid"):
        SqliteReplayLedger(path)

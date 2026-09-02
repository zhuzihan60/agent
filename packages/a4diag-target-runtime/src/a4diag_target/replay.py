"""Durable target nonce and result ledger."""

from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COLUMNS = ("nonce", "expires_at", "transaction_id", "step_id", "lifecycle", "request_digest", "result_digest", "consumed_at", "completed_at")


class ReplayLedgerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ReplayRecord:
    nonce: str
    expires_at: int
    transaction_id: str
    step_id: str
    lifecycle: str
    request_digest: str
    result_digest: str | None
    consumed_at: int
    completed_at: int | None


class SqliteReplayLedger:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        tables = self._connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='replay'").fetchone()
        if tables is None:
            self._connection.execute(
                "CREATE TABLE replay (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, transaction_id TEXT NOT NULL, step_id TEXT NOT NULL, lifecycle TEXT NOT NULL, request_digest TEXT NOT NULL, result_digest TEXT, consumed_at INTEGER NOT NULL, completed_at INTEGER)"
            )
        columns = tuple(row[1] for row in self._connection.execute("PRAGMA table_info(replay)"))
        if columns != _COLUMNS:
            self._connection.close()
            raise ReplayLedgerError("schema_invalid")

    def consume(self, nonce: str, expires_at: int) -> bool:
        return self.consume_request(
            nonce=nonce, expires_at=expires_at, transaction_id="unbound",
            step_id="unbound", lifecycle="unbound", request_digest="0" * 64, now=0,
        )

    def consume_request(self, *, nonce: str, expires_at: int, transaction_id: str, step_id: str, lifecycle: str, request_digest: str, now: int) -> bool:
        if not nonce or not _DIGEST.fullmatch(request_digest):
            raise ReplayLedgerError("record_invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT INTO replay VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)",
                    (nonce, expires_at, transaction_id, step_id, lifecycle, request_digest, now),
                )
            except sqlite3.IntegrityError:
                self._connection.execute("ROLLBACK")
                return False
            except sqlite3.Error as exc:
                self._connection.execute("ROLLBACK")
                raise ReplayLedgerError("ledger_unavailable") from exc
            self._connection.execute("COMMIT")
            return True

    def record_result(self, nonce: str, result_digest: str, *, now: int) -> None:
        if not _DIGEST.fullmatch(result_digest):
            raise ReplayLedgerError("record_invalid")
        cursor = self._connection.execute(
            "UPDATE replay SET result_digest=?, completed_at=? WHERE nonce=? AND result_digest IS NULL",
            (result_digest, now, nonce),
        )
        if cursor.rowcount != 1:
            raise ReplayLedgerError("result_record_invalid")

    def record(self, nonce: str) -> ReplayRecord:
        row = self._connection.execute("SELECT * FROM replay WHERE nonce=?", (nonce,)).fetchone()
        if row is None:
            raise ReplayLedgerError("record_missing")
        return ReplayRecord(*row)

    def close(self) -> None:
        self._connection.close()


__all__ = ["ReplayLedgerError", "ReplayRecord", "SqliteReplayLedger"]

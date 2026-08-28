from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path

from .alertmanager import dedup_key
from .models import Alert


class Store:
    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    dedup_key TEXT PRIMARY KEY,
                    alert_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('queued', 'running', 'completed', 'failed')
                    ),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    report_path TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def claim_alert(self, alert: Alert) -> bool:
        payload = json.dumps(asdict(alert), ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO jobs (dedup_key, alert_json, status)
                VALUES (?, ?, 'queued')
                """,
                (dedup_key(alert), payload),
            )
            return cursor.rowcount == 1

    def next_queued(self, limit: int) -> list[Alert]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_json
                FROM jobs
                WHERE status = 'queued'
                ORDER BY created_at, dedup_key
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [Alert(**json.loads(row[0])) for row in rows]

    def reserve_queued(self, max_concurrency: int) -> list[Alert]:
        if max_concurrency != 2:
            raise ValueError("max_concurrency must equal 2")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE status = 'running'"
            ).fetchone()
            assert row is not None
            available = max(0, max_concurrency - int(row[0]))
            if available == 0:
                return []
            rows = connection.execute(
                """
                SELECT dedup_key, alert_json
                FROM jobs
                WHERE status = 'queued'
                ORDER BY created_at, dedup_key
                LIMIT ?
                """,
                (available,),
            ).fetchall()
            reserved: list[Alert] = []
            for key, payload in rows:
                cursor = connection.execute(
                    """
                    UPDATE jobs
                    SET status = 'running', attempts = attempts + 1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE dedup_key = ? AND status = 'queued'
                    """,
                    (key,),
                )
                if cursor.rowcount == 1:
                    reserved.append(Alert(**json.loads(payload)))
            return reserved

    def mark_running(self, alert: Alert) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = 'running', attempts = attempts + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE dedup_key = ? AND status = 'queued'
                """,
                (dedup_key(alert),),
            )

    def mark_completed(self, alert: Alert, report_path: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = 'completed', report_path = ?, last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE dedup_key = ? AND status = 'running'
                """,
                (report_path, dedup_key(alert)),
            )

    def mark_failed(self, alert: Alert, message: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE jobs
                SET status = 'failed', last_error = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE dedup_key = ? AND status = 'running'
                """,
                (message[:2000], dedup_key(alert)),
            )

    def count_by_status(self, status: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE status = ?", (status,)
            ).fetchone()
        assert row is not None
        return int(row[0])

    def recover_interrupted(self) -> dict[str, int]:
        with self._connect() as connection:
            failed = connection.execute(
                """
                UPDATE jobs
                SET status = 'failed', last_error = 'job interrupted twice',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status = 'running' AND attempts >= 2
                """
            ).rowcount
            requeued = connection.execute(
                """
                UPDATE jobs
                SET status = 'queued', last_error = 'job interrupted; requeued once',
                    updated_at = CURRENT_TIMESTAMP
                WHERE status = 'running' AND attempts < 2
                """
            ).rowcount
        return {"requeued": requeued, "failed": failed}

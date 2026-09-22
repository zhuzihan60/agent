"""Persistent per-resource attempt accounting; uncertainty never expires a lock."""
from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path


class RepairLimitError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RepairStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS repair_reservations (
                id TEXT PRIMARY KEY, target_id TEXT NOT NULL, resource TEXT NOT NULL,
                transaction_id TEXT NOT NULL, reserved_at INTEGER NOT NULL,
                started_at INTEGER, outcome TEXT, job_id TEXT,
                UNIQUE(target_id, resource, transaction_id))''')
            db.execute('''CREATE UNIQUE INDEX IF NOT EXISTS repair_resource_lock
                ON repair_reservations(target_id, resource) WHERE outcome IS NULL''')
            db.execute('CREATE TABLE IF NOT EXISTS repair_clock (id INTEGER PRIMARY KEY CHECK(id=1), highwater INTEGER NOT NULL)')

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        return db

    @contextmanager
    def _transaction(self):
        db = None
        try:
            db = self._connect()
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except sqlite3.Error as error:
            raise RepairLimitError('store_unavailable') from error
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def _clock(db, now):
        if type(now) is not int or now < 0:
            raise RepairLimitError('invalid_clock')
        row = db.execute('SELECT highwater FROM repair_clock WHERE id=1').fetchone()
        if row is not None and now < row[0]:
            raise RepairLimitError('clock_rollback')
        db.execute('INSERT OR REPLACE INTO repair_clock VALUES (1, ?)', (now,))

    def reserve(self, target_id: str, resource: str, transaction_id: str,
                now: int, cooldown_seconds: int, hourly_limit: int) -> str:
        if any(not isinstance(v, str) or not v for v in (target_id, resource, transaction_id)):
            raise RepairLimitError('invalid_resource')
        if any(type(v) is not int or v < 1 for v in (cooldown_seconds, hourly_limit)):
            raise RepairLimitError('invalid_limits')
        with self._transaction() as db:
            self._clock(db, now)
            rows = db.execute('SELECT * FROM repair_reservations WHERE target_id=? AND resource=?', (target_id, resource)).fetchall()
            for row in rows:
                if row['transaction_id'] == transaction_id:
                    if row['outcome'] is not None:
                        raise RepairLimitError('attempt_finished')
                    return row['id']
            if any(row['outcome'] is None for row in rows):
                raise RepairLimitError('resource_busy')
            attempts = [max(row['reserved_at'], row['started_at'] or 0) for row in rows]
            if attempts and now - max(attempts) < cooldown_seconds:
                raise RepairLimitError('cooldown')
            if sum(stamp > now - 3600 for stamp in attempts) >= hourly_limit:
                raise RepairLimitError('hourly_limit')
            reservation = uuid.uuid4().hex
            db.execute('INSERT INTO repair_reservations VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)',
                       (reservation, target_id, resource, transaction_id, now))
            return reservation

    def bind_job(self, reservation_id: str, job_id: str) -> None:
        with self._transaction() as db:
            row = db.execute('SELECT * FROM repair_reservations WHERE id=?', (reservation_id,)).fetchone()
            job = self._job(db, job_id)
            if (row is not None and job is not None and row['transaction_id'] == job['transaction_id']
                and row['job_id'] == job_id and row['outcome'] == job['state']
                and job['state'] in ('succeeded', 'failed', 'partial')):
                return
            if row is None or job is None or row['transaction_id'] != job['transaction_id'] or row['job_id'] not in (None, job_id) or row['outcome'] is not None:
                raise RepairLimitError('job_binding_mismatch')
            db.execute('UPDATE repair_reservations SET job_id=? WHERE id=?', (job_id, reservation_id))

    def reservation_for(self, target_id: str, resource: str, transaction_id: str) -> str:
        with self._transaction() as db:
            row = db.execute('SELECT id FROM repair_reservations WHERE target_id=? AND resource=? AND transaction_id=?',
                             (target_id, resource, transaction_id)).fetchone()
            if row is None:
                raise RepairLimitError('reservation_unavailable')
            return row['id']

    def mark_started(self, reservation_id: str, now: int) -> None:
        with self._transaction() as db:
            self._clock(db, now)
            row = db.execute('SELECT * FROM repair_reservations WHERE id=?', (reservation_id,)).fetchone()
            if row is None or row['outcome'] is not None:
                raise RepairLimitError('reservation_unavailable')
            db.execute('UPDATE repair_reservations SET started_at=COALESCE(started_at, ?) WHERE id=?', (now, reservation_id))

    def finish(self, reservation_id: str, outcome: str) -> None:
        with self._transaction() as db:
            row = db.execute('SELECT * FROM repair_reservations WHERE id=?', (reservation_id,)).fetchone()
            if row is None:
                raise RepairLimitError('reservation_unavailable')
            if row['outcome'] is not None:
                if row['outcome'] != outcome:
                    raise RepairLimitError('outcome_mismatch')
                return
            if row['job_id'] is not None:
                job = self._job(db, row['job_id'])
                if job is None or job['state'] not in ('succeeded', 'failed', 'partial') or job['state'] != outcome:
                    raise RepairLimitError('job_not_terminal')
            elif row['started_at'] is not None or outcome != 'cancelled':
                raise RepairLimitError('job_not_terminal')
            db.execute('UPDATE repair_reservations SET outcome=? WHERE id=?', (outcome, reservation_id))

    def finish_job(self, job_id: str, outcome: str) -> None:
        with self._transaction() as db:
            rows = db.execute('SELECT id FROM repair_reservations WHERE job_id=?', (job_id,)).fetchall()
        for row in rows:
            self.finish(row['id'], outcome)

    @staticmethod
    def _job(db, job_id):
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'repair_jobs' in tables:
            return db.execute('SELECT transaction_id, state FROM repair_jobs WHERE id=?', (job_id,)).fetchone()
        if 'controller_repair_jobs' in tables:
            return db.execute('SELECT transaction_id, state FROM controller_repair_jobs WHERE id=?', (job_id,)).fetchone()
        return None

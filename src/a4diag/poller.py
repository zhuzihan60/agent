from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import threading
import hashlib
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .alertmanager import resolve_target_id
from .report import ReportWriter
from .redaction import redact
from .models import Alert
from .store import Store


class AlertSource(Protocol):
    def active_alerts(self) -> list[Alert]: ...


class Poller:
    def __init__(
        self,
        store: Store,
        diagnose: Callable[[Alert], str],
        max_concurrency: int,
        alert_source: AlertSource | None = None,
        poll_interval_seconds: int = 600,
        error_handler: Callable[[Exception], None] | None = None,
    ) -> None:
        if max_concurrency != 2:
            raise ValueError("max_concurrency must equal 2")
        self._store = store
        self._diagnose = diagnose
        self._max_concurrency = max_concurrency
        self._alert_source = alert_source
        if type(poll_interval_seconds) is not int or not 1 <= poll_interval_seconds <= 3600:
            raise ValueError("poll_interval_seconds must be between 1 and 3600")
        self._poll_interval_seconds = poll_interval_seconds
        self._error_handler = error_handler or self._default_error_handler

    def poll_once(self) -> int:
        if self._alert_source is None:
            raise RuntimeError("alert_source is required")
        claimed = 0
        for alert in self._alert_source.active_alerts():
            if self._store.claim_alert(alert):
                claimed += 1
        return claimed

    def process_queued_batch(self) -> int:
        alerts = self._store.reserve_queued(
            max_concurrency=self._max_concurrency
        )
        if not alerts:
            return 0
        with ThreadPoolExecutor(max_workers=self._max_concurrency) as executor:
            futures = {
                executor.submit(self._diagnose, alert): alert for alert in alerts
            }
            for future in as_completed(futures):
                alert = futures[future]
                try:
                    report_path = future.result()
                except Exception as exc:
                    self._store.mark_failed(alert, f"{type(exc).__name__}: {exc}")
                else:
                    self._store.mark_completed(alert, report_path)
        return len(alerts)

    def run_forever(self, stop_event: threading.Event) -> None:
        polling_thread = threading.Thread(
            target=self._poll_loop,
            args=(stop_event,),
            name="a4diag-alert-poller",
            daemon=True,
        )
        polling_thread.start()
        try:
            while not stop_event.is_set():
                processed = self.process_queued_batch()
                if processed == 0:
                    stop_event.wait(1.0)
        finally:
            stop_event.set()
            polling_thread.join(timeout=5.0)

    def _poll_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                self._error_handler(exc)
            stop_event.wait(self._poll_interval_seconds)

    @staticmethod
    def _default_error_handler(exc: Exception) -> None:
        print(
            f"Alertmanager poll failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )


class RuntimePoller:
    """v3 event loop that routes alerts only by registered target_id labels.

    An alert without an explicitly registered ``target_id`` label is dropped:
    there is no IP matching and no fallback to the first configured target.
    Per-alert dedup and results are durable and keyed by fingerprint + start time.
    """

    _terminal_repair_statuses = frozenset(
        {"succeeded", "failed", "rollback_succeeded", "rollback_partial", "rollback_unknown", "read_only"}
    )

    def __init__(
        self,
        runtime: object,
        alert_source: AlertSource | None = None,
        max_concurrency: int = 2,
        poll_interval_seconds: int = 600,
        state_path: Path = Path("/var/lib/a4diag/poller.sqlite3"),
        report_root: Path = Path("/var/lib/a4diag/reports"),
        repair_interval_seconds: float = 1,
    ) -> None:
        if max_concurrency != 2:
            raise ValueError("max_concurrency must equal 2")
        if type(poll_interval_seconds) is not int or not 1 <= poll_interval_seconds <= 3600:
            raise ValueError("poll_interval_seconds must be between 1 and 3600")
        self._runtime = runtime
        if not 0 < repair_interval_seconds <= 5:
            raise ValueError('repair interval must be greater than zero and at most 5 seconds')
        self._repair_interval_seconds = repair_interval_seconds
        self._alert_source = alert_source
        self._poll_interval_seconds = poll_interval_seconds
        self._state_path = Path(state_path)
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._reports = ReportWriter(Path(report_root))
        self._report_lock = threading.Lock()
        self._initialize_state()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._state_path, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize_state(self) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS alert_results (
                event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                result_json TEXT,
                updated_at TEXT NOT NULL
                )"""
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(alert_results)")}
            for name, definition in (
                ("event_json", "TEXT"),
                ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("next_attempt_at", "REAL NOT NULL DEFAULT 0"),
                ("lease_until", "REAL"),
                ("owner_token", "TEXT"),
            ):
                if name not in columns:
                    connection.execute(f"ALTER TABLE alert_results ADD COLUMN {name} {definition}")
            # Old failed rows were permanently deduplicated. They have no
            # replayable payload, so recovery may only resume a checkpoint.
            if "event_json" not in columns:
                connection.execute(
                    "UPDATE alert_results SET status='retry_wait' WHERE status='failed' AND event_json IS NULL"
                )

    def _discover(self, event_id: str, event: dict[str, object]) -> None:
        payload = json.dumps(redact(event), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(payload.encode("utf-8")) > 65_536:
            status, payload, result = "suppressed", None, '{"reason":"alert_payload_too_large"}'
        else:
            status, result = "pending", None
        with self._connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO alert_results(event_id,status,result_json,updated_at,event_json) VALUES(?,?,?,?,?)",
                (event_id, status, result, datetime.now(timezone.utc).isoformat(), payload),
            )

    def _claim(self, event_id: str) -> tuple[str, int, str | None] | None:
        now = time.time()
        token = uuid.uuid4().hex
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE alert_results SET status='processing', attempts=attempts+1,
                   lease_until=?, owner_token=?, updated_at=? WHERE event_id=?
                   AND attempts<5 AND ((status IN ('pending','retry_wait') AND next_attempt_at<=?)
                   OR (status='processing' AND (lease_until<=? OR
                       (lease_until IS NULL AND updated_at<?))))""",
                (now + 60, token, datetime.now(timezone.utc).isoformat(), event_id,
                 now, now, datetime.fromtimestamp(now - 60, timezone.utc).isoformat()),
            )
            if cursor.rowcount != 1:
                return None
            row = connection.execute(
                "SELECT attempts,event_json FROM alert_results WHERE event_id=?", (event_id,)
            ).fetchone()
            return token, int(row[0]), row[1]

    @contextmanager
    def _report_guard(self, event_id: str):
        with self._report_lock:
            cross_process_guard = getattr(self._runtime, "report_guard", None)
            if callable(cross_process_guard):
                with cross_process_guard(event_id):
                    yield
            else:
                yield

    def _row_status(self, event_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute("SELECT status FROM alert_results WHERE event_id=?", (event_id,)).fetchone()
        return None if row is None else str(row[0])

    def _owns_lease(self, event_id: str, token: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM alert_results WHERE event_id=? AND owner_token=? AND status='processing'",
                (event_id, token),
            ).fetchone()
        return row is not None

    def _finish(self, event_id: str, status: str, result: object, token: str | None = None,
                *, override_processing: bool = False) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            if token is None:
                if override_processing:
                    connection.execute(
                        """UPDATE alert_results SET status=?, result_json=?, updated_at=?,
                           owner_token=NULL, lease_until=NULL WHERE event_id=?
                           AND status NOT IN ('succeeded','failed','rollback_succeeded',
                                              'rollback_partial','rollback_unknown','read_only')""",
                        (status, payload, datetime.now(timezone.utc).isoformat(), event_id),
                    )
                else:
                    connection.execute(
                        "UPDATE alert_results SET status=?, result_json=?, updated_at=? WHERE event_id=? AND status!='processing'",
                        (status, payload, datetime.now(timezone.utc).isoformat(), event_id),
                    )
            else:
                connection.execute(
                    """UPDATE alert_results SET status=?, result_json=?, updated_at=?,
                       owner_token=NULL, lease_until=NULL WHERE event_id=? AND owner_token=? AND status='processing'""",
                    (status, payload, datetime.now(timezone.utc).isoformat(), event_id, token),
                )

    def _fail(self, event_id: str, token: str, attempts: int, error: Exception) -> None:
        now = time.time()
        status = "retry_wait" if attempts < 5 else "suppressed"
        message = type(error).__name__
        with self._connect() as connection:
            connection.execute(
                """UPDATE alert_results SET status=?, result_json=?, next_attempt_at=?,
                   owner_token=NULL, lease_until=NULL, updated_at=?
                   WHERE event_id=? AND owner_token=? AND status='processing'""",
                (status, json.dumps({"error": message}), now + min(300, 5 * 4 ** (attempts - 1)),
                 datetime.now(timezone.utc).isoformat(), event_id, token),
            )

    def _keep_lease(self, event_id: str, token: str, stop: threading.Event) -> None:
        while not stop.wait(15):
            with self._connect() as connection:
                if connection.execute(
                    "UPDATE alert_results SET lease_until=? WHERE event_id=? AND owner_token=? AND status='processing'",
                    (time.time() + 60, event_id, token),
                ).rowcount != 1:
                    return

    def _process_due(self) -> int:
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """UPDATE alert_results SET status='suppressed',
                   result_json='{"reason":"attempt_limit"}', owner_token=NULL, lease_until=NULL
                   WHERE attempts>=5 AND ((status IN ('pending','retry_wait') AND next_attempt_at<=?)
                   OR (status='processing' AND (lease_until<=? OR
                       (lease_until IS NULL AND updated_at<?))))""",
                (now, now, datetime.fromtimestamp(now - 60, timezone.utc).isoformat()),
            )
            rows = connection.execute(
                """SELECT event_id FROM alert_results WHERE
                   (status IN ('pending','retry_wait') AND next_attempt_at<=?) OR
                   (status='processing' AND (lease_until<=? OR
                    (lease_until IS NULL AND updated_at<?)))
                   ORDER BY updated_at LIMIT 64""",
                (now, now, datetime.fromtimestamp(now - 60, timezone.utc).isoformat()),
            ).fetchall()
        processed = 0
        for (event_id,) in rows:
            claim = self._claim(event_id)
            if claim is None:
                continue
            token, attempts, event_json = claim
            stop = threading.Event()
            renewer = threading.Thread(target=self._keep_lease, args=(event_id, token, stop), daemon=True)
            renewer.start()
            try:
                atomic_handler = getattr(self._runtime, "handle_alert_event", None)
                if callable(atomic_handler):
                    if event_json is None:
                        recovery = getattr(self._runtime, "resume")
                        result = recovery(event_id)
                    else:
                        result = atomic_handler(json.loads(event_json))
                elif attempts == 1 and event_json is not None:
                    result = self._runtime.handle(json.loads(event_json))
                else:
                    state_reader = getattr(self._runtime, "poller_recovery_state", None)
                    state = state_reader(event_id) if callable(state_reader) else "unsafe"
                    if state == "resumable":
                        result = self._runtime.resume(event_id)
                    elif state == "new" and event_json is not None:
                        result = self._runtime.handle(json.loads(event_json))
                    else:
                        self._finish(event_id, "suppressed", {"reason": "unsafe_to_replay"}, token)
                        processed += 1
                        continue
                report = dict(result.report)
                report.setdefault("task_id", event_id)
                report.setdefault("finished_at", datetime.now(timezone.utc).isoformat())
                with self._report_guard(event_id):
                    if not self._owns_lease(event_id, token):
                        processed += 1
                        continue
                    report_path = self._reports.write(report)
                    self._finish(event_id, str(result.status),
                                 {"transaction_id": result.transaction_id, "report_path": str(report_path)}, token)
            except Exception as error:
                if event_json is None and getattr(error, "code", None) == "unknown_transaction":
                    self._finish(event_id, "suppressed", {"reason": "legacy_checkpoint_missing"}, token)
                else:
                    self._fail(event_id, token, attempts, error)
            finally:
                stop.set()
                renewer.join(timeout=1)
            processed += 1
        return processed

    def poll_once(self) -> int:
        if self._alert_source is None:
            raise RuntimeError("alert_source is required")
        registered = set(self._runtime.registered_target_ids)
        try:
            alerts = self._alert_source.active_alerts()
        except Exception:
            self._process_due()
            raise
        for alert in alerts:
            target_id = resolve_target_id(alert.labels, registered)
            if target_id is None:
                continue
            event_id = "alert-" + hashlib.sha256(
                f"{alert.fingerprint}:{alert.starts_at}".encode("utf-8")
            ).hexdigest()
            self._discover(event_id, {
                        "event_id": event_id,
                        "target_hint": target_id,
                        "request": {
                            "alertname": alert.name,
                            "severity": alert.severity,
                            "fingerprint": alert.fingerprint,
                            "starts_at": alert.starts_at,
                            "labels": alert.labels,
                            "annotations": alert.annotations,
                        },
                    })
        return self._process_due()

    def process_queued_batch(self) -> int:
        return self.heartbeat()

    def heartbeat(self) -> int:
        """S2 scheduling seam: bounded existing-job observations, no model work."""
        results = self._runtime.poll_repair_jobs()
        for result in results:
            with self._report_guard(result.transaction_id):
                row_status = self._row_status(result.transaction_id)
                if row_status in self._terminal_repair_statuses:
                    continue
                terminal = result.status in self._terminal_repair_statuses
                if row_status == "processing" and not terminal:
                    continue
                report = dict(result.report)
                report.setdefault('task_id', result.transaction_id)
                report.setdefault('finished_at', datetime.now(timezone.utc).isoformat())
                path = self._reports.write(report)
                self._finish(result.transaction_id, result.status,
                             {'transaction_id': result.transaction_id, 'report_path': str(path)},
                             override_processing=terminal)
        return len(results)

    def run_forever(self, stop_event: threading.Event) -> None:
        polling_thread = threading.Thread(
            target=self._poll_loop,
            args=(stop_event,),
            name="a4diag-runtime-poller",
            daemon=True,
        )
        if self._alert_source is not None:
            polling_thread.start()
        try:
            while not stop_event.is_set():
                try:
                    self.heartbeat()
                except Exception as error:
                    print(f'Repair heartbeat failed: {type(error).__name__}: {error}', file=sys.stderr, flush=True)
                stop_event.wait(self._repair_interval_seconds)
        finally:
            stop_event.set()
            if polling_thread.ident is not None:
                polling_thread.join(timeout=5.0)

    def _poll_loop(self, stop_event: threading.Event) -> None:
        next_fetch = 0.0
        while not stop_event.is_set():
            try:
                if time.monotonic() >= next_fetch:
                    next_fetch = time.monotonic() + self._poll_interval_seconds
                    self.poll_once()
                else:
                    self._process_due()
            except Exception as exc:
                print(
                    f"Runtime poll failed: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            stop_event.wait(min(1.0, max(0.0, next_fetch - time.monotonic())))

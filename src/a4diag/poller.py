from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import threading
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .alertmanager import resolve_target_id
from .report import ReportWriter
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
        if poll_interval_seconds != 600:
            raise ValueError("poll_interval_seconds must equal 600")
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

    def __init__(
        self,
        runtime: object,
        alert_source: AlertSource | None = None,
        max_concurrency: int = 2,
        poll_interval_seconds: int = 600,
        state_path: Path = Path("/var/lib/a4diag/poller.sqlite3"),
        report_root: Path = Path("/var/lib/a4diag/reports"),
    ) -> None:
        if max_concurrency != 2:
            raise ValueError("max_concurrency must equal 2")
        if poll_interval_seconds != 600:
            raise ValueError("poll_interval_seconds must equal 600")
        self._runtime = runtime
        self._alert_source = alert_source
        self._poll_interval_seconds = poll_interval_seconds
        self._state_path = Path(state_path)
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._reports = ReportWriter(Path(report_root))
        self._initialize_state()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._state_path, timeout=5.0)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize_state(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS alert_results (
                event_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                result_json TEXT,
                updated_at TEXT NOT NULL
                )"""
            )

    def _claim(self, event_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO alert_results(event_id,status,updated_at) VALUES(?,?,?)",
                (event_id, "processing", datetime.now(timezone.utc).isoformat()),
            )
            return cursor.rowcount == 1

    def _finish(self, event_id: str, status: str, result: object) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                "UPDATE alert_results SET status=?, result_json=?, updated_at=? WHERE event_id=?",
                (status, payload, datetime.now(timezone.utc).isoformat(), event_id),
            )

    def poll_once(self) -> int:
        if self._alert_source is None:
            raise RuntimeError("alert_source is required")
        registered = set(self._runtime.registered_target_ids)
        claimed = 0
        for alert in self._alert_source.active_alerts():
            target_id = resolve_target_id(alert.labels, registered)
            if target_id is None:
                continue
            event_id = "alert-" + hashlib.sha256(
                f"{alert.fingerprint}:{alert.starts_at}".encode("utf-8")
            ).hexdigest()
            if not self._claim(event_id):
                continue
            try:
                result = self._runtime.handle(
                    {
                        "event_id": event_id,
                        "target_hint": target_id,
                        "request": {
                            "alertname": alert.name,
                            "severity": alert.severity,
                        },
                    }
                )
                report = dict(result.report)
                report.setdefault("task_id", event_id)
                report.setdefault("finished_at", datetime.now(timezone.utc).isoformat())
                report_path = self._reports.write(report)
                self._finish(
                    event_id,
                    str(result.status),
                    {"transaction_id": result.transaction_id, "report_path": str(report_path)},
                )
            except Exception as error:
                self._finish(
                    event_id,
                    "failed",
                    {"error": f"{type(error).__name__}: {error}"},
                )
                raise
            claimed += 1
        return claimed

    def process_queued_batch(self) -> int:
        # Single-pass loop: unknown executions are resumed explicitly through
        # the runtime, never replayed automatically.
        return 0

    def run_forever(self, stop_event: threading.Event) -> None:
        polling_thread = threading.Thread(
            target=self._poll_loop,
            args=(stop_event,),
            name="a4diag-runtime-poller",
            daemon=True,
        )
        polling_thread.start()
        try:
            while not stop_event.is_set():
                stop_event.wait(1.0)
        finally:
            stop_event.set()
            polling_thread.join(timeout=5.0)

    def _poll_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                print(
                    f"Runtime poll failed: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            stop_event.wait(self._poll_interval_seconds)

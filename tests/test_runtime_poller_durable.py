from __future__ import annotations

from dataclasses import dataclass
import hashlib
import sqlite3
import threading
from contextlib import nullcontext
from types import SimpleNamespace

from a4diag.models import Alert
from a4diag.poller import RuntimePoller


@dataclass
class RuntimeResult:
    status: str
    report: dict
    transaction_id: str


class Source:
    def active_alerts(self):
        return [
            Alert(
                fingerprint="fp-1",
                starts_at="2026-08-28T00:00:00Z",
                name="DiskFull",
                severity="warning",
                target="lab",
                labels={"target_id": "lab"},
                annotations={},
            )
        ]


class MutableSource:
    def __init__(self, alerts):
        self.alerts = alerts

    def active_alerts(self):
        return list(self.alerts)


@dataclass
class Runtime:
    calls: int = 0
    registered_target_ids = frozenset({"lab"})

    def handle(self, event):
        self.calls += 1
        return RuntimeResult(
            status="succeeded",
            report={"status": "succeeded", "transaction_id": event["event_id"]},
            transaction_id=event["event_id"],
        )


def test_runtime_poller_persists_result_and_dedup_across_restart(tmp_path) -> None:
    runtime = Runtime()
    arguments = {
        "runtime": runtime,
        "alert_source": Source(),
        "state_path": tmp_path / "poller.sqlite3",
        "report_root": tmp_path / "reports",
    }

    assert RuntimePoller(**arguments).poll_once() == 1
    assert RuntimePoller(**arguments).poll_once() == 0
    assert runtime.calls == 1
    assert list((tmp_path / "reports").rglob("*.yaml"))


def test_failed_alert_is_retried_after_it_disappears(tmp_path) -> None:
    class FailingOnce(Runtime):
        def handle(self, event):
            self.calls += 1
            if self.calls == 1:
                raise OSError("temporary failure")
            return RuntimeResult("succeeded", {"status": "succeeded"}, event["event_id"])

        def poller_recovery_state(self, event_id):
            return "new"

    runtime = FailingOnce()
    source = MutableSource(Source().active_alerts())
    path = tmp_path / "poller.sqlite3"
    poller = RuntimePoller(runtime, source, state_path=path, report_root=tmp_path / "reports")
    assert poller.poll_once() == 1
    source.alerts = []
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alert_results SET next_attempt_at=0 WHERE status='retry_wait'")
    assert poller.poll_once() == 1
    assert runtime.calls == 2


def test_interrupted_legacy_processing_resumes_without_replaying_alert(tmp_path) -> None:
    class Resumable(Runtime):
        resumed = 0

        def poller_recovery_state(self, event_id):
            return "resumable"

        def resume(self, event_id):
            self.resumed += 1
            return RuntimeResult("succeeded", {"status": "succeeded"}, event_id)

    runtime = Resumable()
    path = tmp_path / "poller.sqlite3"
    poller = RuntimePoller(runtime, MutableSource([]), state_path=path, report_root=tmp_path / "reports")
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO alert_results(event_id,status,updated_at) VALUES(?,?,?)",
                   ("alert-legacy", "processing", "2020-01-01T00:00:00+00:00"))
    assert poller.poll_once() == 1
    assert runtime.calls == 0
    assert runtime.resumed == 1


def test_one_alert_failure_does_not_abort_other_alerts(tmp_path) -> None:
    class FailsFirst(Runtime):
        def handle(self, event):
            self.calls += 1
            if self.calls == 1:
                raise OSError("temporary failure")
            return RuntimeResult("succeeded", {"status": "succeeded"}, event["event_id"])

        def poller_recovery_state(self, event_id):
            return "new"

    alerts = Source().active_alerts()
    alerts.append(Alert("fp-2", "2026-08-28T00:00:00Z", "DiskFull", "warning",
                        "lab", {"target_id": "lab"}, {}))
    runtime = FailsFirst()
    poller = RuntimePoller(runtime, MutableSource(alerts), state_path=tmp_path / "poller.sqlite3",
                           report_root=tmp_path / "reports", poll_interval_seconds=1)
    assert poller.poll_once() == 2
    assert runtime.calls == 2


def test_real_runtime_alert_entry_resumes_existing_checkpoint(monkeypatch) -> None:
    from a4diag.runtime import Runtime as RealRuntime

    runtime = object.__new__(RealRuntime)
    runtime._deps = SimpleNamespace(transactions=SimpleNamespace(workflow_guard=lambda _: nullcontext()))
    runtime._graph = SimpleNamespace(get_state=lambda _: SimpleNamespace(values={"status": "executing"}))
    monkeypatch.setattr(RealRuntime, "_handle", lambda self, event: (_ for _ in ()).throw(AssertionError("replayed")))
    monkeypatch.setattr(RealRuntime, "_resume", lambda self, event_id: RuntimeResult("succeeded", {}, event_id))
    result = runtime.handle_alert_event({"event_id": "alert-existing"})
    assert result.transaction_id == "alert-existing"


def test_real_runtime_alert_entry_refuses_transaction_without_checkpoint(monkeypatch) -> None:
    import pytest
    from a4diag.runtime import Runtime as RealRuntime, RuntimeFailure

    runtime = object.__new__(RealRuntime)
    runtime._deps = SimpleNamespace(transactions=SimpleNamespace(
        workflow_guard=lambda _: nullcontext(), get=lambda _: object()))
    runtime._graph = SimpleNamespace(get_state=lambda _: SimpleNamespace(values={}))
    monkeypatch.setattr(RealRuntime, "_handle", lambda self, event: (_ for _ in ()).throw(AssertionError("replayed")))
    with pytest.raises(RuntimeFailure, match="recovery_checkpoint_missing"):
        runtime.handle_alert_event({"event_id": "alert-existing"})


def test_persisted_alert_payload_redacts_secret_fields(tmp_path) -> None:
    alerts = Source().active_alerts()
    alerts[0].labels["api_token"] = "secret-token-value"
    path = tmp_path / "poller.sqlite3"
    RuntimePoller(Runtime(), MutableSource(alerts), state_path=path,
                  report_root=tmp_path / "reports").poll_once()
    with sqlite3.connect(path) as db:
        payload = db.execute("SELECT event_json FROM alert_results").fetchone()[0]
    assert "secret-token-value" not in payload
    assert '"api_token":"[REDACTED]"' in payload


def test_active_lease_is_not_stolen_and_stale_owner_cannot_finish(tmp_path) -> None:
    path = tmp_path / "poller.sqlite3"
    poller = RuntimePoller(Runtime(), MutableSource([]), state_path=path,
                           report_root=tmp_path / "reports")
    poller._discover("alert-lease", {"event_id": "alert-lease", "target_hint": "lab"})
    first = poller._claim("alert-lease")
    assert first is not None
    assert poller._claim("alert-lease") is None
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alert_results SET lease_until=0 WHERE event_id='alert-lease'")
    second = poller._claim("alert-lease")
    assert second is not None
    poller._finish("alert-lease", "succeeded", {"owner": "stale"}, first[0])
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM alert_results WHERE event_id='alert-lease'").fetchone()[0] == "processing"
    poller._finish("alert-lease", "succeeded", {"owner": "current"}, second[0])
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT result_json FROM alert_results WHERE event_id='alert-lease'").fetchone()[0] == '{"owner":"current"}'


def test_retry_limit_suppresses_without_sixth_attempt(tmp_path) -> None:
    path = tmp_path / "poller.sqlite3"
    runtime = Runtime()
    poller = RuntimePoller(runtime, MutableSource([]), state_path=path,
                           report_root=tmp_path / "reports")
    poller._discover("alert-limit", {"event_id": "alert-limit", "target_hint": "lab"})
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alert_results SET status='retry_wait', attempts=5 WHERE event_id='alert-limit'")
    assert poller.poll_once() == 0
    assert runtime.calls == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM alert_results WHERE event_id='alert-limit'").fetchone()[0] == "suppressed"


def test_legacy_failed_row_resumes_without_replay(tmp_path) -> None:
    class Resumable(Runtime):
        resumed = 0

        def poller_recovery_state(self, event_id):
            return "resumable"

        def resume(self, event_id):
            self.resumed += 1
            return RuntimeResult("succeeded", {"status": "succeeded"}, event_id)

    alert = Source().active_alerts()[0]
    event_id = "alert-" + hashlib.sha256(f"{alert.fingerprint}:{alert.starts_at}".encode()).hexdigest()
    path = tmp_path / "poller.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE alert_results(event_id TEXT PRIMARY KEY,status TEXT NOT NULL,result_json TEXT,updated_at TEXT NOT NULL)")
        db.execute("INSERT INTO alert_results VALUES(?, 'failed',NULL,'2020-01-01T00:00:00+00:00')", (event_id,))
    runtime = Resumable()
    poller = RuntimePoller(runtime, MutableSource([alert]), state_path=path,
                           report_root=tmp_path / "reports")
    assert poller.poll_once() == 1
    assert runtime.resumed == 1
    assert runtime.calls == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT event_json FROM alert_results WHERE event_id=?", (event_id,)).fetchone()[0] is None


def test_due_retry_runs_even_when_alert_source_fails(tmp_path) -> None:
    import pytest

    class BrokenSource:
        def active_alerts(self):
            raise OSError("Alertmanager unavailable")

    runtime = Runtime()
    path = tmp_path / "poller.sqlite3"
    poller = RuntimePoller(runtime, BrokenSource(), state_path=path,
                           report_root=tmp_path / "reports", poll_interval_seconds=1)
    poller._discover("alert-queued", {"event_id": "alert-queued", "target_hint": "lab"})
    with pytest.raises(OSError, match="Alertmanager unavailable"):
        poller.poll_once()
    assert runtime.calls == 1


def test_legacy_failed_without_checkpoint_is_explicitly_suppressed(tmp_path) -> None:
    class MissingCheckpoint(Runtime):
        def poller_recovery_state(self, event_id):
            return "resumable"

        def resume(self, event_id):
            error = ValueError("unknown_transaction")
            error.code = "unknown_transaction"
            raise error

    path = tmp_path / "poller.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE alert_results(event_id TEXT PRIMARY KEY,status TEXT NOT NULL,result_json TEXT,updated_at TEXT NOT NULL)")
        db.execute("INSERT INTO alert_results VALUES('alert-failed','failed',NULL,'2020-01-01T00:00:00+00:00')")
    runtime = MissingCheckpoint()
    poller = RuntimePoller(runtime, MutableSource(Source().active_alerts()),
                           state_path=path, report_root=tmp_path / "reports")
    assert poller.poll_once() == 2
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM alert_results WHERE event_id='alert-failed'").fetchone()[0] == "suppressed"
    assert runtime.calls == 1  # Only the distinct, freshly discovered alert was ingested.


def test_terminal_heartbeat_result_cannot_be_overwritten_by_older_alert_result(tmp_path) -> None:
    class Repairing(Runtime):
        observed = False

        def handle(self, event):
            self.calls += 1
            return RuntimeResult("execution_unknown", {"status": "execution_unknown"}, event["event_id"])

        def poll_repair_jobs(self):
            if self.observed:
                return ()
            self.observed = True
            event_id = "alert-" + hashlib.sha256(b"fp-1:2026-08-28T00:00:00Z").hexdigest()
            return (RuntimeResult("succeeded", {"status": "succeeded"}, event_id),)

    runtime = Repairing()
    path = tmp_path / "poller.sqlite3"
    poller = RuntimePoller(runtime, Source(), state_path=path, report_root=tmp_path / "reports")
    entered, release = threading.Event(), threading.Event()
    original_write = poller._reports.write

    def held_write(report):
        if report["status"] == "execution_unknown":
            entered.set()
            assert release.wait(5)
        return original_write(report)

    poller._reports.write = held_write
    worker = threading.Thread(target=poller.poll_once)
    worker.start()
    assert entered.wait(5)
    heartbeat_result = []
    heartbeat_worker = threading.Thread(target=lambda: heartbeat_result.append(poller.heartbeat()))
    heartbeat_worker.start()
    heartbeat_worker.join(timeout=0.2)
    release.set()
    worker.join(timeout=5)
    heartbeat_worker.join(timeout=5)
    assert not worker.is_alive()
    assert not heartbeat_worker.is_alive()
    assert heartbeat_result == [1]
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM alert_results").fetchone()[0] == "succeeded"
    report = next((tmp_path / "reports").rglob("*.yaml")).read_text(encoding="utf-8")
    assert "status: succeeded" in report

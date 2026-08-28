from __future__ import annotations

from dataclasses import dataclass

from a4diag.models import Alert
from a4diag.poller import RuntimePoller
from a4diag.runtime import RuntimeResult


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

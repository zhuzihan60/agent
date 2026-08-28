"""Alert-to-runtime adapter.

The legacy fixed-target orchestrator is gone: an incoming alert is converted
into a generic v3 runtime event, and the runtime resolves the target ONLY
against registered target ids (never by IP, never by fallback). Reports keep
the on-disk format used by the legacy reader so old reports remain readable;
old v0.3 permissions are never imported into new settings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from .models import Alert
from .report import ReportWriter
from .runtime import Runtime


class Orchestrator:
    """Drive the generic v3 runtime from an Alertmanager alert."""

    def __init__(self, runtime: Runtime, writer: ReportWriter) -> None:
        if not isinstance(runtime, Runtime):
            raise TypeError("runtime must be Runtime")
        if not isinstance(writer, ReportWriter):
            raise TypeError("writer must be ReportWriter")
        self._runtime = runtime
        self._writer = writer

    def run_alert(self, alert: Alert) -> str:
        event_id = uuid4().hex
        result = self._runtime.handle(
            {
                "event_id": event_id,
                "target_hint": alert.target,
                "request": {
                    "alertname": alert.name,
                    "severity": alert.severity,
                    "fingerprint": alert.fingerprint,
                    "starts_at": alert.starts_at,
                },
            }
        )
        report: dict[str, object] = dict(result.report)
        report["task_id"] = event_id
        report["trigger"] = "alertmanager"
        report["alert"] = {
            "name": alert.name,
            "fingerprint": alert.fingerprint,
            "starts_at": alert.starts_at,
            "severity": alert.severity,
            "labels": alert.labels,
            "annotations": alert.annotations,
        }
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        return str(self._writer.write(report))

"""CLI notification plugin: persist a redacted approval event for local review.

The event is written atomically as a JSON file (temp file + replace) so the
local CLI approval command can read it. Everything stored is passed through
the shared redactor; secrets never reach disk.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from a4diag_builtin_plugins.notification_common import (
    BaseNotificationPlugin,
    NotificationReceipt,
    NotificationSendParams,
    format_iso8601,
    new_nonce,
    redact_event,
)

_VERSION = "0.4.0"


class CliNotification(BaseNotificationPlugin):
    def __init__(
        self,
        *,
        event_dir: Path,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(name="notification-cli", version=_VERSION)
        self._event_dir = Path(event_dir)
        self._clock = clock or time.time
        self._nonce_factory = nonce_factory

    def send(self, params: NotificationSendParams) -> NotificationReceipt:
        event = params.event
        delivered_at = format_iso8601(self._clock)
        payload = {**redact_event(event), "delivered_at": delivered_at}
        self._event_dir.mkdir(parents=True, exist_ok=True)
        path = self._event_dir / f"{event.plan_digest}-{new_nonce(self._nonce_factory)}.json"
        temp = path.with_suffix(".tmp")
        temp.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temp, path)
        return NotificationReceipt(
            channel="cli", external_id=path.stem, delivered_at=delivered_at
        )


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "notification-cli is started by the plugin supervisor with its manifest"
    )


__all__ = ["CliNotification", "main"]

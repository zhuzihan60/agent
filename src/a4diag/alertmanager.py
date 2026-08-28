from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.request import Request, urlopen

from .models import Alert


def resolve_target_id(
    labels: Mapping[str, str], registered_target_ids: set[str] | frozenset[str]
) -> str | None:
    """Route an alert only by an explicitly registered ``target_id`` label.

    IP/hostname labels never select a target: an unregistered or missing
    ``target_id`` yields ``None`` (the caller must drop the alert), and there
    is no fallback to a first configured target.
    """
    if not isinstance(labels, Mapping):
        raise TypeError("labels must be a mapping")
    candidate = labels.get("target_id")
    if isinstance(candidate, str) and candidate in registered_target_ids:
        return candidate
    return None


def dedup_key(alert: Alert) -> str:
    return f"{alert.fingerprint}:{alert.starts_at}"


class AlertmanagerClient:
    def __init__(
        self,
        config: object,
        registered_target_ids: set[str] | frozenset[str] | None = None,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        url = getattr(config, "url", None)
        if not isinstance(url, str):
            url = getattr(config, "alertmanager_url", None)
        if not isinstance(url, str) or not url:
            raise TypeError("config must provide an alertmanager URL")
        self._url = url.rstrip("/")
        timeout = getattr(config, "timeout_seconds", 5.0)
        self._timeout_seconds = float(timeout)
        if registered_target_ids is None:
            targets = getattr(config, "targets", ())
            registered_target_ids = set(targets)
        self._registered_target_ids = frozenset(registered_target_ids)
        self._opener = opener

    def active_alerts(self) -> list[Alert]:
        request = Request(
            f"{self._url}/api/v2/alerts",
            headers={"Accept": "application/json"},
            method="GET",
        )
        with self._opener(request, timeout=self._timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Alertmanager response must be a list")
        return [alert for row in payload if (alert := self.normalize(row)) is not None]

    def normalize(self, row: object) -> Alert | None:
        if not isinstance(row, dict):
            return None
        status = row.get("status")
        if not isinstance(status, dict) or status.get("state") != "active":
            return None
        labels = self._string_mapping(row.get("labels"))
        annotations = self._string_mapping(row.get("annotations"))
        if labels is None or annotations is None:
            return None

        fingerprint = row.get("fingerprint")
        starts_at = row.get("startsAt")
        name = labels.get("alertname")
        if not all(isinstance(value, str) and value for value in (
            fingerprint,
            starts_at,
            name,
        )):
            return None

        target_id = resolve_target_id(labels, self._registered_target_ids)
        if target_id is None:
            return None
        severity = labels.get("severity", "warning")
        if severity not in {"info", "warning", "critical"}:
            severity = "warning"
        return Alert(
            fingerprint=fingerprint,
            starts_at=starts_at,
            name=name,
            severity=severity,
            target=target_id,
            labels=labels,
            annotations=annotations,
        )

    @staticmethod
    def _string_mapping(value: object) -> dict[str, str] | None:
        if not isinstance(value, dict):
            return None
        if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
            return None
        return dict(value)

"""FlashDuty notification plugin: standard alert push with secret key header.

The integration key is resolved from a secret reference and sent only in the
``X-Flashduty-Integration-Key`` header. The payload is the standard FlashDuty
alert schema carrying the redacted event; retries cover connection errors, 429,
and 5xx only.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from a4diag.domain import Risk, canonical_json_bytes
from a4diag_builtin_plugins.notification_common import (
    BaseNotificationPlugin,
    HttpTransport,
    NotificationError,
    NotificationEvent,
    NotificationReceipt,
    NotificationSendParams,
    SecretResolver,
    format_iso8601,
    redact_event,
    retry_post,
)

_VERSION = "0.4.1"
_SAFE_REF = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$")


class FlashDutyConfig(BaseModel):
    """Strict immutable FlashDuty endpoint; the key is a reference only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    integration_key_ref: str
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=300.0)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise ValueError("url must be a bounded https URL")
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("url must be an absolute https URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("url must not contain credentials")
        return value

    @field_validator("integration_key_ref")
    @classmethod
    def validate_key_ref(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_REF.fullmatch(value):
            raise ValueError("integration_key_ref must be a safe secret reference")
        return value


class FlashDutyNotification(BaseNotificationPlugin):
    def __init__(
        self,
        *,
        http: HttpTransport,
        secrets: SecretResolver,
        config: FlashDutyConfig,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if not isinstance(config, FlashDutyConfig):
            raise TypeError("config must be FlashDutyConfig")
        super().__init__(name="notification-flashduty", version=_VERSION)
        self._http = http
        self._secrets = secrets
        self._config = config
        self._clock = clock or time.time
        self._sleep = sleep

    def send(self, params: NotificationSendParams) -> NotificationReceipt:
        event = params.event
        payload = {
            "event_action": "trigger",
            "event_status": "Critical" if event.risk is Risk.HIGH else "Warning",
            "event_description": self._description(event),
            "incident_key": event.plan_digest,
            "occurred_at": event.occurred_at,
            "details": redact_event(event),
        }
        body = canonical_json_bytes(payload)
        headers = {
            "Content-Type": "application/json",
            "X-Flashduty-Integration-Key": self._secrets.resolve(
                self._config.integration_key_ref
            ),
        }
        result = retry_post(
            self._http,
            url=self._config.url,
            headers=headers,
            body=body,
            timeout_seconds=float(self._config.timeout_seconds),
            sleep=self._sleep,
        )
        external_id = self._parse_external_id(result.body, event.plan_digest)
        return NotificationReceipt(
            channel="flashduty",
            external_id=external_id,
            delivered_at=format_iso8601(self._clock),
        )

    def _description(self, event: NotificationEvent) -> str:
        redacted = redact_event(event)
        lines = [
            f"target: {redacted['target_id']}",
            f"plan_digest: {redacted['plan_digest']}",
            f"risk: {redacted['risk']}",
            f"status: {redacted['status']}",
            "operations: "
            + "; ".join(str(operation.get("action", "")) for operation in redacted["operations"]),
            "verify: " + "; ".join(redacted["verify"]),
            "undo: " + "; ".join(redacted["undo"]),
            f"message: {redacted['message']}",
        ]
        return " | ".join(lines)

    def _parse_external_id(self, response_body: str, fallback: str) -> str:
        try:
            response = json.loads(response_body)
            if type(response) is dict:
                event = response.get("event")
                if type(event) is dict and type(event.get("id")) is str and event["id"]:
                    return event["id"]
                if type(response.get("id")) is str and response["id"]:
                    return response["id"]
        except (ValueError, TypeError):
            raise NotificationError("schema_error") from None
        return fallback


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "notification-flashduty is started by the plugin supervisor with its manifest"
    )


__all__ = ["FlashDutyConfig", "FlashDutyNotification", "main"]

"""Webhook notification plugin: canonical JSON with optional HMAC signature.

The payload is canonical sorted JSON containing a timestamp, a nonce, and the
redacted event. When an HMAC secret reference is configured, the signature
``sha256=<hex>`` covers the exact canonical body bytes and is sent in the
``X-A4Diag-Signature`` header; the key itself never leaves the resolver.
Retries cover connection errors, 429, and 5xx only.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from a4diag_builtin_plugins.notification_common import (
    BaseNotificationPlugin,
    HttpTransport,
    NotificationReceipt,
    NotificationSendParams,
    SecretResolver,
    canonical_body,
    format_iso8601,
    hmac_sha256_hex,
    new_nonce,
    redact_event,
    retry_post,
)

_VERSION = "0.4.2"
_SAFE_REF = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$")


class WebhookConfig(BaseModel):
    """Strict immutable webhook endpoint; the HMAC key is a reference only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    hmac_secret_ref: str | None = None
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

    @field_validator("hmac_secret_ref")
    @classmethod
    def validate_key_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_REF.fullmatch(value):
            raise ValueError("hmac_secret_ref must be a safe secret reference")
        return value


class WebhookNotification(BaseNotificationPlugin):
    def __init__(
        self,
        *,
        http: HttpTransport,
        secrets: SecretResolver,
        config: WebhookConfig,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], str] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if not isinstance(config, WebhookConfig):
            raise TypeError("config must be WebhookConfig")
        super().__init__(name="notification-webhook", version=_VERSION)
        self._http = http
        self._secrets = secrets
        self._config = config
        self._clock = clock or time.time
        self._nonce_factory = nonce_factory
        self._sleep = sleep

    def send(self, params: NotificationSendParams) -> NotificationReceipt:
        event = params.event
        timestamp = format_iso8601(self._clock)
        nonce = new_nonce(self._nonce_factory)
        payload = {
            "timestamp": timestamp,
            "nonce": nonce,
            "event": redact_event(event),
        }
        body = canonical_body(payload)
        headers = {"Content-Type": "application/json"}
        if self._config.hmac_secret_ref is not None:
            key = self._secrets.resolve(self._config.hmac_secret_ref)
            headers["X-A4Diag-Signature"] = "sha256=" + hmac_sha256_hex(key, body)
        retry_post(
            self._http,
            url=self._config.url,
            headers=headers,
            body=body,
            timeout_seconds=float(self._config.timeout_seconds),
            sleep=self._sleep,
        )
        return NotificationReceipt(
            channel="webhook", external_id=nonce, delivered_at=timestamp
        )


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "notification-webhook is started by the plugin supervisor with its manifest"
    )


__all__ = ["WebhookConfig", "WebhookNotification", "main"]

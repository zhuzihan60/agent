"""Shared strict contract types for the built-in notification plugins.

Notification ``send`` is not an approval action: it carries an already-typed
``NotificationEvent`` and produces a ``NotificationReceipt``. Secrets are
resolved inside each channel adapter through the injected resolver and are
never written to events, logs, manifests, or delivered payloads. A package-
local recursive redactor scrubs secret-shaped text until Phase 3 centralizes
the shared core redaction service. HTTP retries cover only connection errors,
429, and 5xx with a bounded injected backoff; 4xx, TLS, and schema failures
never retry.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import ssl
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from a4diag.domain import Risk, canonical_json_bytes
from a4diag.plugin_api.protocol import (
    EmptyParams,
    MethodBinding,
    MethodKind,
)

from a4diag_builtin_plugins.transport_common import (
    CapabilityProbeResult,
    DescribeResult,
    HealthResult,
    PLUGIN_TYPE,
)

API_VERSION = "1.0"
MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 2.0
MAX_BODY_BYTES = 1_048_576

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_REDACTED = "[REDACTED]"
_SECRET_KEY_NAMES = frozenset(
    {"token", "key", "secret", "password", "api_key", "apikey", "authorization"}
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:token|key|secret|password|api[_-]?key|authorization)\s*[=:]\s*)(?!Bearer\b)[^\s,;]+"
)
_BEARER = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+")


class NotificationError(RuntimeError):
    """Stable typed notification failure that never contains credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class NotificationReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel: str
    external_id: str
    delivered_at: str


class NotificationEvent(BaseModel):
    """Already-typed, bounded event sent to one notification channel."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    plan_digest: str
    risk: Risk
    status: str
    message: str
    operations: tuple[dict[str, JsonValue], ...] = ()
    equivalent_commands: tuple[str, ...] = ()
    verify: tuple[str, ...] = ()
    undo: tuple[str, ...] = ()
    occurred_at: str = ""

    @field_validator("target_id")
    @classmethod
    def validate_target_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _TARGET_ID.fullmatch(value):
            raise ValueError("target_id must be a safe identifier")
        return value

    @field_validator("plan_digest")
    @classmethod
    def validate_plan_digest(cls, value: str) -> str:
        if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
            raise ValueError("plan_digest must be a lowercase SHA256 digest")
        return value

    @field_validator("status", "message", "occurred_at")
    @classmethod
    def validate_text(cls, value: str, info: object) -> str:
        label = getattr(info, "field_name", "field")
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError(f"{label} must be a bounded string")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError(f"{label} must not contain control characters")
        return value

    @field_validator("operations")
    @classmethod
    def validate_operations(
        cls, values: tuple[dict[str, JsonValue], ...]
    ) -> tuple[dict[str, JsonValue], ...]:
        if len(values) > 20:
            raise ValueError("operations must not exceed 20 entries")
        for value in values:
            canonical_json_bytes(value, max_bytes=64 * 1024)
        return values

    @field_validator("equivalent_commands", "verify", "undo")
    @classmethod
    def validate_string_lists(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        label = getattr(info, "field_name", "field")
        if len(values) > 20:
            raise ValueError(f"{label} must not exceed 20 entries")
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError(f"{label} entries must be bounded nonblank strings")
            if any(ord(character) < 32 or ord(character) == 127 for character in value):
                raise ValueError(f"{label} entries must not contain control characters")
        return values


class HttpResult:
    __slots__ = ("status", "body")

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body


class HttpTransport(Protocol):
    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        *,
        timeout_seconds: float,
    ) -> HttpResult: ...


class SecretResolver(Protocol):
    def resolve(self, ref: str) -> str: ...


def redact_text(value: str) -> str:
    """Scrub secret-shaped assignments and bearer tokens from a string."""
    if not isinstance(value, str):
        return value
    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{_REDACTED}", value
    )
    value = _BEARER.sub(lambda match: f"{match.group(1)}{_REDACTED}", value)
    return value


def redact_value(value: JsonValue) -> JsonValue:
    """Recursively redact secret-keyed values and secret-shaped strings."""
    if type(value) is dict:
        redacted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if key.lower() in _SECRET_KEY_NAMES:
                redacted[key] = _REDACTED
            else:
                redacted[key] = redact_value(item)
        return redacted
    if type(value) is list:
        return [redact_value(item) for item in value]
    if type(value) is str:
        return redact_text(value)
    return value


def redact_event(event: NotificationEvent) -> dict[str, JsonValue]:
    """Return the redacted canonical event payload used by every channel."""
    payload = event.model_dump(mode="json")
    return redact_value(payload)  # type: ignore[return-value]


def format_iso8601(clock: Callable[[], float]) -> str:
    seconds = clock()
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def new_nonce(nonce_factory: Callable[[], str] | None) -> str:
    if nonce_factory is not None:
        return nonce_factory()
    return uuid.uuid4().hex


def retry_post(
    http: HttpTransport,
    *,
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: float,
    max_attempts: int = MAX_ATTEMPTS,
    sleep: Callable[[float], None] | None = None,
) -> HttpResult:
    """POST with bounded retries for connection errors, 429, and 5xx only."""
    sleeper = sleep or time.sleep
    last_connection_error: Exception | None = None
    for attempt in range(max_attempts):
        try:
            result = http.post(url, headers, body, timeout_seconds=timeout_seconds)
        except ssl.SSLError as error:
            raise NotificationError("tls_error") from error
        except ConnectionError as error:
            last_connection_error = error
        except TimeoutError as error:
            last_connection_error = error
        else:
            if result.status == 429 or 500 <= result.status <= 599:
                if attempt + 1 < max_attempts:
                    sleeper(_backoff(attempt))
                    continue
                raise NotificationError("http_retry_exhausted")
            if not 200 <= result.status < 300:
                raise NotificationError("http_error")
            if len(result.body) > MAX_BODY_BYTES:
                raise NotificationError("schema_error")
            return result
        if attempt + 1 < max_attempts:
            sleeper(_backoff(attempt))
            continue
    assert last_connection_error is not None
    raise NotificationError("connection_failed") from last_connection_error


def _backoff(attempt: int) -> float:
    return min(BACKOFF_BASE_SECONDS * (2 ** attempt), BACKOFF_MAX_SECONDS)


def hmac_sha256_hex(key: str, body: bytes) -> str:
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def canonical_body(payload: dict[str, JsonValue]) -> bytes:
    return canonical_json_bytes(payload, max_bytes=MAX_BODY_BYTES)


class BaseNotificationPlugin:
    """Shared notification behavior: mandatory methods and fixed bindings."""

    def __init__(
        self,
        *,
        name: str,
        version: str,
    ) -> None:
        self._name = name
        self._version = version

    def health(self, params: EmptyParams) -> HealthResult:
        return HealthResult(ok=True)

    def describe(self, params: EmptyParams) -> DescribeResult:
        return DescribeResult(
            name=self._name,
            plugin_type=PLUGIN_TYPE,
            version=self._version,
            api_version=API_VERSION,
        )

    def capability_probe(self, params: EmptyParams) -> CapabilityProbeResult:
        return CapabilityProbeResult(
            read_capable=True,
            write_capable=True,
            read_risk_floor=Risk.LOW,
            write_risk_floor=Risk.HIGH,
            reason=None,
        )

    def send(self, params: object) -> NotificationReceipt:  # pragma: no cover - abstract
        raise NotImplementedError


def build_notification_bindings(
    plugin: BaseNotificationPlugin,
) -> dict[str, MethodBinding[Any, Any]]:
    """Register the fixed notification surface with the shared host."""
    return {
        "health": MethodBinding(
            "health", EmptyParams, HealthResult, plugin.health, kind=MethodKind.READ
        ),
        "describe": MethodBinding(
            "describe",
            EmptyParams,
            DescribeResult,
            plugin.describe,
            kind=MethodKind.READ,
        ),
        "capability_probe": MethodBinding(
            "capability_probe",
            EmptyParams,
            CapabilityProbeResult,
            plugin.capability_probe,
            kind=MethodKind.READ,
        ),
        "send": MethodBinding(
            "send",
            NotificationSendParams,
            NotificationReceipt,
            plugin.send,
            kind=MethodKind.NOTIFICATION,
        ),
    }


class NotificationSendParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event: NotificationEvent


__all__ = [
    "API_VERSION",
    "BACKOFF_BASE_SECONDS",
    "BACKOFF_MAX_SECONDS",
    "BaseNotificationPlugin",
    "HttpResult",
    "HttpTransport",
    "MAX_ATTEMPTS",
    "NotificationError",
    "NotificationEvent",
    "NotificationReceipt",
    "NotificationSendParams",
    "SecretResolver",
    "build_notification_bindings",
    "canonical_body",
    "format_iso8601",
    "hmac_sha256_hex",
    "new_nonce",
    "redact_event",
    "redact_text",
    "redact_value",
    "retry_post",
]

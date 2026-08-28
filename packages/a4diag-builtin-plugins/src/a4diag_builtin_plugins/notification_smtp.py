"""SMTP notification plugin: TLS-protected text/plain delivery.

The client is injected so tests never touch a real mail server. STARTTLS (or
implicit TLS by construction of the injected client) with certificate
verification, secret-reference credentials, and a UTF-8 text/plain message
carry the redacted approval event. TLS and authentication failures are typed
and never retried.
"""

from __future__ import annotations

import re
import ssl
import time
from collections.abc import Callable
from email.message import EmailMessage
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from a4diag_builtin_plugins.notification_common import (
    BaseNotificationPlugin,
    NotificationError,
    NotificationEvent,
    NotificationReceipt,
    NotificationSendParams,
    SecretResolver,
    format_iso8601,
    new_nonce,
    redact_event,
)

_VERSION = "0.4.1"
_SAFE_REF = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class SmtpClient(Protocol):
    """Minimal injected SMTP surface (smtplib-compatible subset)."""

    def starttls(self) -> None: ...
    def login(self, user: str, password: str) -> None: ...
    def send_message(self, message: Any) -> None: ...
    def quit(self) -> None: ...


class SmtpConfig(BaseModel):
    """Strict immutable SMTP endpoint; credentials are references only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=1, le=65535)
    tls_mode: Literal["starttls", "implicit"]
    user_ref: str
    password_ref: str
    from_addr: str
    to_addrs: tuple[str, ...] = Field(min_length=1, max_length=10)
    subject: str
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=300.0)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if not isinstance(value, str) or not _HOST.fullmatch(value):
            raise ValueError("host must be a safe hostname")
        return value

    @field_validator("user_ref", "password_ref")
    @classmethod
    def validate_refs(cls, value: str, info: object) -> str:
        if not isinstance(value, str) or not _SAFE_REF.fullmatch(value):
            raise ValueError(
                f"{getattr(info, 'field_name', 'ref')} must be a safe secret reference"
            )
        return value

    @field_validator("from_addr", "to_addrs")
    @classmethod
    def validate_addresses(cls, value: object, info: object) -> object:
        label = getattr(info, "field_name", "address")
        addresses = value if isinstance(value, tuple) else (value,)
        for address in addresses:
            if not isinstance(address, str) or not _EMAIL.fullmatch(address):
                raise ValueError(f"{label} must be a valid email address")
        return value

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ValueError("subject must be a bounded nonblank string")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("subject must not contain control characters")
        return value


class SmtpNotification(BaseNotificationPlugin):
    def __init__(
        self,
        *,
        client: SmtpClient,
        secrets: SecretResolver,
        config: SmtpConfig,
        clock: Callable[[], float] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(config, SmtpConfig):
            raise TypeError("config must be SmtpConfig")
        super().__init__(name="notification-smtp", version=_VERSION)
        self._client = client
        self._secrets = secrets
        self._config = config
        self._clock = clock or time.time
        self._nonce_factory = nonce_factory

    def send(self, params: NotificationSendParams) -> NotificationReceipt:
        event = params.event
        message = self._build_message(event)
        try:
            if self._config.tls_mode == "starttls":
                self._client.starttls()
            user = self._secrets.resolve(self._config.user_ref)
            password = self._secrets.resolve(self._config.password_ref)
            self._client.login(user, password)
            self._client.send_message(message)
        except NotificationError:
            raise
        except ssl.SSLError as error:
            raise NotificationError("tls_error") from error
        except Exception as error:
            raise NotificationError("send_failed") from error
        finally:
            try:
                self._client.quit()
            except Exception:
                pass
        return NotificationReceipt(
            channel="smtp",
            external_id=str(message["Message-ID"]),
            delivered_at=format_iso8601(self._clock),
        )

    def _build_message(self, event: NotificationEvent) -> EmailMessage:
        redacted = redact_event(event)
        message = EmailMessage()
        message["From"] = self._config.from_addr
        message["To"] = ", ".join(self._config.to_addrs)
        message["Subject"] = self._config.subject
        message["Message-ID"] = (
            f"<a4diag-{event.plan_digest[:12]}-{new_nonce(self._nonce_factory)}@a4diag>"
        )
        message["Date"] = format_iso8601(self._clock)
        body_lines = [
            f"target: {redacted['target_id']}",
            f"plan_digest: {redacted['plan_digest']}",
            f"risk: {redacted['risk']}",
            f"status: {redacted['status']}",
            f"message: {redacted['message']}",
            "operations: " + str(redacted["operations"]),
            "equivalent commands: " + "; ".join(redacted["equivalent_commands"]),
            "verify: " + "; ".join(redacted["verify"]),
            "undo: " + "; ".join(redacted["undo"]),
        ]
        message.set_content("\n".join(body_lines))
        return message


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "notification-smtp is started by the plugin supervisor with its manifest"
    )


__all__ = ["SmtpClient", "SmtpConfig", "SmtpNotification", "main"]

"""Contract tests for the CLI, FlashDuty, SMTP, and Webhook notification plugins.

No real email, FlashDuty push, webhook delivery, or server connection is ever
made: HTTP goes through an injected fake transport and SMTP through an
injected fake client. Retries are driven by an injected clock/sleep so no test
sleeps, and secrets exist only in the fake resolver, never in code, manifests,
logs, or delivered payloads.
"""

from __future__ import annotations

import json
import ssl
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from a4diag.domain import Risk
from a4diag.plugin_api.manifest import PluginManifest, PluginType
from a4diag.plugin_api.protocol import MethodKind

from a4diag_builtin_plugins.notification_common import (
    HttpResult,
    NotificationError,
    NotificationEvent,
    NotificationReceipt,
    NotificationSendParams,
    build_notification_bindings,
    redact_text,
)
from a4diag_builtin_plugins.notification_cli import CliNotification
from a4diag_builtin_plugins.notification_flashduty import (
    FlashDutyConfig,
    FlashDutyNotification,
)
from a4diag_builtin_plugins.notification_smtp import (
    SmtpClient,
    SmtpConfig,
    SmtpNotification,
)
from a4diag_builtin_plugins.notification_webhook import (
    WebhookConfig,
    WebhookNotification,
)

MANIFEST_ROOT = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "a4diag-builtin-plugins"
    / "manifests"
)
FLASHDUTY_KEY = "flashduty-secret-key"
WEBHOOK_KEY = "webhook-hmac-secret"
SMTP_PASSWORD = "smtp-secret-password"
FIXED_CLOCK = 1_700_000_000.0
DIGEST = "a" * 64


class FakeSecrets:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = values or {
            "notification:flashduty-integration-key": FLASHDUTY_KEY,
            "notification:webhook-hmac-key": WEBHOOK_KEY,
            "notification:smtp-user": "notify@example.test",
            "notification:smtp-password": SMTP_PASSWORD,
        }

    def resolve(self, ref: str) -> str:
        return self.values[ref]


class FakeHttp:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.statuses: list[int] = []
        self.error: Exception | None = None
        self.error_attempts = 1

    def post(self, url: str, headers: dict[str, str], body: bytes, *, timeout_seconds: float) -> HttpResult:
        self.requests.append(
            {"url": url, "headers": headers, "body": body, "timeout": timeout_seconds}
        )
        if self.error is not None and len(self.requests) <= self.error_attempts:
            raise self.error
        status = self.statuses[min(len(self.requests) - 1, len(self.statuses) - 1)] if self.statuses else 200
        return HttpResult(status=status, body="{}")


class FakeSmtp:
    def __init__(self) -> None:
        self.starttls_called = False
        self.login_args: tuple[str, str] | None = None
        self.sent: list[str] = []
        self.error: Exception | None = None

    def starttls(self) -> None:
        self.starttls_called = True

    def login(self, user: str, password: str) -> None:
        self.login_args = (user, password)
        if self.error is not None:
            raise self.error

    def send_message(self, message: Any) -> None:
        self.sent.append(message.as_string() if hasattr(message, "as_string") else str(message))

    def quit(self) -> None:
        pass


def no_op_sleep(_seconds: float) -> None:
    pass


def notification_event(**updates: object) -> NotificationEvent:
    values: dict[str, object] = {
        "target_id": "lab",
        "plan_digest": DIGEST,
        "risk": Risk.HIGH,
        "status": "pending_approval",
        "message": "approval required",
        "operations": (
            {
                "capability": "services",
                "action": "restart",
                "resource": "example.service",
            },
        ),
        "equivalent_commands": ("systemctl restart example.service",),
        "verify": ("ActiveState=active",),
        "undo": ("systemctl stop example.service",),
        "occurred_at": "2026-08-26T10:00:00Z",
    }
    secret = updates.pop("secret", None)
    if secret is not None:
        values["message"] = f"approval required; token={secret}"
    values.update(updates)
    return NotificationEvent.model_validate(values)


def send(plugin: Any, event: NotificationEvent) -> NotificationReceipt:
    return plugin.send(NotificationSendParams(event=event))


def cli_notification(directory: Path) -> CliNotification:
    return CliNotification(
        event_dir=directory,
        clock=lambda: FIXED_CLOCK,
        nonce_factory=lambda: "nonce-1",
    )


def flashduty_notification(
    http: FakeHttp | None = None,
    *,
    url: str = "https://api.flashduty.example.com/event/push",
    secrets: FakeSecrets | None = None,
) -> FlashDutyNotification:
    return FlashDutyNotification(
        http=http or FakeHttp(),
        secrets=secrets or FakeSecrets(),
        config=FlashDutyConfig(
            url=url,
            integration_key_ref="notification:flashduty-integration-key",
            timeout_seconds=10.0,
        ),
        clock=lambda: FIXED_CLOCK,
        sleep=no_op_sleep,
    )


def smtp_notification(
    smtp: FakeSmtp | None = None,
    *,
    tls_mode: str = "starttls",
    secrets: FakeSecrets | None = None,
) -> SmtpNotification:
    return SmtpNotification(
        client=smtp or FakeSmtp(),
        secrets=secrets or FakeSecrets(),
        config=SmtpConfig(
            host="smtp.example.test",
            port=587,
            tls_mode=tls_mode,
            user_ref="notification:smtp-user",
            password_ref="notification:smtp-password",
            from_addr="a4diag@example.test",
            to_addrs=("ops@example.test",),
            subject="A4Diag approval event",
            timeout_seconds=10.0,
        ),
        clock=lambda: FIXED_CLOCK,
        nonce_factory=lambda: "nonce-1",
    )


def webhook_notification(
    http: FakeHttp | None = None,
    *,
    url: str = "https://hooks.example.test/a4diag",
    secrets: FakeSecrets | None = None,
) -> WebhookNotification:
    return WebhookNotification(
        http=http or FakeHttp(),
        secrets=secrets or FakeSecrets(),
        config=WebhookConfig(
            url=url,
            hmac_secret_ref="notification:webhook-hmac-key",
            timeout_seconds=10.0,
        ),
        clock=lambda: FIXED_CLOCK,
        nonce_factory=lambda: "nonce-1",
        sleep=no_op_sleep,
    )


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------


def test_redactor_scrubs_secret_patterns() -> None:
    assert redact_text("login token=abc123 please") == "login token=[REDACTED] please"
    assert redact_text("password: hunter2") == "password: [REDACTED]"
    assert redact_text("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer [REDACTED]"
    assert redact_text("plain message") == "plain message"


def test_event_rejects_unsafe_fields() -> None:
    with pytest.raises(ValidationError):
        notification_event(plan_digest="not-a-digest")
    with pytest.raises(ValidationError):
        notification_event(target_id="not safe")
    with pytest.raises(ValidationError):
        notification_event(operations=("not-a-dict",))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_persists_redacted_approval_event(tmp_path: Path) -> None:
    plugin = cli_notification(tmp_path)

    receipt = send(plugin, notification_event(secret="token-value"))

    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    content = json.loads(files[0].read_text(encoding="utf-8"))
    assert content["plan_digest"] == DIGEST
    assert content["target_id"] == "lab"
    assert content["risk"] == "high"
    assert content["status"] == "pending_approval"
    assert "restart" in json.dumps(content)
    assert "token-value" not in json.dumps(content)
    assert receipt.channel == "cli"
    assert receipt.external_id == files[0].stem


def test_cli_event_contains_required_approval_content(tmp_path: Path) -> None:
    plugin = cli_notification(tmp_path)
    send(plugin, notification_event())

    content = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    dumped = json.dumps(content)
    assert DIGEST in dumped
    assert "lab" in dumped
    assert "high" in dumped
    assert "systemctl restart example.service" in dumped
    assert "ActiveState=active" in dumped
    assert "systemctl stop example.service" in dumped


# ---------------------------------------------------------------------------
# FlashDuty
# ---------------------------------------------------------------------------


def test_flashduty_payload_contains_digest_but_not_secret() -> None:
    http = FakeHttp()
    receipt = send(
        flashduty_notification(http), notification_event(risk=Risk.LOW, secret="token-value")
    )

    request = http.requests[0]
    body = json.loads(request["body"])
    assert body["event_status"] == "Warning"
    assert "plan_digest" in body["event_description"]
    assert "token-value" not in json.dumps(body)
    assert receipt.external_id
    assert receipt.channel == "flashduty"


def test_flashduty_high_maps_to_critical() -> None:
    http = FakeHttp()
    send(flashduty_notification(http), notification_event())

    body = json.loads(http.requests[0]["body"])
    assert body["event_status"] == "Critical"


def test_flashduty_uses_secret_reference_in_header() -> None:
    http = FakeHttp()
    send(flashduty_notification(http), notification_event())

    request = http.requests[0]
    assert request["headers"]["X-Flashduty-Integration-Key"] == FLASHDUTY_KEY
    assert request["url"] == "https://api.flashduty.example.com/event/push"
    assert FLASHDUTY_KEY not in request["url"]
    assert FLASHDUTY_KEY not in request["body"].decode("utf-8")


def test_flashduty_retries_5xx_and_429() -> None:
    http = FakeHttp()
    http.statuses = [503, 429, 200]
    receipt = send(flashduty_notification(http), notification_event())
    assert receipt.external_id
    assert len(http.requests) == 3


def test_flashduty_4xx_does_not_retry() -> None:
    http = FakeHttp()
    http.statuses = [401, 200]
    with pytest.raises(NotificationError, match="http_error"):
        send(flashduty_notification(http), notification_event())
    assert len(http.requests) == 1


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------


def test_smtp_uses_tls_and_sends_text_plain() -> None:
    smtp = FakeSmtp()
    receipt = send(smtp_notification(smtp), notification_event())

    assert smtp.starttls_called is True
    assert smtp.login_args == ("notify@example.test", SMTP_PASSWORD)
    assert len(smtp.sent) == 1
    message = smtp.sent[0]
    assert "text/plain" in message
    assert DIGEST in message
    assert receipt.channel == "smtp"
    assert receipt.external_id


def test_smtp_implicit_tls_skips_starttls() -> None:
    smtp = FakeSmtp()
    send(smtp_notification(smtp, tls_mode="implicit"), notification_event())
    assert smtp.starttls_called is False


def test_smtp_message_contains_required_content() -> None:
    smtp = FakeSmtp()
    send(smtp_notification(smtp), notification_event())

    message = smtp.sent[0]
    assert DIGEST in message
    assert "lab" in message
    assert "high" in message
    assert "systemctl restart example.service" in message
    assert "ActiveState" in message and "active" in message
    assert "systemctl stop example.service" in message


def test_smtp_redacts_secret() -> None:
    smtp = FakeSmtp()
    send(smtp_notification(smtp), notification_event(secret="token-value"))

    assert "token-value" not in smtp.sent[0]
    assert SMTP_PASSWORD not in smtp.sent[0]


def test_smtp_auth_failure_does_not_retry() -> None:
    smtp = FakeSmtp()
    smtp.error = NotificationError("auth_failed")
    with pytest.raises(NotificationError, match="auth_failed"):
        send(smtp_notification(smtp), notification_event())
    assert smtp.sent == []


def test_smtp_tls_failure_is_typed() -> None:
    smtp = FakeSmtp()
    smtp.error = ssl.SSLError("certificate verify failed")
    with pytest.raises(NotificationError, match="tls_error"):
        send(smtp_notification(smtp), notification_event())
    assert smtp.sent == []


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------


def test_webhook_5xx_retries_but_4xx_does_not() -> None:
    http = FakeHttp()
    http.statuses = [503, 200]
    send(webhook_notification(http), notification_event())
    assert len(http.requests) == 2

    http4xx = FakeHttp()
    http4xx.statuses = [400, 200]
    with pytest.raises(NotificationError, match="http_error"):
        send(webhook_notification(http4xx), notification_event())
    assert len(http4xx.requests) == 1


def test_webhook_429_retries() -> None:
    http = FakeHttp()
    http.statuses = [429, 200]
    send(webhook_notification(http), notification_event())
    assert len(http.requests) == 2


def test_webhook_connection_error_retries_then_succeeds() -> None:
    http = FakeHttp()
    http.error = ConnectionError("connection refused")
    http.error_attempts = 2
    receipt = send(webhook_notification(http), notification_event())
    assert receipt.external_id
    assert len(http.requests) == 3


def test_webhook_connection_error_exhausted_is_typed() -> None:
    http = FakeHttp()
    http.error = ConnectionError("connection refused")
    http.error_attempts = 99
    with pytest.raises(NotificationError, match="connection_failed"):
        send(webhook_notification(http), notification_event())
    assert len(http.requests) == 3


def test_webhook_tls_error_does_not_retry() -> None:
    http = FakeHttp()
    http.error = ssl.SSLError("certificate verify failed")
    http.error_attempts = 99
    with pytest.raises(NotificationError, match="tls_error"):
        send(webhook_notification(http), notification_event())
    assert len(http.requests) == 1


def test_webhook_sends_canonical_json_with_timestamp_nonce_and_hmac() -> None:
    http = FakeHttp()
    send(webhook_notification(http), notification_event())

    request = http.requests[0]
    body = json.loads(request["body"])
    assert body["timestamp"] == "2023-11-14T22:13:20Z"
    assert body["nonce"] == "nonce-1"
    assert body["event"]["plan_digest"] == DIGEST
    assert body["event"]["target_id"] == "lab"
    assert "systemctl restart example.service" in json.dumps(body)
    signature = request["headers"].get("X-A4Diag-Signature")
    assert signature is not None
    assert signature.startswith("sha256=")
    assert len(signature) == 7 + 64
    assert WEBHOOK_KEY not in json.dumps(body)
    assert WEBHOOK_KEY not in request["url"]


def test_webhook_without_hmac_ref_has_no_signature() -> None:
    http = FakeHttp()
    plugin = WebhookNotification(
        http=http,
        secrets=FakeSecrets(),
        config=WebhookConfig(
            url="https://hooks.example.test/a4diag",
            hmac_secret_ref=None,
            timeout_seconds=10.0,
        ),
        clock=lambda: FIXED_CLOCK,
        nonce_factory=lambda: "nonce-1",
        sleep=no_op_sleep,
    )
    send(plugin, notification_event())
    assert "X-A4Diag-Signature" not in http.requests[0]["headers"]


# ---------------------------------------------------------------------------
# Host integration and manifests
# ---------------------------------------------------------------------------


def test_notification_bindings_use_fixed_kinds() -> None:
    plugin = cli_notification(Path("unused"))
    bindings = build_notification_bindings(plugin)
    assert bindings["capability_probe"].kind is MethodKind.READ
    assert bindings["send"].kind is MethodKind.NOTIFICATION
    assert all(binding.ticket_phase is None for binding in bindings.values())


@pytest.mark.parametrize(
    "manifest_name",
    [
        "notification-cli",
        "notification-flashduty",
        "notification-smtp",
        "notification-webhook",
    ],
)
def test_notification_manifest_contract(manifest_name: str) -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / f"{manifest_name}.json").read_text(encoding="utf-8"))
    )
    assert manifest.plugin_type is PluginType.NOTIFICATION
    assert manifest.api_min == "1.0"
    assert manifest.api_max == "1.0"
    assert manifest.operations == ()
    assert manifest.write_risk_floor is Risk.HIGH
    assert "linux:systemd" in manifest.target_compatibility


def test_flashduty_manifest_declares_secret_and_network() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "notification-flashduty.json").read_text(encoding="utf-8"))
    )
    assert manifest.network_access == ("notification-endpoint",)
    assert manifest.secret_refs == ("notification:flashduty-integration-key",)


def test_smtp_manifest_declares_smtp_network_and_credentials() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "notification-smtp.json").read_text(encoding="utf-8"))
    )
    assert manifest.network_access == ("smtp-server",)
    assert manifest.secret_refs == ("notification:smtp-user", "notification:smtp-password")


def test_webhook_manifest_declares_hmac_secret() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "notification-webhook.json").read_text(encoding="utf-8"))
    )
    assert manifest.network_access == ("notification-endpoint",)
    assert manifest.secret_refs == ("notification:webhook-hmac-key",)


def test_cli_manifest_declares_no_network_or_secrets() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "notification-cli.json").read_text(encoding="utf-8"))
    )
    assert manifest.network_access == ("none",)
    assert manifest.secret_refs == ()

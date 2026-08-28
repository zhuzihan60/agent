"""Small production adapters used by the isolated built-in plugin host.

They deliberately expose only the narrow protocols consumed by the model and
notification plugins.  Redirects are disabled so authentication headers can
never be forwarded to a different origin, TLS verification uses the platform
default trust store, and secret values are unwrapped only inside the plugin
process.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

import httpx

from a4diag.secrets import SecretResolver as CoreSecretResolver


class HttpxTransport:
    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        *,
        timeout_seconds: float,
    ) -> object:
        from a4diag_builtin_plugins.notification_common import HttpResult

        try:
            with httpx.Client(
                follow_redirects=False,
                verify=True,
                timeout=timeout_seconds,
            ) as client:
                response = client.post(url, headers=headers, content=body)
        except httpx.TimeoutException as error:
            raise TimeoutError("http_timeout") from error
        except httpx.ConnectError as error:
            raise ConnectionError("http_connection_failed") from error
        except httpx.HTTPError as error:
            raise ConnectionError("http_failed") from error
        return HttpResult(response.status_code, response.text)


class StringSecretResolver:
    def __init__(self, resolver: CoreSecretResolver | None = None) -> None:
        self._resolver = resolver or CoreSecretResolver()

    def resolve(self, ref: str) -> str:
        return self._resolver.resolve(ref).value


class ReusableSmtpClient:
    """Lazy smtplib adapter which reconnects for every notification send."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        tls_mode: str,
        timeout_seconds: float,
    ) -> None:
        self._host = host
        self._port = port
        self._tls_mode = tls_mode
        self._timeout = timeout_seconds
        self._client: smtplib.SMTP | smtplib.SMTP_SSL | None = None

    def _connect(self) -> smtplib.SMTP | smtplib.SMTP_SSL:
        if self._client is not None:
            return self._client
        context = ssl.create_default_context()
        if self._tls_mode == "implicit":
            self._client = smtplib.SMTP_SSL(
                self._host,
                self._port,
                timeout=self._timeout,
                context=context,
            )
        else:
            self._client = smtplib.SMTP(
                self._host, self._port, timeout=self._timeout
            )
        return self._client

    def starttls(self) -> None:
        client = self._connect()
        client.starttls(context=ssl.create_default_context())

    def login(self, user: str, password: str) -> None:
        self._connect().login(user, password)

    def send_message(self, message: EmailMessage) -> None:
        self._connect().send_message(message)

    def quit(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            client.quit()


__all__ = ["HttpxTransport", "ReusableSmtpClient", "StringSecretResolver"]

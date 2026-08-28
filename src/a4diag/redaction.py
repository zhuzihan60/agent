"""Recursive redaction of secret-shaped fields and values.

``redact`` walks nested dictionaries/lists and replaces the value of any key
matching a secret-name pattern (token, password, key, authorization,
credential, ...) with a placeholder, replaces any occurrence of a known secret
value, and scrubs secret-shaped assignment and bearer patterns from strings.
Everything else passes through unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from a4diag.domain import JsonValue

REDACTED = "[REDACTED]"
MAX_KNOWN_SECRETS = 64
MAX_KNOWN_SECRET_LENGTH = 256

_SECRET_KEY_NAME = re.compile(
    r"(?i)(?:token|password|passwd|secret|api[_-]?key|authorization|credential|access[_-]?key)"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:token|password|passwd|secret|api[_-]?key|authorization|credential|access[_-]?key)\s*[=:]\s*)(?!Bearer\b)[^\s,;]+"
)
_BEARER = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+")


def _validate_known_secrets(known_secrets: Iterable[str]) -> list[str]:
    values = list(known_secrets)
    if len(values) > MAX_KNOWN_SECRETS:
        raise ValueError(
            f"known_secrets must not exceed {MAX_KNOWN_SECRETS} entries"
        )
    for value in values:
        if not isinstance(value, str) or not value:
            raise ValueError("known_secrets entries must be nonblank strings")
        if len(value) > MAX_KNOWN_SECRET_LENGTH:
            raise ValueError(
                f"known_secrets entries must not exceed {MAX_KNOWN_SECRET_LENGTH} characters"
            )
    return sorted(set(values), key=len, reverse=True)


def redact(value: JsonValue, known_secrets: Iterable[str] = ()) -> JsonValue:
    """Recursively redact secret keyed fields and known secret values."""
    secrets = _validate_known_secrets(known_secrets)
    return _redact_value(value, secrets)


def _redact_value(value: JsonValue, secrets: list[str]) -> JsonValue:
    if type(value) is dict:
        redacted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if _SECRET_KEY_NAME.search(key):
                redacted[key] = REDACTED  # type: ignore[assignment]
            else:
                redacted[key] = _redact_value(item, secrets)
        return redacted
    if type(value) is list:
        return [_redact_value(item, secrets) for item in value]
    if type(value) is str:
        return _redact_text(value, secrets)
    return value


def _redact_text(value: str, secrets: list[str]) -> str:
    result = value
    for secret in secrets:
        if secret in result:
            result = result.replace(secret, REDACTED)
    if result != value:
        value = result
    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{REDACTED}", value
    )
    value = _BEARER.sub(lambda match: f"{match.group(1)}{REDACTED}", value)
    return value


__all__ = [
    "MAX_KNOWN_SECRETS",
    "MAX_KNOWN_SECRET_LENGTH",
    "REDACTED",
    "redact",
]

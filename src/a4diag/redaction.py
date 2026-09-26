"""Recursive redaction of secret-shaped fields and values.

``redact`` walks nested dictionaries/lists and replaces the value of any key
matching a secret-name pattern (token, password, key, authorization,
credential, ...) with a placeholder, replaces any occurrence of a known secret
value, and scrubs secret-shaped assignment and bearer patterns from strings.
Everything else passes through unchanged.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from a4diag.domain import JsonValue

REDACTED = "[REDACTED]"
MAX_KNOWN_SECRETS = 64
MAX_KNOWN_SECRET_LENGTH = 256
MAX_JSON_TEXT_BYTES = 16_384
MAX_JSON_TEXT_DEPTH = 32
MAX_JSON_TEXT_LAYERS = 8

_SECRET_KEY_NAME = re.compile(
    r"(?i)(?:token|password|passwd|secret|api[_-]?key|authorization|credential|access[_-]?key)"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:token|password|passwd|secret|api[_-]?key|authorization|credential|access[_-]?key)\s*[=:]\s*)(?!Bearer\b)[^\s,;]+"
)
_BEARER = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_QUOTED_ASSIGNMENT = re.compile(
    r'(?P<prefix>(?P<quote>\\?")(?P<key>(?:\\.|[^"\\\r\n])*?)(?P=quote)\s*:\s*(?P<value_quote>\\?"))'
    r'(?P<value>(?:\\{3}"|\\.|[^"\\\r\n])*?)(?P=value_quote)'
)
_QUOTED_LITERAL_ASSIGNMENT = re.compile(
    r'(?P<prefix>(?P<quote>\\?")(?P<key>(?:\\.|[^"\\\r\n])*?)(?P=quote)\s*:\s*)'
    r'(?P<value>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)'
    r'(?=\s*[,}\]])'
)
_URI_PASSWORD = re.compile(
    r"(?i)(\b(?:postgres(?:ql)?|rediss?|mysql|mariadb|mongodb(?:\+srv)?|amqps?)"
    r"(?:\+[A-Za-z][A-Za-z0-9_.-]{0,31})?://[A-Za-z0-9._~!$&'()*+,;=%-]+:)"
    r"[A-Za-z0-9._~!$&'()*+,;=:%-]+(@)"
)
_COMPLETE_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
    r"(?:(?!-----BEGIN ).){0,16384}?-----END (?P=kind)-----",
    re.DOTALL,
)
_ESCAPED_PRIVATE_KEY_TAIL = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r'(?:\\n[A-Za-z0-9+/]{8,}={0,2}(?=\\n|[\s"\',;} ]|$))+'
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----[ \t]*"
    r"(?:\r?\n(?:(?:[A-Za-z0-9+/=]+|(?:Proc-Type|DEK-Info):[^\r\n]*)[ \t]*|[ \t]*)(?=\r?\n|$))*"
    r"(?:\r?\n-----END (?P=kind)-----)?"
)


class _DuplicateJsonKeyError(ValueError):
    """A duplicate member can hide an earlier secret during JSON decoding."""


def _unique_json_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, item in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = item
    return result


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


def _redact_value(value: JsonValue, secrets: list[str], json_layers: int = 0) -> JsonValue:
    if type(value) is dict:
        redacted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if _SECRET_KEY_NAME.search(key):
                redacted[key] = REDACTED  # type: ignore[assignment]
            else:
                redacted[key] = _redact_value(item, secrets, json_layers)
        return redacted
    if type(value) is list:
        return [_redact_value(item, secrets, json_layers) for item in value]
    if type(value) is str:
        return _redact_text(value, secrets, json_layers)
    return value


def _redact_complete_json_text(value: str, secrets: list[str], json_layers: int) -> str | None:
    stripped = value.strip()
    if not stripped or stripped[0] not in "{[" or stripped[-1] not in "}]":
        return None
    if len(value.encode("utf-8")) > MAX_JSON_TEXT_BYTES or json_layers >= MAX_JSON_TEXT_LAYERS:
        return REDACTED
    try:
        parsed = json.loads(stripped, object_pairs_hook=_unique_json_pairs)
    except _DuplicateJsonKeyError:
        return REDACTED
    except RecursionError:
        return REDACTED
    except ValueError:
        return None
    if type(parsed) not in (dict, list):
        return None
    pending = [(parsed, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_JSON_TEXT_DEPTH:
            return REDACTED
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    redacted = _redact_value(parsed, secrets, json_layers + 1)
    try:
        result = json.dumps(redacted, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return REDACTED
    for secret in secrets:
        result = result.replace(secret, REDACTED)
    if redacted == parsed and result == json.dumps(parsed, ensure_ascii=False, separators=(",", ":"), allow_nan=False):
        original = value
        for secret in secrets:
            original = original.replace(secret, REDACTED)
        return original
    return result


def _redact_text(value: str, secrets: list[str], json_layers: int = 0) -> str:
    complete_json = _redact_complete_json_text(value, secrets, json_layers)
    if complete_json is not None:
        return complete_json
    result = _COMPLETE_PRIVATE_KEY_BLOCK.sub(REDACTED, value)
    result = _ESCAPED_PRIVATE_KEY_TAIL.sub(REDACTED, result)
    result = _PRIVATE_KEY_BLOCK.sub(REDACTED, result)
    for secret in secrets:
        if secret in result:
            result = result.replace(secret, REDACTED)
    result = _QUOTED_ASSIGNMENT.sub(_redact_quoted_assignment, result)
    result = _QUOTED_LITERAL_ASSIGNMENT.sub(_redact_quoted_literal, result)
    result = _URI_PASSWORD.sub(
        lambda match: f"{match.group(1)}{REDACTED}{match.group(2)}", result
    )
    result = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{REDACTED}", result
    )
    return _BEARER.sub(lambda match: f"{match.group(1)}{REDACTED}", result)


def _redact_quoted_assignment(match: re.Match[str]) -> str:
    key = match.group("key")
    try:
        key = json.loads(f'"{key}"')
    except json.JSONDecodeError:
        pass
    if not _SECRET_KEY_NAME.search(key):
        return match.group(0)
    return f'{match.group("prefix")}{REDACTED}{match.group("value_quote")}'


def _redact_quoted_literal(match: re.Match[str]) -> str:
    key = match.group("key")
    try:
        key = json.loads(f'"{key}"')
    except json.JSONDecodeError:
        pass
    if not _SECRET_KEY_NAME.search(key):
        return match.group(0)
    return f'{match.group("prefix")}{match.group("quote")}{REDACTED}{match.group("quote")}'


__all__ = [
    "MAX_KNOWN_SECRETS",
    "MAX_KNOWN_SECRET_LENGTH",
    "REDACTED",
    "redact",
]

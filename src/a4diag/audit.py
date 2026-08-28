"""Append-only chained canonical JSONL audit log.

Every record is one canonical JSON line containing ``sequence``, ``timestamp``,
``event``, ``payload``, ``previous_hash``, and ``record_hash``. Each append is
written with append semantics and fsynced; a broken hash/sequence chain — at
startup or detected before a later append — forces the writer read-only and
refuses further appends.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from a4diag.domain import JsonValue, canonical_json_bytes

GENESIS_HASH = "0" * 64
MAX_LINE_BYTES = 1_048_576
AUDIT_FILE_MODE = 0o600


class AuditError(ValueError):
    """Stable typed audit failure carrying a reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class AuditVerification:
    valid: bool
    reason: str | None = None
    records: int = 0


class AuditWriter:
    """Append-only, hash-chained, fsynced canonical JSONL audit writer."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._path = Path(path)
        self._clock = clock or time.time
        self._read_only = False
        self._last_hash = GENESIS_HASH
        self._sequence = 0
        self._fd: int | None = None
        self._startup()

    def append(self, event: Mapping[str, JsonValue]) -> int:
        """Append one chained, fsynced canonical record; returns its sequence."""
        if self._read_only:
            raise AuditError("audit_chain_broken")
        if not isinstance(event, Mapping):
            raise AuditError("invalid_event")
        event_name = event.get("event")
        if type(event_name) is not str or not event_name:
            raise AuditError("event_name_required")
        if self._read_last_hash() != self._last_hash:
            self._read_only = True
            raise AuditError("audit_chain_broken")
        sequence = self._sequence + 1
        payload = {key: value for key, value in event.items() if key != "event"}
        record: dict[str, JsonValue] = {
            "sequence": sequence,
            "timestamp": _iso8601(self._clock()),
            "event": event_name,
            "payload": payload,
            "previous_hash": self._last_hash,
        }
        record["record_hash"] = _record_hash(record)
        try:
            line = canonical_json_bytes(record) + b"\n"
        except ValueError as error:
            raise AuditError("invalid_payload") from error
        assert self._fd is not None
        os.write(self._fd, line)
        os.fsync(self._fd)
        self._last_hash = str(record["record_hash"])
        self._sequence = sequence
        return sequence

    def verify(self) -> AuditVerification:
        """Re-read the whole file and check sequence and hash continuity."""
        return self._verify_file()

    @property
    def read_only(self) -> bool:
        """True when the chain is broken and appends are refused."""
        return self._read_only

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    # ------------------------------------------------------------------

    def _startup(self) -> None:
        if self._path.exists():
            verification = self._verify_file()
            if not verification.valid:
                self._read_only = True
                return
            self._sequence = verification.records
            self._last_hash = self._read_last_hash()
        self._fd = os.open(
            str(self._path),
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            AUDIT_FILE_MODE,
        )

    def _verify_file(self) -> AuditVerification:
        expected_sequence = 1
        previous_hash = GENESIS_HASH
        records = 0
        try:
            with open(self._path, "rb") as handle:
                for raw in handle:
                    if not raw.endswith(b"\n"):
                        return AuditVerification(False, "malformed_line", records)
                    line = raw[:-1]
                    if len(line) > MAX_LINE_BYTES:
                        return AuditVerification(False, "line_too_large", records)
                    record = _parse_line(line)
                    if record is None:
                        return AuditVerification(False, "malformed_line", records)
                    if record.get("sequence") != expected_sequence:
                        return AuditVerification(False, "sequence_gap", records)
                    if record.get("previous_hash") != previous_hash:
                        return AuditVerification(False, "hash_chain_broken", records)
                    if record.get("record_hash") != _record_hash(record):
                        return AuditVerification(False, "record_hash_mismatch", records)
                    records += 1
                    expected_sequence += 1
                    previous_hash = str(record["record_hash"])
        except OSError:
            return AuditVerification(False, "unreadable", records)
        if records < self._sequence:
            # Records were deleted since this writer session opened.
            return AuditVerification(False, "record_deleted", records)
        return AuditVerification(valid=True, reason=None, records=records)

    def _read_last_hash(self) -> str:
        try:
            with open(self._path, "rb") as handle:
                last = None
                for raw in handle:
                    last = raw
        except OSError:
            return GENESIS_HASH
        if last is None:
            # Nothing written yet: the chain is still at its genesis.
            return GENESIS_HASH
        if not last.endswith(b"\n"):
            return ""
        record = _parse_line(last[:-1])
        if record is None:
            return ""
        return str(record.get("record_hash", ""))


def _record_hash(record: Mapping[str, object]) -> str:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def _iso8601(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_line(line: bytes) -> dict[str, JsonValue] | None:
    try:
        value = json.loads(
            line.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        if type(value) is not dict:
            return None
        required = {
            "sequence",
            "timestamp",
            "event",
            "payload",
            "previous_hash",
            "record_hash",
        }
        if not required.issubset(value):
            return None
        if type(value["sequence"]) is not int or type(value["payload"]) is not dict:
            return None
        for field in ("timestamp", "event", "previous_hash", "record_hash"):
            if type(value[field]) is not str or not value[field]:
                return None
        return value
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = item
    return result


def _reject_float(value: str) -> object:
    raise ValueError(f"floating-point JSON value is forbidden: {value}")


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


__all__ = [
    "AUDIT_FILE_MODE",
    "AuditError",
    "AuditVerification",
    "AuditWriter",
    "GENESIS_HASH",
    "MAX_LINE_BYTES",
]

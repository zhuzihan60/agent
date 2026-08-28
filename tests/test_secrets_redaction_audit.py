"""Tests for secret references, recursive redaction, and the append-only audit.

Only temporary directories and injected fake secrets/environments are used;
no real secret file, environment variable, server, mail, or external API is
touched. POSIX-only enforcement (mode 0600, owner match, symlink rejection)
skips on Windows as a mandatory Linux Phase 4 gate.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from a4diag.audit import AuditError, AuditWriter, AuditVerification
from a4diag.redaction import redact
from a4diag.secrets import ResolvedSecret, SecretError, SecretResolver


def canonical_digest(record: dict[str, object]) -> str:
    body = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def read_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def tamper_first_line(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0][:-1] + ("1" if lines[0][-1] != "1" else "2")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Secret references
# ---------------------------------------------------------------------------


def test_resolve_file_relative_returns_value(tmp_path: Path) -> None:
    secret = tmp_path / "model.key"
    secret.write_text("file-secret-value\n", encoding="utf-8")
    if os.name == "posix":
        secret.chmod(0o600)
    resolver = SecretResolver(tmp_path)

    resolved = resolver.resolve("file:model.key")

    assert isinstance(resolved, ResolvedSecret)
    assert resolved.value == "file-secret-value"
    assert resolved.source == "file"
    assert resolved.deprecated is False


def test_resolve_file_nested_relative(tmp_path: Path) -> None:
    (tmp_path / "targets").mkdir()
    secret = tmp_path / "targets" / "lab.key"
    secret.write_text("nested-value", encoding="utf-8")
    if os.name == "posix":
        secret.chmod(0o600)
    resolver = SecretResolver(tmp_path)

    assert resolver.resolve("file:targets/lab.key").value == "nested-value"


def test_secret_file_with_group_or_other_bits_is_rejected(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX mode 0600 enforcement is a mandatory Linux Phase 4 gate")
    path = tmp_path / "model.key"
    path.write_text("secret", encoding="utf-8")
    path.chmod(0o640)

    with pytest.raises(SecretError, match="mode_0600_required"):
        SecretResolver(tmp_path).resolve("file:model.key")


def test_secret_file_owned_by_other_user_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix" or not hasattr(os, "getuid"):
        pytest.skip("POSIX owner enforcement is a mandatory Linux Phase 4 gate")
    path = tmp_path / "model.key"
    path.write_text("secret", encoding="utf-8")
    path.chmod(0o600)
    real_lstat = Path.lstat

    def lstat_as_other_user(candidate: Path) -> os.stat_result:
        info = real_lstat(candidate)
        if candidate != path:
            return info
        values = list(info)
        values[4] = os.getuid() + 1 if os.getuid() < 2**31 - 2 else 0
        return os.stat_result(values)

    monkeypatch.setattr(Path, "lstat", lstat_as_other_user)

    with pytest.raises(SecretError, match="owner"):
        SecretResolver(tmp_path).resolve("file:model.key")


@pytest.mark.parametrize(
    "ref",
    ["file:/etc/passwd", "file:../secret", "file:a/../../b", "file:..", "file:", "file:a//b", "file:a\\b"],
)
def test_resolve_rejects_absolute_or_traversal_refs(tmp_path: Path, ref: str) -> None:
    with pytest.raises(SecretError):
        SecretResolver(tmp_path).resolve(ref)


def test_resolve_rejects_symlink_secret(tmp_path: Path) -> None:
    target = tmp_path / "real.key"
    target.write_text("value", encoding="utf-8")
    link = tmp_path / "link.key"
    try:
        link.symlink_to(target)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("symlink creation requires the Windows symlink privilege")
        raise
    if os.name == "posix":
        link.chmod(0o600)

    with pytest.raises(SecretError, match="symlink"):
        SecretResolver(tmp_path).resolve("file:link.key")


def test_resolve_rejects_non_regular_file(tmp_path: Path) -> None:
    (tmp_path / "adir").mkdir()
    with pytest.raises(SecretError, match="regular"):
        SecretResolver(tmp_path).resolve("file:adir")


def test_resolve_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SecretError, match="missing"):
        SecretResolver(tmp_path).resolve("file:nope.key")


def test_resolve_rejects_oversized_secret(tmp_path: Path) -> None:
    path = tmp_path / "big.key"
    path.write_text("x" * 5000, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)
    with pytest.raises(SecretError, match="large"):
        SecretResolver(tmp_path).resolve("file:big.key")


def test_resolve_env_returns_value_and_deprecation() -> None:
    resolver = SecretResolver(Path("unused"), env={"MODEL_KEY": "env-secret-value"})

    resolved = resolver.resolve("env:MODEL_KEY")

    assert resolved.value == "env-secret-value"
    assert resolved.source == "env"
    assert resolved.deprecated is True


def test_resolve_env_missing_or_invalid_name() -> None:
    resolver = SecretResolver(Path("unused"), env={})
    with pytest.raises(SecretError, match="env_missing"):
        resolver.resolve("env:MISSING_KEY")
    with pytest.raises(SecretError, match="env_name"):
        resolver.resolve("env:1BAD NAME")


def test_resolve_rejects_unsupported_scheme() -> None:
    with pytest.raises(SecretError, match="unsupported_scheme"):
        SecretResolver(Path("unused")).resolve("keyring:model")


def test_resolve_rejects_malformed_reference() -> None:
    with pytest.raises(SecretError, match="malformed"):
        SecretResolver(Path("unused")).resolve("no-scheme")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_nested_secret_is_redacted() -> None:
    value = {"headers": {"Authorization": "Bearer abc"}, "text": "token abc"}

    result = redact(value, {"abc"})

    assert "abc" not in json.dumps(result)
    assert result["headers"]["Authorization"] == "[REDACTED]"
    assert result["text"] == "token [REDACTED]"


def test_secret_keyed_values_are_redacted_recursively() -> None:
    value = {
        "password": "hunter2",
        "api_key": "k-123",
        "nested": {"credential": "cred-9", "ok": "keep-me"},
        "items": [{"token": "tok-7"}, {"authorization": "Bearer xyz"}],
    }

    result = redact(value, set())

    dumped = json.dumps(result)
    assert "hunter2" not in dumped
    assert "k-123" not in dumped
    assert "cred-9" not in dumped
    assert "tok-7" not in dumped
    assert "xyz" not in dumped
    assert "keep-me" in dumped


def test_known_secret_values_are_redacted_in_text() -> None:
    value = {"log": "connected with secret s3cr3t and token=abc123"}

    result = redact(value, {"s3cr3t", "abc123"})

    dumped = json.dumps(result)
    assert "s3cr3t" not in dumped
    assert "abc123" not in dumped


def test_plain_values_are_unchanged() -> None:
    value = {"target": "lab", "os": {"id": "rocky"}, "items": [1, "plain"]}

    assert redact(value, set()) == value


def test_redact_rejects_unbounded_known_secrets() -> None:
    with pytest.raises(ValueError, match="known_secrets"):
        redact({"x": "y"}, {"z" * 300})


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_audit_appends_chained_canonical_records(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl", clock=lambda: 1_700_000_000.0)

    first = writer.append({"event": "prepared", "transaction_id": "tx-1"})
    second = writer.append({"event": "applied", "transaction_id": "tx-1"})

    assert first == 1
    assert second == 2
    records = read_records(tmp_path / "audit.jsonl")
    assert len(records) == 2
    assert records[0]["sequence"] == 1
    assert records[1]["sequence"] == 2
    assert records[0]["event"] == "prepared"
    assert records[1]["event"] == "applied"
    assert records[0]["payload"] == {"transaction_id": "tx-1"}
    assert records[0]["previous_hash"] == "0" * 64
    assert records[0]["record_hash"] == canonical_digest(records[0])
    assert records[1]["previous_hash"] == records[0]["record_hash"]
    assert records[1]["record_hash"] == canonical_digest(records[1])
    assert writer.verify() == AuditVerification(valid=True, reason=None, records=2)


def test_audit_chain_detects_edit(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.append({"event": "prepared"})

    tamper_first_line(tmp_path / "audit.jsonl")

    assert writer.verify().valid is False


def test_audit_tamper_forces_read_only_on_next_append(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.append({"event": "prepared"})

    tamper_first_line(tmp_path / "audit.jsonl")

    with pytest.raises(AuditError, match="audit_chain_broken"):
        writer.append({"event": "applied"})
    assert writer.read_only is True


def test_audit_broken_chain_at_startup_forces_read_only(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.append({"event": "prepared"})
    tamper_first_line(tmp_path / "audit.jsonl")

    restarted = AuditWriter(tmp_path / "audit.jsonl")

    assert restarted.read_only is True
    with pytest.raises(AuditError, match="audit_chain_broken"):
        restarted.append({"event": "applied"})


def test_audit_restart_continues_sequence_and_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditWriter(path).append({"event": "prepared"})
    AuditWriter(path).append({"event": "applied"})

    writer = AuditWriter(path)
    assert writer.append({"event": "verified"}) == 3

    assert writer.verify().valid is True
    records = read_records(path)
    assert [record["sequence"] for record in records] == [1, 2, 3]
    assert records[2]["previous_hash"] == records[1]["record_hash"]


def test_audit_deleted_record_breaks_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.append({"event": "prepared"})
    writer.append({"event": "applied"})

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")

    assert writer.verify().valid is False
    assert writer.verify().reason is not None


def test_audit_rejects_missing_event_name(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")

    with pytest.raises(AuditError, match="event"):
        writer.append({"transaction_id": "tx-1"})


def test_audit_duplicate_key_line_breaks_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(path)
    writer.append({"event": "prepared"})

    # Inject a raw line with a duplicate JSON key; it must fail verification.
    path.write_text('{"sequence":1,"sequence":2}\n', encoding="utf-8")

    verification = writer.verify()
    assert verification.valid is False
    assert verification.reason is not None

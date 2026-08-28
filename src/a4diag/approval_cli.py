"""Digest-bound local CLI approval.

The approval CLI never executes operations: it re-probes the current target
identity, requires the exact displayed plan digest, enforces the notification
barrier, and atomically records the decision through the Phase 1
``ApprovalStore``. Non-TTY stdin approval is rejected by default; the only
escape hatch is a root-owned 0600 signed non-interactive approval request.
All output passes through the shared redactor so secrets never appear.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from a4diag.approvals import (
    ApprovalError,
    ApprovalDigestMismatchError,
    ApprovalExpiredError,
    ApprovalStateError,
    ApprovalStore,
    NotificationStatus,
    UnknownApprovalError,
)
from a4diag.domain import Risk, canonical_json_bytes
from a4diag.redaction import redact

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MAX_APPROVAL_FILE_BYTES = 16_384


class ApprovalCliError(ValueError):
    """Stable typed approval-CLI failure carrying a reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


class IdentityError(ApprovalCliError):
    """The current target identity could not be verified."""


class AdminRequired(ValueError):
    """Raised when an administrator-only approval lacks authority."""


class Authorizer:
    """Injected administrative authority (effective UID 0 by default)."""

    def __init__(self, is_admin: bool | None = None) -> None:
        if is_admin is None:
            is_admin = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
        self.is_admin = is_admin


class PlanDetail(BaseModel):
    """The stored plan snapshot shown to the approver."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str
    target_id: str
    target_fingerprint: str
    plan_digest: str
    risk: Risk
    operations: tuple[dict[str, JsonValue], ...] = ()
    equivalent_commands: tuple[str, ...] = ()
    verify: tuple[str, ...] = ()
    undo: tuple[str, ...] = ()
    expires_at: int = Field(ge=0)

    @field_validator("transaction_id")
    @classmethod
    def validate_transaction_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
            raise ValueError("transaction_id must be a safe identifier")
        return value

    @field_validator("plan_digest")
    @classmethod
    def validate_plan_digest(cls, value: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValueError("plan_digest must be a lowercase SHA256 digest")
        return value

    @field_validator("target_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise ValueError("target_fingerprint must be a bounded string")
        return value

    @field_validator("equivalent_commands", "verify", "undo")
    @classmethod
    def validate_string_lists(cls, values: tuple[str, ...], info: object) -> tuple[str, ...]:
        label = getattr(info, "field_name", "field")
        if len(values) > 20:
            raise ValueError(f"{label} must not exceed 20 entries")
        for value in values:
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError(f"{label} entries must be bounded nonblank strings")
        return values


class PlanSource(Protocol):
    def plan_for(self, transaction_id: str) -> PlanDetail | None: ...


class IdentityProbe(Protocol):
    def probe_fingerprint(self, target_id: str) -> str: ...


class Notifier(Protocol):
    def send(self, event: object) -> None: ...


@dataclass(frozen=True, slots=True)
class ApprovalReceipt:
    transaction_id: str
    approval_id: str
    status: str
    decided_at: int


@dataclass(frozen=True, slots=True)
class ShowResult:
    plan: PlanDetail
    status: str
    notification_status: str
    current_fingerprint: str
    redacted: dict[str, JsonValue]


class ApprovalCli:
    """Digest-bound, identity-rechecked, notification-barriered approval."""

    def __init__(
        self,
        *,
        approvals: ApprovalStore,
        plans: PlanSource,
        notifier: Notifier,
        identity: IdentityProbe,
        authorizer: Authorizer,
        clock: Callable[[], int],
        stdin_isatty: Callable[[], bool] | None = None,
        actor_factory: Callable[[], str] | None = None,
        signing_key: bytes,
    ) -> None:
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise ApprovalCliError("invalid_key")
        self.approvals = approvals
        self.plans = plans
        self.notifier = notifier
        self.identity = identity
        self.authorizer = authorizer
        self._clock = clock
        self._stdin_isatty = stdin_isatty or (lambda: bool(sys.stdin.isatty()))
        self._actor_factory = actor_factory or (lambda: getpass.getuser())
        self._signing_key = signing_key

    def list(self) -> tuple[dict[str, JsonValue], ...]:
        records = self.approvals.list_approvals()
        return tuple(
            {
                "transaction_id": record.transaction_id,
                "status": record.status.value,
                "plan_digest": record.plan_digest,
                "target_id": record.target_id,
                "notification_required": record.notification_required,
            }
            for record in records
        )

    def show(self, transaction_id: str) -> ShowResult:
        plan = self._plan(transaction_id)
        record = self._record(transaction_id)
        notification = self.approvals.notification_status(record.id)
        current = self._probe_fingerprint(plan.target_id)
        redacted_payload: dict[str, JsonValue] = {
            "transaction_id": plan.transaction_id,
            "target_id": plan.target_id,
            "target_fingerprint": plan.target_fingerprint,
            "plan_digest": plan.plan_digest,
            "risk": plan.risk.value,
            "operations": list(plan.operations),
            "equivalent_commands": list(plan.equivalent_commands),
            "verify": list(plan.verify),
            "undo": list(plan.undo),
            "expires_at": plan.expires_at,
            "status": record.status.value,
            "notification_status": notification.value,
            "current_fingerprint": current,
        }
        return ShowResult(
            plan=plan,
            status=record.status.value,
            notification_status=notification.value,
            current_fingerprint=current,
            redacted=redact(redacted_payload),  # type: ignore[arg-type]
        )

    def approve(
        self,
        transaction_id: str,
        digest: str,
        *,
        approval_file: Path | None = None,
    ) -> ApprovalReceipt:
        self._require_admin()
        self._require_terminal_or_file(approval_file)
        digest = self._validate_digest(digest)
        plan = self._plan(transaction_id)
        record = self._record(transaction_id)
        if approval_file is not None:
            self._verify_approval_file(approval_file, transaction_id, digest)
        if record.plan_digest != plan.plan_digest:
            raise ApprovalCliError("state_changed")
        current = self._probe_fingerprint(plan.target_id)
        if current != plan.target_fingerprint:
            raise ApprovalCliError("identity_changed")
        if (
            record.notification_required
            and self.approvals.notification_status(record.id)
            is not NotificationStatus.DELIVERED
        ):
            raise ApprovalCliError("notification_not_delivered")
        try:
            approved = self.approvals.approve(
                record.id,
                approved_digest=digest,
                actor=self._actor_factory(),
                now=self._clock(),
            )
        except ApprovalDigestMismatchError as error:
            raise ApprovalCliError("digest_mismatch") from error
        except ApprovalExpiredError as error:
            raise ApprovalCliError("expired") from error
        except ApprovalStateError as error:
            raise ApprovalCliError("state_changed") from error
        except UnknownApprovalError as error:
            raise ApprovalCliError("not_found") from error
        return ApprovalReceipt(
            transaction_id=transaction_id,
            approval_id=approved.id,
            status=approved.status.value,
            decided_at=approved.decided_at or self._clock(),
        )

    def reject(
        self,
        transaction_id: str,
        reason: str,
        *,
        approval_file: Path | None = None,
    ) -> ApprovalReceipt:
        self._require_admin()
        self._require_terminal_or_file(approval_file)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 4096:
            raise ApprovalCliError("invalid_input", "reason must be nonblank text")
        if approval_file is not None:
            self._verify_approval_file(approval_file, transaction_id, None)
        record = self._record(transaction_id)
        try:
            rejected = self.approvals.reject(
                record.id, actor=self._actor_factory(), now=self._clock()
            )
        except ApprovalExpiredError as error:
            raise ApprovalCliError("expired") from error
        except ApprovalStateError as error:
            raise ApprovalCliError("state_changed") from error
        except UnknownApprovalError as error:
            raise ApprovalCliError("not_found") from error
        return ApprovalReceipt(
            transaction_id=transaction_id,
            approval_id=rejected.id,
            status=rejected.status.value,
            decided_at=rejected.decided_at or self._clock(),
        )

    # ------------------------------------------------------------------

    def _require_admin(self) -> None:
        if not self.authorizer.is_admin:
            raise AdminRequired("administrative authority required")

    def _require_terminal_or_file(self, approval_file: Path | None) -> None:
        if not self._stdin_isatty() and approval_file is None:
            raise ApprovalCliError("non_tty_rejected")

    def _plan(self, transaction_id: str) -> PlanDetail:
        plan = self.plans.plan_for(transaction_id)
        if plan is None:
            raise ApprovalCliError("not_found", transaction_id)
        return plan

    def _record(self, transaction_id: str) -> Any:
        record = self.approvals.for_transaction(transaction_id)
        if record is None:
            raise ApprovalCliError("not_found", transaction_id)
        return record

    def _probe_fingerprint(self, target_id: str) -> str:
        try:
            return self.identity.probe_fingerprint(target_id)
        except IdentityError:
            raise
        except ApprovalError as error:
            raise ApprovalCliError("identity_unavailable") from error
        except Exception as error:
            raise ApprovalCliError("identity_unavailable") from error

    def _validate_digest(self, digest: str) -> str:
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ApprovalCliError("invalid_input", "digest must be a SHA256 hex digest")
        return digest

    def _verify_approval_file(
        self, path: Path, transaction_id: str, digest: str | None
    ) -> None:
        try:
            content = path.read_bytes()
        except OSError as error:
            raise ApprovalCliError("invalid_input", str(path)) from error
        if len(content) > MAX_APPROVAL_FILE_BYTES:
            raise ApprovalCliError("signature_invalid")
        if os.name == "posix":
            info = path.stat()
            if info.st_uid != 0:
                raise ApprovalCliError("signature_invalid", "approval file must be root-owned")
            if (info.st_mode & 0o777) != 0o600:
                raise ApprovalCliError("signature_invalid", "approval file must be mode 0600")
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ApprovalCliError("signature_invalid") from error
        if type(payload) is not dict:
            raise ApprovalCliError("signature_invalid")
        file_transaction = payload.get("transaction_id")
        file_digest = payload.get("digest")
        signature = payload.get("signature")
        if file_transaction != transaction_id or type(file_digest) is not str:
            raise ApprovalCliError("signature_invalid")
        if digest is not None and file_digest != digest:
            raise ApprovalCliError("signature_invalid")
        expected = hmac.new(
            self._signing_key,
            canonical_json_bytes({"transaction_id": file_transaction, "digest": file_digest}),
            hashlib.sha256,
        ).hexdigest()
        if type(signature) is not str or not hmac.compare_digest(expected, signature):
            raise ApprovalCliError("signature_invalid")


__all__ = [
    "AdminRequired",
    "ApprovalCli",
    "ApprovalCliError",
    "ApprovalReceipt",
    "Authorizer",
    "IdentityError",
    "IdentityProbe",
    "Notifier",
    "PlanDetail",
    "PlanSource",
    "ShowResult",
]

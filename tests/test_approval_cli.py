"""Tests for digest-bound local CLI approval.

Only a fake plan source, fake identity probe, fake notifier, fake executor,
and a temporary SQLite approval store are used; no server, mail, systemd, or
real target is touched.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from a4diag.approvals import (
    ApprovalStore,
    NotificationStatus,
)
from a4diag.approval_cli import (
    ApprovalCli,
    ApprovalCliError,
    Authorizer,
    PlanDetail,
)
from a4diag.cli import main as cli_main
from a4diag.domain import Risk, canonical_json_bytes

SIGNING_KEY = b"approval-cli-signing-key-32bytes"
DIGEST = "a" * 64


@dataclass(frozen=True)
class Tx:
    id: str
    digest: str


@dataclass(frozen=True)
class Result:
    exit_code: int
    stdout: str
    stderr: str


class FakePlanSource:
    def __init__(self) -> None:
        self.plans: dict[str, PlanDetail] = {}

    def add(self, plan: PlanDetail) -> None:
        self.plans[plan.transaction_id] = plan

    def plan_for(self, transaction_id: str) -> PlanDetail | None:
        return self.plans.get(transaction_id)


class FakeIdentity:
    def __init__(self) -> None:
        self.fingerprint = "fp-lab"
        self.error: str | None = None

    def probe_fingerprint(self, target_id: str) -> str:
        if self.error is not None:
            from a4diag.approval_cli import IdentityError

            raise IdentityError(self.error)
        return self.fingerprint


class FakeNotifier:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(self, event: object) -> None:
        self.sent.append("sent")


class FakeExecutor:
    def __init__(self) -> None:
        self.apply_count = 0

    def apply(self) -> None:
        self.apply_count += 1


class CliRunner:
    def __init__(self, tmp_path: Path, *, isatty: bool = True) -> None:
        self.now = 1000
        self._approval_ids = iter(range(1, 1000))
        self.approvals = ApprovalStore(
            tmp_path / "approvals.db",
            request_id_factory=lambda: f"appr-{next(self._approval_ids)}",
        )
        self.plans = FakePlanSource()
        self.notifier = FakeNotifier()
        self.identity = FakeIdentity()
        self.executor = FakeExecutor()
        self.authorizer = Authorizer(is_admin=True)
        self.isatty = isatty
        self.approval_cli = ApprovalCli(
            approvals=self.approvals,
            plans=self.plans,
            notifier=self.notifier,
            identity=self.identity,
            authorizer=self.authorizer,
            clock=lambda: self.now,
            stdin_isatty=lambda: self.isatty,
            actor_factory=lambda: "tester",
            signing_key=SIGNING_KEY,
        )

    def seed_pending(
        self,
        plan: PlanDetail,
        *,
        notification_required: bool = False,
        delivered: bool | None = None,
    ) -> Tx:
        approval = self.approvals.request(
            plan.transaction_id,
            plan.target_id,
            plan.plan_digest,
            expires_at=plan.expires_at,
            now=self.now,
            notification_required=notification_required,
        )
        if delivered is not None:
            self.approvals.begin_notification(approval.id, now=self.now)
            self.approvals.complete_notification(
                approval.id, delivered=delivered, now=self.now
            )
        self.plans.add(plan)
        return Tx(plan.transaction_id, plan.plan_digest)

    def run(
        self,
        argv: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> Result:
        monkeypatch.setattr(
            "a4diag.cli._build_approval_cli", lambda: self.approval_cli
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        monkeypatch.setattr("sys.stdout", stdout)
        monkeypatch.setattr("sys.stderr", stderr)
        code = cli_main(argv)
        return Result(code, stdout.getvalue(), stderr.getvalue())


@pytest.fixture
def cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    return CliRunner(tmp_path)


def high_plan(**updates: object) -> PlanDetail:
    values: dict[str, object] = {
        "transaction_id": "tx-1",
        "target_id": "lab",
        "target_fingerprint": "fp-lab",
        "plan_digest": DIGEST,
        "risk": Risk.HIGH,
        "operations": (
            {
                "capability": "packages",
                "action": "install_exact",
                "resource": "httpd",
                "parameters": {"name": "httpd", "version": "2.4.62"},
            },
        ),
        "equivalent_commands": ("dnf -y install httpd-2.4.62",),
        "verify": ("rpm -q httpd == 2.4.62",),
        "undo": ("dnf -y install httpd-2.4.57",),
        "expires_at": 2000,
    }
    values.update(updates)
    return PlanDetail.model_validate(values)


def signed_approval_file(
    tmp_path: Path,
    *,
    transaction_id: str = "tx-1",
    digest: str = DIGEST,
    key: bytes = SIGNING_KEY,
    tamper: str | None = None,
) -> Path:
    payload = {"transaction_id": transaction_id, "digest": digest}
    signature = hmac.new(
        key, canonical_json_bytes(payload), hashlib.sha256
    ).hexdigest()
    content = {**payload, "signature": signature}
    if tamper == "digest":
        content["digest"] = "b" * 64
    if tamper == "signature":
        content["signature"] = "0" * 64
    path = tmp_path / "approval-request.json"
    path.write_bytes(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return path


# ---------------------------------------------------------------------------
# Approve
# ---------------------------------------------------------------------------


def test_approve_requires_exact_displayed_digest(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", "0" * 64], monkeypatch
    )

    assert result.exit_code == 65
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None
    assert cli.executor.apply_count == 0


def test_approve_matching_digest_succeeds(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest, "--json"], monkeypatch
    )

    assert result.exit_code == 0
    assert cli.approvals.valid_digest(tx.id, now=cli.now) == tx.digest
    assert cli.executor.apply_count == 0
    assert "approved" in result.stdout


def test_required_notification_failure_blocks_approval(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(
        high_plan(), notification_required=True, delivered=False
    )

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 69
    assert cli.executor.apply_count == 0
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None


def test_required_notification_delivered_allows_approval(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(
        high_plan(), notification_required=True, delivered=True
    )

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 0
    assert cli.approvals.valid_digest(tx.id, now=cli.now) == tx.digest


def test_optional_notification_failure_still_approvable(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan(), notification_required=False, delivered=False)

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 0
    assert cli.approvals.valid_digest(tx.id, now=cli.now) == tx.digest


def test_identity_change_blocks_approval(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())
    cli.identity.fingerprint = "fp-changed"

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 65
    assert "identity" in result.stderr
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None


def test_identity_probe_failure_blocks_approval(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())
    cli.identity.error = "host_key_mismatch"

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 65
    assert "host_key_mismatch" in result.stderr


def test_expired_approval_is_rejected(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan(expires_at=2000))
    cli.now = 2500

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 65
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None


def test_approve_unknown_transaction(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    result = cli.run(
        ["approvals", "approve", "missing-tx", "--digest", DIGEST], monkeypatch
    )

    assert result.exit_code == 64


def test_approve_invalid_digest_format(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", "not-a-digest"], monkeypatch
    )

    assert result.exit_code == 64


def test_non_admin_cannot_approve(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())
    cli.authorizer.is_admin = False

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 77
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None


def test_non_tty_stdin_rejected_by_default(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())
    cli.isatty = False

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 64
    assert "tty" in result.stderr.lower()


def test_non_tty_with_valid_signed_file_approves(cli: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tx = cli.seed_pending(high_plan())
    cli.isatty = False
    request_file = signed_approval_file(tmp_path)

    result = cli.run(
        [
            "approvals", "approve", tx.id, "--digest", tx.digest,
            "--non-interactive-approval-file", str(request_file),
        ],
        monkeypatch,
    )

    assert result.exit_code == 0
    assert cli.approvals.valid_digest(tx.id, now=cli.now) == tx.digest


def test_non_tty_with_bad_signature_rejected(cli: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tx = cli.seed_pending(high_plan())
    cli.isatty = False
    request_file = signed_approval_file(tmp_path, tamper="signature")

    result = cli.run(
        [
            "approvals", "approve", tx.id, "--digest", tx.digest,
            "--non-interactive-approval-file", str(request_file),
        ],
        monkeypatch,
    )

    assert result.exit_code == 65
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None


def test_approve_plan_digest_mismatch_with_store(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    # The plan source and the approval record disagree: state changed.
    plan = high_plan()
    tx = cli.seed_pending(plan)
    cli.plans.add(
        plan.model_copy(update={"plan_digest": "b" * 64})
    )

    result = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest], monkeypatch
    )

    assert result.exit_code == 65


# ---------------------------------------------------------------------------
# Reject
# ---------------------------------------------------------------------------


def test_reject_with_reason_succeeds(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())

    result = cli.run(
        ["approvals", "reject", tx.id, "--reason", "not acceptable"], monkeypatch
    )

    assert result.exit_code == 0
    record = cli.approvals.for_transaction(tx.id)
    assert record is not None
    assert record.status.value == "rejected"


def test_reject_non_admin(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())
    cli.authorizer.is_admin = False

    result = cli.run(
        ["approvals", "reject", tx.id, "--reason", "no"], monkeypatch
    )

    assert result.exit_code == 77


def test_reject_unknown_transaction(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    result = cli.run(
        ["approvals", "reject", "missing-tx", "--reason", "no"], monkeypatch
    )

    assert result.exit_code == 64


def test_reject_non_tty_rejected(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())
    cli.isatty = False

    result = cli.run(
        ["approvals", "reject", tx.id, "--reason", "no"], monkeypatch
    )

    assert result.exit_code == 64


# ---------------------------------------------------------------------------
# Show and list
# ---------------------------------------------------------------------------


def test_show_displays_required_approval_content(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    tx = cli.seed_pending(high_plan())

    result = cli.run(["approvals", "show", tx.id, "--json"], monkeypatch)

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["target_id"] == "lab"
    assert body["target_fingerprint"] == "fp-lab"
    assert body["plan_digest"] == DIGEST
    assert body["risk"] == "high"
    assert body["operations"][0]["capability"] == "packages"
    assert "dnf -y install httpd-2.4.62" in json.dumps(body)
    assert body["verify"][0] == "rpm -q httpd == 2.4.62"
    assert body["undo"][0] == "dnf -y install httpd-2.4.57"
    assert body["expires_at"] == 2000
    assert body["notification_status"] == "not_started"


def test_list_shows_pending_approvals(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    cli.seed_pending(high_plan(transaction_id="tx-1"))
    cli.seed_pending(high_plan(transaction_id="tx-2"))

    result = cli.run(["approvals", "list", "--json"], monkeypatch)

    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert {entry["transaction_id"] for entry in body["approvals"]} == {"tx-1", "tx-2"}


def test_show_unknown_transaction(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    result = cli.run(["approvals", "show", "missing-tx"], monkeypatch)

    assert result.exit_code == 64


def test_output_never_leaks_secret(cli: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = high_plan(
        equivalent_commands=("curl -H 'Authorization: Bearer super-secret-token' https://example.test",),
    )
    tx = cli.seed_pending(plan)

    show = cli.run(["approvals", "show", tx.id, "--json"], monkeypatch)
    approve = cli.run(
        ["approvals", "approve", tx.id, "--digest", tx.digest, "--json"], monkeypatch
    )

    assert "super-secret-token" not in show.stdout
    assert "super-secret-token" not in approve.stdout
    assert "super-secret-token" not in show.stderr
    assert "super-secret-token" not in approve.stderr

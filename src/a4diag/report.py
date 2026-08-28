from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
from typing import Literal

import yaml

from a4diag.domain import JsonValue, Operation, Plan
from a4diag.redaction import redact
from a4diag.transaction_store import UnknownTransactionError


ReportClass = Literal["normal", "abnormal"]


class ReportWriter:
    def __init__(self, report_root: Path) -> None:
        self._report_root = report_root

    def write(self, report: Mapping[str, object]) -> Path:
        task_id = report.get("task_id")
        finished_at_value = report.get("finished_at")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id is required")
        if not isinstance(finished_at_value, str):
            raise ValueError("finished_at is required")
        finished_at = datetime.fromisoformat(
            finished_at_value.replace("Z", "+00:00")
        )
        if finished_at.tzinfo is None:
            raise ValueError("finished_at must include timezone")

        directory = self._report_root / finished_at.date().isoformat()
        directory.mkdir(parents=True, exist_ok=True, mode=0o750)
        destination = directory / f"{task_id}.yaml"
        payload = yaml.safe_dump(
            dict(report),
            allow_unicode=True,
            sort_keys=True,
        ).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{task_id}.",
            suffix=".tmp",
            dir=directory,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o640)
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return destination


def classify_report(report: Mapping[str, object]) -> ReportClass:
    if (
        report.get("status") == "diagnosed"
        and report.get("conclusion") == "normal"
        and report.get("evidence_complete") is True
    ):
        return "normal"
    return "abnormal"


def cleanup_expired(
    report_root: Path,
    *,
    normal_days: int,
    abnormal_days: int,
    now: datetime | None = None,
) -> list[Path]:
    if normal_days != 1:
        raise ValueError("normal_days must equal 1")
    if abnormal_days != 14:
        raise ValueError("abnormal_days must equal 14")
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    deleted: list[Path] = []
    if not report_root.exists():
        return deleted
    for path in report_root.rglob("*.yaml"):
        if path.is_symlink() or not path.is_file():
            continue
        report = _read_report(path)
        report_class = classify_report(report)
        retention = timedelta(
            days=normal_days if report_class == "normal" else abnormal_days
        )
        finished_at = _finished_at(report, path)
        if current_time - finished_at >= retention:
            path.unlink()
            deleted.append(path)
    return deleted


def _read_report(path: Path) -> Mapping[str, object]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return {}
    return value if isinstance(value, dict) else {}


def _finished_at(report: Mapping[str, object], path: Path) -> datetime:
    value = report.get("finished_at")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None and parsed.tzinfo is not None:
            return parsed
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


# ---------------------------------------------------------------------------
# Generic v3 runtime reports
# ---------------------------------------------------------------------------


def display_operation(operation: Operation) -> str:
    """The fixed, human-checkable command equivalent of one typed operation."""
    if not isinstance(operation, Operation):
        raise TypeError("operation must be Operation")
    return f"{operation.capability} {operation.action} {operation.resource}"


def equivalent_commands(plan: Plan) -> tuple[str, ...]:
    return tuple(display_operation(operation) for operation in plan.operations)


def residual_risk(state: Mapping[str, object]) -> str:
    """Summarize what remains uncertain after the workflow finished."""
    status = state.get("status")
    if status in {"succeeded", "rollback_succeeded"}:
        return "none"
    if status == "rollback_partial":
        return "high: rollback incomplete"
    if status in {"rollback_unknown", "execution_unknown"}:
        return "high: execution outcome unknown"
    if status == "failed":
        return "medium: no durable change recorded"
    if status == "read_only_no_model":
        return "medium: no model available; nothing applied"
    if status == "pending_approval":
        return "low: no change applied yet"
    return "none"


def manual_investigation_commands(transaction_id: str = "") -> tuple[str, ...]:
    """Stable commands an operator can run to investigate or finish manually."""
    commands = [
        "journalctl -u a4diag -n 200 --no-pager",
        "a4diag approvals list --json",
    ]
    if transaction_id:
        commands.append(f"a4diag approvals show {transaction_id}")
    return tuple(commands)


def _parse_payload(payload_json: str) -> JsonValue:
    try:
        value = json.loads(
            payload_json,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, TypeError, UnicodeDecodeError):
        return {"unparsable": True}
    if type(value) not in (dict, list, str, int, float, bool) or value is None:
        return {"unparsable": True}
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = item
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def build_runtime_report(
    state: Mapping[str, object], dependencies: object
) -> dict[str, JsonValue]:
    """Assemble the full redacted runtime report from workflow state.

    ``dependencies`` is the ``WorkflowDependencies`` used to run the graph; it
    provides the durable transaction results and approval/notification status.
    """
    from a4diag.workflow import WorkflowDependencies  # local import: no cycle

    if not isinstance(dependencies, WorkflowDependencies):
        raise TypeError("dependencies must be WorkflowDependencies")

    transaction_id = state.get("transaction_id", "")
    report: dict[str, JsonValue] = {
        "status": state.get("status", "failed"),
        "event_id": state.get("event_id", transaction_id),
        "transaction_id": transaction_id,
        "target_id": state.get("target_id", ""),
        "target_fingerprint": state.get("target_fingerprint", ""),
        "error": state.get("error", ""),
        "policy_reason": state.get("policy_reason", ""),
    }

    evidence = state.get("evidence")
    if isinstance(evidence, list):
        report["evidence"] = evidence

    operations: list[JsonValue] = []
    commands: list[str] = []
    plan_value = state.get("plan")
    if isinstance(plan_value, dict):
        try:
            plan = Plan.model_validate(plan_value)
        except (ValueError, TypeError):
            plan = None
        if plan is not None:
            operations = [
                redact(operation.model_dump(mode="json"))
                for operation in plan.operations
            ]
            commands = list(equivalent_commands(plan))
            if plan.target_fingerprint:
                report["target_fingerprint"] = plan.target_fingerprint
    report["operations"] = operations
    report["equivalent_commands"] = commands
    report["risk"] = state.get("risk", "")

    approval_status = "none"
    notification_status = "none"
    if transaction_id:
        try:
            approval = dependencies.approvals.for_transaction(transaction_id)
        except Exception:
            approval = None
        if approval is not None:
            approval_status = approval.status.value
            try:
                notification_status = dependencies.approvals.notification_status(
                    approval.id
                ).value
            except Exception:
                notification_status = "unknown"

    results: list[JsonValue] = []
    if transaction_id:
        try:
            for record in dependencies.transactions.get_results(transaction_id):
                results.append(
                    {
                        "step_id": record.step_id,
                        "phase": record.phase,
                        "status": record.status,
                        "payload": redact(_parse_payload(record.payload_json)),
                    }
                )
        except UnknownTransactionError:
            results = []

    report["approval_status"] = approval_status
    report["notification_status"] = notification_status
    report["results"] = results
    report["residual_risk"] = residual_risk(state)
    report["manual_commands"] = manual_investigation_commands(
        str(transaction_id) if transaction_id else ""
    )
    return redact(report)

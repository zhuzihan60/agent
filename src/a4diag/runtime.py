"""Generic plugin runtime.

The runtime assembles settings, the audit chain, the pinned plugin registry,
the policy engine, the durable stores, the ticket issuer, the LangGraph
workflow, and the SQLite checkpointer into one object; resolves incoming
events ONLY against registered target ids (never IP/hostname); drives the
graph; resumes unknown executions; and produces full redacted reports.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from langgraph.checkpoint.sqlite import SqliteSaver

from a4diag.approval_cli import IdentityError, PlanDetail
from a4diag.approvals import ApprovalStore
from a4diag.audit import AuditError, AuditWriter
from a4diag.domain import JsonValue, Operation, Plan, Risk, TargetConfig
from a4diag.plugin_api.ticket import TicketIssuer
from a4diag.plugin_registry import PluginPin, PluginRegistry, PluginRegistryError
from a4diag.policy_engine import PolicyEngine
from a4diag.redaction import redact
from a4diag.report import (
    build_runtime_report,
    display_operation,
    equivalent_commands,
    manual_investigation_commands,
)
from a4diag.settings import AgentSettings, load_settings
from a4diag.transaction_store import TransactionStore
from a4diag.workflow import (
    PluginPorts,
    WorkflowDependencies,
    build_graph,
    run_event,
)


class RuntimeFailure(ValueError):
    """Stable typed runtime failure carrying a reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    status: str
    report: dict[str, JsonValue]
    transaction_id: str | None = None
    recoverable: tuple[str, ...] = ()


def _denied_report(
    *,
    event_id: str,
    target_hint: object,
    target_id: str,
    status: str,
    error: str,
    transaction_id: str = "",
) -> dict[str, JsonValue]:
    report: dict[str, JsonValue] = {
        "status": status,
        "event_id": event_id,
        "transaction_id": transaction_id or event_id,
        "target_id": target_id,
        "target_hint": target_hint if isinstance(target_hint, str) else "",
        "error": error,
        "operations": [],
        "equivalent_commands": [],
        "results": [],
        "residual_risk": "none",
        "manual_commands": manual_investigation_commands(transaction_id),
    }
    return redact(report)


class Runtime:
    """One assembled agent runtime bound to one settings/registry snapshot."""

    def __init__(
        self,
        *,
        settings: AgentSettings,
        registry: PluginRegistry,
        policy: PolicyEngine,
        approvals: ApprovalStore,
        transactions: TransactionStore,
        tickets: TicketIssuer,
        checkpointer: object,
        plugins: PluginPorts,
        audit: AuditWriter,
        clock: Callable[[], int] | None = None,
        recoverable: tuple[str, ...] = (),
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._deps = WorkflowDependencies(
            settings=settings,
            registry=registry,
            policy=policy,
            approvals=approvals,
            transactions=transactions,
            tickets=tickets,
            plugins=plugins,
            checkpointer=checkpointer,
            clock=clock,
        )
        self._graph = build_graph(self._deps)
        self._audit = audit
        self._recoverable = tuple(recoverable)
        self._read_only = False
        self._registered_ids = frozenset(target.id for target in settings.targets)

    # -- read-only surface -------------------------------------------------

    @property
    def plugins(self) -> PluginPorts:
        return self._deps.plugins

    @property
    def executor(self) -> object:
        return self._deps.plugins.executor

    @property
    def audit(self) -> AuditWriter:
        return self._audit

    @property
    def approvals(self) -> ApprovalStore:
        return self._deps.approvals

    @property
    def settings(self) -> AgentSettings:
        return self._settings

    @property
    def registered_target_ids(self) -> frozenset[str]:
        return self._registered_ids

    @property
    def recoverable(self) -> tuple[str, ...]:
        return self._recoverable

    # -- event handling ----------------------------------------------------

    def handle(self, event: Mapping[str, object]) -> RuntimeResult:
        if not isinstance(event, Mapping):
            raise TypeError("event must be a mapping")
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise RuntimeFailure("invalid_event", "event requires event_id")
        target_id = self._resolve_target(event)
        target_hint = event.get("target_hint", event.get("target_id", ""))
        status: str
        error = ""
        if self._read_only:
            status = "read_only"
            error = "audit_chain_broken"
        elif target_id is None:
            candidate = event.get("target_id", event.get("target_hint"))
            has_hint = isinstance(candidate, str) and bool(candidate)
            status = "policy_denied" if has_hint else "read_only"
            error = "target_not_registered" if has_hint else ""
        else:
            status = ""
        if status:
            try:
                self._audit.append(
                    {
                        "event": "runtime_ingest",
                        "transaction_id": event_id,
                        "target_id": target_id or "",
                        "status": status,
                    }
                )
            except AuditError as audit_error:
                self._read_only = True
                status = "read_only"
                error = str(audit_error)
            return RuntimeResult(
                status=status,
                report=_denied_report(
                    event_id=event_id,
                    target_hint=target_hint,
                    target_id=target_id or "",
                    status=status,
                    error=error,
                ),
                transaction_id=event_id,
            )

        try:
            self._audit.append(
                {
                    "event": "runtime_ingest",
                    "transaction_id": event_id,
                    "target_id": target_id or "",
                    "status": "dispatched",
                }
            )
        except AuditError:
            self._read_only = True
            return RuntimeResult(
                status="read_only",
                report=_denied_report(
                    event_id=event_id,
                    target_hint=target_hint,
                    target_id=target_id or "",
                    status="read_only",
                    error="audit_chain_broken",
                ),
                transaction_id=event_id,
            )
        state = run_event(
            self._graph,
            {
                "event_id": event_id,
                "target_id": cast(str, target_id),
                "request": event.get("request"),
            },
        )
        result_status = state.get("status", "failed")
        report = build_runtime_report(state, self._deps)
        try:
            self._audit.append(
                {
                    "event": "runtime_finished",
                    "transaction_id": event_id,
                    "status": result_status,
                }
            )
        except AuditError:
            self._read_only = True
        return RuntimeResult(
            status=result_status,
            report=report,
            transaction_id=event_id,
            recoverable=self._recoverable,
        )

    def resume(self, transaction_id: str) -> RuntimeResult:
        if not isinstance(transaction_id, str) or not transaction_id:
            raise RuntimeFailure("invalid_event", "resume requires transaction_id")
        # The checkpoint is the source of truth for a resumable thread; a
        # pending-approval thread legitimately has no transaction row yet
        # (the write transaction only begins after approval).
        try:
            snapshot = self._graph.get_state(
                {"configurable": {"thread_id": transaction_id}}
            )
        except Exception as error:
            raise RuntimeFailure(
                "unknown_transaction", transaction_id
            ) from error
        if not getattr(snapshot, "values", None):
            raise RuntimeFailure("unknown_transaction", transaction_id)
        if self._read_only:
            return RuntimeResult(
                status="read_only",
                report=_denied_report(
                    event_id=transaction_id,
                    target_hint="",
                    target_id="",
                    status="read_only",
                    error="audit_chain_broken",
                    transaction_id=transaction_id,
                ),
                transaction_id=transaction_id,
            )
        try:
            self._audit.append(
                {
                    "event": "runtime_resume",
                    "transaction_id": transaction_id,
                    "status": "dispatched",
                }
            )
        except AuditError:
            self._read_only = True
            return RuntimeResult(
                status="read_only",
                report=_denied_report(
                    event_id=transaction_id,
                    target_hint="",
                    target_id="",
                    status="read_only",
                    error="audit_chain_broken",
                    transaction_id=transaction_id,
                ),
                transaction_id=transaction_id,
            )
        state = run_event(
            self._graph, {"resume": True, "transaction_id": transaction_id}
        )
        result_status = state.get("status", "failed")
        report = build_runtime_report(state, self._deps)
        try:
            self._audit.append(
                {
                    "event": "runtime_finished",
                    "transaction_id": transaction_id,
                    "status": result_status,
                }
            )
        except AuditError:
            self._read_only = True
        return RuntimeResult(
            status=result_status,
            report=report,
            transaction_id=transaction_id,
            recoverable=self._recoverable,
        )

    def _resolve_target(self, event: Mapping[str, object]) -> str | None:
        candidate = event.get("target_id", event.get("target_hint"))
        if not isinstance(candidate, str) or not candidate:
            return None
        if candidate not in self._registered_ids:
            return None
        return candidate

    # -- approval-CLI adapters ---------------------------------------------

    def plan_detail(self, transaction_id: str) -> PlanDetail | None:
        """Reconstruct the approved plan snapshot from the graph checkpoint."""
        try:
            self._deps.transactions.get(transaction_id)
            approval = self._deps.approvals.for_transaction(transaction_id)
        except Exception:
            return None
        if approval is None:
            return None
        try:
            snapshot = self._graph.get_state(
                {"configurable": {"thread_id": transaction_id}}
            )
            values = getattr(snapshot, "values", None)
        except Exception:
            return None
        if not isinstance(values, dict):
            return None
        plan_value = values.get("plan")
        digest = values.get("digest")
        if not isinstance(plan_value, dict) or not isinstance(digest, str):
            return None
        if digest != approval.plan_digest:
            return None
        try:
            plan = Plan.model_validate(plan_value)
            risk = Risk(values.get("risk", Risk.LOW.value))
        except (ValueError, TypeError):
            return None
        return PlanDetail(
            transaction_id=transaction_id,
            target_id=values.get("target_id", approval.target_id),
            target_fingerprint=values.get("target_fingerprint", ""),
            plan_digest=digest,
            risk=risk,
            operations=tuple(
                redact(operation.model_dump(mode="json"))
                for operation in plan.operations
            ),
            equivalent_commands=tuple(equivalent_commands(plan)),
            verify=tuple(
                f"verify {display_operation(operation)}"
                for operation in plan.operations
            ),
            undo=tuple(
                f"undo {display_operation(operation)}"
                for operation in plan.operations
            ),
            expires_at=approval.expires_at,
        )

    def probe_fingerprint(self, target_id: str) -> str:
        """Re-probe the live identity of one registered target."""
        target = self._target(target_id)
        try:
            fingerprint = self._deps.plugins.collector.verify_identity(target)
        except Exception as error:
            raise RuntimeFailure(
                "target_identity_unavailable", f"{target_id}:{type(error).__name__}"
            ) from error
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            raise RuntimeFailure("target_identity_missing", target_id)
        return fingerprint

    def target(self, target_id: str) -> TargetConfig:
        """Return the registered TargetConfig; raises RuntimeFailure when unknown."""
        return self._target(target_id)

    def close(self) -> None:
        """Release the audit file descriptor and the checkpointer connection."""
        self._audit.close()
        connection = getattr(self._deps.checkpointer, "conn", None)
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    def notify(self, event: object) -> None:
        """Record a CLI-side notification event on the audit chain."""
        kind = type(event).__name__ if event is not None else "none"
        try:
            self._audit.append(
                {"event": "cli_notification", "kind": kind}
            )
        except AuditError:
            self._read_only = True

    def _target(self, target_id: str) -> TargetConfig:
        for target in self._settings.targets:
            if target.id == target_id:
                return target
        raise RuntimeFailure("unknown_target", target_id)


class RuntimePlanSource:
    """Expose the runtime's plan snapshot as an ApprovalCli PlanSource."""

    def __init__(self, runtime: Runtime) -> None:
        if not isinstance(runtime, Runtime):
            raise TypeError("runtime must be Runtime")
        self._runtime = runtime

    def plan_for(self, transaction_id: str) -> PlanDetail | None:
        return self._runtime.plan_detail(transaction_id)


class RuntimeIdentityProbe:
    """Re-probe live target identity through the runtime's collector port."""

    def __init__(self, runtime: Runtime) -> None:
        if not isinstance(runtime, Runtime):
            raise TypeError("runtime must be Runtime")
        self._runtime = runtime

    def probe_fingerprint(self, target_id: str) -> str:
        try:
            return self._runtime.probe_fingerprint(target_id)
        except RuntimeFailure as error:
            raise IdentityError(str(error)) from error
        except Exception as error:
            raise IdentityError(f"identity_unavailable: {target_id}") from error


class RuntimeNotifier:
    """Route CLI notification events onto the runtime's audit chain."""

    def __init__(self, runtime: Runtime) -> None:
        if not isinstance(runtime, Runtime):
            raise TypeError("runtime must be Runtime")
        self._runtime = runtime

    def send(self, event: object) -> None:
        self._runtime.notify(event)


def build_runtime(
    settings_path: str | Path,
    *,
    audit_path: str | Path,
    checkpoints_path: str | Path,
    transactions_path: str | Path,
    approvals_path: str | Path,
    registry_pins: tuple[PluginPin, ...],
    manifest_root: str | Path,
    plugin_ports_factory: Callable[[AgentSettings, PluginRegistry], PluginPorts],
    ticket_key: bytes,
    policy_key: bytes,
    clock: Callable[[], int] | None = None,
) -> Runtime:
    """Assemble one runtime from a settings file, verifying every input.

    Startup verification order: audit chain integrity, plugin pin digests,
    then a live identity probe of every configured target. Incomplete
    transactions are listed as recoverable for the caller.
    """
    if not callable(plugin_ports_factory):
        raise TypeError("plugin_ports_factory must be callable")
    settings = load_settings(Path(settings_path))
    audit = AuditWriter(
        Path(audit_path),
        clock=(lambda: float(clock())) if clock is not None else None,
    )
    if audit.read_only:
        raise RuntimeFailure("audit_chain_broken")
    try:
        registry = PluginRegistry.load(
            tuple(registry_pins), Path(manifest_root), core_api="1.0"
        )
    except PluginRegistryError as error:
        raise RuntimeFailure("registry_verification_failed", str(error)) from error
    policy = PolicyEngine(settings, registry, authorization_key=policy_key)
    approvals = ApprovalStore(Path(approvals_path))
    transactions = TransactionStore(Path(transactions_path))
    tickets = TicketIssuer(ticket_key, authorization_key=policy_key, clock=clock)
    connection = sqlite3.connect(str(Path(checkpoints_path)), check_same_thread=False)
    checkpointer = SqliteSaver(connection)
    plugins = plugin_ports_factory(settings, registry)
    if not isinstance(plugins, PluginPorts):
        raise RuntimeFailure("plugin_ports_invalid", "factory must return PluginPorts")
    for target in settings.targets:
        try:
            plugins.collector.verify_identity(target)
        except Exception as error:
            raise RuntimeFailure(
                "target_identity_unavailable",
                f"{target.id}:{type(error).__name__}",
            ) from error
    recoverable = transactions.incomplete_transaction_ids()
    return Runtime(
        settings=settings,
        registry=registry,
        policy=policy,
        approvals=approvals,
        transactions=transactions,
        tickets=tickets,
        checkpointer=checkpointer,
        plugins=plugins,
        audit=audit,
        clock=clock,
        recoverable=recoverable,
    )


__all__ = [
    "Runtime",
    "RuntimeFailure",
    "RuntimeIdentityProbe",
    "RuntimeNotifier",
    "RuntimePlanSource",
    "RuntimeResult",
    "build_runtime",
]

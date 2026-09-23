"""Services capability plugin: typed systemd unit lifecycle operations.

Only complete validated unit names are accepted; every command is a fixed
``/usr/bin/systemctl`` argv template. The marker records the unit's
ActiveState, SubState, UnitFileState, and invocation ID so undo restores the
recorded state and reconcile can distinguish a restart from other changes.
"""

from __future__ import annotations

import re
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from a4diag_builtin_plugins.capability_common import (
    BaseCapabilityPlugin,
    CapabilityApplyParams,
    CapabilityPrepareParams,
    CapabilityReconcileParams,
    CapabilityUndoParams,
    CapabilityVerifyParams,
    CapabilityError,
    CommandOutcome,
    EffectResult,
    PrepareResult,
    ReconcileResult,
    ReconcileState,
    ServiceState,
    TransportAdapter,
    VerifyResult,
    marker_from,
)

_VERSION = "1.0.0"
SYSTEMCTL_EXECUTABLE = "/usr/bin/systemctl"
_UNIT_NAME = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,255}\.(service|socket|timer|target|mount|path)$"
)
_ACTIONS = frozenset({"restart", "start", "stop", "enable", "disable", "reset-failed", "reset-failed-start", "reset-failed-restart"})
_RUNTIME_ACTIONS = frozenset({"restart", "start", "stop"})
FAULT_PROPERTIES = ('ActiveState', 'SubState', 'InvocationID', 'MainPID', 'ExecMainStatus', 'Result', 'NRestarts')


class ServiceFaultSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    active_state: Literal['active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance', 'refreshing']
    sub_state: str = Field(min_length=1, max_length=256)
    invocation_id: str = Field(max_length=256)
    main_pid: int = Field(ge=0, strict=True)
    exec_main_status: int = Field(ge=0, strict=True)
    result: str = Field(min_length=1, max_length=256)
    n_restarts: int = Field(ge=0, strict=True)
    observed_at: int = Field(ge=0, strict=True)

    @model_validator(mode='after')
    def valid_identity(self):
        if self.active_state == 'active' and (not self.invocation_id or self.main_pid == 0):
            raise ValueError('service_identity_unavailable')
        for value in (self.sub_state, self.invocation_id, self.result):
            if any(ord(c)<32 or ord(c)==127 for c in value) or value in ('unknown', '[not set]'):
                raise ValueError('service_evidence_unavailable')
        return self


def parse_service_fault_snapshot(output: str, observed_at: int) -> ServiceFaultSnapshot:
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition('=')
        if not sep or key not in FAULT_PROPERTIES or key in values:
            raise ValueError('service_evidence_unavailable')
        values[key] = value
    if set(values) != set(FAULT_PROPERTIES):
        raise ValueError('service_evidence_unavailable')
    for key in ('MainPID', 'ExecMainStatus', 'NRestarts'):
        if not re.fullmatch(r'[0-9]{1,20}', values[key]):
            raise ValueError('service_evidence_unavailable')
        values[key] = int(values[key])
    return ServiceFaultSnapshot(active_state=values['ActiveState'], sub_state=values['SubState'],
        invocation_id=values['InvocationID'], main_pid=values['MainPID'], exec_main_status=values['ExecMainStatus'],
        result=values['Result'], n_restarts=values['NRestarts'], observed_at=observed_at)


class ServiceMarker(BaseModel):
    """Bounded typed pre-state for one systemd unit operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal["restart", "start", "stop", "enable", "disable", "reset-failed", "reset-failed-start", "reset-failed-restart"]
    unit: str
    prior: ServiceState

    @field_validator("unit")
    @classmethod
    def validate_unit(cls, value: str) -> str:
        if not isinstance(value, str) or not _UNIT_NAME.fullmatch(value):
            raise CapabilityError("unit_name_invalid")
        return value


def service_show_argv(unit: str) -> list[str]:
    return [
        SYSTEMCTL_EXECUTABLE,
        "show",
        unit,
        "--no-pager",
        "--property=ActiveState,SubState,UnitFileState,InvocationID",
    ]


def service_action_argv(action: str, unit: str) -> list[str]:
    return [SYSTEMCTL_EXECUTABLE, action, unit]


def parse_service_state(output: str) -> ServiceState:
    values: dict[str, str] = {}
    for raw_line in output.splitlines():
        key, _, value = raw_line.partition("=")
        key = key.strip()
        if key in {"ActiveState", "SubState", "UnitFileState", "InvocationID"}:
            values[key] = value.strip()
    required = {"ActiveState", "SubState", "UnitFileState", "InvocationID"}
    if not required.issubset(values):
        raise CapabilityError("state_unavailable")
    return ServiceState(
        active_state=values["ActiveState"],
        sub_state=values["SubState"],
        unit_file_state=values["UnitFileState"],
        invocation_id=values["InvocationID"],
    )


class ServicesPlugin(BaseCapabilityPlugin):
    def __init__(self, *, transport: TransportAdapter) -> None:
        super().__init__(transport=transport, name="capability-services", version=_VERSION, actions=_ACTIONS)

    async def prepare(
        self, params: CapabilityPrepareParams, invocation: object | None = None
    ) -> PrepareResult:
        action = params.operation.action
        self._require_action(action)
        unit = self._unit(params)
        prior = await self._read_state(unit, params)
        marker = ServiceMarker(action=action, unit=unit, prior=prior)
        return PrepareResult(marker=marker.model_dump(mode="json"))

    async def apply(
        self, params: CapabilityApplyParams, invocation: object | None = None
    ) -> EffectResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action != params.operation.action:
            raise CapabilityError("marker_action_mismatch")
        actions = ('reset-failed', marker.action.removeprefix('reset-failed-')) if marker.action.startswith('reset-failed-') else (marker.action,)
        started = time.monotonic()
        changed = False
        for action in actions:
            remaining = self._timeout(params) - (time.monotonic() - started)
            if remaining <= 0:
                return EffectResult(ok=False, changed=changed, reason='command_budget_exceeded')
            outcome = await self._transport.run_command(service_action_argv(action, marker.unit),
                timeout_seconds=remaining, output_limit_bytes=self._output_limit(params))
            if outcome.returncode != 0:
                return EffectResult(ok=False, changed=changed, reason='command_failed')
            changed = True
        return EffectResult(ok=True, changed=not (marker.action == 'stop' and marker.prior.active_state == 'inactive'),
                            reason='reset_counters_not_restorable' if marker.action.startswith('reset-failed') else None)

    async def undo(
        self, params: CapabilityUndoParams, invocation: object | None = None
    ) -> EffectResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action.startswith('reset-failed'):
            return EffectResult(ok=False, changed=False, reason='reset_counters_not_restorable')
        if marker.action != params.operation.action:
            raise CapabilityError("marker_action_mismatch")
        target_action = self._restore_action(marker)
        outcome = await self._run(service_action_argv(target_action, marker.unit), params)
        if outcome.returncode != 0:
            return EffectResult(ok=False, changed=False, reason="undo_failed")
        current = await self._read_state_or_none(marker.unit, params)
        if current is None or not self._state_satisfies(current, marker, target_action):
            return EffectResult(ok=False, changed=False, reason="undo_verification_failed")
        return EffectResult(ok=True, changed=True)

    async def verify(self, params: CapabilityVerifyParams) -> VerifyResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        current = await self._read_state_or_none(marker.unit, params)
        if current is None:
            return VerifyResult(ok=False, reason="state_unavailable")
        if not self._state_satisfies(current, marker, marker.action):
            return VerifyResult(ok=False, reason="state_mismatch")
        if marker.action.startswith('reset-failed'):
            outcome = await self._run([SYSTEMCTL_EXECUTABLE,'show',marker.unit,'--no-pager',
                                      '--property='+','.join(FAULT_PROPERTIES)],params)
            try:
                fault = parse_service_fault_snapshot(outcome.stdout,observed_at=int(time.time()))
                if outcome.returncode != 0 or fault.n_restarts != 0:
                    return VerifyResult(ok=False,reason='reset_counters_not_zero')
            except ValueError:
                return VerifyResult(ok=False,reason='state_unavailable')
        return VerifyResult(ok=True)

    async def verify_restored(self, params: CapabilityVerifyParams) -> VerifyResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action.startswith('reset-failed'):
            return VerifyResult(ok=False,reason='reset_counters_not_restorable')
        current = await self._read_state_or_none(marker.unit, params)
        if current is None:
            return VerifyResult(ok=False, reason="state_unavailable")
        if not self._same_runtime_state(current, marker.prior):
            return VerifyResult(ok=False, reason="restored_state_mismatch")
        return VerifyResult(ok=True)

    async def reconcile(self, params: CapabilityReconcileParams) -> ReconcileResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        current = await self._read_state_or_none(marker.unit, params)
        if current is None:
            return ReconcileResult(state=ReconcileState.UNKNOWN, reason="state_unavailable")
        if marker.action == "restart":
            if current.invocation_id != marker.prior.invocation_id:
                return ReconcileResult(state=ReconcileState.APPLIED)
            return ReconcileResult(state=ReconcileState.NOT_APPLIED)
        if self._state_satisfies(current, marker, marker.action):
            return ReconcileResult(state=ReconcileState.APPLIED)
        if self._same_runtime_state(current, marker.prior):
            return ReconcileResult(state=ReconcileState.NOT_APPLIED)
        return ReconcileResult(state=ReconcileState.PARTIAL)

    # ------------------------------------------------------------------

    def _marker(self, params: object) -> ServiceMarker:
        marker = getattr(params, "marker", None)
        if not isinstance(marker, dict):
            raise CapabilityError("invalid_marker")
        parsed = marker_from(ServiceMarker, marker)  # type: ignore[arg-type]
        assert isinstance(parsed, ServiceMarker)
        if parsed.unit != self._unit(params):
            raise CapabilityError('marker_resource_mismatch')
        return parsed

    def _unit(self, params: CapabilityPrepareParams) -> str:
        unit = params.operation.resource
        if not isinstance(unit, str) or not _UNIT_NAME.fullmatch(unit):
            raise CapabilityError("unit_name_invalid")
        parameters = params.operation.parameters
        if parameters.get("unit") != unit:
            raise CapabilityError("unit_mismatch")
        if any(key != "unit" for key in parameters):
            raise CapabilityError("invalid_parameters")
        return unit

    async def _read_state(self, unit: str, params: object) -> ServiceState:
        outcome = await self._run(service_show_argv(unit), params)
        if outcome.returncode != 0:
            raise CapabilityError("unit_unavailable")
        try:
            return parse_service_state(outcome.stdout)
        except CapabilityError:
            raise

    async def _read_state_or_none(self, unit: str, params: object) -> ServiceState | None:
        try:
            return await self._read_state(unit, params)
        except CapabilityError:
            return None

    async def _run(self, argv: list[str], params: object) -> CommandOutcome:
        return await self._transport.run_command(
            argv,
            timeout_seconds=self._timeout(params),
            output_limit_bytes=self._output_limit(params),
        )

    def _restore_action(self, marker: ServiceMarker) -> str:
        if marker.action in _RUNTIME_ACTIONS:
            return "start" if marker.prior.active_state == "active" else "stop"
        return "enable" if marker.prior.unit_file_state == "enabled" else "disable"

    def _state_satisfies(self, current: ServiceState, marker: ServiceMarker, action: str) -> bool:
        if action in {"restart", "start", "reset-failed-start", "reset-failed-restart"}:
            return current.active_state == "active"
        if action == 'reset-failed':
            return current.active_state != 'failed'
        if action == "stop":
            return current.active_state != "active"
        if action == "enable":
            return current.unit_file_state == "enabled"
        if action == "disable":
            return current.unit_file_state != "enabled"
        return False

    def _same_runtime_state(self, current: ServiceState, prior: ServiceState) -> bool:
        return (
            current.active_state == prior.active_state
            and current.sub_state == prior.sub_state
            and current.unit_file_state == prior.unit_file_state
        )


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "capability-services is started by the plugin supervisor with its manifest"
    )


__all__ = [
    "SYSTEMCTL_EXECUTABLE",
    "ServiceMarker",
    "ServicesPlugin",
    "main",
    "parse_service_state",
    "service_action_argv",
    "service_show_argv",
]

"""Contract tests for the files, services, and packages capability plugins.

No real target modification happens: every file operation and command runs
against the in-memory ``FakeTarget`` adapter, and the only real-filesystem
exercises are the symlink/device guards repeated on Windows where supported.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from a4diag.domain import Operation, Risk, canonical_json_bytes
from a4diag.plugin_api.manifest import PluginManifest, PluginType
from a4diag.plugin_api.protocol import (
    MethodKind,
    PluginHost,
    RpcRequest,
    effect_fields_digest,
)
from a4diag.plugin_api.ticket import (
    OperationPhase,
    OperationTicketRequest,
    TicketIssuer,
    TicketVerifier,
)
from a4diag.policy_engine import PolicyAuthorization, canonical_operation_digest

from a4diag_builtin_plugins.capability_common import (
    CapabilityApplyParams,
    CapabilityPrepareParams,
    CapabilityReconcileParams,
    CapabilityUndoParams,
    CapabilityVerifyParams,
    CapabilityError,
    CommandOutcome,
    ReconcileState,
    ServiceState,
    StatInfo,
    TransportAdapter,
    build_capability_bindings,
)
from a4diag_builtin_plugins.capability_files import (
    FileMarker,
    FilesPlugin,
)
from a4diag_builtin_plugins.capability_services import (
    ServiceMarker,
    ServicesPlugin,
    parse_service_state,
    service_action_argv,
    service_show_argv,
)
from a4diag_builtin_plugins.capability_packages import (
    PackageMarker,
    PackagesPlugin,
    apt_install_argv,
    apt_remove_argv,
    dnf_install_argv,
    dnf_remove_argv,
)

KEY = b"capability-contract-ticket-key-32bytes"
POLICY_KEY = b"capability-contract-policy-key-32bytes"
MANIFEST_ROOT = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "a4diag-builtin-plugins"
    / "manifests"
)


class ReplayStore:
    def __init__(self) -> None:
        self.consumed: set[str] = set()

    def consume(self, ticket_id: str) -> bool:
        if ticket_id in self.consumed:
            return False
        self.consumed.add(ticket_id)
        return True


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class FakeTarget:
    """In-memory target adapter: files, service states, packages, and calls."""

    def __init__(self, *, os_id: str = "rocky", os_version_id: str = "9") -> None:
        self.os_id = os_id
        self.os_version_id = os_version_id
        self.files: dict[str, bytes] = {}
        self.modes: dict[str, int] = {}
        self.owners: dict[str, tuple[int, int]] = {}
        self.nodes: dict[str, str] = {}  # path -> file|dir|symlink|device
        self.calls: list[tuple[str, object]] = []
        self.service_state: dict[str, ServiceState] = {}
        self.installed: dict[str, str] = {}  # package -> version
        self.available: dict[str, set[str]] = {}  # package -> available versions

    def add_file(self, path: str, content: bytes, *, mode: int = 0o100644) -> None:
        self._add_parents(path)
        self.files[path] = content
        self.modes[path] = mode
        self.owners[path] = (0, 0)
        self.nodes[path] = "file"

    def add_dir(self, path: str) -> None:
        self._add_parents(path)
        self.nodes[path] = "dir"

    def _add_parents(self, path: str) -> None:
        components = path.split("/")[1:-1]
        for index in range(1, len(components) + 1):
            prefix = "/" + "/".join(components[:index])
            self.nodes.setdefault(prefix, "dir")

    def add_symlink(self, path: str) -> None:
        self.nodes[path] = "symlink"

    def add_device(self, path: str) -> None:
        self.nodes[path] = "device"

    async def lstat(self, path: str) -> StatInfo:
        self.calls.append(("lstat", path))
        node = self.nodes.get(path)
        if node is None:
            raise CapabilityError("path_not_found")
        mode = {
            "file": self.modes.get(path, 0o100644),
            "dir": 0o40755,
            "symlink": 0o120777,
            "device": 0o60066,
        }[node]
        owner = self.owners.get(path, (0, 0))
        return StatInfo(mode=mode, uid=owner[0], gid=owner[1])

    async def read_file(self, path: str, limit: int) -> bytes:
        self.calls.append(("read_file", path))
        if path not in self.files:
            raise CapabilityError("read_failed")
        return self.files[path][:limit]

    async def write_file(self, path: str, content: bytes, mode: int | None) -> None:
        self.calls.append(("write_file", path))
        self.files[path] = content
        self.nodes[path] = "file"
        if mode is not None:
            self.modes[path] = mode

    async def set_mode(self, path: str, mode: int) -> None:
        self.calls.append(("set_mode", path))
        self.modes[path] = mode

    async def chown(self, path: str, uid: int, gid: int) -> None:
        self.calls.append(("chown", (path, uid, gid)))
        self.owners[path] = (uid, gid)

    async def run_command(
        self,
        argv: list[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> CommandOutcome:
        self.calls.append(("run_command", list(argv)))
        if "--property=ActiveState,SubState,UnitFileState,InvocationID" in argv:
            unit = argv[2]
            state = self.service_state.get(unit)
            if state is None:
                return CommandOutcome(returncode=1, stdout="", stderr="Unit not found")
            return CommandOutcome(
                returncode=0,
                stdout=(
                    f"ActiveState={state.active_state}\n"
                    f"SubState={state.sub_state}\n"
                    f"UnitFileState={state.unit_file_state}\n"
                    f"InvocationID={state.invocation_id}\n"
                ),
                stderr="",
            )
        if argv[:1] == ["/usr/bin/systemctl"]:
            action, unit = argv[1], argv[-1]
            current = self.service_state.get(unit)
            if current is None:
                return CommandOutcome(returncode=1, stdout="", stderr="Unit not found")
            if action in ("restart", "start"):
                next_state = current.model_copy(
                    update={
                        "active_state": "active",
                        "sub_state": "running",
                        "invocation_id": f"inv-{len(self.calls)}",
                    }
                )
            elif action == "stop":
                next_state = current.model_copy(
                    update={"active_state": "inactive", "sub_state": "dead"}
                )
            elif action == "enable":
                next_state = current.model_copy(update={"unit_file_state": "enabled"})
            else:  # disable
                next_state = current.model_copy(update={"unit_file_state": "disabled"})
            self.service_state[unit] = next_state
            return CommandOutcome(returncode=0, stdout="", stderr="")
        if argv[:2] == ["/usr/bin/rpm", "-q"]:
            name = argv[-1]
            if name in self.installed:
                return CommandOutcome(returncode=0, stdout=self.installed[name], stderr="")
            return CommandOutcome(returncode=1, stdout="", stderr="")
        if argv[:1] == ["/usr/bin/dpkg-query"]:
            name = argv[-1]
            if name in self.installed:
                return CommandOutcome(returncode=0, stdout=self.installed[name] + "\n", stderr="")
            return CommandOutcome(returncode=1, stdout="", stderr="")
        if argv[:2] == ["/usr/bin/dnf", "repoquery"]:
            name, _, version = argv[-1].rpartition("-")
            found = version in self.available.get(name, set())
            return CommandOutcome(
                returncode=0 if found else 1,
                stdout=f"{argv[-1]}\n" if found else "",
                stderr="",
            )
        if argv[:1] == ["/usr/bin/apt-cache"]:
            name = argv[-1]
            candidates = self.available.get(name, set())
            candidate = sorted(candidates)[-1] if candidates else ""
            return CommandOutcome(
                returncode=0,
                stdout=f"{name}:\n  Candidate: {candidate}\n",
                stderr="",
            )
        if argv[:1] == ["/usr/bin/dnf"] and argv[2] in ("install", "remove"):
            if argv[2] == "install":
                name, _, version = argv[3].rpartition("-")
                self.installed[name] = version
            else:
                self.installed.pop(argv[3], None)
            return CommandOutcome(returncode=0, stdout="", stderr="")
        if argv[:1] == ["/usr/bin/apt-get"]:
            if argv[1] == "install":
                spec = argv[-1]
                name, _, version = spec.partition("=")
                self.installed[name] = version
            elif argv[1] == "remove":
                self.installed.pop(argv[-1], None)
            return CommandOutcome(returncode=0, stdout="", stderr="")
        return CommandOutcome(returncode=1, stdout="", stderr="unexpected command")

    async def os_release(self) -> tuple[str, str]:
        return (self.os_id, self.os_version_id)


def operation(**updates: object) -> Operation:
    values: dict[str, object] = {
        "capability": "files",
        "action": "replace_managed_file",
        "resource": "/etc/example/app.conf",
        "parameters": {"content": base64.b64encode(b"new").decode()},
        "model_risk": Risk.LOW,
        "verify": {"content_sha256": sha256_bytes(b"new")},
        "undo": {"restore": True},
        "timeout_seconds": 5,
        "output_limit_bytes": 4096,
    }
    values.update(updates)
    return Operation.model_validate(values)


def prepare_params(operation_value: Operation) -> CapabilityPrepareParams:
    return CapabilityPrepareParams(
        transaction_id="tx-1",
        step_id="step-1",
        target_id="lab",
        target_fingerprint="machine-1",
        operation=operation_value,
        plan_digest="a" * 64,
        risk=Risk.LOW,
        approval_id=None,
    )


def apply_params(
    operation_value: Operation, marker: dict[str, Any]
) -> CapabilityApplyParams:
    return CapabilityApplyParams(
        transaction_id="tx-1",
        step_id="step-1",
        target_id="lab",
        target_fingerprint="machine-1",
        operation=operation_value,
        plan_digest="a" * 64,
        risk=Risk.LOW,
        approval_id=None,
        marker=marker,
    )


def undo_params(
    operation_value: Operation, marker: dict[str, Any]
) -> CapabilityUndoParams:
    return CapabilityUndoParams(
        transaction_id="tx-1",
        step_id="step-1",
        target_id="lab",
        target_fingerprint="machine-1",
        operation=operation_value,
        plan_digest="a" * 64,
        risk=Risk.LOW,
        approval_id=None,
        marker=marker,
    )


def verify_params(
    operation_value: Operation, marker: dict[str, Any]
) -> CapabilityVerifyParams:
    return CapabilityVerifyParams(
        transaction_id="tx-1",
        step_id="step-1",
        operation=operation_value,
        marker=marker,
    )


def reconcile_params(
    operation_value: Operation, marker: dict[str, Any]
) -> CapabilityReconcileParams:
    return CapabilityReconcileParams(
        transaction_id="tx-1",
        step_id="step-1",
        operation=operation_value,
        marker=marker,
    )


def authorization(params: CapabilityApplyParams) -> PolicyAuthorization:
    unsigned = PolicyAuthorization(
        target_id=params.target_id,
        target_fingerprint=params.target_fingerprint,
        plan_digest=params.plan_digest,
        risk=params.risk,
        approval_id=params.approval_id,
        operation_digests=(canonical_operation_digest(params.operation),),
        mac="0" * 64,
    )
    payload = canonical_json_bytes(unsigned.model_dump(mode="json", exclude={"mac"}))
    tag = hmac.new(
        POLICY_KEY,
        b"a4diag-policy-authorization-v1\x00" + payload,
        hashlib.sha256,
    ).hexdigest()
    return unsigned.model_copy(update={"mac": tag})


_TICKET_IDS = itertools.count()


def issue_ticket(params: CapabilityApplyParams, phase: OperationPhase) -> str:
    request = OperationTicketRequest(
        **params.model_dump(exclude={"marker"}),
        phase=phase,
        effect_payload_digest=effect_fields_digest(params),
        ttl_seconds=30,
    )
    return TicketIssuer(
        KEY,
        authorization_key=POLICY_KEY,
        clock=lambda: 100,
        ticket_id_factory=lambda: f"ticket-{next(_TICKET_IDS)}",
    ).issue(request, authorization(params))


def files_plugin(target: FakeTarget) -> FilesPlugin:
    return FilesPlugin(transport=target)


def services_plugin(target: FakeTarget) -> ServicesPlugin:
    return ServicesPlugin(transport=target)


def packages_plugin(target: FakeTarget) -> PackagesPlugin:
    return PackagesPlugin(transport=target)


def service_state(
    *, active: str = "inactive", sub: str = "dead", file_state: str = "disabled", invocation: str = "inv-0"
) -> ServiceState:
    return ServiceState(
        active_state=active,
        sub_state=sub,
        unit_file_state=file_state,
        invocation_id=invocation,
    )


def manifest_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "capability-files",
        "plugin_type": "capability",
        "version": "0.4.0",
        "api_min": "1.0",
        "api_max": "1.0",
        "executable": "a4diag_builtin_plugins.capability_files:main",
        "socket": "/run/a4diag/capability-files.sock",
        "config_schema": "schemas/capability-files.json",
        "operations": [
            {
                "name": "files.replace_managed_file",
                "risk_floor": "low",
                "reversible": True,
                "supports_prepare": True,
                "supports_verify": True,
                "supports_reconcile": True,
                "supports_undo": True,
                "parameters_schema": {
                    "type": "object",
                    "properties": {"content": {"type": "string"}},
                    "required": ["content"],
                    "additionalProperties": False,
                },
            }
        ],
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# Files capability
# ---------------------------------------------------------------------------


def test_files_rejects_symlink_escape() -> None:
    target = FakeTarget()
    target.add_dir("/etc")
    target.add_dir("/etc/example")
    target.add_symlink("/etc/example/managed")
    plugin = files_plugin(target)
    request = prepare_params(
        operation(resource="/etc/example/managed/app.conf")
    )

    with pytest.raises(CapabilityError, match="symlink_escape"):
        asyncio.run(plugin.prepare(request))


def test_files_rejects_device_file() -> None:
    target = FakeTarget()
    target.add_dir("/dev")
    target.add_device("/dev/sda")
    plugin = files_plugin(target)
    request = prepare_params(operation(resource="/dev/sda"))

    with pytest.raises(CapabilityError, match="device_file"):
        asyncio.run(plugin.prepare(request))


def test_files_prepare_saves_prior_state_and_marker() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before", mode=0o100600)
    target.owners["/etc/example/app.conf"] = (1000, 1000)
    plugin = files_plugin(target)
    request = prepare_params(operation(resource="/etc/example/app.conf"))

    result = asyncio.run(plugin.prepare(request))
    marker = FileMarker.model_validate(result.marker)

    assert marker.action == "replace_managed_file"
    assert marker.path == "/etc/example/app.conf"
    assert marker.prior_content_sha256 == sha256_bytes(b"before")
    assert marker.prior_mode == 0o100600
    assert marker.prior_uid == 1000
    assert marker.prior_gid == 1000
    assert base64.b64decode(marker.prior_content_b64) == b"before"


def test_files_apply_replaces_and_verify_passes() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before")
    plugin = files_plugin(target)
    op = operation(resource="/etc/example/app.conf")
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))

    applied = asyncio.run(plugin.apply(apply_params(op, prepared.marker)))
    assert applied.ok is True and applied.changed is True
    assert target.files["/etc/example/app.conf"] == b"new"

    verified = asyncio.run(plugin.verify(verify_params(op, prepared.marker)))
    assert verified.ok is True


def test_files_verify_detects_missing_expected_state() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before")
    plugin = files_plugin(target)
    op = operation(resource="/etc/example/app.conf")
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    # Simulate an external modification that does not match the plan.
    target.files["/etc/example/app.conf"] = b"tampered"

    verified = asyncio.run(plugin.verify(verify_params(op, prepared.marker)))

    assert verified.ok is False
    assert verified.reason == "content_mismatch"


def test_files_undo_restores_exact_prior_state() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before", mode=0o100600)
    target.owners["/etc/example/app.conf"] = (1000, 1000)
    plugin = files_plugin(target)
    op = operation(resource="/etc/example/app.conf")
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))

    undone = asyncio.run(plugin.undo(undo_params(op, prepared.marker)))

    assert undone.ok is True
    assert target.files["/etc/example/app.conf"] == b"before"
    assert target.modes["/etc/example/app.conf"] == 0o100600
    assert target.owners["/etc/example/app.conf"] == (1000, 1000)


def test_files_set_mode_prepare_apply_undo() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"data", mode=0o100644)
    plugin = files_plugin(target)
    op = operation(
        action="set_mode",
        resource="/etc/example/app.conf",
        parameters={"mode": 0o100600},
        verify={"mode": 0o100600},
    )

    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    marker = FileMarker.model_validate(prepared.marker)
    assert marker.new_mode == 0o100600

    applied = asyncio.run(plugin.apply(apply_params(op, prepared.marker)))
    assert applied.ok is True
    assert target.modes["/etc/example/app.conf"] == 0o100600

    verified = asyncio.run(plugin.verify(verify_params(op, prepared.marker)))
    assert verified.ok is True

    undone = asyncio.run(plugin.undo(undo_params(op, prepared.marker)))
    assert undone.ok is True
    assert target.modes["/etc/example/app.conf"] == 0o100644


@pytest.mark.parametrize(
    "path",
    ["relative/path", "../etc/passwd", "/etc//app.conf", "/etc/app.conf\n", "/etc/ap;p.conf"],
)
def test_files_rejects_unsafe_or_ambiguous_paths(path: str) -> None:
    target = FakeTarget()
    plugin = files_plugin(target)
    # Some paths are already rejected by the strict Operation resource model,
    # others only by the plugin's managed-path validation; both must fail.
    with pytest.raises((ValidationError, CapabilityError)):
        asyncio.run(plugin.prepare(prepare_params(operation(resource=path))))


def test_files_managed_file_missing_fails_closed() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    plugin = files_plugin(target)

    with pytest.raises(CapabilityError, match="path_not_found"):
        asyncio.run(
            plugin.prepare(
                prepare_params(operation(resource="/etc/example/missing.conf"))
            )
        )


def test_files_reconcile_four_ways() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before")
    plugin = files_plugin(target)
    op = operation(resource="/etc/example/app.conf")
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    marker = prepared.marker

    not_applied = asyncio.run(plugin.reconcile(reconcile_params(op, marker)))
    assert not_applied.state is ReconcileState.NOT_APPLIED

    asyncio.run(plugin.apply(apply_params(op, marker)))
    applied = asyncio.run(plugin.reconcile(reconcile_params(op, marker)))
    assert applied.state is ReconcileState.APPLIED

    target.files["/etc/example/app.conf"] = b"something-else"
    partial = asyncio.run(plugin.reconcile(reconcile_params(op, marker)))
    assert partial.state is ReconcileState.PARTIAL


def test_files_reconcile_unknown_when_unreadable() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before")
    plugin = files_plugin(target)
    op = operation(resource="/etc/example/app.conf")
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    # The managed file disappears between prepare and reconcile.
    target.files.pop("/etc/example/app.conf")
    target.nodes.pop("/etc/example/app.conf")

    result = asyncio.run(plugin.reconcile(reconcile_params(op, prepared.marker)))

    assert result.state is ReconcileState.UNKNOWN


def test_files_apply_rejects_tampered_marker() -> None:
    target = FakeTarget()
    target.add_dir("/etc/example")
    target.add_file("/etc/example/app.conf", b"before")
    plugin = files_plugin(target)
    op = operation(resource="/etc/example/app.conf")
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    tampered = {**prepared.marker, "path": "../etc/example/other.conf"}

    with pytest.raises(CapabilityError, match="invalid_marker"):
        asyncio.run(plugin.apply(apply_params(op, tampered)))


# ---------------------------------------------------------------------------
# Services capability
# ---------------------------------------------------------------------------


def test_services_prepare_records_state() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state(
        active="active", sub="running", file_state="enabled", invocation="inv-7"
    )
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="restart", resource="example.service",
        parameters={"unit": "example.service"},
    )

    result = asyncio.run(plugin.prepare(prepare_params(op)))
    marker = ServiceMarker.model_validate(result.marker)

    assert marker.unit == "example.service"
    assert marker.prior.active_state == "active"
    assert marker.prior.sub_state == "running"
    assert marker.prior.unit_file_state == "enabled"
    assert marker.prior.invocation_id == "inv-7"


def test_services_apply_dispatches_fixed_systemctl_argv() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state()
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="start", resource="example.service",
        parameters={"unit": "example.service"},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))

    applied = asyncio.run(plugin.apply(apply_params(op, prepared.marker)))

    assert applied.ok is True
    assert target.calls[-1] == ("run_command", ["/usr/bin/systemctl", "start", "example.service"])


def test_service_undo_restores_prior_state() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state(active="inactive")
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="restart", resource="example.service",
        parameters={"unit": "example.service"},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))

    undone = asyncio.run(plugin.undo(undo_params(op, prepared.marker)))

    assert undone.ok is True
    assert ("run_command", ["/usr/bin/systemctl", "stop", "example.service"]) in target.calls


def test_service_restart_undo_starts_when_prior_active() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state(active="active", sub="running")
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="restart", resource="example.service",
        parameters={"unit": "example.service"},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))

    undone = asyncio.run(plugin.undo(undo_params(op, prepared.marker)))

    assert undone.ok is True
    assert ("run_command", ["/usr/bin/systemctl", "start", "example.service"]) in target.calls


def test_services_rejects_incomplete_unit_name() -> None:
    target = FakeTarget()
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="restart", resource="example",
        parameters={"unit": "example"},
    )

    with pytest.raises(CapabilityError, match="unit"):
        asyncio.run(plugin.prepare(prepare_params(op)))


def test_services_verify_expected_states() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state()
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="start", resource="example.service",
        parameters={"unit": "example.service"},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))

    before = asyncio.run(plugin.verify(verify_params(op, prepared.marker)))
    assert before.ok is False

    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))
    after = asyncio.run(plugin.verify(verify_params(op, prepared.marker)))
    assert after.ok is True


def test_services_reconcile_restart_uses_invocation_id() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state(
        active="active", sub="running", invocation="inv-old"
    )
    plugin = services_plugin(target)
    op = operation(
        capability="services", action="restart", resource="example.service",
        parameters={"unit": "example.service"},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))

    not_applied = asyncio.run(plugin.reconcile(reconcile_params(op, prepared.marker)))
    assert not_applied.state is ReconcileState.NOT_APPLIED

    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))
    applied = asyncio.run(plugin.reconcile(reconcile_params(op, prepared.marker)))
    assert applied.state is ReconcileState.APPLIED


def test_services_marker_action_mismatch_rejected() -> None:
    target = FakeTarget()
    target.service_state["example.service"] = service_state()
    plugin = services_plugin(target)
    start_op = operation(
        capability="services", action="start", resource="example.service",
        parameters={"unit": "example.service"},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(start_op)))
    stop_op = start_op.model_copy(update={"action": "stop"})

    with pytest.raises(CapabilityError, match="marker"):
        asyncio.run(plugin.apply(apply_params(stop_op, prepared.marker)))


# ---------------------------------------------------------------------------
# Packages capability
# ---------------------------------------------------------------------------


def test_packages_requires_exact_name_and_version() -> None:
    target = FakeTarget()
    plugin = packages_plugin(target)
    wildcard = operation(
        capability="packages", action="install_exact", resource="example",
        parameters={"name": "example*", "version": None},
        model_risk=Risk.HIGH, undo={"restore": True},
    )

    with pytest.raises(CapabilityError, match="exact_package_required"):
        asyncio.run(plugin.prepare(prepare_params(wildcard)))


def test_packages_selects_dnf_on_rhel_family() -> None:
    target = FakeTarget(os_id="rocky", os_version_id="9")
    plugin = packages_plugin(target)
    op = operation(
        capability="packages", action="install_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))

    assert dnf_install_argv("httpd", "2.4.62", None)[0] == "/usr/bin/dnf"
    applied = asyncio.run(plugin.apply(apply_params(op, prepared.marker)))
    assert applied.ok is True
    assert target.calls[-1] == ("run_command", dnf_install_argv("httpd", "2.4.62", None))
    assert target.installed["httpd"] == "2.4.62"


def test_packages_selects_apt_on_debian_family() -> None:
    target = FakeTarget(os_id="ubuntu", os_version_id="24.04")
    plugin = packages_plugin(target)
    op = operation(
        capability="packages", action="install_exact", resource="curl",
        parameters={"name": "curl", "version": "8.5.0-2"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))

    applied = asyncio.run(plugin.apply(apply_params(op, prepared.marker)))
    assert applied.ok is True
    assert target.calls[-1] == ("run_command", apt_install_argv("curl", "8.5.0-2", None))
    assert target.installed["curl"] == "8.5.0-2"


def test_packages_install_argv_pins_repository() -> None:
    assert dnf_install_argv("httpd", "2.4.62", "appstream") == [
        "/usr/bin/dnf", "-y", "install", "httpd-2.4.62",
        "--disablerepo=*", "--enablerepo=appstream",
    ]
    assert apt_install_argv("curl", "8.5.0-2", "stable") == [
        "/usr/bin/apt-get", "install", "-y", "--no-install-recommends", "curl=8.5.0-2",
        "-o", "Dir::Etc::sourcelist=sources.list.d/a4diag-stable.list",
    ]


def test_packages_remove_exact_argv() -> None:
    assert dnf_remove_argv("httpd") == ["/usr/bin/dnf", "-y", "remove", "httpd"]
    assert apt_remove_argv("curl") == ["/usr/bin/apt-get", "remove", "-y", "curl"]


def test_packages_verify_install_and_remove() -> None:
    target = FakeTarget()
    plugin = packages_plugin(target)
    install_op = operation(
        capability="packages", action="install_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(install_op)))
    asyncio.run(plugin.apply(apply_params(install_op, prepared.marker)))

    assert asyncio.run(plugin.verify(verify_params(install_op, prepared.marker))).ok is True

    remove_op = operation(
        capability="packages", action="remove_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    removed = asyncio.run(plugin.prepare(prepare_params(remove_op)))
    asyncio.run(plugin.apply(apply_params(remove_op, removed.marker)))

    assert asyncio.run(plugin.verify(verify_params(remove_op, removed.marker))).ok is True


def test_packages_undo_install_restores_prior_version_when_available() -> None:
    target = FakeTarget()
    target.installed["httpd"] = "2.4.57"
    target.available["httpd"] = {"2.4.57"}
    plugin = packages_plugin(target)
    op = operation(
        capability="packages", action="install_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))

    undone = asyncio.run(plugin.undo(undo_params(op, prepared.marker)))

    assert undone.ok is True
    assert target.installed["httpd"] == "2.4.57"
    assert target.calls[-1] == ("run_command", dnf_install_argv("httpd", "2.4.57", None))


def test_packages_undo_fails_honestly_when_artifact_unavailable() -> None:
    target = FakeTarget()
    target.installed["httpd"] = "2.4.57"
    target.available["httpd"] = set()
    plugin = packages_plugin(target)
    op = operation(
        capability="packages", action="install_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    asyncio.run(plugin.apply(apply_params(op, prepared.marker)))

    with pytest.raises(CapabilityError, match="prior_artifact_unavailable"):
        asyncio.run(plugin.undo(undo_params(op, prepared.marker)))


def test_packages_reconcile_four_ways() -> None:
    target = FakeTarget()
    plugin = packages_plugin(target)
    op = operation(
        capability="packages", action="install_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )
    prepared = asyncio.run(plugin.prepare(prepare_params(op)))
    marker = prepared.marker

    not_applied = asyncio.run(plugin.reconcile(reconcile_params(op, marker)))
    assert not_applied.state is ReconcileState.NOT_APPLIED

    asyncio.run(plugin.apply(apply_params(op, marker)))
    applied = asyncio.run(plugin.reconcile(reconcile_params(op, marker)))
    assert applied.state is ReconcileState.APPLIED

    target.installed["httpd"] = "9.9.9"
    partial = asyncio.run(plugin.reconcile(reconcile_params(op, marker)))
    assert partial.state is ReconcileState.PARTIAL


def test_packages_rejects_unsafe_repository() -> None:
    target = FakeTarget()
    plugin = packages_plugin(target)
    op = operation(
        capability="packages", action="install_exact", resource="httpd",
        parameters={"name": "httpd", "version": "2.4.62", "repository": "repo; rm -rf /"},
        model_risk=Risk.HIGH, undo={"restore": True},
    )

    with pytest.raises(CapabilityError, match="repository"):
        asyncio.run(plugin.prepare(prepare_params(op)))


# ---------------------------------------------------------------------------
# Host integration and manifests
# ---------------------------------------------------------------------------


def test_capability_effect_methods_require_tickets_and_bind_markers() -> None:
    async def scenario() -> None:
        target = FakeTarget()
        target.add_dir("/etc/example")
        target.add_file("/etc/example/app.conf", b"before")
        plugin = files_plugin(target)
        bindings = build_capability_bindings(plugin)
        replay = ReplayStore()
        host = PluginHost(
            bindings, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100)
        )
        op = operation(resource="/etc/example/app.conf")
        prepare_request = RpcRequest(
            jsonrpc="2.0",
            api_version="1.0",
            id="prepare",
            method="prepare",
            params=prepare_params(op).model_dump(mode="json"),
        )
        missing = await host.dispatch(prepare_request)
        assert missing.error is not None
        assert missing.error.data.reason == "ticket_required"
        assert target.calls == []

        token = issue_ticket(prepare_params(op), OperationPhase.PREPARE)
        prepared = await host.dispatch(
            prepare_request.model_copy(update={"ticket": token})
        )
        assert prepared.result is not None
        marker = prepared.result["marker"]

        apply_params_obj = apply_params(op, marker)
        apply_token = issue_ticket(apply_params_obj, OperationPhase.APPLY)
        tampered = apply_params_obj.model_copy(
            update={"marker": {**marker, "path": "/etc/example/other.conf"}}
        )
        rejected = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="tamper",
                method="apply",
                params=tampered.model_dump(mode="json"),
                ticket=apply_token,
            )
        )
        assert rejected.error is not None
        assert rejected.error.data.reason == "effect_payload_mismatch"

        applied = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="apply",
                method="apply",
                params=apply_params_obj.model_dump(mode="json"),
                ticket=apply_token,
            )
        )
        assert applied.result is not None and applied.result["ok"] is True
        assert target.files["/etc/example/app.conf"] == b"new"

    asyncio.run(scenario())


def test_capability_bindings_use_fixed_kinds() -> None:
    plugin = files_plugin(FakeTarget())
    bindings = build_capability_bindings(plugin)
    assert bindings["prepare"].kind is MethodKind.PREPARE
    assert bindings["apply"].kind is MethodKind.APPLY
    assert bindings["undo"].kind is MethodKind.UNDO
    assert bindings["verify"].kind is MethodKind.VERIFY
    assert bindings["reconcile"].kind is MethodKind.RECONCILE


@pytest.mark.parametrize(
    "manifest_name",
    ["capability-files", "capability-services", "capability-packages"],
)
def test_capability_manifest_contract(manifest_name: str) -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / f"{manifest_name}.json").read_text(encoding="utf-8"))
    )
    assert manifest.plugin_type is PluginType.CAPABILITY
    assert manifest.api_min == "1.0"
    assert manifest.api_max == "1.0"
    assert manifest.operations
    assert all(operation.supports_prepare for operation in manifest.operations)
    assert all(operation.supports_verify for operation in manifest.operations)
    assert all(operation.supports_reconcile for operation in manifest.operations)
    assert all(operation.supports_undo for operation in manifest.operations)
    assert manifest.read_risk_floor is Risk.LOW
    assert manifest.permissions
    assert "linux:systemd" in manifest.target_compatibility


def test_packages_manifest_operations_are_high() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "capability-packages.json").read_text(encoding="utf-8"))
    )
    assert {operation.name: operation.risk_floor for operation in manifest.operations} == {
        "packages.install_exact": Risk.HIGH,
        "packages.remove_exact": Risk.HIGH,
    }
    assert manifest.write_risk_floor is Risk.HIGH


def test_services_manifest_declares_five_operations() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "capability-services.json").read_text(encoding="utf-8"))
    )
    assert {
        operation.name: operation.risk_floor for operation in manifest.operations
    } == {
        "services.restart": Risk.LOW,
        "services.start": Risk.LOW,
        "services.stop": Risk.LOW,
        "services.enable": Risk.LOW,
        "services.disable": Risk.LOW,
    }


def test_manifest_rejects_lower_write_floor_than_read_floor() -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(
            manifest_data(read_risk_floor="high", write_risk_floor="low")
        )

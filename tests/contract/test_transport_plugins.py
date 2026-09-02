"""Contract tests for the local and SSH transport plugins.

No real SSH connection, network traffic, or target modification is ever
performed: every process boundary is an injected fake runner and every
identity source is an injected fake probe.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
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

from a4diag_builtin_plugins.transport_common import (
    TRANSPORT_HELPER_EXECUTABLE,
    ExecuteTypedParams,
    HelperAction,
    ReadKind,
    ReadParams,
    RunOutcome,
    TargetIdentity,
    TransportIdentityError,
    TransportReadError,
    TransportStatus,
    VerifyIdentityParams,
    build_transport_bindings,
    identity_fingerprint,
)
from a4diag_builtin_plugins.transport_local import (
    LocalTransport,
    parse_os_release,
)
from a4diag_builtin_plugins.transport_ssh import (
    SSH_CONNECT_TIMEOUT,
    SSH_EXECUTABLE,
    SshTargetConfig,
    SshTransport,
    build_ssh_argv,
)

KEY = b"transport-contract-ticket-key-32bytes"
POLICY_KEY = b"transport-contract-policy-key-32bytes"
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


class FakeIdentity:
    """Mutable identity probe that tests can change to simulate identity drift."""

    def __init__(
        self,
        *,
        machine_id: str = "machine-1",
        os_id: str = "rocky",
        os_version_id: str = "9",
        systemd_version: str = "252",
    ) -> None:
        self.machine_id = machine_id
        self.os_id = os_id
        self.os_version_id = os_version_id
        self.systemd_version = systemd_version
        self.fail: str | None = None
        self.probe_calls = 0

    def target_identity(self) -> TargetIdentity:
        return TargetIdentity(
            machine_id=self.machine_id,
            host_key_sha256=None,
            os_id=self.os_id,
            os_version_id=self.os_version_id,
            systemd_version=self.systemd_version,
        )

    async def probe(self) -> TargetIdentity:
        self.probe_calls += 1
        if self.fail is not None:
            raise TransportIdentityError(self.fail)
        return self.target_identity()


class FakeRunner:
    """Injected runner that records argv/payload and never touches a process."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.outcome = RunOutcome(
            started=True, timed_out=False, returncode=0, stdout="{}", stderr=""
        )
        self.hang = False
        self.killed = 0

    async def run(
        self, argv: list[str], *, payload: bytes, output_limit_bytes: int
    ) -> RunOutcome:
        self.calls.append(
            {"argv": tuple(argv), "payload": payload, "limit": output_limit_bytes}
        )
        if self.hang:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                # The real runner kills its process group before re-raising.
                self.killed += 1
                raise
        return self.outcome


def identity_outcome(identity: TargetIdentity) -> RunOutcome:
    return RunOutcome(
        started=True,
        timed_out=False,
        returncode=0,
        stdout=json.dumps(
            {
                "machine_id": identity.machine_id,
                "os_id": identity.os_id,
                "os_version_id": identity.os_version_id,
                "systemd_version": identity.systemd_version,
            }
        ),
        stderr="",
    )


def make_operation(**updates: object) -> Operation:
    values: dict[str, object] = {
        "capability": "services",
        "action": "restart",
        "resource": "example.service",
        "parameters": {"unit": "example.service"},
        "model_risk": Risk.LOW,
        "verify": {"active": True},
        "undo": {"restore": True},
        "timeout_seconds": 5,
        "output_limit_bytes": 4096,
    }
    values.update(updates)
    return Operation.model_validate(values)


def execute_params(identity: TargetIdentity, **updates: object) -> ExecuteTypedParams:
    values: dict[str, object] = {
        "transaction_id": "tx-1",
        "step_id": "step-1",
        "target_id": "lab",
        "target_fingerprint": identity_fingerprint(identity),
        "operation": make_operation(),
        "plan_digest": "a" * 64,
        "risk": Risk.LOW,
        "approval_id": None,
        "helper_action": HelperAction.DISPATCH,
        "payload": {"op": "restart", "unit": "example.service"},
    }
    values.update(updates)
    return ExecuteTypedParams.model_validate(values)


def authorization(params: ExecuteTypedParams) -> PolicyAuthorization:
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


def issue_ticket(params: ExecuteTypedParams, phase: OperationPhase) -> str:
    request = OperationTicketRequest(
        **params.model_dump(exclude={"helper_action", "payload"}),
        phase=phase,
        effect_payload_digest=effect_fields_digest(params),
        ttl_seconds=30,
    )
    return TicketIssuer(
        KEY,
        authorization_key=POLICY_KEY,
        clock=lambda: 100,
        ticket_id_factory=lambda: "ticket-transport",
    ).issue(request, authorization(params))


def local_transport(
    *,
    identity: FakeIdentity | None = None,
    runner: FakeRunner | None = None,
    read_file: Any = None,
) -> LocalTransport:
    return LocalTransport(
        identity=identity or FakeIdentity(),
        runner=runner or FakeRunner(),
        read_file=read_file,
    )


def ssh_config(**updates: object) -> SshTargetConfig:
    values: dict[str, object] = {
        "host": "192.0.2.10",
        "port": 2222,
        "user": "a4diag",
        "identity_file": "/run/a4diag/secrets/lab.key",
        "known_hosts": "/run/a4diag/secrets/lab.known_hosts",
        "host_key_sha256": "a" * 64,
    }
    values.update(updates)
    return SshTargetConfig.model_validate(values)


def ssh_identity() -> TargetIdentity:
    return TargetIdentity(
        machine_id="machine-1",
        host_key_sha256="a" * 64,
        os_id="rocky",
        os_version_id="9",
        systemd_version="252",
    )


def ssh_transport(
    *,
    config: SshTargetConfig | None = None,
    runner: FakeRunner | None = None,
) -> SshTransport:
    return SshTransport(config=config or ssh_config(), runner=runner or FakeRunner())


def manifest_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "transport-local",
        "plugin_type": "transport",
        "version": "0.4.1",
        "api_min": "1.0",
        "api_max": "1.0",
        "executable": "a4diag_builtin_plugins.transport_local:main",
        "socket": "/run/a4diag/transport-local.sock",
        "config_schema": "schemas/transport-local.json",
        "operations": [],
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# Identity contract
# ---------------------------------------------------------------------------


def test_target_identity_is_strict_and_frozen() -> None:
    with pytest.raises(ValidationError):
        TargetIdentity.model_validate(
            {
                "machine_id": "m-1",
                "host_key_sha256": None,
                "os_id": "rocky",
                "os_version_id": "9",
                "systemd_version": "252",
                "surprise": True,
            }
        )
    with pytest.raises(ValidationError):
        TargetIdentity(
            machine_id="",
            host_key_sha256=None,
            os_id="rocky",
            os_version_id="9",
            systemd_version="252",
        )
    with pytest.raises(ValidationError):
        TargetIdentity(
            machine_id="m-1",
            host_key_sha256="not-a-digest",
            os_id="rocky",
            os_version_id="9",
            systemd_version="252",
        )
    identity = TargetIdentity(
        machine_id="m-1",
        host_key_sha256="a" * 64,
        os_id="rocky",
        os_version_id="9",
        systemd_version="252",
    )
    with pytest.raises(ValidationError):
        identity.machine_id = "other"  # type: ignore[misc]


def test_identity_fingerprint_tracks_machine_id_and_host_key() -> None:
    base = TargetIdentity(
        machine_id="m-1",
        host_key_sha256=None,
        os_id="rocky",
        os_version_id="9",
        systemd_version="252",
    )
    changed_machine = base.model_copy(update={"machine_id": "m-2"})
    changed_host_key = base.model_copy(update={"host_key_sha256": "b" * 64})
    assert identity_fingerprint(base) == identity_fingerprint(base)
    assert identity_fingerprint(base) != identity_fingerprint(changed_machine)
    assert identity_fingerprint(base) != identity_fingerprint(changed_host_key)


def test_parse_os_release_extracts_id_and_version() -> None:
    content = (
        'NAME="Rocky Linux"\n'
        'ID="rocky"\n'
        'VERSION_ID="9.4"\n'
        'ID_LIKE="rhel fedora"\n'
        "VERSION=\"9.4 (Blue Onyx)\"\n"
    )
    assert parse_os_release(content) == ("rocky", "9.4")


# ---------------------------------------------------------------------------
# SSH argv contract
# ---------------------------------------------------------------------------


def test_ssh_argv_pins_host_key_and_has_no_remote_shell() -> None:
    argv = build_ssh_argv(ssh_config())
    assert argv[0] == SSH_EXECUTABLE
    assert "BatchMode=yes" in argv
    assert "IdentitiesOnly=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert f"UserKnownHostsFile={ssh_config().known_hosts}" in argv
    assert f"ConnectTimeout={SSH_CONNECT_TIMEOUT}" in argv
    assert argv[argv.index("-p") + 1] == "2222"
    assert argv[argv.index("-i") + 1] == "/run/a4diag/secrets/lab.key"
    assert argv[-2] == "a4diag@192.0.2.10"
    assert argv[-1] == TRANSPORT_HELPER_EXECUTABLE
    assert all(";" not in item for item in argv)
    assert all(character not in "".join(argv) for character in ";|&$`\n\t")


def test_ssh_argv_never_appends_operation_text() -> None:
    argv = build_ssh_argv(ssh_config())
    operation_text = json.dumps({"op": "restart", "unit": "example.service"})
    assert all(operation_text not in item for item in argv)
    assert argv == build_ssh_argv(ssh_config())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "host; rm -rf /"),
        ("host", "host name"),
        ("host", "host\x00name"),
        ("host", "host$()x"),
        ("port", 0),
        ("port", 65536),
        ("user", "root;x"),
        ("user", "root user"),
        ("identity_file", "relative/key"),
        ("identity_file", "../etc/ssh.key"),
        ("known_hosts", ""),
        ("known_hosts", "/run/../etc/known_hosts"),
        ("host_key_sha256", "xyz"),
    ],
)
def test_ssh_target_config_rejects_unsafe_fields(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        ssh_config(**{field: value})


# ---------------------------------------------------------------------------
# Local transport execution
# ---------------------------------------------------------------------------


def test_local_execute_typed_dispatches_with_fixed_helper_argv() -> None:
    identity = FakeIdentity()
    runner = FakeRunner()
    transport = local_transport(identity=identity, runner=runner)
    params = execute_params(identity.target_identity())

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is True
    assert result.status is TransportStatus.APPLIED
    assert runner.calls == [
        {
            "argv": (TRANSPORT_HELPER_EXECUTABLE,),
            "payload": canonical_json_bytes(
                {
                    "method": "execute",
                    "action": "dispatch",
                    "operation": params.operation.model_dump(mode="json"),
                    "payload": {"op": "restart", "unit": "example.service"},
                }
            ),
            "limit": 4096,
        }
    ]


def test_machine_id_change_blocks_write_with_zero_spawn() -> None:
    identity = FakeIdentity(machine_id="machine-1")
    runner = FakeRunner()
    transport = local_transport(identity=identity, runner=runner)
    params = execute_params(identity.target_identity())

    identity.machine_id = "changed"
    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.status is TransportStatus.IDENTITY_MISMATCH
    assert result.reason == "target_identity_mismatch"
    assert runner.calls == []


def test_identity_probe_failure_blocks_write_with_zero_spawn() -> None:
    identity = FakeIdentity()
    identity.fail = "machine_id_missing"
    runner = FakeRunner()
    transport = local_transport(identity=identity, runner=runner)
    params = execute_params(identity.target_identity())

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.reason == "machine_id_missing"
    assert runner.calls == []


def test_execute_typed_timeout_kills_process_group_and_returns_execution_unknown() -> None:
    identity = FakeIdentity()
    runner = FakeRunner()
    runner.hang = True
    transport = local_transport(identity=identity, runner=runner)
    params = execute_params(
        identity.target_identity(), operation=make_operation(timeout_seconds=1)
    )

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.status is TransportStatus.EXECUTION_UNKNOWN
    assert result.reason == "execution_unknown"
    assert runner.killed == 1
    # Unknown executions are never automatically retried.
    assert len(runner.calls) == 1


def test_helper_failure_is_deterministic_not_unknown() -> None:
    identity = FakeIdentity()
    runner = FakeRunner()
    runner.outcome = RunOutcome(
        started=True, timed_out=False, returncode=1, stdout="", stderr="boom"
    )
    transport = local_transport(identity=identity, runner=runner)
    params = execute_params(identity.target_identity())

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.status is TransportStatus.FAILED
    assert result.reason == "helper_failed"
    assert result.stderr == "boom"


def test_pre_spawn_failure_is_deterministic_not_unknown() -> None:
    identity = FakeIdentity()
    runner = FakeRunner()
    runner.outcome = RunOutcome(started=False, timed_out=False, returncode=None)
    transport = local_transport(identity=identity, runner=runner)
    params = execute_params(identity.target_identity())

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.status is TransportStatus.FAILED
    assert result.reason == "spawn_failed"


# ---------------------------------------------------------------------------
# SSH transport execution
# ---------------------------------------------------------------------------


def test_ssh_execute_typed_dispatches_through_pinned_ssh() -> None:
    runner = FakeRunner()
    runner.outcome = identity_outcome(ssh_identity())
    transport = ssh_transport(runner=runner)
    params = execute_params(ssh_identity())

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is True
    assert result.status is TransportStatus.APPLIED
    assert len(runner.calls) == 2
    probe_call, execute_call = runner.calls
    assert probe_call["argv"][0] == SSH_EXECUTABLE
    assert json.loads(probe_call["payload"]) == {"method": "identity"}
    assert execute_call["argv"][-1] == TRANSPORT_HELPER_EXECUTABLE
    assert json.loads(execute_call["payload"]) == {
        "method": "execute",
        "action": "dispatch",
        "operation": params.operation.model_dump(mode="json"),
        "payload": {"op": "restart", "unit": "example.service"},
    }


def test_ssh_machine_id_change_blocks_write_with_zero_dispatch() -> None:
    runner = FakeRunner()
    registered = ssh_identity()
    runner.outcome = identity_outcome(registered.model_copy(update={"machine_id": "changed"}))
    transport = ssh_transport(runner=runner)
    params = execute_params(registered)

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.reason == "target_identity_mismatch"
    assert [
        json.loads(call["payload"]).get("method") for call in runner.calls
    ] == ["identity"]


def test_ssh_host_key_change_blocks_write_with_zero_dispatch() -> None:
    runner = FakeRunner()
    registered = ssh_identity()
    runner.outcome = identity_outcome(ssh_identity())
    # The registered host key was "a"*64 but the endpoint now pins "b"*64.
    transport = ssh_transport(config=ssh_config(host_key_sha256="b" * 64), runner=runner)
    params = execute_params(registered)

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.reason == "target_identity_mismatch"
    assert [
        json.loads(call["payload"]).get("method") for call in runner.calls
    ] == ["identity"]


def test_ssh_identity_probe_failure_blocks_write_with_zero_dispatch() -> None:
    runner = FakeRunner()
    runner.outcome = RunOutcome(
        started=True,
        timed_out=False,
        returncode=255,
        stdout="",
        stderr="Host key verification failed",
    )
    transport = ssh_transport(runner=runner)
    params = execute_params(ssh_identity())

    result = asyncio.run(transport.execute_typed(params, None))

    assert result.ok is False
    assert result.reason == "identity_unavailable"
    assert len(runner.calls) == 1
    assert json.loads(runner.calls[0]["payload"]) == {"method": "identity"}


def test_ssh_verify_identity_probes_remotely() -> None:
    runner = FakeRunner()
    runner.outcome = identity_outcome(ssh_identity())
    transport = ssh_transport(runner=runner)

    result = asyncio.run(transport.verify_identity(VerifyIdentityParams()))

    assert result.ok is True
    assert result.status is TransportStatus.IDENTITY_VERIFIED
    assert result.data["fingerprint"] == identity_fingerprint(ssh_identity())
    assert len(runner.calls) == 1
    assert json.loads(runner.calls[0]["payload"]) == {"method": "identity"}


# ---------------------------------------------------------------------------
# Read channel
# ---------------------------------------------------------------------------


def test_local_read_bounds_output_and_flags_truncation() -> None:
    calls: list[tuple[str, int]] = []

    async def read_file(path: str, limit: int) -> tuple[str, bool]:
        calls.append((path, limit))
        content = "y" * 64
        return content[:limit], len(content) > limit

    transport = local_transport(read_file=read_file)

    result = asyncio.run(
        transport.read(
            ReadParams(
                kind=ReadKind.FILE, path="/etc/example.conf", output_limit_bytes=32
            )
        )
    )

    assert result.ok is True
    assert result.status is TransportStatus.READ_COMPLETED
    assert len(result.stdout) == 32
    assert result.data == {"kind": "file", "truncated": True}
    assert calls == [("/etc/example.conf", 32)]


def test_local_read_machine_id_uses_probed_identity() -> None:
    identity = FakeIdentity(machine_id="machine-7")
    transport = local_transport(identity=identity)

    result = asyncio.run(transport.read(ReadParams(kind=ReadKind.MACHINE_ID)))

    assert result.ok is True
    assert result.stdout == "machine-7"


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "etc/passwd",
        "/etc//passwd",
        "/etc/passwd\n",
        "/",
        "",
        "/etc/pa;sswd",
    ],
)
def test_read_rejects_unsafe_or_ambiguous_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        ReadParams(kind=ReadKind.FILE, path=path)


def test_read_path_is_only_valid_for_file_kind() -> None:
    with pytest.raises(ValidationError):
        ReadParams(kind=ReadKind.MACHINE_ID, path="/etc/machine-id")


def test_read_failure_returns_typed_reason() -> None:
    async def read_file(path: str, limit: int) -> tuple[str, bool]:
        raise TransportReadError("not_regular_file")

    transport = local_transport(read_file=read_file)

    result = asyncio.run(
        transport.read(ReadParams(kind=ReadKind.FILE, path="/etc/example.conf"))
    )

    assert result.ok is False
    assert result.status is TransportStatus.FAILED
    assert result.reason == "not_regular_file"


def test_ssh_read_uses_pinned_ssh_and_typed_request() -> None:
    runner = FakeRunner()
    runner.outcome = RunOutcome(
        started=True,
        timed_out=False,
        returncode=0,
        stdout=json.dumps({"content": "data", "truncated": False}),
    )
    transport = ssh_transport(runner=runner)

    result = asyncio.run(
        transport.read(
            ReadParams(
                kind=ReadKind.FILE, path="/etc/os-release", output_limit_bytes=128
            )
        )
    )

    assert result.ok is True
    assert result.stdout == "data"
    call = runner.calls[0]
    assert call["argv"][0] == SSH_EXECUTABLE
    assert call["argv"][-1] == TRANSPORT_HELPER_EXECUTABLE
    assert json.loads(call["payload"]) == {
        "method": "read",
        "kind": "file",
        "path": "/etc/os-release",
        "limit": 128,
    }


# ---------------------------------------------------------------------------
# Host integration: tickets, digest binding, and risk envelope
# ---------------------------------------------------------------------------


def test_execute_typed_requires_ticket_and_binds_payload() -> None:
    async def scenario() -> None:
        runner = FakeRunner()
        identity = FakeIdentity()
        transport = local_transport(identity=identity, runner=runner)
        bindings = build_transport_bindings(transport)
        replay = ReplayStore()
        host = PluginHost(
            bindings, ticket_verifier=TicketVerifier(KEY, replay, clock=lambda: 100)
        )
        params = execute_params(identity.target_identity())

        request = RpcRequest(
            jsonrpc="2.0",
            api_version="1.0",
            id="exec",
            method="execute_typed",
            params=params.model_dump(mode="json"),
        )
        missing = await host.dispatch(request)
        assert missing.error is not None
        assert missing.error.data.reason == "ticket_required"
        assert runner.calls == []

        token = issue_ticket(params, OperationPhase.APPLY)
        tampered = params.model_copy(
            update={"payload": {"op": "restart", "unit": "evil"}}
        )
        rejected = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="tamper",
                method="execute_typed",
                params=tampered.model_dump(mode="json"),
                ticket=token,
            )
        )
        assert rejected.error is not None
        assert rejected.error.data.reason == "effect_payload_mismatch"
        assert runner.calls == []

        accepted = await host.dispatch(request.model_copy(update={"ticket": token}))
        assert accepted.result is not None
        assert accepted.result["ok"] is True
        assert accepted.result["status"] == "applied"
        assert len(runner.calls) == 1

    asyncio.run(scenario())


def test_high_execute_typed_without_approval_is_invalid_params_and_zero_dispatch() -> None:
    async def scenario() -> None:
        runner = FakeRunner()
        transport = local_transport(identity=FakeIdentity(), runner=runner)
        host = PluginHost(
            build_transport_bindings(transport),
            ticket_verifier=TicketVerifier(KEY, ReplayStore(), clock=lambda: 100),
        )
        params = execute_params(FakeIdentity().target_identity())
        raw = {**params.model_dump(mode="json"), "risk": "high", "approval_id": None}

        response = await host.dispatch(
            RpcRequest(
                jsonrpc="2.0",
                api_version="1.0",
                id="high",
                method="execute_typed",
                params=raw,
            )
        )

        assert response.error is not None
        assert response.error.data.reason == "invalid_params"
        assert runner.calls == []

    asyncio.run(scenario())


def test_transport_methods_are_bound_to_fixed_kinds() -> None:
    transport = local_transport()
    bindings = build_transport_bindings(transport)
    assert bindings["health"].kind is MethodKind.READ
    assert bindings["verify_identity"].kind is MethodKind.READ
    assert bindings["read"].kind is MethodKind.READ
    assert bindings["execute_typed"].kind is MethodKind.APPLY
    assert bindings["prepare_typed"].kind is MethodKind.PREPARE
    assert bindings["apply_typed"].kind is MethodKind.APPLY
    assert bindings["verify_typed"].kind is MethodKind.VERIFY
    assert bindings["undo_typed"].kind is MethodKind.UNDO
    assert bindings["reconcile_typed"].kind is MethodKind.RECONCILE


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("manifest_name", ["transport-local", "transport-ssh"])
def test_transport_manifest_contract(manifest_name: str) -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / f"{manifest_name}.json").read_text(encoding="utf-8"))
    )
    assert manifest.plugin_type is PluginType.TRANSPORT
    assert manifest.api_min == "1.0"
    assert manifest.api_max == "1.0"
    assert manifest.operations == ()
    assert manifest.read_risk_floor is Risk.LOW
    assert manifest.write_risk_floor is Risk.HIGH
    assert manifest.permissions
    assert manifest.target_compatibility
    assert "linux:systemd" in manifest.target_compatibility


def test_transport_ssh_manifest_declares_network_and_secrets() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "transport-ssh.json").read_text(encoding="utf-8"))
    )
    assert manifest.network_access == ("target-ssh",)
    assert manifest.secret_refs
    assert manifest.permissions == (
        "read:machine-id",
        "read:os-release",
        "exec:ssh",
        "exec:a4diag-transport-helper",
    )


def test_transport_local_manifest_declares_no_outbound_network() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "transport-local.json").read_text(encoding="utf-8"))
    )
    assert manifest.network_access == ("none",)
    assert manifest.secret_refs == ()


def test_manifest_rejects_write_floor_below_read_floor() -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(
            manifest_data(read_risk_floor="high", write_risk_floor="low")
        )

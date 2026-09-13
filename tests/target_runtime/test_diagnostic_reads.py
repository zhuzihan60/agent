from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from a4diag_builtin_plugins.transport_common import ReadParams, RunOutcome
from a4diag_builtin_plugins.transport_local import LocalTransport
from a4diag_target.helper import run_helper
from a4diag_target.policy import TargetPolicy
from a4diag_target.server import TargetSocketServer


def policy() -> TargetPolicy:
    return TargetPolicy(
        target_id="host", target_fingerprint="sha256:" + "a" * 64,
        controller_key_fingerprint="sha256:" + "b" * 64,
        allowed_units=("demo.service",), managed_roots=("/srv/demo", "/etc"),
    )


def server(root: Path) -> TargetSocketServer:
    instance = object.__new__(TargetSocketServer)
    instance._identity_root = root / "identity"
    instance._diagnostic_root = root
    instance._policy = policy()
    return instance


def read(root: Path, **request: object) -> dict:
    return json.loads(asyncio.run(server(root).handle(json.dumps({
        "method": "read", "limit": 100, **request,
    }).encode())))


@pytest.mark.parametrize("kind", ["service_state", "service_logs"])
def test_unsigned_service_reads_require_exact_granted_unit(tmp_path: Path, kind: str) -> None:
    assert read(tmp_path, kind=kind, unit="other.service") == {
        "ok": False, "reason": "unit_not_granted",
    }


@pytest.mark.parametrize("path", ["/etc/ssh/sshd_config", "/etc/sudoers", "/etc/a4diag-target/policy.json",
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group", "/etc/a4diag/secrets/core-policy.key",
    "/etc/systemd/system/private.service"])
def test_unsigned_file_reads_deny_protected_resources(tmp_path: Path, path: str) -> None:
    assert read(tmp_path, kind="file", path=path) == {
        "ok": False, "reason": "protected_resource",
    }


def test_unsigned_file_reads_deny_unmanaged_paths(tmp_path: Path) -> None:
    assert read(tmp_path, kind="file", path="/tmp/secret") == {
        "ok": False, "reason": "resource_not_granted",
    }


def test_file_read_rejects_normalization_alias_before_open(tmp_path: Path) -> None:
    instance = server(tmp_path)
    instance._policy = policy().model_copy(update={"managed_roots": ("/srv/caf\u00e9",)})
    request = {"method": "read", "kind": "file", "path": "/srv/cafe\u0301/private", "limit": 100}
    result = json.loads(asyncio.run(instance.handle(json.dumps(request).encode())))
    assert result == {"ok": False, "reason": "resource_not_canonical"}


def test_raw_diagnostic_limit_rejects_unframeable_size_before_read(tmp_path: Path) -> None:
    assert read(tmp_path, kind="file", path="/srv/demo/log", limit=65537) == {
        "ok": False, "reason": "read_limit_invalid",
    }


@pytest.mark.skipif(os.name != "posix", reason="secure file reads require POSIX")
def test_maximum_escaped_file_diagnostic_fits_real_helper_envelope(tmp_path: Path) -> None:
    folder = tmp_path / "srv/demo"
    folder.mkdir(parents=True)
    (folder / "log").write_bytes(b"\x01" * 65537)
    runner = RelayRunner(server(tmp_path))
    result = asyncio.run(LocalTransport(runner=runner).read(ReadParams(kind="file", path="/srv/demo/log")))
    assert result.ok is True
    assert result.stdout == "\x01" * 65536
    assert result.data["truncated"] is True
    assert runner.requests[0]["limit"] == 65536


@pytest.mark.skipif(os.name != "posix", reason="target secure file reads require POSIX dir_fd")
def test_file_reads_are_bounded_and_reject_symlink_ancestors_and_nonfiles(tmp_path: Path) -> None:
    folder = tmp_path / "srv/demo"
    folder.mkdir(parents=True)
    (folder / "log").write_bytes(b"x" * 200)
    assert read(tmp_path, kind="file", path="/srv/demo/log") == {
        "content": "x" * 100, "truncated": True,
    }
    (folder / "link").symlink_to(folder / "log")
    (folder / "linked-dir").symlink_to(folder, target_is_directory=True)
    os.mkfifo(folder / "pipe")
    for path in ("/srv/demo/link", "/srv/demo/linked-dir/log", "/srv/demo/pipe", "/srv/demo"):
        assert read(tmp_path, kind="file", path=path)["ok"] is False


@pytest.mark.parametrize("unit", ["*.service", "--all", "demo.service\n", "demo.service;id", "../demo.service", "a" * 256 + ".service"])
def test_service_read_contract_rejects_unsafe_units(unit: str) -> None:
    with pytest.raises(ValidationError):
        ReadParams(kind="service_logs", unit=unit)


def test_service_read_contract_requires_unit_and_rejects_other_resources() -> None:
    assert ReadParams(kind="service_state", unit="demo.service").unit == "demo.service"
    for request in (
        {"kind": "service_state"},
        {"kind": "file", "path": "/srv/demo/log", "unit": "demo.service"},
        {"kind": "machine_id", "unit": "demo.service"},
        {"kind": "service_logs", "unit": "demo.service", "path": "/srv/demo/log"},
    ):
        with pytest.raises(ValidationError):
            ReadParams(**request)


class RelayRunner:
    def __init__(self, target: TargetSocketServer) -> None:
        self.target = target
        self.requests: list[dict] = []

    async def run(self, argv, *, payload, output_limit_bytes):
        self.requests.append(json.loads(payload))
        response = await self.target.handle(payload)
        output = io.BytesIO()
        run_helper(io.BytesIO(payload), output, env={}, connector=lambda *_args: response)
        raw = output.getvalue()
        return RunOutcome(started=True, timed_out=False, returncode=0,
                          stdout=raw[:output_limit_bytes].decode(),
                          stdout_truncated=len(raw) > output_limit_bytes)


def test_local_transport_cannot_bypass_policy_with_injected_reader(tmp_path: Path) -> None:
    async def unsafe_reader(*_args):
        raise AssertionError("must authorize through target helper")

    transport = LocalTransport(runner=RelayRunner(server(tmp_path)), read_file=unsafe_reader)
    result = asyncio.run(transport.read(ReadParams(kind="file", path="/tmp/secret")))
    assert result.ok is False
    assert result.reason == "resource_not_granted"


def test_service_state_survives_helper_json_framing(tmp_path: Path, monkeypatch) -> None:
    from a4diag_target import diagnostics

    class StateRunner:
        async def run(self, argv, *, payload, output_limit_bytes):
            assert argv[0:2] == ["/usr/bin/systemctl", "show"]
            assert argv[-2:] == ["--", "demo.service"]
            return RunOutcome(started=True, timed_out=False, returncode=0,
                              stdout="ActiveState=failed\nSubState=failed\nLoadState=loaded\nResult=exit-code\n")

    monkeypatch.setattr(diagnostics, "SubprocessRunner", StateRunner)
    runner = RelayRunner(server(tmp_path))
    result = asyncio.run(LocalTransport(runner=runner).read(
        ReadParams(kind="service_state", unit="demo.service", output_limit_bytes=100)))
    assert result.ok is True
    assert json.loads(result.stdout)["ActiveState"] == "failed"
    assert result.data["truncated"] is False
    assert runner.requests[0]["unit"] == "demo.service"


def test_service_logs_fixed_tail_and_byte_limit(tmp_path: Path, monkeypatch) -> None:
    from a4diag_target import diagnostics

    class LogRunner:
        async def run(self, argv, *, payload, output_limit_bytes):
            assert argv == ["/usr/bin/journalctl", "--no-pager", "--quiet", "--output=short-iso", "--lines=200", "--unit=demo.service"]
            assert output_limit_bytes == 100
            return RunOutcome(started=True, timed_out=False, returncode=0,
                              stdout="x" * 100, stdout_truncated=True)

    monkeypatch.setattr(diagnostics, "SubprocessRunner", LogRunner)
    assert read(tmp_path, kind="service_logs", unit="demo.service") == {
        "content": "x" * 100, "truncated": True,
    }


def test_service_read_deadline_cancels_command(tmp_path: Path, monkeypatch) -> None:
    from a4diag_target import diagnostics

    cancelled = []

    class HungRunner:
        async def run(self, *_args, **_kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(True)

    monkeypatch.setattr(diagnostics, "SubprocessRunner", HungRunner)
    monkeypatch.setattr(diagnostics, "DIAGNOSTIC_TIMEOUT_SECONDS", 0.01)
    assert read(tmp_path, kind="service_logs", unit="demo.service") == {
        "ok": False, "reason": "read_timeout",
    }
    assert cancelled == [True]


def test_invalid_unsigned_read_never_executes_command(tmp_path: Path, monkeypatch) -> None:
    from a4diag_target import diagnostics

    def forbidden_runner():
        raise AssertionError("invalid request must not spawn")

    monkeypatch.setattr(diagnostics, "SubprocessRunner", forbidden_runner)
    for request in (
        {"unit": "*.service"}, {"unit": "demo.service", "argv": ["id"]},
        {"unit": "demo.service", "limit": True},
        {"unit": "demo.service", "path": "/etc/hosts"},
    ):
        assert read(tmp_path, kind="service_logs", **request)["ok"] is False


def test_bounded_pipe_reader_drains_excess_without_retaining_it() -> None:
    from a4diag_builtin_plugins.transport_common import _read_bounded

    async def scenario():
        stream = asyncio.StreamReader()
        stream.feed_data(b"x" * 200_000)
        stream.feed_eof()
        content, truncated = await _read_bounded(stream, 100)
        assert (content, truncated) == ("x" * 100, True)
        assert stream.at_eof(), "unread excess output can deadlock process completion"

    asyncio.run(scenario())


def test_local_identity_read_obeys_requested_byte_limit() -> None:
    from a4diag_builtin_plugins.transport_common import TargetIdentity

    class Identity:
        async def probe(self):
            return TargetIdentity(machine_id="machine-123", host_key_sha256=None,
                                  os_id="ubuntu", os_version_id="24.04", systemd_version="255")

    result = asyncio.run(LocalTransport(identity=Identity()).read(
        ReadParams(kind="machine_id", output_limit_bytes=3)))
    assert result.stdout == "mac"
    assert result.data["truncated"] is True


@pytest.mark.skipif(os.name == "posix", reason="non-POSIX fail-closed behavior")
def test_file_read_fails_closed_without_secure_platform_support(tmp_path: Path) -> None:
    assert read(tmp_path, kind="file", path="/srv/demo/log") == {
        "ok": False, "reason": "secure_file_read_unavailable",
    }

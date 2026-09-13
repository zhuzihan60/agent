"""Probe IDs cross the real helper/server interface; definitions stay local."""
from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from a4diag.linux_probes import LinuxProbe
from a4diag_builtin_plugins.transport_common import ReadParams, RunOutcome
from a4diag_builtin_plugins.transport_local import LocalTransport
from a4diag_builtin_plugins.transport_ssh import SshTargetConfig, SshTransport
from a4diag_target import diagnostics
from a4diag_target.helper import run_helper
from a4diag_target.policy import TargetPolicy
from a4diag_target.server import TargetSocketServer


def server(root: Path) -> TargetSocketServer:
    instance = object.__new__(TargetSocketServer)
    instance._identity_root = root / "identity"
    instance._diagnostic_root = root
    instance._policy = TargetPolicy(
        target_id="host", target_fingerprint="sha256:" + "a" * 64,
        controller_key_fingerprint="sha256:" + "b" * 64,
        managed_roots=("/srv/demo",),
        diagnostic_probes=(LinuxProbe(id="config", kind="file", resource="/srv/demo/config"),
                           LinuxProbe(id="memory", kind="memory", resource="host")),
    )
    return instance


class RelayRunner:
    def __init__(self, target):
        self.target = target
        self.calls = []

    async def run(self, argv, *, payload, output_limit_bytes):
        self.calls.append((argv, json.loads(payload)))
        response = await self.target.handle(payload)
        output = io.BytesIO()
        run_helper(io.BytesIO(payload), output, env={}, connector=lambda *_: response)
        raw = output.getvalue()
        return RunOutcome(started=True, timed_out=False, returncode=0,
                          stdout=raw[:output_limit_bytes].decode(), stdout_truncated=len(raw) > output_limit_bytes)


def read(target, **kwargs):
    return json.loads(asyncio.run(target.handle(json.dumps({
        "method": "read", "kind": "probe", "probe_id": "config", "limit": 1000, **kwargs,
    }).encode())))


@pytest.mark.parametrize("probe_id", ["", "../config", "config.name", "config\n", "--config", "config;id", "a" * 65, 123, True])
def test_probe_id_contract_is_strict(probe_id):
    with pytest.raises(ValidationError):
        ReadParams(kind="probe", probe_id=probe_id)


@pytest.mark.parametrize("params", [
    {"kind": "probe"}, {"kind": "probe", "probe_id": "config", "path": "/srv/demo/config"},
    {"kind": "probe", "probe_id": "config", "unit": "demo.service"},
    {"kind": "probe", "probe_id": "config", "resource": "host"},
    {"kind": "machine_id", "probe_id": "config"},
    {"kind": "file", "path": "/srv/demo/config", "probe_id": "config"},
    {"kind": "probe", "probe_id": "config", "output_limit_bytes": True},
])
def test_probe_id_is_exclusive_resource(params):
    with pytest.raises(ValidationError):
        ReadParams(**params)


@pytest.mark.parametrize("overrides", [{"probe_id": "unknown"}, {"resource": "/etc/shadow"}, {"path": None}, {"kind": "probe", "probe": {"kind": "memory"}}, {"max_bytes": 100}, {"probe_id": "../config"}])
def test_unregistered_or_injected_probe_never_runs(tmp_path, monkeypatch, overrides):
    async def forbidden(*args):
        raise AssertionError("invalid probe must not run")
    monkeypatch.setattr(diagnostics, "run_probe", forbidden)
    result = read(server(tmp_path), **overrides)
    assert result["ok"] is False
    assert result["reason"] in {"read_request_invalid", "probe_not_granted"}


@pytest.mark.parametrize("transport_kind", ["local", "ssh"])
def test_probe_survives_production_transport_helper_and_server(tmp_path, monkeypatch, transport_kind):
    seen = []
    data = {"exists": True, "mode": 0o640, "size_bytes": 2, "sha256": "a" * 64}
    async def probe(root, definition):
        seen.append((root, definition))
        return data
    monkeypatch.setattr(diagnostics, "run_probe", probe)
    target = server(tmp_path)
    runner = RelayRunner(target)
    if transport_kind == "local":
        transport = LocalTransport(runner=runner)
    else:
        transport = SshTransport(runner=runner, config=SshTargetConfig(
            host="example.com", port=22, user="a4diag", identity_file="/etc/key", known_hosts="/etc/known_hosts"))
    result = asyncio.run(transport.read(ReadParams(kind="probe", probe_id="config")))
    assert result.ok is True
    assert json.loads(result.stdout) == data
    assert result.data == {"kind": "probe", "truncated": False}
    assert runner.calls[0][1] == {"method": "read", "kind": "probe", "probe_id": "config", "limit": 65536}
    assert seen == [(tmp_path, target._policy.diagnostic_probes[0])]


@pytest.mark.parametrize("data", [{"exists": True}, {"exists": "true", "mode": 0, "size_bytes": 0, "sha256": ""}, {"exists": False, "mode": 0, "size_bytes": 0, "sha256": "", "secret": "value"}])
def test_malformed_probe_output_rejected_at_target(tmp_path, monkeypatch, data):
    async def probe(*args):
        return data
    monkeypatch.setattr(diagnostics, "run_probe", probe)
    assert read(server(tmp_path)) == {"ok": False, "reason": "read_failed"}


@pytest.mark.parametrize("error,reason", [(ValueError("bad"), "read_failed"), (OSError("bad"), "read_failed"), (asyncio.TimeoutError(), "read_timeout")])
def test_probe_read_failures_fail_closed(tmp_path, monkeypatch, error, reason):
    async def probe(*args):
        raise error
    monkeypatch.setattr(diagnostics, "run_probe", probe)
    assert read(server(tmp_path)) == {"ok": False, "reason": reason}


def test_probe_output_does_not_allow_partial_health(tmp_path, monkeypatch):
    async def probe(*args):
        return {"exists": False, "mode": 0, "size_bytes": 0, "sha256": ""}
    monkeypatch.setattr(diagnostics, "run_probe", probe)
    assert read(server(tmp_path), limit=4) == {"ok": False, "reason": "read_failed"}


@pytest.mark.skipif(os.open not in os.supports_dir_fd, reason="secure POSIX file probe")
def test_actual_file_probe_through_transport(tmp_path):
    folder = tmp_path / "srv/demo"
    folder.mkdir(parents=True)
    (folder / "config").write_text("ok")
    (folder / "config").chmod(0o640)
    result = asyncio.run(LocalTransport(runner=RelayRunner(server(tmp_path))).read(ReadParams(kind="probe", probe_id="config")))
    assert result.ok and not result.data["truncated"]
    assert json.loads(result.stdout)["mode"] == 0o640


def test_transport_rejects_truncated_probe_response():
    class Runner:
        async def run(self, *args, **kwargs):
            return RunOutcome(started=True, timed_out=False, returncode=0,
                              stdout=json.dumps({"content": '{"reachable":true}', "truncated": True}))
    result = asyncio.run(LocalTransport(runner=Runner()).read(ReadParams(kind="probe", probe_id="config")))
    assert not result.ok and result.reason == "read_failed"

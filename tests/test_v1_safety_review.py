"""Release safety regression tests: probes must not manufacture recovery."""
import errno
import json
import pytest

from a4diag.linux_probes import LinuxProbe, probe_definition_digest
from a4diag_target import diagnostics, probe_network
from a4diag_target.policy import TargetPolicy
from test_recovery_loop import Client, collector, target


@pytest.mark.parametrize("resource,max_bytes,expected", [
    ("/srv/app/backup", 1048576, False),
    ("/srv/app/live", 1, False),
    ("/srv/app/live", 1048576, True),
])
def test_recovery_rejects_target_probe_definition_drift(tmp_path, monkeypatch, resource, max_bytes, expected):
    controller = target(
        diagnostic_probes=[dict(id="config", kind="file", resource="/srv/app/live")],
        evidence_sources=[dict(id="attrs", kind="probe", resource="config")],
        recovery_checks=[dict(id="restored", kind="probe", resource="config", attempts=1,
            conditions=[dict(field="exists", operator="eq", value=True),
                        dict(field="mode", operator="eq", value=420)])],
    )
    policy = TargetPolicy(target_id="target-1", target_fingerprint="sha256:" + "a" * 64,
        controller_key_fingerprint="sha256:" + "b" * 64, managed_roots=("/srv/app",),
        diagnostic_probes=(LinuxProbe(id="config", kind="file", resource=resource, max_bytes=max_bytes),))
    seen = []

    async def actual_probe(root, definition):
        seen.append(definition.resource)
        return dict(exists=True, mode=420, size_bytes=1, sha256="a" * 64)

    monkeypatch.setattr(diagnostics, "run_probe", actual_probe)

    class TargetClient(Client):
        async def call(self, method, params):
            if method == "verify_identity":
                return await super().call(method, params)
            reply = await diagnostics.read_diagnostic(tmp_path, {
                "method": "read", "kind": params["kind"],
                "probe_id": params["probe_id"], "limit": params["output_limit_bytes"],
            }, policy)
            return dict(ok=True, stdout=reply["content"], data=dict(truncated=reply["truncated"]))

    outcome = collector(TargetClient()).final_verify(controller, "machine-1", [])
    assert seen == [resource]
    assert outcome.ok is expected, f"Definition drift was accepted as {outcome.status}"
    evidence = collector(TargetClient()).collect_requested(controller, "machine-1", ["attrs"])
    assert evidence[0]["available"] is expected


def test_probe_digest_includes_defaults_and_all_definition_fields():
    probe = LinuxProbe(id="health", kind="tcp", resource="tcp://localhost:80")
    explicit = LinuxProbe(id="health", kind="tcp", resource="tcp://localhost:80", max_bytes=1048576)
    assert probe_definition_digest(probe) == probe_definition_digest(explicit)
    for changes in ({"id": "other"}, {"kind": "dns", "resource": "localhost"},
                    {"resource": "tcp://localhost:81"}, {"max_bytes": 1}):
        other = LinuxProbe.model_validate({**probe.model_dump(), **changes})
        assert probe_definition_digest(probe) != probe_definition_digest(other)


@pytest.mark.parametrize("mutation", ["missing", "wrong", "duplicate", "extra", "invalid_result"])
def test_malformed_bound_probe_response_cannot_recover(mutation):
    from test_linux_probe_recovery import ProbeClient, configured

    class MalformedClient(ProbeClient):
        async def call(self, method, params):
            reply = await super().call(method, params)
            if method == "verify_identity":
                return reply
            envelope = json.loads(reply["stdout"])
            envelope["result"]["mode"] = 420
            if mutation == "missing":
                envelope = envelope["result"]
            elif mutation == "wrong":
                envelope["probe_digest"] = "0" * 64
            elif mutation == "extra":
                envelope["extra"] = True
            elif mutation == "invalid_result":
                envelope["result"]["mode"] = True
            raw = json.dumps(envelope)
            if mutation == "duplicate":
                raw = '{"probe_digest":"' + envelope["probe_digest"] + '",' + raw[1:]
            reply["stdout"] = raw
            return reply

    port = collector(MalformedClient())
    assert not port.final_verify(configured(), "machine-1", []).ok
    assert not port.collect_requested(configured(), "machine-1", ["attrs"])[0]["available"]


def test_tcp_local_resource_failure_is_unavailable_not_unreachable(monkeypatch, capsys):
    def cannot_open_socket(*args, **kwargs):
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(probe_network.socket, "create_connection", cannot_open_socket)
    status = probe_network.main(["tcp", "tcp://127.0.0.1:8080"])
    output = capsys.readouterr().out
    assert status != 0, f"Local probe failure emitted valid negative health: {output}"

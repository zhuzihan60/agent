import json
import pytest
from a4diag.linux_probes import LinuxProbe, parse_probe_output
from test_recovery_loop import Client, collector, target


def configured():
    return target(diagnostic_probes=[dict(id="config", kind="file", resource="/srv/app/config")],
        evidence_sources=[dict(id="attrs", kind="probe", resource="config")],
        recovery_checks=[dict(id="restored", kind="probe", resource="config", attempts=1,
            conditions=[dict(field="exists", operator="eq", value=True),
                        dict(field="mode", operator="eq", value=420)])])


class ProbeClient(Client):
    def __init__(self):
        super().__init__()
        self.mode = 384
        self.truncated = False
    async def call(self, method, params):
        if method == "verify_identity":
            return await super().call(method, params)
        self.calls.append((method, params))
        return dict(ok=True, stdout=json.dumps(dict(exists=True, mode=self.mode, size_bytes=1, sha256="")),
                    data=dict(truncated=self.truncated))


def test_file_permission_recovery_requires_fresh_read():
    client = ProbeClient()
    port = collector(client)
    t = configured()
    old = port.collect_requested(t, "machine-1", ["attrs"])
    assert old[0]["available"]
    assert not port.final_verify(t, "machine-1", [{"healthy": True}]).ok
    client.mode = 420
    assert port.final_verify(t, "machine-1", old).ok
    client.mode = 384
    assert not port.final_verify(t, "machine-1", [{"mode": 420}]).ok
    assert all(p["probe_id"] == "config" for m, p in client.calls if m == "read")


@pytest.mark.parametrize("mode,truncated", [(True, False), (420, True), (-1, False)])
def test_bad_probe_response_cannot_pass(mode, truncated):
    client = ProbeClient()
    client.mode, client.truncated = mode, truncated
    port = collector(client)
    assert not port.final_verify(configured(), "machine-1", []).ok
    assert not port.collect_requested(configured(), "machine-1", ["attrs"])[0]["available"]


@pytest.mark.parametrize("text", ['{"reachable":true,"reachable":false}', '{"reachable":1}', '{"reachable":true,"extra":1}'])
def test_strict_probe_parser(text):
    with pytest.raises(ValueError):
        parse_probe_output(LinuxProbe(id="web", kind="tcp", resource="tcp://localhost:80"), text)


@pytest.mark.parametrize("resource", ["tcp://localhost:80?", "tcp://localhost:80#"])
def test_tcp_rejects_empty_query_or_fragment(resource):
    with pytest.raises(ValueError):
        LinuxProbe(id="web", kind="tcp", resource=resource)


def test_capacity_cannot_lie_about_usage():
    p = LinuxProbe(id="disk", kind="filesystem", resource="/")
    with pytest.raises(ValueError, match="percentage"):
        parse_probe_output(p, json.dumps(dict(total_bytes=100, available_bytes=0, used_percent=0, free_inodes=1)))


def test_probe_check_respects_admin_timeout():
    import asyncio
    class SlowClient(ProbeClient):
        async def call(self, method, params):
            if method == "read":
                await asyncio.sleep(1.2)
            return await super().call(method, params)
    client = SlowClient()
    client.mode = 420
    t = configured()
    t = t.model_copy(update={"recovery_checks": (t.recovery_checks[0].model_copy(update={"timeout_seconds": 1}),)})
    result = collector(client).final_verify(t, "machine-1", [])
    assert not result.ok
    assert result.data["checks"][0]["status"] == "probe_unavailable"

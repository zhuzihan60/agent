from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from a4diag.config import Config
from a4diag.models import ToolResult
from a4diag.prometheus import PrometheusClient
from a4diag.ssh_collector import SshCollector, build_ssh_argv
from a4diag.tool_router import ToolRouter, ToolRouterError

from test_config_policy import CONFIG_TEXT, write_config


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.read_sizes: list[int] = []

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.payload[:size]


class CollectorRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config = Config.load(write_config(self.root, CONFIG_TEXT))
        self.target = self.config.targets["t_01"]

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_ssh_argv_is_exact_and_has_no_remote_command(self) -> None:
        argv = build_ssh_argv(self.config, self.target)
        self.assertEqual(
            argv,
            [
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-T",
                "-p",
                "22122",
                "-i",
                "/var/lib/a4diag/.ssh/id_ed25519",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=/var/lib/a4diag/.ssh/known_hosts",
                "a4diag-ro@10.3.12.131",
            ],
        )

    def test_ssh_request_goes_only_to_stdin(self) -> None:
        seen: dict[str, object] = {}

        def run_process(argv: list[str], payload: bytes, timeout: int) -> tuple[int, bytes, bytes]:
            seen.update(argv=argv, payload=payload, timeout=timeout)
            return 0, b'{"ok":true,"tool":"cpu"}\n', b""

        result = SshCollector(self.config, run_process=run_process).call(
            self.target, "cpu", {}
        )
        self.assertTrue(result.ok)
        self.assertEqual(seen["timeout"], 20)
        self.assertEqual(seen["argv"][-1], "a4diag-ro@10.3.12.131")
        self.assertEqual(
            json.loads(seen["payload"].decode("utf-8")),
            {"tool": "cpu", "params": {}},
        )

    def test_prometheus_uses_fixed_query_id_and_endpoint(self) -> None:
        payload = b'{"status":"success","data":{"result":[]}}'
        response = FakeResponse(payload)
        seen: dict[str, object] = {}

        def opener(request: object, *, timeout: float) -> FakeResponse:
            seen.update(url=request.full_url, timeout=timeout)
            return response

        result = PrometheusClient(self.config, opener=opener).query("cpu_busy", self.target)
        self.assertTrue(result.ok)
        parsed = urlparse(str(seen["url"]))
        self.assertEqual(parsed.scheme + "://" + parsed.netloc + parsed.path,
                         "http://prometheus.example:9090/api/v1/query")
        query = parse_qs(parsed.query)["query"][0]
        self.assertIn('instance="10.3.12.131:9100"', query)
        self.assertEqual(seen["timeout"], 5.0)
        self.assertEqual(response.read_sizes, [1_048_577])

    def test_prometheus_rejects_arbitrary_promql(self) -> None:
        with self.assertRaisesRegex(ValueError, "query_id is not allowed"):
            PrometheusClient(self.config).query("up or vector(1)", self.target)

    def test_router_rejects_unknown_target_before_collection(self) -> None:
        class MustNotRun:
            def call(self, *args: object, **kwargs: object) -> ToolResult:
                raise AssertionError("collector must not be called")

        router = ToolRouter(self.config, ssh=MustNotRun(), prometheus=MustNotRun())
        with self.assertRaisesRegex(ToolRouterError, "^POLICY_DENIED:"):
            router.call("cpu", {"target": "unknown"})

    def test_router_marks_timeout_with_stable_error(self) -> None:
        class TimeoutCollector:
            def call(self, *args: object, **kwargs: object) -> ToolResult:
                return ToolResult(False, "", "timeout", 124, 20_000, False)

        router = ToolRouter(
            self.config,
            ssh=TimeoutCollector(),
            prometheus=TimeoutCollector(),
        )
        with self.assertRaisesRegex(ToolRouterError, "^COLLECTION_TIMEOUT:"):
            router.call("cpu", {"target": "t_01"})


if __name__ == "__main__":
    unittest.main()

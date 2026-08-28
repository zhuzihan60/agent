from __future__ import annotations

import json
import time
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import Config
from .models import Target, ToolResult
from .policy import bounded_output


PROM_QUERIES = {
    "up": 'up{instance="%s:9100"}',
    "cpu_busy": (
        '100-(avg by(instance)(rate(node_cpu_seconds_total{instance="%s:9100",'
        'mode="idle"}[5m]))*100)'
    ),
    "memory_used": (
        '(1-node_memory_MemAvailable_bytes{instance="%s:9100"}/'
        'node_memory_MemTotal_bytes{instance="%s:9100"})*100'
    ),
    "disk_used": (
        '100*(1-node_filesystem_avail_bytes{instance="%s:9100",'
        'fstype!~"tmpfs|overlay"}/node_filesystem_size_bytes{instance="%s:9100",'
        'fstype!~"tmpfs|overlay"})'
    ),
    "network_errors": (
        'rate(node_network_receive_errs_total{instance="%s:9100"}[5m])+'
        'rate(node_network_transmit_errs_total{instance="%s:9100"}[5m])'
    ),
}
PROMETHEUS_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 1_048_576
Opener = Callable[[Request, float], object]


def _format_query(query_id: str, target: Target) -> str:
    template = PROM_QUERIES.get(query_id)
    if template is None:
        raise ValueError("query_id is not allowed")
    count = template.count("%s")
    return template % tuple(target.ip for _ in range(count))


class PrometheusClient:
    def __init__(self, config: Config, opener: Opener = urlopen):
        self._config = config
        self._opener = opener

    def query(self, query_id: str, target: Target) -> ToolResult:
        query = _format_query(query_id, target)
        url = self._config.prometheus_url.rstrip("/") + "/api/v1/query?" + urlencode(
            {"query": query}
        )
        request = Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "a4diag/0.1.0"},
            method="GET",
        )
        started = time.monotonic()
        try:
            with self._opener(
                request,
                timeout=PROMETHEUS_TIMEOUT_SECONDS,
            ) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            stderr = str(error).encode("utf-8", "replace")
            _, stderr_text, truncated = bounded_output(b"", stderr)
            return ToolResult(
                False,
                "",
                stderr_text,
                75,
                int((time.monotonic() - started) * 1000),
                truncated,
            )

        if len(raw) > MAX_RESPONSE_BYTES:
            return ToolResult(
                False,
                "",
                "Prometheus response exceeds 1 MiB",
                65,
                int((time.monotonic() - started) * 1000),
                True,
            )
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            return ToolResult(
                False,
                "",
                "Prometheus returned invalid JSON",
                65,
                int((time.monotonic() - started) * 1000),
                False,
            )
        if not isinstance(payload, dict) or payload.get("status") != "success":
            return ToolResult(
                False,
                raw.decode("utf-8", "replace"),
                "Prometheus query was not successful",
                69,
                int((time.monotonic() - started) * 1000),
                False,
            )
        return ToolResult(
            True,
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            "",
            0,
            int((time.monotonic() - started) * 1000),
            False,
        )

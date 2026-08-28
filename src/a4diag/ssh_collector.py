from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable

from .config import Config
from .models import Target, ToolResult
from .policy import TOOL_TIMEOUT_SECONDS, bounded_output


ProcessRunner = Callable[[list[str], bytes, int], tuple[int, bytes, bytes]]


def build_ssh_argv(config: Config, target: Target) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-T",
        "-p",
        str(target.ssh_port),
        "-i",
        config.ssh_private_key,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config.ssh_known_hosts}",
        f"{config.ssh_user}@{target.ip}",
    ]


def _run_process(argv: list[str], payload: bytes, timeout: int) -> tuple[int, bytes, bytes]:
    try:
        completed = subprocess.run(
            argv,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            shell=False,
            start_new_session=True,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as error:
        return 124, error.stdout or b"", error.stderr or b"tool timed out"


class SshCollector:
    def __init__(self, config: Config, run_process: ProcessRunner = _run_process):
        self._config = config
        self._run_process = run_process

    def call(self, target: Target, tool: str, params: dict[str, object]) -> ToolResult:
        payload = (
            json.dumps(
                {"tool": tool, "params": params},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        started = time.monotonic()
        exit_code, stdout, stderr = self._run_process(
            build_ssh_argv(self._config, target), payload, TOOL_TIMEOUT_SECONDS
        )
        stdout_text, stderr_text, truncated = bounded_output(stdout, stderr)
        gateway_ok = False
        try:
            decoded = json.loads(stdout_text)
            gateway_ok = isinstance(decoded, dict) and decoded.get("ok") is True
        except (TypeError, ValueError):
            gateway_ok = False
        return ToolResult(
            ok=exit_code == 0 and gateway_ok,
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

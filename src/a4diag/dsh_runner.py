from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml


class DshError(RuntimeError):
    pass


SENSITIVE_COMPONENT_IDS = frozenset(
    {
        "tool-bash",
        "tool-pwsh",
        "tool-jobs",
        "tool-fs",
        "tool-fs-search",
        "skill",
        "skill-filesystem",
        "skill-badge",
        "tool-skill",
        "subagent",
        "subagent-spawn-in-process",
        "subagent-fork-in-process",
        "tool-subagent-control",
        "tool-subagent-list-agents",
        "tool-subagent",
        "tool-subagent-fork",
        "tool-subagent-report",
        "workflow-worker-thread",
        "tool-workflow",
        "tool-todo",
        "tool-goal",
        "tool-ralph",
        "tool-str-replace-editor",
        "web",
        "web-search-deepseek",
        "tool-web",
        "code-runtime",
    }
)
SAFE_ACTIVE_CAPABILITIES = {
    "mcp-a4diag": "@deepseek-ai/dsh-mcp-client",
    "timeout-policy": "@deepseek-ai/dsh-tool-call-timeout-policy",
    "tool-result-pruner": "@deepseek-ai/dsh-compaction-tool-result-pruner",
    "repeat-tool-reminder": "@deepseek-ai/dsh-repeat-tool-reminder",
}
SAFE_ACTIVE_CAPABILITY_IDS = frozenset(SAFE_ACTIVE_CAPABILITIES)


class _DshYamlLoader(yaml.SafeLoader):
    pass


def _construct_javascript_tag(
    loader: _DshYamlLoader,
    _suffix: str,
    node: yaml.Node,
) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    raise ValueError("unsupported DSH YAML node")


_DshYamlLoader.add_multi_constructor(
    "tag:yaml.org,2002:js",
    _construct_javascript_tag,
)


class DshRunner:
    def __init__(
        self,
        process_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        settings_path: Path = Path("/var/lib/a4diag/.dsh/settings.yaml"),
    ) -> None:
        self._process_runner = process_runner
        self._settings_path = settings_path

    def run(self, prompt: str) -> str:
        environment = self._environment()
        self.verify_profile(environment)
        argv = [
            "/usr/local/bin/dsh",
            "--profile",
            "a4diag-headless",
            prompt,
        ]
        try:
            completed = self._process_runner(
                argv,
                cwd="/var/lib/a4diag",
                env=environment,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise DshError("DSH timed out") from exc
        if completed.returncode != 0:
            raise DshError(f"DSH exited with status {completed.returncode}")
        if not completed.stdout.strip():
            raise DshError("DSH returned empty output")
        return completed.stdout

    @staticmethod
    def _environment() -> dict[str, str]:
        environment = {
            "HOME": "/var/lib/a4diag",
            "DSH_HOME": "/var/lib/a4diag/.dsh",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if api_key:
            environment["DEEPSEEK_API_KEY"] = api_key
        return environment

    def verify_profile(self, environment: dict[str, str] | None = None) -> None:
        effective_environment = environment or self._environment()
        argv = [
            "/usr/local/bin/dsh",
            "--profile",
            "a4diag-headless",
            "--dump-config",
        ]
        try:
            completed = self._process_runner(
                argv,
                cwd="/var/lib/a4diag",
                env=effective_environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DshError("restricted DSH profile validation failed") from exc
        if completed.returncode != 0:
            raise DshError("restricted DSH profile validation failed")
        try:
            rows = yaml.load(completed.stdout, Loader=_DshYamlLoader)
            settings = yaml.safe_load(
                self._settings_path.read_text(encoding="utf-8")
            )
            self._validate_profile_rows(rows)
            self._validate_settings(settings)
        except Exception as exc:
            raise DshError("restricted DSH profile validation failed") from exc

    @staticmethod
    def _validate_profile_rows(rows: object) -> None:
        if not isinstance(rows, list):
            raise ValueError("effective DSH profile must be a list")
        by_id = {
            row["id"]: row
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
        if not SENSITIVE_COMPONENT_IDS.issubset(by_id):
            raise ValueError("sensitive DSH components are missing")
        if any(by_id[item].get("disabled") is not True for item in SENSITIVE_COMPONENT_IDS):
            raise ValueError("sensitive DSH component is active")
        for row in rows:
            if not isinstance(row, dict) or row.get("disabled") is True:
                continue
            component_id = row.get("id")
            component_name = row.get("name", "")
            if not isinstance(component_id, str) or not isinstance(component_name, str):
                raise ValueError("active DSH component is malformed")
            if component_id.startswith("mcp-") and component_id != "mcp-a4diag":
                raise ValueError("an extra MCP component is active")
            capability_like = (
                component_id.startswith(("tool-", "skill", "subagent", "web"))
                or component_id in {"code-runtime", "workflow-worker-thread"}
                or "mcp-client" in component_name
                or "dsh-tool-" in component_name
            )
            if capability_like and SAFE_ACTIVE_CAPABILITIES.get(component_id) != component_name:
                raise ValueError("an unapproved capability component is active")
        mcp = by_id.get("mcp-a4diag")
        if not isinstance(mcp, dict) or mcp.get("name") != "@deepseek-ai/dsh-mcp-client":
            raise ValueError("a4diag MCP client is missing")
        expected_config = {
            "transport": "stdio",
            "serverName": "a4diag",
            "command": "/opt/a4diag/venv/bin/python",
            "args": ["-m", "a4diag.mcp_server"],
            "env": {"A4DIAG_CONFIG": "/etc/a4diag/config.yaml"},
            "cwd": "/var/lib/a4diag",
            "toolCallTimeoutMs": 20000,
            "failOnStartupError": True,
        }
        if mcp.get("config") != expected_config:
            raise ValueError("a4diag MCP configuration does not match policy")

    @staticmethod
    def _validate_settings(settings: object) -> None:
        if not isinstance(settings, dict):
            raise ValueError("DSH settings must be a mapping")
        if settings.get("agent-default-model") != {
            "provider": "deepseek-official",
            "model": "deepseek-v4-flash",
            "reasoningEffort": "high",
        }:
            raise ValueError("DSH model settings do not match policy")
        if settings.get("llm-deepseek") != {"apiKeyEnv": "DEEPSEEK_API_KEY"}:
            raise ValueError("DSH credential routing does not match policy")


def parse_model_report(output: str) -> dict[str, object]:
    start = output.find("{")
    end = output.rfind("}")
    if start < 0 or end < start:
        raise ValueError("model output is not JSON")
    try:
        value = json.loads(output[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError("model output is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("model report must be an object")

    required: Mapping[str, type[Any]] = {
        "status": str,
        "conclusion": str,
        "evidence_complete": bool,
        "summary": str,
    }
    for name, expected_type in required.items():
        if name not in value or type(value[name]) is not expected_type:
            raise ValueError(f"{name} is missing or invalid")
    if value["status"] not in {"diagnosed", "insufficient_evidence"}:
        raise ValueError("status is invalid")
    if value["conclusion"] not in {"normal", "abnormal"}:
        raise ValueError("conclusion is invalid")
    summary = value["summary"]
    assert isinstance(summary, str)
    if not summary.strip() or len(summary) > 4000:
        raise ValueError("summary is invalid")
    if value["status"] != "diagnosed" and value["evidence_complete"] is True:
        raise ValueError("insufficient evidence cannot be complete")
    return {name: value[name] for name in required}

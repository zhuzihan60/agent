from __future__ import annotations

import json

from .config import Config
from .policy import (
    PolicyError,
    authorize_target,
    validate_lines,
    validate_tool_params,
    validate_unit,
)
from .prometheus import PrometheusClient
from .ssh_collector import SshCollector


class ToolRouterError(RuntimeError):
    pass


class ToolRouter:
    def __init__(
        self,
        config: Config,
        ssh: object | None = None,
        prometheus: object | None = None,
    ):
        self._config = config
        self._ssh = ssh if ssh is not None else SshCollector(config)
        self._prometheus = (
            prometheus if prometheus is not None else PrometheusClient(config)
        )

    def call(self, tool: str, params: dict[str, object]) -> dict[str, object]:
        try:
            validate_tool_params(tool, params)
            target = authorize_target(self._config, params["target"])  # type: ignore[arg-type]
            gateway_params = dict(params)
            gateway_params.pop("target", None)
            if "unit" in gateway_params:
                gateway_params["unit"] = validate_unit(
                    target, gateway_params["unit"]  # type: ignore[arg-type]
                )
            if "lines" in gateway_params:
                gateway_params["lines"] = validate_lines(
                    gateway_params["lines"]  # type: ignore[arg-type]
                )
        except (KeyError, PolicyError) as error:
            raise ToolRouterError(f"POLICY_DENIED: {error}") from error

        if tool == "prom_query":
            query_id = gateway_params.pop("query_id")
            try:
                result = self._prometheus.query(query_id, target)  # type: ignore[attr-defined]
            except ValueError as error:
                raise ToolRouterError(f"POLICY_DENIED: {error}") from error
            source = "prometheus"
        else:
            result = self._ssh.call(target, tool, gateway_params)  # type: ignore[attr-defined]
            source = "ssh"

        if not result.ok:
            code = "COLLECTION_TIMEOUT" if result.exit_code == 124 else "COLLECTION_FAILED"
            detail = result.stderr.strip() or f"collector exit code {result.exit_code}"
            raise ToolRouterError(f"{code}: {detail}")

        try:
            evidence: object = json.loads(result.stdout)
        except ValueError:
            evidence = result.stdout
        return {
            "target": target.name,
            "target_ip": target.ip,
            "tool": tool,
            "source": source,
            "duration_ms": result.duration_ms,
            "truncated": result.truncated,
            "evidence": evidence,
        }

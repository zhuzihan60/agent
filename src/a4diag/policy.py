from __future__ import annotations

import re

from .config import Config
from .models import Target


ALLOWED_TOOLS = frozenset(
    {
        "host_summary",
        "cpu",
        "memory",
        "disk",
        "network",
        "failed_services",
        "service_status",
        "journal_tail",
        "prom_query",
    }
)
MAX_OUTPUT_BYTES = 262_144
MAX_JOURNAL_LINES = 200
TOOL_TIMEOUT_SECONDS = 20
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_SAFE_QUERY_ID = re.compile(r"^[a-z_]+$")
_PARAMETERS = {
    "host_summary": frozenset({"target"}),
    "cpu": frozenset({"target"}),
    "memory": frozenset({"target"}),
    "disk": frozenset({"target"}),
    "network": frozenset({"target"}),
    "failed_services": frozenset({"target"}),
    "service_status": frozenset({"target", "unit"}),
    "journal_tail": frozenset({"target", "unit", "lines"}),
    "prom_query": frozenset({"target", "query_id"}),
}


class PolicyError(ValueError):
    pass


def authorize_target(config: Config, target: str) -> Target:
    """Resolve a legacy read-only target by its registered name only.

    An IP address or hostname never authorizes: there is no IP matching and
    no fallback to the first configured target.
    """
    if not isinstance(target, str) or target not in config.targets:
        raise PolicyError("target is not allowed")
    return config.targets[target]


def validate_unit(target: Target, unit: str) -> str:
    if not isinstance(unit, str) or unit not in target.allowed_units:
        raise PolicyError("unit is not allowed")
    return unit


def validate_lines(lines: int) -> int:
    if isinstance(lines, bool) or not isinstance(lines, int):
        raise PolicyError("lines must be an integer")
    if not 1 <= lines <= MAX_JOURNAL_LINES:
        raise PolicyError("lines must be between 1 and 200")
    return lines


def validate_tool_params(tool: str, params: dict[str, object]) -> None:
    if tool not in ALLOWED_TOOLS:
        raise PolicyError("tool is not allowed")
    if not isinstance(params, dict) or set(params) != _PARAMETERS[tool]:
        raise PolicyError("invalid parameter set")
    target = params.get("target")
    if not isinstance(target, str) or not _SAFE_NAME.fullmatch(target):
        raise PolicyError("invalid target")
    if "unit" in params:
        unit = params["unit"]
        if not isinstance(unit, str) or any(ord(char) < 32 for char in unit):
            raise PolicyError("invalid unit")
        if any(token in unit for token in ("/", "..", ";", "|", "&", "`", "$")):
            raise PolicyError("invalid unit")
    if "lines" in params:
        validate_lines(params["lines"])  # type: ignore[arg-type]
    if "query_id" in params:
        query_id = params["query_id"]
        if not isinstance(query_id, str) or not _SAFE_QUERY_ID.fullmatch(query_id):
            raise PolicyError("invalid query_id")


def _clip(data: bytes, budget: int) -> tuple[str, bool]:
    marker = b"\n...[truncated by a4diag]"
    if len(data) <= budget:
        return data.decode("utf-8", "replace"), False
    if budget <= len(marker):
        return marker[:budget].decode("utf-8", "replace"), True
    kept = data[: budget - len(marker)] + marker
    return kept.decode("utf-8", "replace"), True


def bounded_output(stdout: bytes, stderr: bytes) -> tuple[str, str, bool]:
    if len(stdout) + len(stderr) <= MAX_OUTPUT_BYTES:
        return (
            stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"),
            False,
        )
    stdout_budget = min(len(stdout), MAX_OUTPUT_BYTES)
    stderr_budget = MAX_OUTPUT_BYTES - stdout_budget
    stdout_text, stdout_cut = _clip(stdout, stdout_budget)
    stderr_text, stderr_cut = _clip(stderr, stderr_budget)
    return stdout_text, stderr_text, stdout_cut or stderr_cut

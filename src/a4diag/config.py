"""Compatibility configuration for legacy read-only diagnostics.

v3 settings live in :mod:`a4diag.settings`; this module re-exports them for
compatibility. The legacy :class:`Config` loader is generic: it validates
shapes and types only — never a fixed target list, a fixed IP, or a frozen
unit allowlist. v0.3 frozen permissions are never trusted or auto-converted
into v3 settings; ``a4diag init`` is the only path to a v3 settings file
(see ``docs/migration/v0.3-to-v0.4.md``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .domain import CapabilityGrant, TargetConfig, TargetMode  # re-export
from .models import Target
from .settings import AgentSettings, load_settings  # re-export

__all__ = [
    "AgentSettings",
    "CapabilityGrant",
    "Config",
    "EXPECTED_TARGET_KEYS",
    "TargetConfig",
    "TargetMode",
    "load_settings",
]


EXPECTED_TOP_LEVEL_KEYS = frozenset(
    {
        "alertmanager_url",
        "prometheus_url",
        "poll_interval_seconds",
        "max_concurrency",
        "normal_report_days",
        "abnormal_report_days",
        "audit_days",
        "ssh_private_key",
        "ssh_known_hosts",
        "ssh_user",
        "targets",
    }
)
EXPECTED_TARGET_KEYS = frozenset({"ip", "ssh_port", "allowed_units"})
_SAFE_TARGET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_POSITIVE_INTEGER_KEYS = frozenset(
    {
        "poll_interval_seconds",
        "max_concurrency",
        "normal_report_days",
        "abnormal_report_days",
        "audit_days",
    }
)


@dataclass(frozen=True)
class Config:
    alertmanager_url: str
    prometheus_url: str
    poll_interval_seconds: int
    max_concurrency: int
    normal_report_days: int
    abnormal_report_days: int
    audit_days: int
    ssh_private_key: str
    ssh_known_hosts: str
    ssh_user: str
    targets: dict[str, Target]

    @classmethod
    def load(cls, path: Path) -> "Config":
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("configuration must be a mapping")
        keys = set(raw)
        if keys != EXPECTED_TOP_LEVEL_KEYS:
            unknown = sorted(keys - EXPECTED_TOP_LEVEL_KEYS)
            missing = sorted(EXPECTED_TOP_LEVEL_KEYS - keys)
            raise ValueError(
                f"unknown configuration keys={unknown}; missing configuration keys={missing}"
            )

        for name in _POSITIVE_INTEGER_KEYS:
            value = raw[name]
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("alertmanager_url", "prometheus_url", "ssh_private_key",
                     "ssh_known_hosts", "ssh_user"):
            value = raw[name]
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a nonblank string")

        target_rows = raw["targets"]
        if not isinstance(target_rows, dict):
            raise ValueError("targets must be a mapping of target id to settings")
        targets: dict[str, Target] = {}
        for name, row in target_rows.items():
            if not isinstance(name, str) or not _SAFE_TARGET_NAME.fullmatch(name):
                raise ValueError("target id is not a safe identifier")
            if not isinstance(row, dict) or set(row) != EXPECTED_TARGET_KEYS:
                raise ValueError(f"target {name!r} has invalid configuration keys")
            ip = row["ip"]
            if not isinstance(ip, str) or not ip:
                raise ValueError(f"target {name!r} ip must be a nonblank string")
            ssh_port = row["ssh_port"]
            if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
                raise ValueError(f"target {name!r} ssh_port must be a valid port")
            units = row["allowed_units"]
            if not isinstance(units, list) or not units:
                raise ValueError(f"target {name!r} allowed_units must be a nonempty list")
            normalized_units: list[str] = []
            for unit in units:
                if not isinstance(unit, str) or not unit.strip():
                    raise ValueError(f"target {name!r} allowed_units entries must be nonblank")
                if any(ord(char) < 32 or ord(char) == 127 for char in unit):
                    raise ValueError(f"target {name!r} allowed_units entries must not contain control characters")
                normalized_units.append(unit)
            if len(normalized_units) != len(set(normalized_units)):
                raise ValueError(f"target {name!r} allowed_units must be unique")
            targets[name] = Target(
                name=name,
                ip=ip,
                ssh_port=ssh_port,
                allowed_units=tuple(normalized_units),
            )

        return cls(
            alertmanager_url=raw["alertmanager_url"],
            prometheus_url=raw["prometheus_url"],
            poll_interval_seconds=raw["poll_interval_seconds"],
            max_concurrency=raw["max_concurrency"],
            normal_report_days=raw["normal_report_days"],
            abnormal_report_days=raw["abnormal_report_days"],
            audit_days=raw["audit_days"],
            ssh_private_key=raw["ssh_private_key"],
            ssh_known_hosts=raw["ssh_known_hosts"],
            ssh_user=raw["ssh_user"],
            targets=targets,
        )

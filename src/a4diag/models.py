from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    name: str
    ip: str
    ssh_port: int
    allowed_units: tuple[str, ...]


@dataclass(frozen=True)
class Alert:
    fingerprint: str
    starts_at: str
    name: str
    severity: str
    target: str
    labels: dict[str, str]
    annotations: dict[str, str]


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    truncated: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "truncated": self.truncated,
        }

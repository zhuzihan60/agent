"""SSH transport plugin: identity-pinned remote execution through /usr/bin/ssh.

The argv is built from a validated target endpoint plus a fixed remote helper
executable only. Every connection uses ``BatchMode=yes``, ``IdentitiesOnly=yes``,
``StrictHostKeyChecking=yes``, a pinned user-known-hosts file, a pinned
identity file, a pinned port, and ``ConnectTimeout=10``. Typed canonical JSON
is written to stdin; user or model operation text is never appended as a
remote command and ``shell=True`` is never used.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from a4diag_builtin_plugins.transport_common import (
    IDENTITY_PROBE_TIMEOUT_SECONDS,
    BaseTransport,
    ProcessRunner,
    ReadParams,
    SubprocessRunner,
    TRANSPORT_HELPER_EXECUTABLE,
    TRANSPORT_READ_TIMEOUT_SECONDS,
    TargetIdentity,
    TransportIdentityError,
    TransportReadError,
    validate_absolute_path,
    validate_sha256_digest,
)

SSH_EXECUTABLE = "/usr/bin/ssh"
SSH_CONNECT_TIMEOUT = "10"
SSH_IDENTITY_PROBE_OUTPUT_LIMIT = 65_536
_VERSION = "0.4.2"

_HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_IPV6_PATTERN = re.compile(r"^[0-9A-Fa-f:]+$")
_USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class SshTargetConfig(BaseModel):
    """Strict immutable SSH endpoint pinned by the registered target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    port: int = Field(ge=1, le=65535)
    user: str
    identity_file: str
    known_hosts: str
    host_key_sha256: str | None = None

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 253:
            raise ValueError("host must be a bounded hostname or IP address")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("host must not contain control characters")
        if not (_HOSTNAME_PATTERN.fullmatch(value) or _IPV6_PATTERN.fullmatch(value)):
            raise ValueError("host must be a hostname or IP address")
        return value

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not isinstance(value, str) or not _USERNAME_PATTERN.fullmatch(value):
            raise ValueError("user must be a safe SSH username")
        return value

    @field_validator("identity_file", "known_hosts")
    @classmethod
    def validate_absolute_paths(cls, value: str, info: object) -> str:
        return validate_absolute_path(
            value, getattr(info, "field_name", "path")
        )

    @field_validator("host_key_sha256")
    @classmethod
    def validate_host_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha256_digest(value, "host_key_sha256")


def build_ssh_argv(config: SshTargetConfig) -> list[str]:
    """Return the fixed pinned ssh argv; the destination is never last."""
    if not isinstance(config, SshTargetConfig):
        raise TypeError("config must be SshTargetConfig")
    destination = f"{config.user}@{config.host}"
    if ":" in config.host:
        destination = f"{config.user}@[{config.host}]"
    return [
        SSH_EXECUTABLE,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={config.known_hosts}",
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}",
        "-p", str(config.port),
        "-i", config.identity_file,
        destination,
        TRANSPORT_HELPER_EXECUTABLE,
    ]


class SshTransport(BaseTransport):
    """SSH identity-pinned transport over the fixed /usr/bin/ssh argv."""

    def __init__(
        self,
        *,
        config: SshTargetConfig,
        runner: ProcessRunner | None = None,
    ) -> None:
        if not isinstance(config, SshTargetConfig):
            raise TypeError("config must be SshTargetConfig")
        super().__init__(
            name="transport-ssh",
            version=_VERSION,
            runner=runner or SubprocessRunner(),
        )
        self._config = config

    async def _probe_identity(self) -> TargetIdentity:
        outcome = await self._run_helper(
            build_ssh_argv(self._config),
            {"method": "identity"},
            timeout_seconds=IDENTITY_PROBE_TIMEOUT_SECONDS,
            output_limit_bytes=SSH_IDENTITY_PROBE_OUTPUT_LIMIT,
        )
        if outcome.timed_out or not outcome.started or outcome.returncode != 0:
            raise TransportIdentityError("identity_unavailable")
        try:
            payload = json.loads(outcome.stdout)
            if type(payload) is not dict:
                raise ValueError("identity response must be an object")
            return TargetIdentity(
                machine_id=str(payload["machine_id"]),
                host_key_sha256=self._config.host_key_sha256,
                os_id=str(payload["os_id"]),
                os_version_id=str(payload["os_version_id"]),
                systemd_version=str(payload["systemd_version"]),
            )
        except (ValueError, KeyError, TypeError) as error:
            raise TransportIdentityError("identity_unavailable") from error

    def _build_helper_argv(self) -> list[str]:
        return build_ssh_argv(self._config)

    async def _perform_read(self, params: ReadParams) -> tuple[str, bool]:
        request: dict[str, Any] = {
            "method": "read",
            "kind": params.kind.value,
            "path": params.path,
            "limit": int(params.output_limit_bytes),
        }
        outcome = await self._run_helper(
            build_ssh_argv(self._config),
            request,
            timeout_seconds=TRANSPORT_READ_TIMEOUT_SECONDS,
            output_limit_bytes=int(params.output_limit_bytes),
        )
        if outcome.timed_out or not outcome.started or outcome.returncode != 0:
            raise TransportReadError("read_failed")
        try:
            payload = json.loads(outcome.stdout)
            if type(payload) is not dict:
                raise ValueError("read response must be an object")
            return str(payload["content"]), bool(payload.get("truncated", False))
        except (ValueError, KeyError, TypeError) as error:
            raise TransportReadError("read_failed") from error


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "transport-ssh is started by the plugin supervisor with its manifest"
    )


__all__ = [
    "SSH_CONNECT_TIMEOUT",
    "SSH_EXECUTABLE",
    "SshTargetConfig",
    "SshTransport",
    "build_ssh_argv",
    "main",
]

"""Systemd socket-activated target executor service and identity probe."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from a4diag.domain import canonical_json_bytes
from a4diag.plugin_api.target_protocol import SignedTargetRequest, TargetVerifier
from a4diag_builtin_plugins.capability_common import LocalFileAdapter
from a4diag_builtin_plugins.transport_common import TargetIdentity, identity_fingerprint
from a4diag_target.executor import ExecutorError, TargetExecutor
from a4diag_target.policy import TargetPolicy
from a4diag_target.replay import SqliteReplayLedger

MAX_FRAME_BYTES = 1_048_576


def probe_identity(
    root: Path = Path("/"), *, machine_id_override: str | None = None,
    os_release_path: Path | None = None,
) -> TargetIdentity:
    root = Path(root)
    machine_id = machine_id_override or (root / "etc/machine-id").read_text(
        encoding="utf-8"
    ).strip()
    values: dict[str, str] = {}
    release_path = os_release_path or (root / "etc/os-release")
    for line in release_path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    systemd = subprocess.run(
        ["/usr/bin/systemd", "--version"], check=True, capture_output=True,
        text=True, timeout=10,
    ).stdout.splitlines()[0]
    return TargetIdentity(
        machine_id=machine_id,
        host_key_sha256=_host_key_sha256(root),
        os_id=values.get("ID", "unknown"),
        os_version_id=values.get("VERSION_ID", "unknown"),
        systemd_version=systemd,
    )


def target_fingerprint(
    root: Path = Path("/"), *, machine_id_override: str | None = None,
    os_release_path: Path | None = None,
) -> str:
    return identity_fingerprint(
        probe_identity(
            root, machine_id_override=machine_id_override,
            os_release_path=os_release_path,
        )
    )


def _host_key_sha256(root: Path) -> str | None:
    for name in (
        "ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub",
        "ssh_host_rsa_key.pub",
    ):
        path = root / "etc/ssh" / name
        if not path.is_file():
            continue
        fields = path.read_text(encoding="ascii").split()
        if len(fields) < 2:
            continue
        try:
            raw = base64.b64decode(fields[1], validate=True)
        except ValueError:
            continue
        return hashlib.sha256(raw).hexdigest()
    return None


class TargetSocketServer:
    def __init__(
        self,
        *,
        policy_path: Path = Path("/etc/a4diag-target/policy.json"),
        public_key_path: Path = Path("/etc/a4diag-target/operation-public.pem"),
        replay_path: Path = Path("/var/lib/a4diag-target/executor/replay.sqlite3"),
    ) -> None:
        policy = TargetPolicy.model_validate_json(policy_path.read_text(encoding="utf-8"))
        key = serialization.load_pem_public_key(public_key_path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("target operation public key must be Ed25519")
        self._executor = TargetExecutor(
            verifier=TargetVerifier(
                key, replay_store=SqliteReplayLedger(replay_path),
                clock=lambda: int(time.time()),
            ),
            policy=policy,
            identity_probe=target_fingerprint,
            adapter=LocalFileAdapter(),
        )

    async def handle(self, payload: bytes) -> bytes:
        try:
            value = json.loads(payload)
            if type(value) is not dict:
                raise ValueError("request must be object")
            if value == {"method": "identity"}:
                return canonical_json_bytes(probe_identity().model_dump(mode="json"))
            result = await self._executor.execute(
                SignedTargetRequest.model_validate(value)
            )
            return canonical_json_bytes(result)
        except (ValueError, OSError, ExecutorError) as error:
            return canonical_json_bytes(
                {"ok": False, "reason": str(error) or type(error).__name__}
            )


def serve_socket(listener: socket.socket, server: TargetSocketServer) -> None:
    while True:
        connection, _address = listener.accept()
        with connection:
            try:
                length = struct.unpack("!I", _recv_exact(connection, 4))[0]
                if length > MAX_FRAME_BYTES:
                    raise ValueError("request_too_large")
                response = asyncio.run(server.handle(_recv_exact(connection, length)))
            except Exception as error:
                response = canonical_json_bytes(
                    {"ok": False, "reason": str(error) or type(error).__name__}
                )
            connection.sendall(struct.pack("!I", len(response)) + response)


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ValueError("request_truncated")
        chunks.extend(chunk)
    return bytes(chunks)


def activated_socket() -> socket.socket:
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        raise RuntimeError("systemd_socket_activation_required")
    if os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("exactly_one_systemd_socket_required")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def main() -> int:
    listener = activated_socket()
    try:
        serve_socket(listener, TargetSocketServer())
    finally:
        listener.close()
    return 0


__all__ = ["TargetSocketServer", "activated_socket", "main", "probe_identity", "serve_socket", "target_fingerprint"]

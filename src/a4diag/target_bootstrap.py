"""Offline generation of public target installation material."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, field_validator

from a4diag.domain import canonical_json_bytes

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class TargetBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    allowed_source_cidrs: tuple[str, ...] = ()

    @field_validator("target_id")
    @classmethod
    def target_name(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_TARGET.fullmatch(value):
            raise ValueError("unsafe target identifier")
        return value

    @field_validator("allowed_source_cidrs")
    @classmethod
    def source_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ValueError("invalid source CIDR") from exc
            if network.prefixlen == 0:
                raise ValueError("world-wide source CIDR is forbidden")
            normalized.append(str(network))
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate source CIDR")
        return tuple(normalized)


@dataclass(frozen=True, slots=True)
class TargetBootstrapReceipt:
    install_document: Path
    ssh_private_key: Path
    operation_private_key: Path


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def build_target_bootstrap(
    request: TargetBootstrapRequest,
    output_dir: Path,
    *,
    secret_root: Path = Path("/etc/a4diag/secrets/targets"),
) -> TargetBootstrapReceipt:
    if not isinstance(request, TargetBootstrapRequest):
        raise TypeError("TargetBootstrapRequest required")
    output_dir = Path(output_dir)
    secret_root = Path(secret_root)
    target_secret_dir = secret_root / request.target_id
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError(output_dir)
    if target_secret_dir.exists() or target_secret_dir.is_symlink():
        raise FileExistsError(target_secret_dir)

    output_dir.mkdir(parents=True, mode=0o755)
    target_secret_dir.mkdir(parents=True, mode=0o700)
    os.chmod(target_secret_dir, 0o700)

    ssh_private = Ed25519PrivateKey.generate()
    operation_private = Ed25519PrivateKey.generate()
    ssh_private_path = target_secret_dir / "ssh-ed25519"
    operation_private_path = target_secret_dir / "operation-ed25519.pem"
    _write_private(
        ssh_private_path,
        ssh_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        ),
    )
    _write_private(
        operation_private_path,
        operation_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    ssh_public = ssh_private.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("ascii")
    operation_public_raw = operation_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    operation_public_pem = operation_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    document = {
        "protocol_version": "1.0",
        "target_id": request.target_id,
        "ssh_public_key": f"{ssh_public} a4diag-{request.target_id}",
        "operation_public_key": operation_public_pem,
        "controller_key_fingerprint": "sha256:"
        + hashlib.sha256(operation_public_raw).hexdigest(),
        "allowed_source_cidrs": list(request.allowed_source_cidrs),
        "managed_resources": [],
        "confirm_managed_resources": "DISABLED",
    }
    install_document = output_dir / "target-install.json"
    descriptor = os.open(
        install_document, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_json_bytes(document, max_bytes=262_144) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    return TargetBootstrapReceipt(
        install_document=install_document,
        ssh_private_key=ssh_private_path,
        operation_private_key=operation_private_path,
    )


__all__ = [
    "TargetBootstrapReceipt",
    "TargetBootstrapRequest",
    "build_target_bootstrap",
]

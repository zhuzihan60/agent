"""Least-privilege secret references.

A secret reference is ``file:<relative-name>`` beneath the secret root
(``/etc/a4diag/secrets`` by default, an injected root in tests) or
``env:<NAME>`` for model-provider compatibility (deprecated). File secrets
must be regular files owned by the current user with mode 0600, and no path
component may be a symlink. Only the resolved value is ever returned; nothing
is logged or echoed.

Systemd credentials additionally support its root-owned, read-only ACL form:
only the service UID may have named read access; the owning group and others
have none. ACLs are verified on the opened descriptor before reading content.
"""

from __future__ import annotations

import os
import hashlib
import re
import stat
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

DEFAULT_SECRET_ROOT = "/etc/a4diag/secrets"
MAX_SECRET_BYTES = 4096
MAX_RELATIVE_PATH_LENGTH = 256
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def credential_name(reference: str) -> str:
    """Stable systemd-safe identifier, including nested secret references."""
    return "a4diag-" + hashlib.sha256(reference.encode("utf-8")).hexdigest()


class SecretError(ValueError):
    """Stable typed secret-resolution failure carrying a reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ResolvedSecret:
    value: str
    source: Literal["file", "env"]
    deprecated: bool


class SecretResolver:
    """Resolves strict secret references from a root directory and env."""

    def __init__(
        self,
        secret_root: Path | None = None,
        *,
        env: Mapping[str, str] | None = None,
        trusted_owner_uid: int | None = None,
    ) -> None:
        self._root = Path(secret_root) if secret_root is not None else Path(DEFAULT_SECRET_ROOT)
        self._env = dict(env) if env is not None else dict(os.environ)
        self._credentials = secret_root is None and bool(self._env.get("CREDENTIALS_DIRECTORY"))
        if self._credentials:
            self._root = Path(self._env["CREDENTIALS_DIRECTORY"])
        self._trusted_owner_uid = trusted_owner_uid

    def resolve(self, ref: str) -> ResolvedSecret:
        if not isinstance(ref, str) or ref.count(":") != 1:
            raise SecretError("malformed_reference")
        scheme, _, remainder = ref.partition(":")
        if not scheme or not remainder:
            raise SecretError("malformed_reference")
        if scheme == "file":
            return self._resolve_file(remainder)
        if scheme == "env":
            return self._resolve_env(remainder)
        raise SecretError("unsupported_scheme")

    # ------------------------------------------------------------------

    def _resolve_file(self, relative_name: str) -> ResolvedSecret:
        relative = self._validate_relative(relative_name)
        if self._credentials:
            relative = PurePosixPath(credential_name("file:" + relative_name))
        candidate = self._root.joinpath(*relative.parts)
        self._reject_symlinks(candidate)
        try:
            info = candidate.lstat()
        except OSError:
            raise SecretError("file_missing", str(relative)) from None
        self._check_file_access(info, str(relative))
        try:
            fd = os.open(
                str(candidate), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(fd, "rb") as handle:
                self._check_file_access(os.fstat(fd), str(relative), descriptor=fd)
                content = handle.read(MAX_SECRET_BYTES + 1)
        except OSError:
            raise SecretError("read_failed", str(relative)) from None
        if len(content) > MAX_SECRET_BYTES:
            raise SecretError("secret_too_large", str(relative))
        try:
            value = content.decode("utf-8", errors="strict").rstrip("\r\n")
        except UnicodeDecodeError:
            raise SecretError("invalid_encoding", str(relative)) from None
        return ResolvedSecret(
            value=value,
            source="file",
            deprecated=False,
        )

    def _check_file_access(
        self, info: os.stat_result, relative: str, *, descriptor: int | None = None,
    ) -> None:
        if not stat.S_ISREG(info.st_mode):
            raise SecretError("not_regular_file", relative)
        if os.name != "posix":
            return
        mode = stat.S_IMODE(info.st_mode)
        if self._credentials and info.st_uid == 0 and mode == 0o440:
            # systemd write_credential() retains root ownership and adds a
            # named-user ACL. The apparent group-read bit is its ACL mask.
            # Defer ACL lookup until the same file descriptor will be read.
            if descriptor is not None:
                self._check_credential_acl(descriptor, relative)
            return
        allowed_modes = {0o400, 0o600} if self._credentials else {0o600}
        if mode not in allowed_modes:
            raise SecretError("mode_0600_required", relative)
        owner = self._trusted_owner_uid if self._trusted_owner_uid is not None else os.getuid()
        if info.st_uid != owner:
            raise SecretError("owner_mismatch", relative)

    @staticmethod
    def _check_credential_acl(descriptor: int, relative: str) -> None:
        try:
            acl = os.getxattr(descriptor, "system.posix_acl_access")
        except (AttributeError, OSError):
            raise SecretError("credential_acl_invalid", relative) from None
        # Linux POSIX ACL xattr v2: a 32-bit version followed by five entries
        # (16-bit tag, 16-bit permissions, 32-bit qualifier), little-endian.
        # Accept exactly systemd's root:r, service:r, group:0, mask:r, other:0.
        expected = {
            (1, 4, 0xFFFFFFFF), (2, 4, os.getuid()), (4, 0, 0xFFFFFFFF),
            (16, 4, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF),
        }
        if (len(acl) != 44 or acl[:4] != struct.pack("<I", 2)
                or set(struct.iter_unpack("<HHI", acl[4:])) != expected):
            raise SecretError("credential_acl_invalid", relative)

    def _resolve_env(self, name: str) -> ResolvedSecret:
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            raise SecretError("env_name_invalid", name)
        if name not in self._env:
            raise SecretError("env_missing", name)
        return ResolvedSecret(
            value=self._env[name],
            source="env",
            deprecated=True,
        )

    def _validate_relative(self, relative_name: str) -> PurePosixPath:
        if (
            not isinstance(relative_name, str)
            or not relative_name
            or len(relative_name) > MAX_RELATIVE_PATH_LENGTH
        ):
            raise SecretError("path_invalid")
        if relative_name.startswith("/") or "\\" in relative_name:
            raise SecretError("absolute_path_rejected")
        if any(ord(character) < 32 or ord(character) == 127 for character in relative_name):
            raise SecretError("path_invalid")
        path = PurePosixPath(relative_name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise SecretError("path_traversal_rejected")
        return path

    def _reject_symlinks(self, candidate: Path) -> None:
        components = candidate.relative_to(self._root).parts
        current = self._root
        for index in range(len(components)):
            current = current.joinpath(components[index])
            try:
                info = current.lstat()
            except OSError:
                raise SecretError("file_missing", str(current)) from None
            if stat.S_ISLNK(info.st_mode):
                raise SecretError("symlink_rejected", str(current))


__all__ = [
    "DEFAULT_SECRET_ROOT",
    "MAX_SECRET_BYTES",
    "ResolvedSecret",
    "SecretError",
    "SecretResolver",
    "credential_name",
]

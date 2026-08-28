"""Least-privilege secret references.

A secret reference is ``file:<relative-name>`` beneath the secret root
(``/etc/a4diag/secrets`` by default, an injected root in tests) or
``env:<NAME>`` for model-provider compatibility (deprecated). File secrets
must be regular files owned by the current user with mode 0600, and no path
component may be a symlink. Only the resolved value is ever returned; nothing
is logged or echoed.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

DEFAULT_SECRET_ROOT = "/etc/a4diag/secrets"
MAX_SECRET_BYTES = 4096
MAX_RELATIVE_PATH_LENGTH = 256
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


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
    ) -> None:
        self._root = Path(secret_root) if secret_root is not None else Path(DEFAULT_SECRET_ROOT)
        self._env = dict(env) if env is not None else dict(os.environ)

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
        candidate = self._root.joinpath(*relative.parts)
        self._reject_symlinks(candidate)
        try:
            info = candidate.lstat()
        except OSError:
            raise SecretError("file_missing", str(relative)) from None
        if not stat.S_ISREG(info.st_mode):
            raise SecretError("not_regular_file", str(relative))
        if os.name == "posix":
            if (info.st_mode & 0o777) != 0o600:
                raise SecretError("mode_0600_required", str(relative))
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise SecretError("owner_mismatch", str(relative))
        fd = os.open(
            str(candidate),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            with os.fdopen(fd, "rb") as handle:
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
]

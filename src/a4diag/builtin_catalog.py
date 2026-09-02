"""Strict, release-attested catalog for repository-owned built-in plugins."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from .plugin_api.manifest import PluginManifest, PluginType, parse_api_version
from .plugin_registry import PluginPin


EXPECTED_BUILTINS = frozenset(
    {
        "capability-files",
        "capability-packages",
        "capability-services",
        "model-openai-compatible",
        "notification-cli",
        "notification-flashduty",
        "notification-smtp",
        "notification-webhook",
        "transport-local",
        "transport-ssh",
    }
)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_INDEX_BYTES = 1_048_576
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024


class BuiltinCatalogError(ValueError):
    """The built-in catalog or one of its bound files is invalid."""


class BuiltinEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    plugin_type: PluginType
    version: str
    api_version: Literal["1.0"]
    manifest_path: str
    manifest_sha256: str
    artifact_path: str
    artifact_sha256: str

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        if not _SAFE_NAME.fullmatch(value):
            raise ValueError("unsafe built-in name")
        return value

    @field_validator("version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        if not _SAFE_VERSION.fullmatch(value):
            raise ValueError("unsafe built-in version")
        return value

    @field_validator("manifest_path", "artifact_path")
    @classmethod
    def _valid_relative_path(cls, value: str) -> str:
        _validate_relative_path(value)
        return value

    @field_validator("manifest_sha256", "artifact_sha256")
    @classmethod
    def _valid_digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("digest must be lowercase SHA256")
        return value


class BuiltinCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    release_version: str
    plugins: tuple[BuiltinEntry, ...]

    @field_validator("release_version")
    @classmethod
    def _valid_release_version(cls, value: str) -> str:
        if not _SAFE_VERSION.fullmatch(value):
            raise ValueError("unsafe release version")
        return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BuiltinCatalogError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise BuiltinCatalogError(f"non-finite JSON value: {value}")


def _load_json(path: Path, limit: int) -> object:
    try:
        if path.is_symlink() or not path.is_file():
            raise BuiltinCatalogError(f"not a regular file: {path.name}")
        if path.stat().st_size > limit:
            raise BuiltinCatalogError(f"file exceeds size bound: {path.name}")
        content = path.read_bytes()
        return json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except BuiltinCatalogError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BuiltinCatalogError(f"invalid JSON file: {path.name}") from error


def _validate_relative_path(value: str) -> None:
    if not value or "\\" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("unsafe catalog path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("unsafe catalog path")
    if path.as_posix() != value:
        raise ValueError("non-canonical catalog path")


def _resolve_regular(root: Path, relative: str, limit: int) -> Path:
    try:
        _validate_relative_path(relative)
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        current = root
        for part in PurePosixPath(relative).parts:
            current = current / part
            if current.is_symlink():
                raise BuiltinCatalogError(f"catalog path is a symlink: {relative}")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > limit:
            raise BuiltinCatalogError(f"invalid catalog file: {relative}")
        return resolved
    except BuiltinCatalogError:
        raise
    except (OSError, ValueError) as error:
        raise BuiltinCatalogError(f"catalog path escapes or is missing: {relative}") from error


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_catalog_files(catalog: BuiltinCatalog, root: Path) -> None:
    names = [entry.name for entry in catalog.plugins]
    if len(names) != len(set(names)):
        raise BuiltinCatalogError("duplicate built-in name")
    if set(names) != EXPECTED_BUILTINS:
        raise BuiltinCatalogError("built-in inventory mismatch")

    manifest_paths = {entry.manifest_path for entry in catalog.plugins}
    artifact_paths = {entry.artifact_path for entry in catalog.plugins}
    actual_manifests = {
        path.relative_to(root).as_posix()
        for path in (root / "manifests").glob("*")
        if path.is_file()
    }
    actual_artifacts = {
        path.relative_to(root).as_posix()
        for path in (root / "artifacts").glob("*")
        if path.is_file()
    }
    if manifest_paths != actual_manifests or artifact_paths != actual_artifacts:
        raise BuiltinCatalogError("catalog file inventory mismatch")
    if len(artifact_paths) != 1:
        raise BuiltinCatalogError("catalog must bind exactly one built-in wheel")

    for entry in catalog.plugins:
        if entry.version != catalog.release_version:
            raise BuiltinCatalogError(f"version mismatch for {entry.name}")
        manifest_path = _resolve_regular(root, entry.manifest_path, _MAX_MANIFEST_BYTES)
        artifact_path = _resolve_regular(root, entry.artifact_path, _MAX_ARTIFACT_BYTES)
        if _digest(manifest_path) != entry.manifest_sha256:
            raise BuiltinCatalogError(f"manifest digest mismatch for {entry.name}")
        if _digest(artifact_path) != entry.artifact_sha256:
            raise BuiltinCatalogError(f"artifact digest mismatch for {entry.name}")
        try:
            manifest = PluginManifest.model_validate(_load_json(manifest_path, _MAX_MANIFEST_BYTES))
        except (ValidationError, ValueError) as error:
            raise BuiltinCatalogError(f"invalid manifest for {entry.name}") from error
        if (
            manifest.name != entry.name
            or manifest.version != entry.version
            or manifest.plugin_type is not entry.plugin_type
            or not (
                parse_api_version(manifest.api_min)
                <= parse_api_version(entry.api_version)
                <= parse_api_version(manifest.api_max)
            )
        ):
            raise BuiltinCatalogError(f"manifest binding mismatch for {entry.name}")


def load_builtin_catalog(path: Path) -> BuiltinCatalog:
    """Load and verify an exact ten-plugin catalog and every bound byte."""
    try:
        index = Path(path).resolve(strict=True)
        root = index.parent.resolve(strict=True)
    except OSError as error:
        raise BuiltinCatalogError("built-in index is unavailable") from error
    try:
        catalog = BuiltinCatalog.model_validate(_load_json(index, _MAX_INDEX_BYTES))
    except (ValidationError, ValueError) as error:
        raise BuiltinCatalogError("invalid built-in index") from error
    _verify_catalog_files(catalog, root)
    return catalog


def merge_builtin_registry(
    existing: Iterable[PluginPin],
    catalog: BuiltinCatalog,
    plugin_root: Path,
) -> tuple[PluginPin, ...]:
    """Return release pins while retaining explicit enable state only by name."""
    root = Path(plugin_root).resolve(strict=True)
    catalog_root = root / "releases" / catalog.release_version
    _verify_catalog_files(catalog, catalog_root.resolve(strict=True))
    prior = {pin.name: pin.enabled for pin in existing}
    pins = [
        PluginPin(
            name=entry.name,
            version=entry.version,
            api_version=entry.api_version,
            artifact_path=f"releases/{catalog.release_version}/{entry.artifact_path}",
            artifact_sha256=entry.artifact_sha256,
            manifest_sha256=entry.manifest_sha256,
            enabled=prior.get(entry.name, False),
        )
        for entry in catalog.plugins
    ]
    return tuple(sorted(pins, key=lambda pin: pin.name))


def _read_registry(path: Path) -> tuple[PluginPin, ...]:
    if not path.exists():
        return ()
    payload = _load_json(path, _MAX_INDEX_BYTES)
    if type(payload) is not dict or type(payload.get("plugins")) is not list:
        raise BuiltinCatalogError("invalid plugin registry")
    try:
        return tuple(PluginPin(**entry) for entry in payload["plugins"])
    except (TypeError, ValueError) as error:
        raise BuiltinCatalogError("invalid plugin registry") from error


def _pin_payload(pin: PluginPin) -> dict[str, object]:
    return {
        "name": pin.name,
        "version": pin.version,
        "api_version": pin.api_version,
        "artifact_path": pin.artifact_path,
        "artifact_sha256": pin.artifact_sha256,
        "manifest_sha256": pin.manifest_sha256,
        "enabled": pin.enabled,
    }


def _write_atomic(path: Path, content: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temp.unlink(missing_ok=True)
        raise


def install_builtin_catalog(index_path: Path, plugin_root: Path, registry_path: Path) -> None:
    """Atomically install catalog bytes and merge disabled-by-default pins."""
    source_index = Path(index_path)
    catalog = load_builtin_catalog(source_index)
    plugin_root = Path(plugin_root)
    plugin_root.mkdir(parents=True, exist_ok=True)
    releases = plugin_root / "releases"
    releases.mkdir(exist_ok=True)
    destination = releases / catalog.release_version
    if destination.exists():
        raise BuiltinCatalogError("built-in catalog release already exists")
    staging = Path(tempfile.mkdtemp(prefix=f".{catalog.release_version}.", dir=releases))
    old_registry = registry_path.read_bytes() if registry_path.exists() else None
    old_manifests = {
        name: ((plugin_root / f"{name}.json").read_bytes() if (plugin_root / f"{name}.json").exists() else None)
        for name in EXPECTED_BUILTINS
    }
    installed = False
    try:
        shutil.copytree(source_index.parent, staging, dirs_exist_ok=True)
        staged_catalog = load_builtin_catalog(staging / "builtin-index.json")
        os.replace(staging, destination)
        installed = True
        pins = merge_builtin_registry(_read_registry(registry_path), staged_catalog, plugin_root)
        for entry in staged_catalog.plugins:
            content = (destination / entry.manifest_path).read_bytes()
            _write_atomic(plugin_root / f"{entry.name}.json", content)
        registry_payload = {"plugins": [_pin_payload(pin) for pin in pins]}
        _write_atomic(
            registry_path,
            json.dumps(registry_payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n",
        )
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        for name, content in old_manifests.items():
            path = plugin_root / f"{name}.json"
            if content is None:
                path.unlink(missing_ok=True)
            else:
                _write_atomic(path, content)
        if old_registry is None:
            registry_path.unlink(missing_ok=True)
        else:
            _write_atomic(registry_path, old_registry)
        if installed:
            shutil.rmtree(destination, ignore_errors=True)
        raise


def _main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[0] != "install":
        raise SystemExit("usage: python -m a4diag.builtin_catalog install INDEX PLUGIN_ROOT REGISTRY")
    install_builtin_catalog(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))


__all__ = [
    "BuiltinCatalog",
    "BuiltinCatalogError",
    "BuiltinEntry",
    "EXPECTED_BUILTINS",
    "install_builtin_catalog",
    "load_builtin_catalog",
    "merge_builtin_registry",
]

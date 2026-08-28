from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import ValidationError

from a4diag.plugin_api.manifest import (
    OperationContract,
    PluginManifest,
    PluginType,
    parse_api_version,
)


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PluginRegistryError(ValueError):
    """A plugin pin or installed manifest failed fail-closed verification."""


@dataclass(frozen=True)
class PluginPin:
    name: str
    version: str
    api_version: str
    artifact_path: str
    artifact_sha256: str
    manifest_sha256: str
    enabled: bool


@dataclass(frozen=True, init=False)
class PluginRegistry:
    pins: tuple[PluginPin, ...]
    _enabled: Mapping[str, PluginManifest]
    _operations: Mapping[str, OperationContract]

    @classmethod
    def load(
        cls,
        pins: tuple[PluginPin, ...],
        manifest_root: Path,
        core_api: str,
    ) -> PluginRegistry:
        root = _resolve_manifest_root(manifest_root)
        core_version = _parse_api(core_api, "core API")
        enabled: dict[str, PluginManifest] = {}
        operations: dict[str, OperationContract] = {}
        operation_owners: dict[str, str] = {}
        pin_names: set[str] = set()

        for pin in pins:
            _validate_pin_syntax(pin)
            if pin.name in pin_names:
                raise PluginRegistryError(f"duplicate pin name: {pin.name}")
            pin_names.add(pin.name)
            if not pin.enabled:
                continue

            pin_api = _parse_api(pin.api_version, f"pin {pin.name} API")
            if pin_api != core_version:
                raise PluginRegistryError(f"pin {pin.name} API is incompatible with core API")

            manifest_path = _resolve_beneath(root / f"{pin.name}.json", root, "manifest path")
            manifest_bytes = _read_regular_file(manifest_path, "manifest path")
            _verify_sha256(manifest_bytes, pin.manifest_sha256, "manifest")
            manifest = _parse_manifest(manifest_bytes, pin.name)
            _verify_compatibility(manifest, pin, pin_api, core_version)
            for operation in manifest.operations:
                _validate_parameters_schema(operation, manifest.name)
                owner = operation_owners.get(operation.name)
                if owner is not None:
                    raise PluginRegistryError(
                        f"duplicate operation name {operation.name!r}: "
                        f"{owner!r} and {manifest.name!r}"
                    )
                operation_owners[operation.name] = manifest.name
                if manifest.plugin_type is PluginType.CAPABILITY:
                    _validate_full_operation_name(operation.name, manifest.name)
                    operations[operation.name] = operation

            artifact_path = _resolve_artifact_path(pin.artifact_path, root)
            artifact_bytes = _read_regular_file(artifact_path, "artifact path")
            _verify_sha256(artifact_bytes, pin.artifact_sha256, "artifact")

            if manifest.name in enabled:
                raise PluginRegistryError(f"duplicate plugin name: {manifest.name}")
            enabled[manifest.name] = manifest

        registry = object.__new__(cls)
        object.__setattr__(registry, "pins", tuple(pins))
        object.__setattr__(registry, "_enabled", MappingProxyType(enabled))
        object.__setattr__(registry, "_operations", MappingProxyType(operations))
        return registry

    def require(self, name: str, plugin_type: PluginType) -> PluginManifest:
        manifest = self._enabled.get(name)
        if manifest is None:
            raise PluginRegistryError(f"plugin {name!r} is not enabled")
        if manifest.plugin_type is not plugin_type:
            raise PluginRegistryError(
                f"plugin {name!r} is {manifest.plugin_type.value}, not {plugin_type.value}"
            )
        return manifest.model_copy(deep=True)

    def require_operation(self, capability: str, action: str) -> OperationContract:
        if not isinstance(capability, str) or not _SAFE_NAME.fullmatch(capability):
            raise PluginRegistryError("capability operation has an unsafe capability name")
        if not isinstance(action, str) or not _SAFE_NAME.fullmatch(action):
            raise PluginRegistryError("capability operation has an unsafe action name")
        full_name = f"{capability}.{action}"
        contract = self._operations.get(full_name)
        if contract is None:
            raise PluginRegistryError(
                f"capability operation {full_name!r} is not enabled"
            )
        return contract.model_copy(deep=True)


def _resolve_manifest_root(manifest_root: Path) -> Path:
    try:
        root = manifest_root.resolve(strict=True)
    except OSError as error:
        raise PluginRegistryError("manifest root does not exist") from error
    if not root.is_dir():
        raise PluginRegistryError("manifest root must be a directory")
    return root


def _validate_pin_syntax(pin: PluginPin) -> None:
    if not isinstance(pin, PluginPin):
        raise PluginRegistryError("plugin pin must be a PluginPin")
    if not isinstance(pin.name, str) or not _SAFE_NAME.fullmatch(pin.name):
        raise PluginRegistryError("plugin pin has an unsafe name")
    for label, value in (("version", pin.version), ("artifact path", pin.artifact_path)):
        if not isinstance(value, str) or not value or _contains_control_characters(value):
            raise PluginRegistryError(f"plugin pin has an invalid {label}")
    _parse_api(pin.api_version, f"pin {pin.name} API")
    for label, value in (
        ("artifact SHA256", pin.artifact_sha256),
        ("manifest SHA256", pin.manifest_sha256),
    ):
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise PluginRegistryError(f"plugin pin has an invalid {label}")
    if type(pin.enabled) is not bool:
        raise PluginRegistryError("plugin pin enabled must be a boolean")


def _parse_api(value: str, label: str) -> tuple[int, int]:
    try:
        return parse_api_version(value)
    except ValueError as error:
        raise PluginRegistryError(f"{label} must be an ASCII MAJOR.MINOR pair") from error


def _resolve_beneath(candidate: Path, root: Path, label: str) -> Path:
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise PluginRegistryError(f"{label} does not exist") from error
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise PluginRegistryError(f"{label} escapes manifest root") from error
    return resolved


def _resolve_artifact_path(value: str, root: Path) -> Path:
    raw = Path(value)
    if any(part in {".", ".."} for part in raw.parts):
        raise PluginRegistryError("artifact path is unsafe")
    candidate = raw if raw.is_absolute() else root / raw
    return _resolve_beneath(candidate, root, "artifact path")


def _read_regular_file(path: Path, label: str) -> bytes:
    if not path.is_file():
        raise PluginRegistryError(f"{label} must be a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise PluginRegistryError(f"could not read {label}") from error


def _verify_sha256(content: bytes, expected: str, label: str) -> None:
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        raise PluginRegistryError(f"{label} SHA256 does not match its pin")


def _parse_manifest(content: bytes, pin_name: str) -> PluginManifest:
    try:
        payload = json.loads(content.decode("utf-8"))
        manifest = PluginManifest.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
        raise PluginRegistryError(f"manifest for {pin_name} is invalid: {error}") from error
    if manifest.name != pin_name:
        raise PluginRegistryError(f"manifest name does not match pin name: {pin_name}")
    return manifest


def _verify_compatibility(
    manifest: PluginManifest,
    pin: PluginPin,
    pin_api: tuple[int, int],
    core_api: tuple[int, int],
) -> None:
    if manifest.version != pin.version:
        raise PluginRegistryError(f"manifest version does not match pin: {pin.name}")
    api_min = _parse_api(manifest.api_min, f"manifest {pin.name} API minimum")
    api_max = _parse_api(manifest.api_max, f"manifest {pin.name} API maximum")
    if api_min > api_max:
        raise PluginRegistryError(f"manifest API range is inverted: {pin.name}")
    if not api_min <= pin_api <= api_max:
        raise PluginRegistryError(f"manifest API range is incompatible: {pin.name}")
    if not (api_min[0] == api_max[0] == pin_api[0] == core_api[0]):
        raise PluginRegistryError(f"manifest API major version is incompatible: {pin.name}")


def _validate_full_operation_name(operation_name: str, plugin_name: str) -> None:
    components = operation_name.split(".")
    if len(components) != 2 or any(not _SAFE_NAME.fullmatch(part) for part in components):
        raise PluginRegistryError(
            f"capability plugin {plugin_name!r} operation must use capability.action"
        )


def _validate_parameters_schema(
    operation: OperationContract, plugin_name: str
) -> None:
    schema = operation.parameters_schema
    label = f"parameters schema for {plugin_name}.{operation.name}"
    if schema.get("type") != "object":
        raise PluginRegistryError(f"{label} must have root type object")
    if schema.get("additionalProperties") is not False:
        raise PluginRegistryError(
            f"{label} must set root additionalProperties to false"
        )
    prohibited = {
        "$ref",
        "$dynamicRef",
        "$id",
        "$schema",
        "$vocabulary",
        "$anchor",
        "$dynamicAnchor",
    }
    stack: list[object] = [schema]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            invalid = prohibited.intersection(value)
            if invalid:
                keyword = sorted(invalid)[0]
                raise PluginRegistryError(
                    f"{label} must be self-contained; {keyword} is not allowed"
                )
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise PluginRegistryError(f"{label} is invalid: {error.message}") from error


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)

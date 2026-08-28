from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from a4diag.plugin_api.manifest import (
    OperationContract,
    PluginManifest,
    PluginType,
)
from a4diag.plugin_registry import PluginPin, PluginRegistry, PluginRegistryError


def manifest_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "transport-local",
        "plugin_type": "transport",
        "version": "1.2.3",
        "api_min": "1.0",
        "api_max": "1.1",
        "executable": "a4diag_plugins.transport_local:main",
        "socket": "/run/a4diag/transport-local.sock",
        "config_schema": "schemas/transport-local.json",
        "operations": [
            {
                "name": "collect-status",
                "risk_floor": "low",
                "reversible": True,
                "supports_prepare": True,
                "supports_verify": True,
                "supports_reconcile": False,
                "parameters_schema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ],
    }
    data.update(overrides)
    return data


def write_manifest_fixture(
    root: Path,
    *,
    pin_overrides: dict[str, object] | None = None,
    manifest_overrides: dict[str, object] | None = None,
) -> tuple[Path, PluginPin]:
    plugin_dir = root / "plugins"
    plugin_dir.mkdir()
    artifact = plugin_dir / "transport-local.whl"
    artifact.write_bytes(b"signed plugin wheel bytes")
    manifest_path = root / "transport-local.json"
    manifest_path.write_bytes(
        json.dumps(manifest_data(**(manifest_overrides or {})), separators=(",", ":")).encode(
            "utf-8"
        )
    )
    pin_data: dict[str, object] = {
        "name": "transport-local",
        "version": "1.2.3",
        "api_version": "1.0",
        "artifact_path": "plugins/transport-local.whl",
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "enabled": True,
    }
    pin_data.update(pin_overrides or {})
    return manifest_path, PluginPin(**pin_data)  # type: ignore[arg-type]


def write_capability_fixture(
    root: Path,
    *,
    plugin_name: str,
    operation_name: str,
    parameters_schema: dict[str, object] | None = None,
) -> PluginPin:
    plugin_dir = root / "plugins"
    plugin_dir.mkdir(exist_ok=True)
    artifact = plugin_dir / f"{plugin_name}.whl"
    artifact.write_bytes(f"artifact:{plugin_name}".encode("ascii"))
    manifest_path = root / f"{plugin_name}.json"
    operation = {
        "name": operation_name,
        "risk_floor": "low",
        "reversible": True,
        "supports_prepare": True,
        "supports_verify": True,
        "supports_reconcile": True,
        "supports_undo": True,
        "parameters_schema": parameters_schema
        or {
            "type": "object",
            "properties": {"content": {"type": "string"}},
            "required": ["content"],
            "additionalProperties": False,
        },
    }
    payload = manifest_data(
        name=plugin_name,
        plugin_type="capability",
        executable=f"a4diag_plugins.{plugin_name.replace('-', '_')}:main",
        socket=f"/run/a4diag/{plugin_name}.sock",
        config_schema=f"schemas/{plugin_name}.json",
        operations=[operation],
    )
    manifest_path.write_bytes(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return PluginPin(
        name=plugin_name,
        version="1.2.3",
        api_version="1.0",
        artifact_path=f"plugins/{plugin_name}.whl",
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        enabled=True,
    )


def test_registry_loads_only_enabled_compatible_plugin(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path)

    registry = PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")

    manifest = registry.require("transport-local", PluginType.TRANSPORT)
    assert manifest.name == "transport-local"
    assert manifest.operations[0].name == "collect-status"


@pytest.mark.parametrize("field", ["artifact_sha256", "manifest_sha256"])
def test_registry_rejects_digest_mismatch(tmp_path: Path, field: str) -> None:
    manifest_path, pin = write_manifest_fixture(
        tmp_path, pin_overrides={field: "0" * 64}
    )

    with pytest.raises(PluginRegistryError, match="SHA256"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


def test_registry_rejects_manifest_outside_pin_api_range(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(
        tmp_path, manifest_overrides={"api_min": "1.1", "api_max": "1.2"}
    )

    with pytest.raises(PluginRegistryError, match="API"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


def test_registry_rejects_inverted_api_range(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(
        tmp_path, manifest_overrides={"api_min": "1.1", "api_max": "1.0"}
    )

    with pytest.raises(PluginRegistryError, match="range"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


@pytest.mark.parametrize("api", ["1", "1.0.0", "1.-1", "1.0\n"])
def test_registry_rejects_malformed_api_versions(tmp_path: Path, api: str) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path, pin_overrides={"api_version": api})

    with pytest.raises(PluginRegistryError, match="API"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


def test_registry_rejects_duplicate_pin_names(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path)

    with pytest.raises(PluginRegistryError, match="duplicate pin"):
        PluginRegistry.load((pin, pin), manifest_path.parent, core_api="1.0")


def test_registry_rejects_manifest_name_not_covered_by_pin(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(
        tmp_path, manifest_overrides={"name": "transport-other"}
    )

    with pytest.raises(PluginRegistryError, match="manifest.*name"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


def test_disabled_pin_skips_artifact_and_manifest_verification(tmp_path: Path) -> None:
    _manifest_path, pin = write_manifest_fixture(
        tmp_path,
        pin_overrides={
            "enabled": False,
            "artifact_path": "missing.whl",
            "artifact_sha256": "0" * 64,
            "manifest_sha256": "0" * 64,
        },
    )

    registry = PluginRegistry.load((pin,), tmp_path, core_api="1.0")

    with pytest.raises(PluginRegistryError, match="not enabled"):
        registry.require("transport-local", PluginType.TRANSPORT)


def test_registry_rejects_artifact_path_traversal(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(
        tmp_path, pin_overrides={"artifact_path": "../transport-local.whl"}
    )

    with pytest.raises(PluginRegistryError, match="artifact path"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


def test_registry_rejects_artifact_symlink_escape(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path)
    external = tmp_path.parent / "external.whl"
    external.write_bytes(b"external")
    artifact = tmp_path / "plugins" / "transport-local.whl"
    artifact.unlink()
    try:
        artifact.symlink_to(external)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("symlink creation requires the Windows symlink privilege")
        raise

    with pytest.raises(PluginRegistryError, match="artifact path"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


def test_registry_rejects_manifest_symlink_escape(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path)
    external = tmp_path.parent / "external.json"
    external.write_bytes(manifest_path.read_bytes())
    manifest_path.unlink()
    try:
        manifest_path.symlink_to(external)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("symlink creation requires the Windows symlink privilege")
        raise

    with pytest.raises(PluginRegistryError, match="manifest path"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("socket", "run/a4diag.sock"),
        ("executable", "a4diag/../main"),
        ("config_schema", "../schema.json"),
    ],
)
def test_manifest_rejects_unsafe_paths(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(manifest_data(**{field: value}))


@pytest.mark.parametrize("schema_path", [".", "schemas/.", "C:schema"])
def test_manifest_rejects_unsafe_raw_schema_components(schema_path: str) -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(manifest_data(config_schema=schema_path))


def test_manifest_accepts_safe_nested_schema_path() -> None:
    manifest = PluginManifest.model_validate(
        manifest_data(config_schema="schemas/transport-local.json")
    )

    assert manifest.config_schema == "schemas/transport-local.json"


def test_manifest_rejects_duplicate_operation_names() -> None:
    first_operation = manifest_data()["operations"]
    assert isinstance(first_operation, list)

    with pytest.raises(ValidationError, match="duplicate operation"):
        PluginManifest.model_validate(manifest_data(operations=[*first_operation, first_operation[0]]))


def test_operation_contract_requires_a_parameters_schema() -> None:
    operation = dict(manifest_data()["operations"][0])  # type: ignore[arg-type,index]
    operation.pop("parameters_schema")

    with pytest.raises(ValidationError, match="parameters_schema"):
        OperationContract.model_validate(operation)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "array", "additionalProperties": False},
        {"type": "object", "additionalProperties": True},
        {"type": "object", "$ref": "#/$defs/input", "additionalProperties": False},
        {
            "type": "object",
            "properties": {"x": {"$dynamicRef": "https://example.invalid/schema"}},
            "additionalProperties": False,
        },
        {
            "type": "object",
            "$id": "https://example.invalid/schema",
            "additionalProperties": False,
        },
        {
            "type": "object",
            "$schema": "https://example.invalid/schema",
            "additionalProperties": False,
        },
        {
            "type": "object",
            "$vocabulary": {"https://example.invalid/vocab": True},
            "additionalProperties": False,
        },
        {"type": "object", "$anchor": "external", "additionalProperties": False},
        {
            "type": "object",
            "$dynamicAnchor": "external",
            "additionalProperties": False,
        },
        {"type": "not-a-json-schema-type", "additionalProperties": False},
    ],
)
def test_enabled_capability_rejects_unsafe_or_invalid_parameter_schema(
    tmp_path: Path, schema: dict[str, object]
) -> None:
    pin = write_capability_fixture(
        tmp_path,
        plugin_name="capability-files",
        operation_name="files.replace",
        parameters_schema=schema,
    )

    with pytest.raises(PluginRegistryError, match="parameters schema"):
        PluginRegistry.load((pin,), tmp_path, core_api="1.0")


def test_registry_resolves_exact_enabled_capability_operation(tmp_path: Path) -> None:
    pin = write_capability_fixture(
        tmp_path,
        plugin_name="capability-files",
        operation_name="files.replace",
    )
    registry = PluginRegistry.load((pin,), tmp_path, core_api="1.0")

    contract = registry.require_operation("files", "replace")

    assert contract.name == "files.replace"
    with pytest.raises(PluginRegistryError, match="not enabled"):
        registry.require_operation("files", "delete")


def test_registry_rejects_duplicate_full_operation_names_across_plugins(
    tmp_path: Path,
) -> None:
    first = write_capability_fixture(
        tmp_path,
        plugin_name="capability-files-a",
        operation_name="files.replace",
    )
    second = write_capability_fixture(
        tmp_path,
        plugin_name="capability-files-b",
        operation_name="files.replace",
    )

    with pytest.raises(PluginRegistryError, match="duplicate operation"):
        PluginRegistry.load((first, second), tmp_path, core_api="1.0")


def test_registry_lookups_do_not_expose_mutable_parameter_schema_state(
    tmp_path: Path,
) -> None:
    pin = write_capability_fixture(
        tmp_path,
        plugin_name="capability-files",
        operation_name="files.replace",
    )
    registry = PluginRegistry.load((pin,), tmp_path, core_api="1.0")

    contract = registry.require_operation("files", "replace")
    contract.parameters_schema["additionalProperties"] = True
    manifest = registry.require("capability-files", PluginType.CAPABILITY)
    manifest.operations[0].parameters_schema["additionalProperties"] = True

    assert (
        registry.require_operation("files", "replace").parameters_schema[
            "additionalProperties"
        ]
        is False
    )


def test_registry_cannot_be_constructed_without_verified_load() -> None:
    with pytest.raises(TypeError):
        PluginRegistry(pins=(), _enabled={}, _operations={})  # type: ignore[call-arg]


def test_manifest_models_are_frozen_and_forbid_unknown_fields() -> None:
    operation = OperationContract.model_validate(manifest_data()["operations"][0])  # type: ignore[index]
    with pytest.raises(ValidationError):
        operation.name = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(manifest_data(unexpected=True))


def test_manifest_exposes_safe_default_permission_and_compatibility_contracts() -> None:
    manifest = PluginManifest.model_validate(manifest_data())

    assert manifest.permissions == ()
    assert manifest.network_access == ()
    assert manifest.secret_refs == ()
    assert manifest.target_compatibility == ()
    assert manifest.operations[0].supports_undo is False


def test_manifest_preserves_explicit_permission_and_compatibility_contracts() -> None:
    operation = dict(manifest_data()["operations"][0])  # type: ignore[arg-type,index]
    operation["supports_undo"] = True
    manifest = PluginManifest.model_validate(
        manifest_data(
            permissions=["read:machine-id"],
            network_access=["target-ssh"],
            secret_refs=["target:ssh-key"],
            target_compatibility=["linux:systemd"],
            operations=[operation],
        )
    )

    assert manifest.permissions == ("read:machine-id",)
    assert manifest.network_access == ("target-ssh",)
    assert manifest.secret_refs == ("target:ssh-key",)
    assert manifest.target_compatibility == ("linux:systemd",)
    assert manifest.operations[0].supports_undo is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("permissions", ["read:machine-id", "read:machine-id"]),
        ("network_access", ["ssh:target\n"]),
        ("secret_refs", [""]),
        ("target_compatibility", ["linux:systemd", "linux:systemd"]),
        ("permissions", ["Read:machine-id"]),
        ("permissions", ["read:machine id"]),
        ("permissions", ["read:*"]),
        ("network_access", ["none", "target-ssh"]),
        ("network_access", ["arbitrary-outbound"]),
        ("secret_refs", ["Target:ssh-key"]),
        ("secret_refs", ["target:../ssh-key"]),
        ("target_compatibility", ["Linux:systemd"]),
        ("target_compatibility", ["linux:system d"]),
    ],
)
def test_manifest_rejects_ambiguous_security_declarations(
    field: str, value: list[str]
) -> None:
    with pytest.raises(ValidationError):
        PluginManifest.model_validate(manifest_data(**{field: value}))

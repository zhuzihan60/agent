"""Conformance harness run over every built-in plugin manifest.

One parameterized test drives all manifests through the same checks: strict
schema, API negotiation, absolute socket paths, resolvable executables,
operation parameter schemas, risk floors, secret/network declarations, the
claimed prepare/apply/undo/verify/reconcile surface of each plugin type, and
(only when a wheel has already been built) wheel contents, entrypoint, and
artifact hygiene.
"""

from __future__ import annotations

import importlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from a4diag.domain import Risk
from a4diag.plugin_api.manifest import PluginManifest, PluginType, parse_api_version
from a4diag.plugin_registry import _validate_parameters_schema  # noqa: PLC2701

MANIFEST_ROOT = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "a4diag-builtin-plugins"
    / "manifests"
)
DIST_ROOT = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "a4diag-builtin-plugins"
    / "dist"
)

_RISK_RANK = {Risk.LOW: 0, Risk.HIGH: 1}

# Expected RPC surface per plugin type, keyed by manifest name.
_EXPECTED_SURFACE: dict[str, frozenset[str]] = {
    "transport-local": frozenset({"health", "describe", "capability_probe", "verify_identity", "read", "execute_typed"}),
    "transport-ssh": frozenset({"health", "describe", "capability_probe", "verify_identity", "read", "execute_typed"}),
    "capability-files": frozenset({"health", "describe", "capability_probe", "prepare", "apply", "undo", "verify", "reconcile"}),
    "capability-services": frozenset({"health", "describe", "capability_probe", "prepare", "apply", "undo", "verify", "reconcile"}),
    "capability-packages": frozenset({"health", "describe", "capability_probe", "prepare", "apply", "undo", "verify", "reconcile"}),
    "model-openai-compatible": frozenset({"health", "describe", "capability_probe", "diagnose", "plan", "critic"}),
    "notification-cli": frozenset({"health", "describe", "capability_probe", "send"}),
    "notification-flashduty": frozenset({"health", "describe", "capability_probe", "send"}),
    "notification-smtp": frozenset({"health", "describe", "capability_probe", "send"}),
    "notification-webhook": frozenset({"health", "describe", "capability_probe", "send"}),
}

# Plugin class name per manifest for surface attribute checks.
_CLASS_NAMES: dict[str, str] = {
    "transport-local": "LocalTransport",
    "transport-ssh": "SshTransport",
    "capability-files": "FilesPlugin",
    "capability-services": "ServicesPlugin",
    "capability-packages": "PackagesPlugin",
    "model-openai-compatible": "ModelPlugin",
    "notification-cli": "CliNotification",
    "notification-flashduty": "FlashDutyNotification",
    "notification-smtp": "SmtpNotification",
    "notification-webhook": "WebhookNotification",
}

_RPC_METHODS = frozenset(
    {"health", "describe", "capability_probe", "verify_identity", "read", "execute_typed",
     "prepare", "apply", "undo", "verify", "reconcile", "diagnose", "plan", "critic", "send"}
)


@dataclass(frozen=True)
class ManifestConformance:
    errors: tuple[str, ...]
    manifest: PluginManifest | None = None


def verify_manifest(manifest_path: Path) -> ManifestConformance:
    """Run the full conformance harness over one manifest file."""
    errors: list[str] = []
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = PluginManifest.model_validate(payload)
    except Exception as error:  # noqa: BLE001 - conformance surfaces all failures
        return ManifestConformance(errors=(f"invalid manifest: {error}",))

    name = manifest.name
    _check_api_negotiation(manifest, errors)
    _check_executable(manifest, errors)
    _check_risk_floors(manifest, errors)
    _check_operation_schemas(manifest, errors)
    _check_claimed_surface(manifest, errors)
    _check_declarations(manifest, errors)
    if not errors:
        errors.extend(_wheel_consistency_errors())
    return ManifestConformance(errors=tuple(errors), manifest=manifest)


def _check_api_negotiation(manifest: PluginManifest, errors: list[str]) -> None:
    minimum = parse_api_version(manifest.api_min)
    maximum = parse_api_version(manifest.api_max)
    if minimum > (1, 0) or maximum < (1, 0) or minimum[0] != 1:
        errors.append(
            f"API range {manifest.api_min}..{manifest.api_max} is incompatible with core 1.0"
        )
    if not manifest.socket.startswith("/"):
        errors.append("socket must be an absolute Unix path")


def _check_executable(manifest: PluginManifest, errors: list[str]) -> None:
    module_name, _, function = manifest.executable.partition(":")
    if not module_name or not function:
        errors.append(f"executable {manifest.executable!r} must be module:function")
        return
    try:
        module = importlib.import_module(module_name)
    except Exception as error:  # noqa: BLE001
        errors.append(f"executable module {module_name!r} is not importable: {error}")
        return
    if not callable(getattr(module, function, None)):
        errors.append(f"executable function {function!r} missing from {module_name}")
    class_name = _CLASS_NAMES.get(manifest.name)
    if class_name is not None:
        plugin_cls = getattr(module, class_name, None)
        if plugin_cls is None:
            errors.append(f"plugin class {class_name!r} missing from {module_name}")


def _check_risk_floors(manifest: PluginManifest, errors: list[str]) -> None:
    if _RISK_RANK[manifest.write_risk_floor] < _RISK_RANK[manifest.read_risk_floor]:
        errors.append("write risk floor is lower than the read risk floor")
    for operation in manifest.operations:
        if operation.risk_floor not in (Risk.LOW, Risk.HIGH):
            errors.append(f"operation {operation.name} has an invalid risk floor")
        if manifest.plugin_type is PluginType.CAPABILITY:
            # The blanket write floor must not understate any operation floor.
            if _RISK_RANK[operation.risk_floor] > _RISK_RANK[manifest.write_risk_floor]:
                errors.append(
                    f"operation {operation.name} floor exceeds the manifest write floor"
                )


def _check_operation_schemas(manifest: PluginManifest, errors: list[str]) -> None:
    for operation in manifest.operations:
        try:
            _validate_parameters_schema(operation, manifest.name)
        except Exception as error:  # noqa: BLE001
            errors.append(f"operation {operation.name} schema invalid: {error}")


def _check_claimed_surface(manifest: PluginManifest, errors: list[str]) -> None:
    expected = _EXPECTED_SURFACE.get(manifest.name)
    if expected is None:
        errors.append(f"no expected surface mapping for manifest {manifest.name}")
        return
    if manifest.plugin_type is PluginType.CAPABILITY:
        for operation in manifest.operations:
            for method, flag in (
                ("prepare", operation.supports_prepare),
                ("apply", True),
                ("undo", operation.supports_undo),
                ("verify", operation.supports_verify),
                ("reconcile", operation.supports_reconcile),
            ):
                if flag and method not in expected:
                    errors.append(f"operation {operation.name} claims {method} but it is not registered")
    missing = sorted(expected - _RPC_METHODS)
    if missing:
        errors.append(f"expected surface names are not RPC methods: {missing}")


def _check_declarations(manifest: PluginManifest, errors: list[str]) -> None:
    if manifest.plugin_type is PluginType.TRANSPORT:
        if not manifest.permissions:
            errors.append("transport manifest must declare permissions")
    if manifest.plugin_type is PluginType.MODEL:
        if "model-provider" not in manifest.network_access:
            errors.append("model manifest must declare model-provider network access")
        if not any(ref.startswith("model:") for ref in manifest.secret_refs):
            errors.append("model manifest must declare a model secret reference")
    if manifest.plugin_type is PluginType.NOTIFICATION:
        if not manifest.permissions:
            errors.append("notification manifest must declare permissions")


def _wheel_consistency_errors() -> list[str]:
    """Inspect the built wheel when present; skip silently when absent."""
    wheels = sorted(DIST_ROOT.glob("*.whl"))
    sdists = sorted(DIST_ROOT.glob("*.tar.gz"))
    if not wheels:
        return []
    errors: list[str] = []
    if len(wheels) != 1:
        errors.append(f"expected exactly one plugin wheel, found {len(wheels)}")
    if sdists:
        errors.append("plugin build must not produce an sdist")
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        for manifest_path in MANIFEST_ROOT.glob("*.json"):
            member = f"a4diag_builtin_plugins/manifests/{manifest_path.name}"
            if member not in names:
                errors.append(f"wheel is missing manifest {member}")
        for entrypoint_name in (
            "a4diag_builtin_plugins/host.py",
            "a4diag_builtin_plugins/transport_local.py",
            "a4diag_builtin_plugins/transport_ssh.py",
            "a4diag_builtin_plugins/capability_files.py",
            "a4diag_builtin_plugins/capability_services.py",
            "a4diag_builtin_plugins/capability_packages.py",
            "a4diag_builtin_plugins/model_openai.py",
            "a4diag_builtin_plugins/notification_cli.py",
            "a4diag_builtin_plugins/notification_flashduty.py",
            "a4diag_builtin_plugins/notification_smtp.py",
            "a4diag_builtin_plugins/notification_webhook.py",
        ):
            if entrypoint_name not in names:
                errors.append(f"wheel is missing module {entrypoint_name}")
        for member in names:
            lowered = member.lower()
            if (
                member.endswith(".pyc")
                or "/tests/" in member
                or "test_" in member
                or "secret" in lowered
            ):
                errors.append(f"wheel contains a prohibited artifact: {member}")
        entry_points = archive.read(
            "a4diag_builtin_plugins-0.4.0.dist-info/entry_points.txt"
        ).decode("utf-8")
        if "a4diag-plugin = a4diag_builtin_plugins.host:main" not in entry_points:
            errors.append("wheel entrypoint is not a4diag-plugin = a4diag_builtin_plugins.host:main")
    return errors


@pytest.mark.parametrize(
    "manifest_path",
    sorted(MANIFEST_ROOT.glob("*.json")),
    ids=lambda path: path.stem,
)
def test_manifest_contract(manifest_path: Path) -> None:
    result = verify_manifest(manifest_path)
    assert result.errors == (), "; ".join(result.errors)
    assert result.manifest is not None


def test_all_builtin_manifests_are_covered() -> None:
    names = sorted(path.stem for path in MANIFEST_ROOT.glob("*.json"))
    assert names == sorted(
        [
            "transport-local",
            "transport-ssh",
            "capability-files",
            "capability-services",
            "capability-packages",
            "model-openai-compatible",
            "notification-cli",
            "notification-flashduty",
            "notification-smtp",
            "notification-webhook",
        ]
    )
    assert set(names) == set(_EXPECTED_SURFACE)
    assert set(names) == set(_CLASS_NAMES)

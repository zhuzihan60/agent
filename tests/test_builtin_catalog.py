from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from a4diag.builtin_catalog import (
    EXPECTED_BUILTINS,
    BuiltinCatalogError,
    load_builtin_catalog,
    merge_builtin_registry,
)
from a4diag.plugin_registry import PluginPin
from tools import build_release


MANIFEST_SOURCE = (
    Path(__file__).parents[1] / "packages" / "a4diag-builtin-plugins" / "manifests"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_catalog(root: Path) -> Path:
    catalog_root = root / "plugins" / "releases" / build_release.RELEASE_VERSION
    manifests = catalog_root / "manifests"
    artifacts = catalog_root / "artifacts"
    manifests.mkdir(parents=True)
    artifacts.mkdir()
    wheel = artifacts / build_release.BUILTIN_WHEEL
    wheel.write_bytes(b"verified builtin wheel fixture")
    wheel_digest = _sha256(wheel)
    entries: list[dict[str, object]] = []
    for source in sorted(MANIFEST_SOURCE.glob("*.json")):
        destination = manifests / source.name
        shutil.copyfile(source, destination)
        manifest = json.loads(destination.read_text(encoding="utf-8"))
        entries.append(
            {
                "name": manifest["name"],
                "plugin_type": manifest["plugin_type"],
                "version": build_release.RELEASE_VERSION,
                "api_version": "1.0",
                "manifest_path": f"manifests/{source.name}",
                "manifest_sha256": _sha256(destination),
                "artifact_path": f"artifacts/{wheel.name}",
                "artifact_sha256": wheel_digest,
            }
        )
    index = {
        "release_version": build_release.RELEASE_VERSION,
        "plugins": entries,
    }
    index_path = catalog_root / "builtin-index.json"
    index_path.write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return index_path


def test_loads_exact_digest_pinned_builtin_catalog(tmp_path: Path) -> None:
    index = make_catalog(tmp_path)

    catalog = load_builtin_catalog(index)

    assert len(catalog.plugins) == 10
    assert {entry.name for entry in catalog.plugins} == EXPECTED_BUILTINS
    assert all(entry.version == build_release.RELEASE_VERSION for entry in catalog.plugins)
    assert all(len(entry.manifest_sha256) == 64 for entry in catalog.plugins)
    assert len({entry.artifact_sha256 for entry in catalog.plugins}) == 1


def test_fresh_registry_pins_all_builtins_disabled(tmp_path: Path) -> None:
    index = make_catalog(tmp_path)
    catalog = load_builtin_catalog(index)

    pins = merge_builtin_registry((), catalog, index.parents[2])

    assert len(pins) == 10
    assert all(pin.enabled is False for pin in pins)


def test_registry_merge_preserves_only_matching_builtin_enabled_state(tmp_path: Path) -> None:
    index = make_catalog(tmp_path)
    catalog = load_builtin_catalog(index)
    entry = catalog.plugins[0]
    existing = PluginPin(
        name=entry.name,
        version="old",
        api_version="1.0",
        artifact_path="old.whl",
        artifact_sha256="0" * 64,
        manifest_sha256="1" * 64,
        enabled=True,
    )

    pins = merge_builtin_registry((existing,), catalog, index.parents[2])

    assert {pin.name: pin.enabled for pin in pins}[entry.name] is True


@pytest.mark.parametrize("tamper", ("manifest", "artifact", "extra_manifest", "index_path"))
def test_catalog_tampering_fails_closed(tmp_path: Path, tamper: str) -> None:
    index = make_catalog(tmp_path)
    payload = json.loads(index.read_text(encoding="utf-8"))
    if tamper == "manifest":
        path = index.parent / payload["plugins"][0]["manifest_path"]
        path.write_bytes(path.read_bytes() + b"\n")
    elif tamper == "artifact":
        path = index.parent / payload["plugins"][0]["artifact_path"]
        path.write_bytes(b"tampered")
    elif tamper == "extra_manifest":
        (index.parent / "manifests" / "extra.json").write_text("{}", encoding="utf-8")
    else:
        payload["plugins"][0]["manifest_path"] = "../escape.json"
        index.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(BuiltinCatalogError):
        load_builtin_catalog(index)

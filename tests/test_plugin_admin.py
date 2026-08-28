"""Tests for pinned plugin administration.

Only fake packages, temporary directories, a fake registry, and a fake
service manager are used; no real plugin is installed, no systemd call, and
no server connection is made.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from a4diag.cli import main as cli_main
from a4diag.plugin_admin import (
    AdminRequired,
    Authorizer,
    PluginAdmin,
    PluginAdminError,
)
from a4diag.plugin_registry import PluginPin

SIGNING_KEY = b"plugin-admin-signing-key-32bytes"
REGISTRY_BODY = {"plugins": []}


class FakeServiceManager:
    def __init__(self) -> None:
        self.stopped: list[str] = []
        self.started: list[str] = []

    def stop(self, name: str) -> None:
        self.stopped.append(name)

    def start(self, name: str) -> None:
        self.started.append(name)


def make_admin(tmp_path: Path, *, is_admin: bool = True) -> PluginAdmin:
    return PluginAdmin(
        authorizer=Authorizer(is_admin=is_admin),
        service_manager=FakeServiceManager(),
        plugin_root=tmp_path / "plugins",
        registry_path=tmp_path / "registry.json",
        signing_key=SIGNING_KEY,
    )


def manifest_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "example-plugin",
        "plugin_type": "capability",
        "version": "1.0.0",
        "api_min": "1.0",
        "api_max": "1.0",
        "executable": "a4diag_builtin_plugins.example_plugin:main",
        "socket": "/run/a4diag/example-plugin.sock",
        "config_schema": "schemas/example-plugin.json",
        "operations": [
            {
                "name": "files.replace_managed_file",
                "risk_floor": "low",
                "reversible": True,
                "supports_prepare": True,
                "supports_verify": True,
                "supports_reconcile": True,
                "supports_undo": True,
                "parameters_schema": {
                    "type": "object",
                    "properties": {"content": {"type": "string"}},
                    "required": ["content"],
                    "additionalProperties": False,
                },
            }
        ],
        "read_risk_floor": "low",
        "write_risk_floor": "high",
    }
    data.update(overrides)
    return data


def make_wheel_bytes(name: str = "example_plugin", version: str = "1.0.0") -> bytes:
    buffer = io.BytesIO()
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nTag: py3-none-any\n",
        )
    return buffer.getvalue()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sign_sums(sums: str) -> str:
    return hmac.new(SIGNING_KEY, sums.encode("utf-8"), hashlib.sha256).hexdigest()


def make_package(
    root: Path,
    *,
    name: str = "example-plugin",
    version: str = "1.0.0",
    tamper: str | None = None,
    missing: str | None = None,
    manifest_overrides: dict[str, object] | None = None,
) -> Path:
    package = root / "package"
    package.mkdir(parents=True, exist_ok=True)
    manifest_bytes = json.dumps(
        manifest_data(name=name, version=version, **(manifest_overrides or {})),
        separators=(",", ":"),
    ).encode("utf-8")
    (package / "manifest.json").write_bytes(manifest_bytes)
    wheel = make_wheel_bytes(name.replace("-", "_"), version)
    (package / "plugin.whl").write_bytes(wheel)
    sums = (
        f"{sha256_bytes(manifest_bytes)}  manifest.json\n"
        f"{sha256_bytes(wheel)}  plugin.whl\n"
    )
    (package / "SHA256SUMS").write_bytes(sums.encode("utf-8"))
    (package / "signature.sig").write_bytes(sign_sums(sums).encode("utf-8"))
    if tamper == "digest":
        (package / "plugin.whl").write_bytes(wheel + b"tampered")
    if tamper == "signature":
        (package / "signature.sig").write_text("0" * 64, encoding="utf-8")
    if tamper == "manifest":
        (package / "manifest.json").write_text("{bad json", encoding="utf-8")
    if missing == "wheel":
        (package / "plugin.whl").unlink()
    if missing == "manifest":
        (package / "manifest.json").unlink()
    return package


def write_registry(path: Path, pins: list[dict[str, Any]]) -> None:
    path.write_text(
        json.dumps({"plugins": pins}, sort_keys=True), encoding="utf-8"
    )


def pin_dict(
    name: str = "example-plugin",
    version: str = "1.0.0",
    enabled: bool = True,
    **updates: object,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": name,
        "version": version,
        "api_version": "1.0",
        "artifact_path": f"{name}-{version}/plugin.whl",
        "artifact_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "enabled": enabled,
    }
    data.update(updates)
    return data


# ---------------------------------------------------------------------------
# List and verify
# ---------------------------------------------------------------------------


def test_list_empty_registry(tmp_path: Path) -> None:
    assert make_admin(tmp_path).list() == ()


def test_list_shows_installed_pins(tmp_path: Path) -> None:
    write_registry(tmp_path / "registry.json", [pin_dict(), pin_dict(name="other", version="2.0.0")])
    admin = make_admin(tmp_path)

    pins = admin.list()

    assert [pin.name for pin in pins] == ["example-plugin", "other"]


def test_verify_valid_package(tmp_path: Path) -> None:
    package = make_package(tmp_path)
    result = make_admin(tmp_path).verify(package)

    assert result.ok is True
    assert result.manifest.name == "example-plugin"


def test_verify_bad_digest_fails(tmp_path: Path) -> None:
    package = make_package(tmp_path, tamper="digest")

    result = make_admin(tmp_path).verify(package)

    assert result.ok is False
    assert "digest" in result.reason


def test_verify_bad_signature_fails(tmp_path: Path) -> None:
    package = make_package(tmp_path, tamper="signature")

    result = make_admin(tmp_path).verify(package)

    assert result.ok is False
    assert "signature" in result.reason


def test_verify_invalid_manifest_fails(tmp_path: Path) -> None:
    package = make_package(tmp_path, tamper="manifest")

    result = make_admin(tmp_path).verify(package)

    assert result.ok is False


def test_verify_api_incompatible_fails(tmp_path: Path) -> None:
    package = make_package(tmp_path, manifest_overrides={"api_min": "2.0", "api_max": "2.1"})

    result = make_admin(tmp_path).verify(package)

    assert result.ok is False
    assert "api_incompatible" in result.reason


def test_verify_missing_wheel_is_unavailable_dependency(tmp_path: Path) -> None:
    package = make_package(tmp_path, missing="wheel")

    with pytest.raises(PluginAdminError, match="unavailable_dependency"):
        make_admin(tmp_path).verify(package)


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


def test_non_admin_cannot_install(tmp_path: Path) -> None:
    admin = make_admin(tmp_path, is_admin=False)
    package = make_package(tmp_path)

    with pytest.raises(AdminRequired):
        admin.install(package)


def test_bad_digest_never_changes_registry(tmp_path: Path) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path, tamper="digest")
    before = admin.registry_path.read_bytes() if admin.registry_path.exists() else b""

    with pytest.raises(PluginAdminError, match="verification_failed"):
        admin.install(package)

    assert admin.registry_path.read_bytes() if admin.registry_path.exists() else b"" == before


def test_install_stages_and_updates_registry(tmp_path: Path) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path)

    pin = admin.install(package)

    assert isinstance(pin, PluginPin)
    assert pin.name == "example-plugin"
    assert pin.enabled is True
    assert pin.artifact_sha256 == sha256_bytes((package / "plugin.whl").read_bytes())
    versioned = tmp_path / "plugins" / "example-plugin-1.0.0"
    assert versioned.is_dir()
    assert (versioned / "plugin.whl").is_file()
    assert not (tmp_path / "plugins" / ".staging").exists()
    assert (tmp_path / "plugins" / "example-plugin.json").is_file()
    assert (tmp_path / "plugins" / "example-plugin.yaml").is_file()
    assert admin.service_manager.started == ["example-plugin"]  # type: ignore[attr-defined]
    pins = admin.list()
    assert len(pins) == 1
    assert pins[0].version == "1.0.0"


def test_install_upgrade_replaces_pin(tmp_path: Path) -> None:
    admin = make_admin(tmp_path)
    first = make_package(tmp_path / "a", version="1.0.0")
    second = make_package(tmp_path / "b", version="2.0.0")
    admin.install(first)

    pin = admin.install(second)

    assert pin.version == "2.0.0"
    assert len(admin.list()) == 1
    assert (tmp_path / "plugins" / "example-plugin-1.0.0").is_dir()
    assert (tmp_path / "plugins" / "example-plugin-2.0.0").is_dir()


def test_install_rejects_unsafe_version_dir(tmp_path: Path) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path, version="1.0/../evil")

    with pytest.raises(PluginAdminError, match="version"):
        admin.install(package)


def test_install_registry_corrupt_fails_closed(tmp_path: Path) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path)
    (tmp_path / "registry.json").write_text("{corrupt", encoding="utf-8")

    with pytest.raises(PluginAdminError, match="registry"):
        admin.install(package)


# ---------------------------------------------------------------------------
# Disable
# ---------------------------------------------------------------------------


def test_disable_changes_only_target_pin_and_stops_service(tmp_path: Path) -> None:
    write_registry(
        tmp_path / "registry.json",
        [pin_dict(), pin_dict(name="other", version="2.0.0")],
    )
    admin = make_admin(tmp_path)
    service_manager: FakeServiceManager = admin.service_manager  # type: ignore[assignment]

    disabled = admin.disable("example-plugin")

    assert disabled.enabled is False
    assert service_manager.stopped == ["example-plugin"]
    pins = {pin.name: pin for pin in admin.list()}
    assert pins["other"].enabled is True
    assert pins["example-plugin"].enabled is False


def test_disable_non_admin(tmp_path: Path) -> None:
    admin = make_admin(tmp_path, is_admin=False)

    with pytest.raises(AdminRequired):
        admin.disable("example-plugin")


def test_disable_unknown_fails_without_stopping(tmp_path: Path) -> None:
    admin = make_admin(tmp_path)
    service_manager: FakeServiceManager = admin.service_manager  # type: ignore[assignment]

    with pytest.raises(PluginAdminError, match="not_found"):
        admin.disable("missing-plugin")

    assert service_manager.stopped == []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run_cli(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    admin: PluginAdmin | None = None,
) -> tuple[int, str, str]:
    import sys

    admin = admin or make_admin(Path("unused"))
    monkeypatch.setattr("a4diag.cli._build_plugin_admin", lambda: admin)
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    code = cli_main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_plugin_list_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_registry(tmp_path / "registry.json", [pin_dict()])
    admin = make_admin(tmp_path)

    code, stdout, _stderr = run_cli(["plugin", "list", "--json"], monkeypatch, admin)

    assert code == 0
    assert "example-plugin" in stdout
    json.loads(stdout)


def test_cli_plugin_verify_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path)

    code, stdout, _stderr = run_cli(
        ["plugin", "verify", str(package), "--json"], monkeypatch, admin
    )

    assert code == 0
    assert "example-plugin" in stdout


def test_cli_plugin_verify_failure_exit_65(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path, tamper="signature")

    code, _stdout, stderr = run_cli(
        ["plugin", "verify", str(package)], monkeypatch, admin
    )

    assert code == 65
    assert "signature" in stderr


def test_cli_plugin_install_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path)

    code, stdout, _stderr = run_cli(
        ["plugin", "install", str(package), "--json"], monkeypatch, admin
    )

    assert code == 0
    assert "example-plugin" in stdout
    assert len(admin.list()) == 1


def test_cli_plugin_install_non_admin_exit_77(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = make_admin(tmp_path, is_admin=False)
    package = make_package(tmp_path)

    code, _stdout, stderr = run_cli(
        ["plugin", "install", str(package)], monkeypatch, admin
    )

    assert code == 77
    assert "admin" in stderr.lower()


def test_cli_plugin_disable_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_registry(tmp_path / "registry.json", [pin_dict()])
    admin = make_admin(tmp_path)

    code, _stdout, _stderr = run_cli(
        ["plugin", "disable", "example-plugin", "--json"], monkeypatch, admin
    )

    assert code == 0
    assert admin.list()[0].enabled is False
    assert admin.service_manager.stopped == ["example-plugin"]  # type: ignore[attr-defined]


def test_cli_plugin_disable_unknown_exit_64(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = make_admin(tmp_path)

    code, _stdout, stderr = run_cli(
        ["plugin", "disable", "missing-plugin"], monkeypatch, admin
    )

    assert code == 64
    assert "not_found" in stderr


def test_cli_output_never_leaks_signing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = make_admin(tmp_path)
    package = make_package(tmp_path)

    _code, stdout, _stderr = run_cli(
        ["plugin", "install", str(package), "--json"], monkeypatch, admin
    )

    assert SIGNING_KEY.decode("ascii") not in stdout

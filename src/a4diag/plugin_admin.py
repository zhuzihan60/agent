"""Administrator plugin lifecycle: list, verify, install, disable.

A plugin package is a directory containing ``manifest.json``, ``plugin.whl``,
``SHA256SUMS`` (exact digests of the manifest and wheel), and
``signature.sig`` (an HMAC over the SHA256SUMS content with the trusted admin
key). Verification checks archive content safety, the strict manifest schema,
API compatibility, wheel metadata, digests, and the signature. Install stages
the package, re-verifies the staged copy, atomically renames it to a versioned
directory, copies the manifest, and atomically updates the registry pins.
Disable flips only the matching pin and stops the service through an injected
service manager. Any failure before the registry write leaves the registry
byte-for-byte unchanged; command output never contains secret values.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import shutil
import yaml
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from a4diag.plugin_api.manifest import PluginManifest, parse_api_version
from a4diag.plugin_registry import PluginPin

CORE_API = "1.0"
MAX_MANIFEST_BYTES = 1_048_576
MAX_SUMS_BYTES = 65_536
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_SIGNATURE_BYTES = 1_024

_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


class AdminRequired(ValueError):
    """Raised when an administrator-only operation lacks authority."""


class PluginAdminError(ValueError):
    """Stable typed plugin-administration failure carrying a reason code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)


class Authorizer:
    """Injected administrative authority (effective UID 0 by default)."""

    def __init__(self, is_admin: bool | None = None) -> None:
        if is_admin is None:
            is_admin = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
        self.is_admin = is_admin


class ServiceManager(Protocol):
    def stop(self, plugin_name: str) -> None: ...
    def start(self, plugin_name: str) -> None: ...


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    reason: str | None = None
    manifest: PluginManifest | None = None
    artifact_sha256: str = ""
    manifest_sha256: str = ""


class PluginAdmin:
    """Pinned plugin lifecycle over a plugin root and a JSON registry."""

    def __init__(
        self,
        *,
        authorizer: Authorizer,
        service_manager: ServiceManager,
        plugin_root: Path,
        registry_path: Path,
        signing_key: bytes | None = None,
    ) -> None:
        if not isinstance(authorizer, Authorizer):
            raise TypeError("authorizer must be an Authorizer")
        if signing_key is not None and (
            type(signing_key) is not bytes or len(signing_key) < 32
        ):
            raise PluginAdminError("invalid_key")
        self.authorizer = authorizer
        self.service_manager = service_manager
        self.plugin_root = Path(plugin_root)
        self.registry_path = Path(registry_path)
        self._signing_key = signing_key
        self._staging = self.plugin_root / ".staging"
        self._manifest_root = self.plugin_root
        self._instance_config_root = self.registry_path.parent / "plugins"

    def list(self) -> tuple[PluginPin, ...]:
        return tuple(self._read_registry())

    def verify(self, package_path: Path) -> VerificationResult:
        """Verify a package without changing any state."""
        signing_key = self._require_package_trust()
        package = Path(package_path)
        try:
            manifest_bytes = _read_bounded(package / "manifest.json", MAX_MANIFEST_BYTES)
            wheel_bytes = _read_bounded(package / "plugin.whl", MAX_WHEEL_BYTES)
            sums_bytes = _read_bounded(package / "SHA256SUMS", MAX_SUMS_BYTES)
            signature = (
                _read_bounded(package / "signature.sig", MAX_SIGNATURE_BYTES)
                .decode("utf-8", errors="strict")
                .strip()
            )
        except PluginAdminError:
            raise
        except OSError:
            raise PluginAdminError("unavailable_dependency", str(package)) from None
        try:
            manifest = PluginManifest.model_validate(json.loads(manifest_bytes.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            return VerificationResult(ok=False, reason=f"invalid_manifest: {error}")
        if not _verify_signature(sums_bytes, signature, signing_key):
            return VerificationResult(ok=False, reason="signature_mismatch")
        digest_error = _verify_sums(sums_bytes, {"manifest.json": manifest_bytes, "plugin.whl": wheel_bytes})
        if digest_error is not None:
            return VerificationResult(ok=False, reason=digest_error)
        if not _api_compatible(manifest):
            return VerificationResult(ok=False, reason="api_incompatible")
        wheel_error = _verify_wheel(wheel_bytes)
        if wheel_error is not None:
            return VerificationResult(ok=False, reason=wheel_error)
        return VerificationResult(
            ok=True,
            manifest=manifest,
            artifact_sha256=hashlib.sha256(wheel_bytes).hexdigest(),
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def install(self, package_path: Path) -> PluginPin:
        self._require_admin()
        result = self.verify(package_path)
        if not result.ok:
            raise PluginAdminError("verification_failed", result.reason)
        manifest = result.manifest
        assert manifest is not None
        if not _SAFE_VERSION.fullmatch(manifest.version):
            raise PluginAdminError("invalid_version", manifest.version)
        source = Path(package_path)
        versioned = self.plugin_root / f"{manifest.name}-{manifest.version}"
        self._staging.mkdir(parents=True, exist_ok=True)
        staged = self._staging / f"{manifest.name}-{manifest.version}"
        if staged.exists():
            shutil.rmtree(staged)
        try:
            staged.mkdir()
            # Copy only the four verified artifacts; never arbitrary content.
            for artifact in ("manifest.json", "plugin.whl", "SHA256SUMS", "signature.sig"):
                shutil.copyfile(source / artifact, staged / artifact)
            staged_result = self.verify(staged)
            if not staged_result.ok:
                raise PluginAdminError("verification_failed", staged_result.reason)
            manifest_bytes = _read_bounded(
                staged / "manifest.json", MAX_MANIFEST_BYTES
            )
            if versioned.exists():
                shutil.rmtree(versioned)
            os.replace(staged, versioned)
            self._manifest_root.mkdir(parents=True, exist_ok=True)
            _write_atomic(self._manifest_root / f"{manifest.name}.json", manifest_bytes)
            try:
                self._staging.rmdir()
            except OSError:
                pass
        except PluginAdminError:
            self._remove_staged(manifest.name, manifest.version)
            raise
        except OSError as error:
            self._remove_staged(manifest.name, manifest.version)
            raise PluginAdminError("write_failed") from error

        pin = PluginPin(
            name=manifest.name,
            version=manifest.version,
            api_version=CORE_API,
            artifact_path=f"{manifest.name}-{manifest.version}/plugin.whl",
            artifact_sha256=result.artifact_sha256,
            manifest_sha256=result.manifest_sha256,
            enabled=True,
        )
        previous_pins = self._read_registry()
        instance_config = self._instance_config_root / f"{manifest.name}.yaml"
        self._instance_config_root.mkdir(parents=True, exist_ok=True)
        try:
            previous_instance_config = (
                instance_config.read_bytes() if instance_config.exists() else None
            )
        except OSError as error:
            raise PluginAdminError("write_failed") from error
        _write_atomic(
            instance_config,
            yaml.safe_dump(
                {
                    "manifest": manifest.name,
                    "socket": manifest.socket,
                    "ticket_key_ref": "file:core-ticket.key",
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        try:
            pins = [existing for existing in previous_pins if existing.name != pin.name]
            pins.append(pin)
            _write_registry_atomic(self.registry_path, pins)
        except PluginAdminError:
            raise
        except OSError as error:
            raise PluginAdminError("write_failed") from error
        try:
            self.service_manager.start(pin.name)
        except Exception as error:
            _write_registry_atomic(self.registry_path, previous_pins)
            try:
                if previous_instance_config is None:
                    instance_config.unlink()
                else:
                    _write_atomic(instance_config, previous_instance_config)
            except OSError:
                pass
            raise PluginAdminError("unavailable_dependency", "plugin service failed") from error
        return pin

    def disable(self, name: str) -> PluginPin:
        self._require_admin()
        pins = self._read_registry()
        disabled_pin: PluginPin | None = None
        updated: list[PluginPin] = []
        for pin in pins:
            if pin.name == name:
                disabled_pin = PluginPin(
                    name=pin.name,
                    version=pin.version,
                    api_version=pin.api_version,
                    artifact_path=pin.artifact_path,
                    artifact_sha256=pin.artifact_sha256,
                    manifest_sha256=pin.manifest_sha256,
                    enabled=False,
                )
                updated.append(disabled_pin)
            else:
                updated.append(pin)
        if disabled_pin is None:
            raise PluginAdminError("not_found", name)
        try:
            _write_registry_atomic(self.registry_path, updated)
        except OSError as error:
            raise PluginAdminError("write_failed") from error
        self.service_manager.stop(name)
        return disabled_pin

    # ------------------------------------------------------------------

    def _require_admin(self) -> None:
        if not self.authorizer.is_admin:
            raise AdminRequired("administrative authority required")

    def _require_package_trust(self) -> bytes:
        if self._signing_key is None:
            raise PluginAdminError("third_party_plugins_unsupported")
        return self._signing_key

    def _read_registry(self) -> list[PluginPin]:
        path = self.registry_path
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if type(payload) is not dict or type(payload.get("plugins")) is not list:
                raise ValueError("registry document must contain a plugins list")
            pins = [PluginPin(**entry) for entry in payload["plugins"]]
            names = [pin.name for pin in pins]
            if len(names) != len(set(names)):
                raise ValueError("duplicate plugin name in registry")
            return pins
        except (OSError, ValueError, TypeError) as error:
            raise PluginAdminError("registry_corrupt", str(error)) from error

    def _remove_staged(self, name: str, version: str) -> None:
        staged = self._staging / f"{name}-{version}"
        try:
            if staged.exists():
                shutil.rmtree(staged)
        except OSError:
            pass


def _read_bounded(path: Path, limit: int) -> bytes:
    if not path.is_file():
        raise PluginAdminError("unavailable_dependency", str(path))
    info = path.stat()
    if info.st_size > limit:
        raise PluginAdminError("verification_failed", f"{path.name} exceeds size bound")
    with open(path, "rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise PluginAdminError("verification_failed", f"{path.name} exceeds size bound")
    return content


def _verify_signature(sums: bytes, signature: str, key: bytes) -> bool:
    expected = hmac.new(key, sums, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_sums(sums: bytes, files: dict[str, bytes]) -> str | None:
    try:
        lines = sums.decode("utf-8").splitlines()
        entries: dict[str, str] = {}
        for line in lines:
            parts = line.split()
            if len(parts) != 2:
                return "malformed_sums"
            digest, name = parts
            if name in entries:
                return "malformed_sums"
            entries[name] = digest
    except UnicodeDecodeError:
        return "malformed_sums"
    if set(entries) != set(files):
        return "sums_missing_or_extra"
    for name, content in files.items():
        if not _is_sha256(entries[name]):
            return "malformed_sums"
        if entries[name] != hashlib.sha256(content).hexdigest():
            return f"digest_mismatch: {name}"
    return None


def _is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _api_compatible(manifest: PluginManifest) -> bool:
    minimum = parse_api_version(manifest.api_min)
    maximum = parse_api_version(manifest.api_max)
    core = parse_api_version(CORE_API)
    return minimum <= core <= maximum and minimum[0] == 1


def _verify_wheel(wheel_bytes: bytes) -> str | None:
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            names = archive.namelist()
            wheel_entries = [name for name in names if name.endswith("/WHEEL")]
            metadata_entries = [name for name in names if name.endswith(".dist-info/METADATA")]
            if not wheel_entries or not metadata_entries:
                return "invalid_wheel"
            wheel_text = archive.read(wheel_entries[0]).decode("utf-8", errors="strict")
            if not wheel_text.startswith("Wheel-Version:"):
                return "invalid_wheel"
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, KeyError):
        return "invalid_wheel"
    return None


def _write_atomic(path: Path, content: bytes) -> None:
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    temp = directory / f".{path.name}.a4diag-tmp"
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except OSError:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def _write_registry_atomic(path: Path, pins: list[PluginPin]) -> None:
    payload = {"plugins": [_pin_dict(pin) for pin in pins]}
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _write_atomic(path, content)


def _pin_dict(pin: PluginPin) -> dict[str, object]:
    return {
        "name": pin.name,
        "version": pin.version,
        "api_version": pin.api_version,
        "artifact_path": pin.artifact_path,
        "artifact_sha256": pin.artifact_sha256,
        "manifest_sha256": pin.manifest_sha256,
        "enabled": pin.enabled,
    }


__all__ = [
    "AdminRequired",
    "Authorizer",
    "PluginAdmin",
    "PluginAdminError",
    "ServiceManager",
    "VerificationResult",
]

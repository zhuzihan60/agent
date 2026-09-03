"""A4Diag 0.4.2 release assembly and static verification.

Commands:
- ``stage-systemd``: stage the exact systemd unit inventory atomically.
- ``assemble``: verify and stage the exact core + builtin-plugin wheels, the
  verified dependency wheelhouse, locks, config example, systemd units, a
  version lock, and a top-level SHA256 manifest (optionally RSA-signed).
- ``verify-source``: reject fixed-target literals in runtime source and the
  default configuration.
- ``verify-release``: reread every hash, require exact manifest coverage, and
  reject any undeclared file or wheel.

The release never carries test files, private keys, or fixed target
information; signing uses an injected key file (CI signs with repository
secret material).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from email.parser import BytesParser
from pathlib import Path

RELEASE_VERSION = "0.4.2"
CORE_WHEEL = f"a4diag-{RELEASE_VERSION}-py3-none-any.whl"
BUILTIN_WHEEL = f"a4diag_builtin_plugins-{RELEASE_VERSION}-py3-none-any.whl"
TARGET_WHEEL = f"a4diag_target_runtime-{RELEASE_VERSION}-py3-none-any.whl"
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

EXPECTED_SYSTEMD_UNITS = frozenset(
    {
        "a4diag-cleanup.service",
        "a4diag-cleanup.timer",
        "a4diag-core.service",
        "a4diag-plugin@.service",
        "a4diag-plugin@.socket",
    }
)
EXPECTED_TARGET_SYSTEMD_UNITS = frozenset(
    {"a4diag-target-executor.service", "a4diag-target-executor.socket"}
)

FORBIDDEN_RUNTIME_LITERALS = (
    "t_11",
    "targets must contain exactly",
    "fixed-target executor",
    "a4diag-ro",
)
FORBIDDEN_IP = re.compile(
    r"(?<![0-9])(?:10(?:\.(?:[0-9]{1,3})){3}|192\.168(?:\.(?:[0-9]{1,3})){2}"
    r"|192\.0\.2\.(?:[0-9]{1,3})|198\.51\.100\.(?:[0-9]{1,3})"
    r"|203\.0\.113\.(?:[0-9]{1,3}))(?![0-9])"
)
FORBIDDEN_SSH_DESTINATION = re.compile(
    r"[A-Za-z0-9_.-]+@(?:[0-9]{1,3}(?:\.[0-9]{1,3}){1,3})"
)
_SKIPPED_BUILD_DIRS = frozenset({"build", "dist", "__pycache__", ".egg-info"})
_FORBIDDEN_WHEEL_NAME_SEGMENTS = (
    "tests",
    "test_",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sig",
)


# ---------------------------------------------------------------------------
# systemd staging
# ---------------------------------------------------------------------------


def copy_systemd_units(project_root: Path, output: Path) -> None:
    deploy_dir = project_root / "deploy"
    output.mkdir()
    for unit_name in sorted(EXPECTED_SYSTEMD_UNITS):
        shutil.copy2(deploy_dir / unit_name, output / unit_name)
    for subdir in ("tmpfiles.d", "sysusers.d"):
        source = deploy_dir / subdir / "a4diag.conf"
        destination = output / subdir
        destination.mkdir()
        shutil.copy2(source, destination / "a4diag.conf")


def stage_systemd(project_root: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        copy_systemd_units(project_root, staging / "systemd")
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# source verification
# ---------------------------------------------------------------------------


def _scan_targets(project_root: Path) -> list[Path]:
    targets: list[Path] = []
    for directory in (
        project_root / "src",
        project_root / "packages",
        project_root / "deploy",
    ):
        if directory.is_dir():
            for path in directory.rglob("*"):
                if not path.is_file():
                    continue
                if any(part in _SKIPPED_BUILD_DIRS for part in path.parts):
                    continue
                targets.append(path)
    for pattern in ("config/*.yaml", "config/*.yml"):
        targets.extend(project_root.glob(pattern))
    return sorted(set(targets))


def verify_source(project_root: Path) -> list[Path]:
    """Reject fixed-target literals in runtime source and default config."""
    project_root = Path(project_root).resolve()
    scanned = _scan_targets(project_root)
    if not scanned:
        raise ValueError("no source files found to verify")
    for path in scanned:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for literal in FORBIDDEN_RUNTIME_LITERALS:
            if literal in text:
                raise ValueError(
                    f"fixed target literal {literal!r} in {path.relative_to(project_root)}"
                )
        if FORBIDDEN_IP.search(text):
            raise ValueError(
                "fixed target literal: IP in "
                f"{path.relative_to(project_root)}"
            )
        if FORBIDDEN_SSH_DESTINATION.search(text):
            raise ValueError(
                "fixed target literal: hardcoded SSH destination in "
                f"{path.relative_to(project_root)}"
            )
    return scanned


# ---------------------------------------------------------------------------
# wheel verification
# ---------------------------------------------------------------------------


def _wheel_metadata(wheel: Path) -> object:
    try:
        with zipfile.ZipFile(wheel) as archive:
            if archive.testzip() is not None:
                raise ValueError("damaged ZIP member")
            metadata_paths = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_paths) != 1:
                raise ValueError("expected exactly one METADATA")
            return BytesParser().parsebytes(archive.read(metadata_paths[0]))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("unreadable ZIP archive") from exc


def _wheels_are_clean(wheel: Path) -> None:
    """Reject wheels carrying test files, keys, or fixed target literals."""
    forbidden = FORBIDDEN_RUNTIME_LITERALS
    try:
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                lowered = name.lower()
                if any(segment in lowered for segment in _FORBIDDEN_WHEEL_NAME_SEGMENTS):
                    raise ValueError(f"forbidden wheel member: {name}")
                if lowered.endswith((".py", ".json", ".yaml", ".yml", ".toml", ".md")):
                    try:
                        text = archive.read(name).decode("utf-8")
                    except (KeyError, UnicodeDecodeError):
                        continue
                    for literal in forbidden:
                        if literal in text:
                            raise ValueError(
                                f"forbidden literal {literal!r} in wheel member {name}"
                            )
                    if FORBIDDEN_IP.search(text):
                        raise ValueError(
                            f"fixed target IP in wheel member {name}"
                        )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"invalid project wheel: unreadable {wheel.name}") from exc


def verify_project_wheels(project_wheels: Sequence[Path]) -> None:
    if len(project_wheels) != 2:
        raise ValueError("missing project wheel: exactly two wheels are required")
    by_name = {wheel.name: wheel for wheel in project_wheels}
    missing = [name for name in (CORE_WHEEL, BUILTIN_WHEEL) if name not in by_name]
    if missing:
        raise ValueError(
            "missing project wheel: " + ", ".join(sorted(missing))
        )

    for wheel_name, expected_name, expected_distribution in (
        (CORE_WHEEL, "a4diag", "a4diag"),
        (BUILTIN_WHEEL, "a4diag-builtin-plugins", "a4diag_builtin_plugins"),
    ):
        wheel = by_name[wheel_name]
        _wheels_are_clean(wheel)
        metadata = _wheel_metadata(wheel)
        python_clauses = {
            clause.strip() for clause in (metadata["Requires-Python"] or "").split(",")
        }
        if (
            metadata["Name"] != expected_name
            or metadata["Version"] != RELEASE_VERSION
            or python_clauses != {">=3.11", "<3.12"}
        ):
            raise ValueError(
                f"invalid project wheel {wheel_name}: METADATA contract mismatch"
            )


def verify_target_project_wheels(project_wheels: Sequence[Path]) -> None:
    if len(project_wheels) != 3:
        raise ValueError("missing target project wheel: exactly three wheels are required")
    verify_project_wheels(project_wheels[:2])
    wheel = project_wheels[2]
    if wheel.name != TARGET_WHEEL:
        raise ValueError(f"missing target project wheel: {TARGET_WHEEL}")
    _wheels_are_clean(wheel)
    metadata = _wheel_metadata(wheel)
    python_clauses = {
        clause.strip() for clause in (metadata["Requires-Python"] or "").split(",")
    }
    if (
        metadata["Name"] != "a4diag-target-runtime"
        or metadata["Version"] != RELEASE_VERSION
        or python_clauses != {">=3.11", "<3.12"}
    ):
        raise ValueError(f"invalid project wheel {TARGET_WHEEL}: METADATA contract mismatch")


def verified_dependency_wheels(wheelhouse: Path) -> list[Path]:
    manifest = wheelhouse / "SHA256SUMS"
    if not manifest.is_file():
        raise ValueError("dependency wheelhouse is missing SHA256SUMS")
    files = sorted(path for path in wheelhouse.iterdir() if path.is_file())
    unexpected = [
        path.name
        for path in files
        if path.name != "SHA256SUMS" and path.suffix != ".whl"
    ]
    if unexpected:
        raise ValueError(f"unexpected dependency wheelhouse entries: {unexpected}")

    declared: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid dependency manifest line: {line!r}")
        digest, name = parts
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or Path(name).name != name
            or not name.endswith(".whl")
            or name in declared
        ):
            raise ValueError(f"invalid dependency manifest line: {line!r}")
        declared[name] = digest

    wheels = [path for path in files if path.suffix == ".whl"]
    if not wheels:
        raise ValueError("dependency wheelhouse contains no wheels")
    if set(declared) != {path.name for path in wheels}:
        raise ValueError("dependency manifest does not exactly cover wheelhouse")
    for wheel in wheels:
        actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if actual != declared[wheel.name]:
            raise ValueError(f"SHA256 mismatch for dependency wheel: {wheel.name}")
    return wheels


# ---------------------------------------------------------------------------
# release assembly
# ---------------------------------------------------------------------------


def _canonical_manifest(artifacts: Sequence[Path], release_root: Path) -> dict[str, object]:
    entries = {}
    for artifact in artifacts:
        relative = artifact.relative_to(release_root).as_posix()
        entries[relative] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    return {
        "version": RELEASE_VERSION,
        "artifacts": {key: entries[key] for key in sorted(entries)},
    }


def write_manifest(release_root: Path) -> None:
    def artifacts() -> list[Path]:
        return sorted(
            (
                path
                for path in release_root.rglob("*")
                if path.is_file()
                and path.name not in {"SHA256SUMS", "MANIFEST.sig"}
            ),
            key=lambda path: path.relative_to(release_root).as_posix(),
        )

    # MANIFEST.json first so the SHA256 manifest can also bind it.
    manifest = _canonical_manifest(artifacts(), release_root)
    manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    (release_root / "MANIFEST.json").write_bytes(manifest_json + b"\n")

    lines = []
    for artifact in artifacts():
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        relative_path = artifact.relative_to(release_root).as_posix()
        lines.append(f"{digest}  {relative_path}")
    (release_root / "SHA256SUMS").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
    )


def copy_builtin_catalog(project_root: Path, builtin_wheel: Path, release_root: Path) -> None:
    """Stage the exact built-in manifests and their shared wheel with digests."""
    source_root = project_root / "packages" / "a4diag-builtin-plugins" / "manifests"
    sources = sorted(source_root.glob("*.json"))
    parsed: list[tuple[Path, dict[str, object]]] = []
    for source in sources:
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid built-in manifest: {source.name}") from error
        if type(payload) is not dict:
            raise ValueError(f"invalid built-in manifest: {source.name}")
        parsed.append((source, payload))
    if {str(payload.get("name")) for _, payload in parsed} != EXPECTED_BUILTINS:
        raise ValueError("built-in manifest inventory mismatch")
    if len(parsed) != len(EXPECTED_BUILTINS):
        raise ValueError("duplicate or extra built-in manifest")

    catalog_root = release_root / "builtin-plugins"
    manifest_root = catalog_root / "manifests"
    artifact_root = catalog_root / "artifacts"
    manifest_root.mkdir(parents=True)
    artifact_root.mkdir()
    installed_wheel = artifact_root / BUILTIN_WHEEL
    shutil.copy2(builtin_wheel, installed_wheel)
    wheel_digest = hashlib.sha256(installed_wheel.read_bytes()).hexdigest()
    entries: list[dict[str, object]] = []
    for source, payload in parsed:
        name = str(payload.get("name"))
        if payload.get("version") != RELEASE_VERSION:
            raise ValueError(f"built-in manifest version mismatch: {name}")
        plugin_type = payload.get("plugin_type")
        if plugin_type not in {"transport", "capability", "model", "notification"}:
            raise ValueError(f"built-in manifest type mismatch: {name}")
        destination = manifest_root / source.name
        shutil.copy2(source, destination)
        entries.append(
            {
                "name": name,
                "plugin_type": plugin_type,
                "version": RELEASE_VERSION,
                "api_version": "1.0",
                "manifest_path": f"manifests/{source.name}",
                "manifest_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                "artifact_path": f"artifacts/{BUILTIN_WHEEL}",
                "artifact_sha256": wheel_digest,
            }
        )
    index = {"release_version": RELEASE_VERSION, "plugins": entries}
    (catalog_root / "builtin-index.json").write_text(
        json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def verify_builtin_catalog(release_root: Path) -> None:
    root = release_root / "builtin-plugins"
    index_path = root / "builtin-index.json"
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        entries = index["plugins"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("invalid built-in index") from error
    if index.get("release_version") != RELEASE_VERSION or type(entries) is not list:
        raise ValueError("built-in index version mismatch")
    if {entry.get("name") for entry in entries if type(entry) is dict} != EXPECTED_BUILTINS:
        raise ValueError("built-in index inventory mismatch")
    if len(entries) != len(EXPECTED_BUILTINS):
        raise ValueError("duplicate built-in index entry")
    declared_manifests: set[str] = set()
    declared_artifacts: set[str] = set()
    for entry in entries:
        if type(entry) is not dict:
            raise ValueError("invalid built-in index entry")
        if entry.get("version") != RELEASE_VERSION or entry.get("api_version") != "1.0":
            raise ValueError("built-in index entry version mismatch")
        for path_key, digest_key, declared in (
            ("manifest_path", "manifest_sha256", declared_manifests),
            ("artifact_path", "artifact_sha256", declared_artifacts),
        ):
            relative = entry.get(path_key)
            digest = entry.get(digest_key)
            if (
                type(relative) is not str
                or "\\" in relative
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
                or type(digest) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise ValueError("unsafe built-in index entry")
            path = root / relative
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"built-in catalog digest mismatch: {relative}")
            declared.add(relative)
        manifest_path = root / entry["manifest_path"]
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid built-in manifest") from error
        if (
            manifest.get("name") != entry.get("name")
            or manifest.get("version") != entry.get("version")
            or manifest.get("plugin_type") != entry.get("plugin_type")
        ):
            raise ValueError("built-in manifest binding mismatch")
    actual_manifests = {
        path.relative_to(root).as_posix() for path in (root / "manifests").glob("*") if path.is_file()
    }
    actual_artifacts = {
        path.relative_to(root).as_posix() for path in (root / "artifacts").glob("*") if path.is_file()
    }
    if declared_manifests != actual_manifests or declared_artifacts != actual_artifacts:
        raise ValueError("built-in catalog file inventory mismatch")
    if declared_artifacts != {f"artifacts/{BUILTIN_WHEEL}"}:
        raise ValueError("built-in artifact inventory mismatch")


def _run_openssl(arguments: Sequence[str], *, failure: str) -> None:
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ValueError("openssl executable is required for release signing") from exc
    if completed.returncode != 0:
        raise ValueError(failure)


def sign_manifest(release_root: Path, signing_key: Path) -> None:
    """Create an RSA/SHA-256 signature over canonical ``MANIFEST.json``."""
    signing_key = Path(signing_key).resolve()
    if not signing_key.is_file():
        raise ValueError(f"signing key is missing: {signing_key}")
    _run_openssl(
        (
            "dgst",
            "-sha256",
            "-sign",
            str(signing_key),
            "-out",
            str(release_root / "MANIFEST.sig"),
            str(release_root / "MANIFEST.json"),
        ),
        failure="release manifest signing failed",
    )


def assemble_release(
    project_root: Path,
    dependency_wheelhouse: Path,
    project_wheels: Sequence[Path],
    output: Path,
    *,
    signing_key: Path | None = None,
) -> None:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    verify_project_wheels(project_wheels)

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        wheelhouse = staging / "wheelhouse"
        wheelhouse.mkdir()
        dependency_wheels = verified_dependency_wheels(dependency_wheelhouse)
        for wheel in dependency_wheels:
            shutil.copy2(wheel, wheelhouse / wheel.name)
        for wheel in project_wheels:
            shutil.copy2(wheel, wheelhouse / wheel.name)

        builtin_wheel = next(wheel for wheel in project_wheels if wheel.name == BUILTIN_WHEEL)
        copy_builtin_catalog(project_root, builtin_wheel, staging)

        (staging / "VERSION").write_text(RELEASE_VERSION + "\n", encoding="utf-8")
        shutil.copy2(project_root / "requirements.lock", staging / "requirements.lock")
        shutil.copy2(
            project_root / "requirements-build.lock", staging / "requirements-build.lock"
        )
        shutil.copy2(project_root / "install.sh", staging / "install.sh")
        tools_dir = staging / "tools"
        tools_dir.mkdir()
        shutil.copy2(project_root / "tools" / "install_lib.sh", tools_dir / "install_lib.sh")
        config_dir = staging / "config"
        config_dir.mkdir()
        shutil.copy2(
            project_root / "config" / "config.example.yaml",
            config_dir / "config.example.yaml",
        )
        copy_systemd_units(project_root, staging / "systemd")
        write_manifest(staging)
        if signing_key is not None:
            sign_manifest(staging, signing_key)
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def copy_target_systemd(project_root: Path, output: Path) -> None:
    output.mkdir()
    for unit in sorted(EXPECTED_TARGET_SYSTEMD_UNITS):
        shutil.copy2(project_root / "deploy" / unit, output / unit)
    for subdir in ("sysusers.d", "tmpfiles.d"):
        destination = output / subdir
        destination.mkdir()
        shutil.copy2(
            project_root / "deploy" / subdir / "a4diag-target.conf",
            destination / "a4diag-target.conf",
        )


def assemble_target_release(
    project_root: Path,
    dependency_wheelhouse: Path,
    project_wheels: Sequence[Path],
    output: Path,
    *,
    signing_key: Path | None = None,
) -> None:
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    verify_source(project_root)
    verify_target_project_wheels(project_wheels)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        wheelhouse = staging / "wheelhouse"
        wheelhouse.mkdir()
        for wheel in verified_dependency_wheels(dependency_wheelhouse):
            shutil.copy2(wheel, wheelhouse / wheel.name)
        for wheel in project_wheels:
            shutil.copy2(wheel, wheelhouse / wheel.name)
        (staging / "VERSION").write_text(RELEASE_VERSION + "\n", encoding="utf-8")
        shutil.copy2(
            project_root / "install-a4diag-target.sh",
            staging / "install-a4diag-target.sh",
        )
        tools_dir = staging / "tools"
        tools_dir.mkdir()
        shutil.copy2(
            project_root / "tools" / "install_target_lib.sh",
            tools_dir / "install_target_lib.sh",
        )
        copy_target_systemd(project_root, staging / "systemd")
        write_manifest(staging)
        if signing_key is not None:
            sign_manifest(staging, signing_key)
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# release verification
# ---------------------------------------------------------------------------


def _read_hash_manifest(release_root: Path) -> dict[str, str]:
    manifest_path = release_root / "SHA256SUMS"
    if not manifest_path.is_file():
        raise ValueError("release is missing SHA256SUMS")
    declared: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid release manifest line: {line!r}")
        digest, name = parts
        relative = Path(name)
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative.is_absolute()
            or ".." in relative.parts
            or name in declared
        ):
            raise ValueError(f"invalid release manifest line: {line!r}")
        declared[name] = digest
    return declared


def verify_release(
    release_root: Path, *, verification_key: Path | None = None
) -> None:
    release_root = Path(release_root).resolve()
    declared = _read_hash_manifest(release_root)

    actual_paths = {
        path.relative_to(release_root).as_posix()
        for path in release_root.rglob("*")
        if path.is_file()
        and path.name not in {"SHA256SUMS", "MANIFEST.sig"}
    }
    if set(declared) != actual_paths:
        undeclared = sorted(actual_paths - set(declared))
        missing = sorted(set(declared) - actual_paths)
        raise ValueError(
            f"undeclared files={undeclared}; missing files={missing}"
        )
    for relative, digest in declared.items():
        actual = hashlib.sha256((release_root / relative).read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"SHA256 mismatch for release artifact: {relative}")

    manifest_path = release_root / "MANIFEST.json"
    if not manifest_path.is_file():
        raise ValueError("release is missing MANIFEST.json")
    manifest = json.loads(manifest_path.read_bytes())
    if manifest.get("version") != RELEASE_VERSION:
        raise ValueError("release manifest version mismatch")
    if set(manifest.get("artifacts", {})) != (set(declared) - {"MANIFEST.json"}):
        raise ValueError("release manifest does not exactly cover artifacts")
    for relative, digest in manifest["artifacts"].items():
        if declared.get(relative) != digest:
            raise ValueError(f"release manifest digest mismatch: {relative}")

    if (release_root / "VERSION").read_text(encoding="utf-8").strip() != RELEASE_VERSION:
        raise ValueError("release VERSION lock mismatch")
    verify_builtin_catalog(release_root)

    signature_path = release_root / "MANIFEST.sig"
    if verification_key is not None:
        if not signature_path.is_file():
            raise ValueError("release is missing MANIFEST.sig")
        verification_key = Path(verification_key).resolve()
        if not verification_key.is_file():
            raise ValueError(f"verification key is missing: {verification_key}")
        _run_openssl(
            (
                "dgst",
                "-sha256",
                "-verify",
                str(verification_key),
                "-signature",
                str(signature_path),
                str(manifest_path),
            ),
            failure="release manifest signature mismatch",
        )
    elif signature_path.is_file():
        raise ValueError("release carries a signature but no verification key was provided")

    wheelhouse = release_root / "wheelhouse"
    if not wheelhouse.is_dir():
        raise ValueError("release is missing wheelhouse")
    wheel_names = {path.name for path in wheelhouse.iterdir() if path.is_file()}
    if not {CORE_WHEEL, BUILTIN_WHEEL} <= wheel_names:
        raise ValueError("release wheelhouse is missing a required project wheel")
    for wheel_name in wheel_names:
        if f"wheelhouse/{wheel_name}" not in declared:
            raise ValueError(f"wheelhouse file not in release manifest: {wheel_name}")

    systemd_dir = release_root / "systemd"
    if not systemd_dir.is_dir():
        raise ValueError("release is missing systemd units")
    staged_units = {path.name for path in systemd_dir.iterdir() if path.is_file()}
    if staged_units != EXPECTED_SYSTEMD_UNITS:
        raise ValueError("release systemd inventory mismatch")
    for subdir in ("tmpfiles.d", "sysusers.d"):
        if not (systemd_dir / subdir / "a4diag.conf").is_file():
            raise ValueError(f"release is missing systemd/{subdir}/a4diag.conf")

    if not (release_root / "config" / "config.example.yaml").is_file():
        raise ValueError("release is missing the default configuration example")
    for name in ("requirements.lock", "requirements-build.lock"):
        if not (release_root / name).is_file():
            raise ValueError(f"release is missing {name}")
    if not (release_root / "install.sh").is_file():
        raise ValueError("release is missing install.sh")
    if not (release_root / "tools" / "install_lib.sh").is_file():
        raise ValueError("release is missing tools/install_lib.sh")


def verify_target_release(
    release_root: Path, *, verification_key: Path | None = None
) -> None:
    release_root = Path(release_root).resolve()
    declared = _read_hash_manifest(release_root)
    actual = {
        path.relative_to(release_root).as_posix()
        for path in release_root.rglob("*")
        if path.is_file() and path.name not in {"SHA256SUMS", "MANIFEST.sig"}
    }
    if set(declared) != actual:
        raise ValueError(
            f"undeclared files={sorted(actual - set(declared))}; "
            f"missing files={sorted(set(declared) - actual)}"
        )
    for relative, digest in declared.items():
        if hashlib.sha256((release_root / relative).read_bytes()).hexdigest() != digest:
            raise ValueError(f"SHA256 mismatch for release artifact: {relative}")
    try:
        manifest = json.loads((release_root / "MANIFEST.json").read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("target release is missing a valid MANIFEST.json") from exc
    if manifest.get("version") != RELEASE_VERSION:
        raise ValueError("target release manifest version mismatch")
    if set(manifest.get("artifacts", {})) != set(declared) - {"MANIFEST.json"}:
        raise ValueError("target release manifest does not exactly cover artifacts")
    if any(declared.get(name) != digest for name, digest in manifest["artifacts"].items()):
        raise ValueError("target release manifest digest mismatch")
    if (release_root / "VERSION").read_text(encoding="utf-8").strip() != RELEASE_VERSION:
        raise ValueError("target release VERSION lock mismatch")
    signature = release_root / "MANIFEST.sig"
    if verification_key is not None:
        if not signature.is_file():
            raise ValueError("target release is missing MANIFEST.sig")
        _run_openssl(
            ("dgst", "-sha256", "-verify", str(Path(verification_key).resolve()),
             "-signature", str(signature), str(release_root / "MANIFEST.json")),
            failure="target release manifest signature mismatch",
        )
    elif signature.is_file():
        raise ValueError("target release carries a signature but no verification key was provided")
    wheel_names = {path.name for path in (release_root / "wheelhouse").glob("*.whl")}
    if not {CORE_WHEEL, BUILTIN_WHEEL, TARGET_WHEEL} <= wheel_names:
        raise ValueError("target release wheelhouse is missing a required project wheel")
    systemd = release_root / "systemd"
    if {path.name for path in systemd.iterdir() if path.is_file()} != EXPECTED_TARGET_SYSTEMD_UNITS:
        raise ValueError("target release systemd inventory mismatch")
    for subdir in ("sysusers.d", "tmpfiles.d"):
        if not (systemd / subdir / "a4diag-target.conf").is_file():
            raise ValueError(f"target release is missing systemd/{subdir}/a4diag-target.conf")
    for relative in ("install-a4diag-target.sh", "tools/install_target_lib.sh"):
        if not (release_root / relative).is_file():
            raise ValueError(f"target release is missing {relative}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage_parser = subparsers.add_parser("stage-systemd")
    stage_parser.add_argument("--project-root", type=Path, required=True)
    stage_parser.add_argument("--output", type=Path, required=True)
    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--project-root", type=Path, required=True)
    assemble_parser.add_argument("--dependency-wheelhouse", type=Path, required=True)
    assemble_parser.add_argument("--core-wheel", type=Path, required=True)
    assemble_parser.add_argument("--builtin-wheel", type=Path, required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)
    assemble_parser.add_argument("--signing-key", type=Path)
    assemble_target_parser = subparsers.add_parser("assemble-target")
    assemble_target_parser.add_argument("--project-root", type=Path, required=True)
    assemble_target_parser.add_argument("--dependency-wheelhouse", type=Path, required=True)
    assemble_target_parser.add_argument("--core-wheel", type=Path, required=True)
    assemble_target_parser.add_argument("--builtin-wheel", type=Path, required=True)
    assemble_target_parser.add_argument("--target-wheel", type=Path, required=True)
    assemble_target_parser.add_argument("--output", type=Path, required=True)
    assemble_target_parser.add_argument("--signing-key", type=Path)
    verify_source_parser = subparsers.add_parser("verify-source")
    verify_source_parser.add_argument("--project-root", type=Path, required=True)
    verify_release_parser = subparsers.add_parser("verify-release")
    verify_release_parser.add_argument("--release-root", type=Path, required=True)
    verify_release_parser.add_argument("--verification-key", type=Path)
    verify_target_parser = subparsers.add_parser("verify-target-release")
    verify_target_parser.add_argument("--release-root", type=Path, required=True)
    verify_target_parser.add_argument("--verification-key", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "stage-systemd":
            stage_systemd(args.project_root.resolve(), args.output.resolve())
            return 0
        if args.command == "assemble":
            assemble_release(
                args.project_root.resolve(),
                args.dependency_wheelhouse.resolve(),
                (args.core_wheel.resolve(), args.builtin_wheel.resolve()),
                args.output.resolve(),
                signing_key=args.signing_key.resolve() if args.signing_key else None,
            )
            return 0
        if args.command == "assemble-target":
            assemble_target_release(
                args.project_root.resolve(),
                args.dependency_wheelhouse.resolve(),
                (args.core_wheel.resolve(), args.builtin_wheel.resolve(), args.target_wheel.resolve()),
                args.output.resolve(),
                signing_key=args.signing_key.resolve() if args.signing_key else None,
            )
            return 0
        if args.command == "verify-source":
            verify_source(args.project_root.resolve())
            return 0
        if args.command == "verify-release":
            verify_release(
                args.release_root.resolve(),
                verification_key=(
                    args.verification_key.resolve() if args.verification_key else None
                ),
            )
            return 0
        if args.command == "verify-target-release":
            verify_target_release(
                args.release_root.resolve(),
                verification_key=args.verification_key.resolve() if args.verification_key else None,
            )
            return 0
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

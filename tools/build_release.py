"""A4Diag 0.4.0 release assembly and static verification.

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

RELEASE_VERSION = "0.4.0"
CORE_WHEEL = f"a4diag-{RELEASE_VERSION}-py3-none-any.whl"
BUILTIN_WHEEL = f"a4diag_builtin_plugins-{RELEASE_VERSION}-py3-none-any.whl"

EXPECTED_SYSTEMD_UNITS = frozenset(
    {
        "a4diag-cleanup.service",
        "a4diag-cleanup.timer",
        "a4diag-core.service",
        "a4diag-plugin@.service",
        "a4diag-plugin@.socket",
    }
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
    verify_source_parser = subparsers.add_parser("verify-source")
    verify_source_parser.add_argument("--project-root", type=Path, required=True)
    verify_release_parser = subparsers.add_parser("verify-release")
    verify_release_parser.add_argument("--release-root", type=Path, required=True)
    verify_release_parser.add_argument("--verification-key", type=Path)
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
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

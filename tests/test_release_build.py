from __future__ import annotations

import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile
import json
import os
import re
import hashlib
import shutil
from email.parser import BytesParser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SYSTEMD_UNITS = {
    "a4diag-cleanup.service",
    "a4diag-cleanup.timer",
    "a4diag-core.service",
    "a4diag-plugin@.service",
    "a4diag-plugin@.socket",
}
EXPECTED_RUNTIME_REQUIREMENTS = {
    "httpx",
    "jsonschema",
    "langgraph",
    "langgraph-checkpoint-sqlite",
    "mcp",
    "pydantic",
    "pyyaml",
}
EXPECTED_RUNTIME_PINS = {
    "httpx": "==0.28.1",
    "jsonschema": "==4.26.0",
    "langgraph": "==1.2.11",
    "langgraph-checkpoint-sqlite": "==3.1.1",
    "mcp": "==2.0.0",
    "pydantic": "==2.13.4",
    "pyyaml": "==6.0.3",
}
EXPECTED_BUILD_REQUIREMENTS = {
    "build",
    "colorama",
    "pytest",
    "setuptools",
    "uv",
    "wheel",
}


class ReleaseBuildContractTests(unittest.TestCase):
    @staticmethod
    def write_minimal_wheel(path: Path, distribution: str, version: str) -> None:
        dist_info = f"{distribution}-{version}.dist-info"
        requires_python = "Requires-Python: >=3.11,<3.12\n"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                f"{dist_info}/METADATA",
                (
                    f"Metadata-Version: 2.1\nName: {distribution}\n"
                    f"Version: {version}\n{requires_python}"
                ),
            )
            archive.writestr(
                f"{dist_info}/WHEEL",
                "Wheel-Version: 1.0\nTag: py3-none-any\n",
            )

    def create_assembly_fixture(
        self, root: Path
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        project = root / "project"
        dependency_wheelhouse = root / "dependency-wheelhouse"
        core_wheel = root / "a4diag-0.4.1-py3-none-any.whl"
        builtin_wheel = root / "a4diag_builtin_plugins-0.4.1-py3-none-any.whl"
        output = root / "release-v4-br0-final"
        (project / "deploy").mkdir(parents=True)
        (project / "config").mkdir()
        dependency_wheelhouse.mkdir()

        for unit_name in EXPECTED_SYSTEMD_UNITS:
            (project / "deploy" / unit_name).write_text(
                f"[Unit]\nDescription={unit_name}\n", encoding="utf-8"
            )
        (project / "deploy" / "tmpfiles.d").mkdir()
        (project / "deploy" / "sysusers.d").mkdir()
        (project / "deploy" / "tmpfiles.d" / "a4diag.conf").write_text(
            "d /run/a4diag 0750 a4diag a4diag -\n", encoding="utf-8"
        )
        (project / "deploy" / "sysusers.d" / "a4diag.conf").write_text(
            "u a4diag - \"A4Diag agent\" /var/lib/a4diag /usr/sbin/nologin\ng a4diag - -\n",
            encoding="utf-8",
        )
        (project / "config" / "config.example.yaml").write_text(
            "global_mode: read_only\ntargets: []\nplugins: []\n", encoding="utf-8"
        )
        (project / "requirements.lock").write_text(
            "dependency==1.0 --hash=sha256:" + "1" * 64 + "\n",
            encoding="utf-8",
        )
        (project / "requirements-build.lock").write_text(
            "build==1.0 --hash=sha256:" + "2" * 64 + "\n",
            encoding="utf-8",
        )
        (project / "install.sh").write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n", encoding="utf-8"
        )
        (project / "tools").mkdir()
        (project / "tools" / "install_lib.sh").write_text(
            "#!/usr/bin/env bash\n", encoding="utf-8"
        )
        manifest_source = PROJECT_ROOT / "packages" / "a4diag-builtin-plugins" / "manifests"
        manifest_target = project / "packages" / "a4diag-builtin-plugins" / "manifests"
        manifest_target.mkdir(parents=True)
        for source in manifest_source.glob("*.json"):
            shutil.copy2(source, manifest_target / source.name)
        dependency_wheel = dependency_wheelhouse / "dependency-1.0-py3-none-any.whl"
        self.write_minimal_wheel(dependency_wheel, "dependency", "1.0")
        dependency_digest = hashlib.sha256(dependency_wheel.read_bytes()).hexdigest()
        (dependency_wheelhouse / "SHA256SUMS").write_text(
            f"{dependency_digest}  {dependency_wheel.name}\n", encoding="utf-8"
        )
        self.write_minimal_wheel(core_wheel, "a4diag", "0.4.1")
        self.write_minimal_wheel(builtin_wheel, "a4diag-builtin-plugins", "0.4.1")
        return (
            project,
            dependency_wheelhouse,
            core_wheel,
            builtin_wheel,
            output,
            dependency_wheel,
        )

    def test_assembled_release_is_complete_and_hash_manifested(self) -> None:
        """Catch publishing a bundle that omits or fails to bind an input artifact."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                project,
                dependency_wheelhouse,
                core_wheel,
                builtin_wheel,
                output,
                dependency_wheel,
            ) = self.create_assembly_fixture(root)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "assemble",
                    "--project-root",
                    str(project),
                    "--dependency-wheelhouse",
                    str(dependency_wheelhouse),
                    "--core-wheel",
                    str(core_wheel),
                    "--builtin-wheel",
                    str(builtin_wheel),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, msg=completed.stderr)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "MANIFEST.json",
                    "SHA256SUMS",
                    "VERSION",
                    "builtin-plugins",
                    "config",
                    "install.sh",
                    "requirements-build.lock",
                    "requirements.lock",
                    "systemd",
                    "tools",
                    "wheelhouse",
                },
            )
            self.assertEqual(
                {path.name for path in (output / "wheelhouse").iterdir()},
                {dependency_wheel.name, core_wheel.name, builtin_wheel.name},
            )
            self.assertEqual(
                {path.name for path in (output / "systemd").iterdir() if path.is_file()},
                EXPECTED_SYSTEMD_UNITS,
            )
            self.assertEqual(
                {path.name for path in (output / "systemd").iterdir() if path.is_dir()},
                {"tmpfiles.d", "sysusers.d"},
            )
            self.assertEqual(
                (output / "VERSION").read_text("utf-8").strip(), "0.4.1"
            )
            builtin_index = json.loads(
                (output / "builtin-plugins" / "builtin-index.json").read_text("utf-8")
            )
            self.assertEqual(len(builtin_index["plugins"]), 10)
            self.assertEqual(
                {entry["name"] for entry in builtin_index["plugins"]},
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
                },
            )

            manifest_lines = (output / "SHA256SUMS").read_text("utf-8").splitlines()
            self.assertEqual(manifest_lines, sorted(manifest_lines, key=lambda line: line[66:]))
            manifested_paths = set()
            for line in manifest_lines:
                digest, relative_path = line.split("  ", 1)
                artifact = output / Path(relative_path)
                self.assertTrue(artifact.is_file(), msg=relative_path)
                self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(), digest)
                manifested_paths.add(relative_path)
            actual_paths = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file() and path.name not in {"SHA256SUMS", "MANIFEST.sig"}
            }
            self.assertEqual(manifested_paths, actual_paths)

            manifest = json.loads((output / "MANIFEST.json").read_bytes())
            self.assertEqual(manifest["version"], "0.4.1")
            self.assertEqual(set(manifest["artifacts"]), actual_paths - {"MANIFEST.json"})

    def test_assembly_rejects_a_wheel_that_changed_after_input_manifest(self) -> None:
        """Catch copying a dependency whose bytes no longer match the reviewed manifest."""
        with tempfile.TemporaryDirectory() as temporary:
            (
                project,
                dependency_wheelhouse,
                core_wheel,
                builtin_wheel,
                output,
                dependency_wheel,
            ) = self.create_assembly_fixture(Path(temporary))
            dependency_wheel.write_bytes(dependency_wheel.read_bytes() + b"tampered")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "assemble",
                    "--project-root",
                    str(project),
                    "--dependency-wheelhouse",
                    str(dependency_wheelhouse),
                    "--core-wheel",
                    str(core_wheel),
                    "--builtin-wheel",
                    str(builtin_wheel),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("SHA256 mismatch", completed.stderr)
            self.assertFalse(output.exists())

    def test_assembly_rejects_sdists_and_other_unreviewed_inputs(self) -> None:
        """Catch silently ignoring a source archive placed beside reviewed wheels."""
        with tempfile.TemporaryDirectory() as temporary:
            (
                project,
                dependency_wheelhouse,
                core_wheel,
                builtin_wheel,
                output,
                _,
            ) = self.create_assembly_fixture(Path(temporary))
            (dependency_wheelhouse / "dependency-1.0.tar.gz").write_bytes(b"source")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "assemble",
                    "--project-root",
                    str(project),
                    "--dependency-wheelhouse",
                    str(dependency_wheelhouse),
                    "--core-wheel",
                    str(core_wheel),
                    "--builtin-wheel",
                    str(builtin_wheel),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("unexpected dependency wheelhouse entries", completed.stderr)
            self.assertFalse(output.exists())

    def test_assembly_rejects_a_corrupt_project_wheel(self) -> None:
        """Catch accepting an invalid archive solely because its filename looks correct."""
        with tempfile.TemporaryDirectory() as temporary:
            (
                project,
                dependency_wheelhouse,
                core_wheel,
                builtin_wheel,
                output,
                _,
            ) = self.create_assembly_fixture(Path(temporary))
            core_wheel.write_bytes(b"not a wheel")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "assemble",
                    "--project-root",
                    str(project),
                    "--dependency-wheelhouse",
                    str(dependency_wheelhouse),
                    "--core-wheel",
                    str(core_wheel),
                    "--builtin-wheel",
                    str(builtin_wheel),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("invalid project wheel", completed.stderr)
            self.assertFalse(output.exists())

    def test_assembly_rejects_missing_builtin_wheel(self) -> None:
        """Catch assembling a release with only the core wheel."""
        with tempfile.TemporaryDirectory() as temporary:
            (
                project,
                dependency_wheelhouse,
                core_wheel,
                _builtin_wheel,
                output,
                _,
            ) = self.create_assembly_fixture(Path(temporary))
            missing = Path(temporary) / "missing.whl"
            missing.write_bytes(b"unused")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "assemble",
                    "--project-root",
                    str(project),
                    "--dependency-wheelhouse",
                    str(dependency_wheelhouse),
                    "--core-wheel",
                    str(core_wheel),
                    "--builtin-wheel",
                    str(missing),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("missing project wheel", completed.stderr)
            self.assertFalse(output.exists())

    def test_verify_release_rejects_tampered_artifact_and_signature(self) -> None:
        """Catch silent corruption after assembly."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                project,
                dependency_wheelhouse,
                core_wheel,
                builtin_wheel,
                output,
                _,
            ) = self.create_assembly_fixture(root)
            signing_key = root / "release-private.pem"
            verification_key = root / "release-public.pem"
            generated = subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(signing_key),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generated.returncode, 0, msg=generated.stderr)
            exported = subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(signing_key),
                    "-pubout",
                    "-out",
                    str(verification_key),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(exported.returncode, 0, msg=exported.stderr)

            def run_verify() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        str(PROJECT_ROOT / "tools" / "build_release.py"),
                        "verify-release",
                        "--release-root",
                        str(output),
                        "--verification-key",
                        str(verification_key),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            assembled = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "assemble",
                    "--project-root",
                    str(project),
                    "--dependency-wheelhouse",
                    str(dependency_wheelhouse),
                    "--core-wheel",
                    str(core_wheel),
                    "--builtin-wheel",
                    str(builtin_wheel),
                    "--output",
                    str(output),
                    "--signing-key",
                    str(signing_key),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(assembled.returncode, 0, msg=assembled.stderr)
            verified = run_verify()
            self.assertEqual(verified.returncode, 0, msg=verified.stderr)
            self.assertTrue((output / "MANIFEST.sig").is_file())

            original_signature = (output / "MANIFEST.sig").read_bytes()
            (output / "MANIFEST.sig").write_bytes(b"invalid-signature")
            bad_signature = run_verify()
            self.assertEqual(bad_signature.returncode, 2)
            self.assertIn("signature mismatch", bad_signature.stderr)
            (output / "MANIFEST.sig").write_bytes(original_signature)

            (output / "wheelhouse" / core_wheel.name).write_bytes(b"tampered")
            rejected = run_verify()
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("SHA256 mismatch", rejected.stderr)

    @staticmethod
    def requirement_name(statement: str) -> str:
        match = re.match(r"^([A-Za-z0-9_.-]+)", statement)
        if match is None:
            raise AssertionError(f"invalid requirement: {statement!r}")
        return match.group(1).lower().replace("_", "-").replace(".", "-")

    def direct_requirement_names(self, path: Path) -> set[str]:
        statements = [
            line.strip()
            for line in path.read_text("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        return {self.requirement_name(statement) for statement in statements}

    def assert_complete_hash_lock(self, path: Path) -> set[str]:
        self.assertTrue(path.is_file(), msg=f"missing lock file: {path.name}")
        logical_statements: list[str] = []
        continued: list[str] = []
        for raw_line in path.read_text("utf-8").splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("--") and not continued:
                continue
            is_continued = stripped.endswith("\\")
            continued.append(stripped[:-1].strip() if is_continued else stripped)
            if not is_continued:
                logical_statements.append(" ".join(continued))
                continued = []
        self.assertEqual(continued, [], msg=f"unterminated requirement in {path.name}")
        self.assertGreater(len(logical_statements), 0, msg=f"empty lock file: {path.name}")

        locked_names: set[str] = set()
        for statement in logical_statements:
            with self.subTest(lock=path.name, requirement=statement):
                pin = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", statement)
                self.assertIsNotNone(pin, msg="every resolved dependency must use ==")
                self.assertNotIn("*", pin.group(2))
                hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)", statement)
                self.assertGreater(len(hashes), 0, msg="every resolved dependency needs SHA256")
                locked_names.add(self.requirement_name(statement))
        return locked_names

    def test_runtime_and_build_requirements_are_fully_hash_locked(self) -> None:
        """Catch mutable or incomplete dependency sets in an offline release."""
        contracts = (
            (
                PROJECT_ROOT / "requirements.in",
                PROJECT_ROOT / "requirements.lock",
                EXPECTED_RUNTIME_REQUIREMENTS,
            ),
            (
                PROJECT_ROOT / "requirements-build.in",
                PROJECT_ROOT / "requirements-build.lock",
                EXPECTED_BUILD_REQUIREMENTS,
            ),
        )
        for input_path, lock_path, expected_direct in contracts:
            with self.subTest(input=input_path.name):
                self.assertTrue(input_path.is_file(), msg=f"missing input: {input_path.name}")
                self.assertEqual(self.direct_requirement_names(input_path), expected_direct)
                locked_names = self.assert_complete_hash_lock(lock_path)
                self.assertTrue(expected_direct <= locked_names)

    def test_pytest_rejects_unknown_markers_and_registers_live_t11(self) -> None:
        """Catch a misspelled live marker silently entering the offline suite."""
        configuration = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text("utf-8"))
        tool_configuration = configuration.get("tool", {})
        self.assertIn("pytest", tool_configuration)
        pytest_options = tool_configuration["pytest"]["ini_options"]

        addopts = pytest_options.get("addopts", "").split()
        self.assertIn("--strict-markers", addopts)

        marker_names = {
            declaration.split(":", 1)[0].split("(", 1)[0].strip()
            for declaration in pytest_options.get("markers", [])
        }
        self.assertIn("live_t11", marker_names)

    def build_v3_wheel(self, wheel_dir: Path) -> Path:
        source_copy = wheel_dir / ".source-copy"
        source_copy.mkdir()
        shutil.copy2(PROJECT_ROOT / "pyproject.toml", source_copy / "pyproject.toml")
        shutil.copytree(
            PROJECT_ROOT / "src",
            source_copy / "src",
            ignore=shutil.ignore_patterns("*.egg-info", "__pycache__", "*.pyc"),
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(wheel_dir),
                str(source_copy),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"wheel build failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )

        wheels = sorted(wheel_dir.glob("a4diag-*.whl"))
        self.assertEqual([wheel.name for wheel in wheels], ["a4diag-0.4.1-py3-none-any.whl"])
        return wheels[0]

    def test_built_wheel_declares_v3_and_python311_runtime(self) -> None:
        """Catch publishing a v4 release with the old version or Python range."""
        with tempfile.TemporaryDirectory() as temporary:
            wheel = self.build_v3_wheel(Path(temporary))

            with zipfile.ZipFile(wheel) as archive:
                metadata_paths = [
                    name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
                ]
                self.assertEqual(len(metadata_paths), 1)
                metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))

            self.assertEqual(metadata["Name"], "a4diag")
            self.assertEqual(metadata["Version"], "0.4.1")
            python_clauses = {
                clause.strip() for clause in metadata["Requires-Python"].split(",")
            }
            self.assertEqual(python_clauses, {">=3.11", "<3.12"})

    def test_built_wheel_declares_every_locked_direct_runtime_dependency(self) -> None:
        """Catch a release wheel that imports packages absent from its metadata."""
        with tempfile.TemporaryDirectory() as temporary:
            wheel = self.build_v3_wheel(Path(temporary))
            with zipfile.ZipFile(wheel) as archive:
                metadata_path = next(
                    name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
                )
                metadata = BytesParser().parsebytes(archive.read(metadata_path))

            observed: dict[str, str] = {}
            for declaration in metadata.get_all("Requires-Dist", []):
                match = re.match(r"^([A-Za-z0-9_.-]+)(.*)$", declaration)
                self.assertIsNotNone(match)
                name = self.requirement_name(match.group(1))
                observed[name] = match.group(2).replace(" ", "")
            self.assertEqual(observed, EXPECTED_RUNTIME_PINS)

    def test_staged_release_contains_exact_systemd_inventory(self) -> None:
        """Catch omitting a required unit or shipping an unreviewed extra unit."""
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-v3-br0-final"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "stage-systemd",
                    "--project-root",
                    str(PROJECT_ROOT),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"release staging failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )

            systemd_dir = output / "systemd"
            self.assertTrue(systemd_dir.is_dir())
            staged_units = {path.name for path in systemd_dir.iterdir() if path.is_file()}
            self.assertEqual(staged_units, EXPECTED_SYSTEMD_UNITS)
            self.assertEqual(len(list(systemd_dir.iterdir())), 7)
            self.assertTrue((systemd_dir / "tmpfiles.d" / "a4diag.conf").is_file())
            self.assertTrue((systemd_dir / "sysusers.d" / "a4diag.conf").is_file())

    def test_failed_staging_leaves_no_partial_release(self) -> None:
        """Catch exposing a partially copied release after a staging failure."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_project = root / "project"
            deploy_dir = fake_project / "deploy"
            deploy_dir.mkdir(parents=True)
            missing_unit = "a4diag-plugin@.socket"
            for unit_name in EXPECTED_SYSTEMD_UNITS - {missing_unit}:
                (deploy_dir / unit_name).write_text("[Unit]\n", encoding="utf-8")

            output = root / "release-v3-br0-final"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "tools" / "build_release.py"),
                    "stage-systemd",
                    "--project-root",
                    str(fake_project),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertFalse(output.exists())

    def test_installed_wheel_reports_v3_package_version(self) -> None:
        """Catch a v3 wheel whose importable package still reports an old version."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel_dir = root / "wheel"
            install_dir = root / "installed"
            wheel_dir.mkdir()
            wheel = self.build_v3_wheel(wheel_dir)

            installed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--ignore-requires-python",
                    "--no-deps",
                    "--no-index",
                    "--target",
                    str(install_dir),
                    str(wheel),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                installed.returncode,
                0,
                msg=f"wheel install failed\nstdout:\n{installed.stdout}\nstderr:\n{installed.stderr}",
            )

            child_env = os.environ.copy()
            child_env.pop("PYTHONPATH", None)
            imported = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import a4diag, json; "
                        "print(json.dumps({'version': a4diag.__version__, "
                        "'file': a4diag.__file__}))"
                    ),
                ],
                cwd=install_dir,
                env=child_env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(imported.returncode, 0, msg=imported.stderr)
            observed = json.loads(imported.stdout)
            self.assertTrue(Path(observed["file"]).is_relative_to(install_dir))
            self.assertEqual(observed["version"], "0.4.1")


if __name__ == "__main__":
    unittest.main()

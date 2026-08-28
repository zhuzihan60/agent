"""Installer contract tests: static (all platforms) + POSIX harness.

The POSIX harness exercises ``install.sh`` under bash with a fake root, fake
pip/python/systemctl shims, and injected failures. bash (msys2) cannot start
under the Windows file sandbox (it creates an internal signal pipe at
startup), so those tests skip on Windows with a documented reason and run on
the Linux CI matrix.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "install.sh"
INSTALL_LIB = ROOT / "tools" / "install_lib.sh"
EXPECTED_SYSTEMD_UNITS = {
    "a4diag-cleanup.service",
    "a4diag-cleanup.timer",
    "a4diag-core.service",
    "a4diag-plugin@.service",
    "a4diag-plugin@.socket",
}

FORBIDDEN_TARGET_IP = re.compile(
    r"(?<![0-9])(?:10|192\.168)(?:\.[0-9]{1,3}){3}(?![0-9])"
)


def test_installer_scripts_exist() -> None:
    assert INSTALL_SH.is_file()
    assert INSTALL_LIB.is_file()


def test_installer_is_fail_closed_by_default() -> None:
    install = INSTALL_SH.read_text(encoding="utf-8")
    lib = INSTALL_LIB.read_text(encoding="utf-8")
    assert "set -euo pipefail" in install
    assert "set -euo pipefail" in lib
    assert "a4diag_require_root" in lib
    assert "must run as root" in lib


def test_install_lib_uses_offline_wheelhouse_flags() -> None:
    lib = INSTALL_LIB.read_text(encoding="utf-8")
    assert "--no-index" in lib
    assert "--find-links" in lib
    assert "wheelhouse" in lib


def test_installer_switches_current_atomically() -> None:
    lib = INSTALL_LIB.read_text(encoding="utf-8")
    # The switch must stage a temporary symlink then atomically replace it.
    assert "ln -s" in lib
    assert "mv -T" in lib
    assert "A4DIAG_INJECT_FAILURE" in lib


def test_installer_never_overwrites_existing_config() -> None:
    lib = INSTALL_LIB.read_text(encoding="utf-8")
    assert 'if [ ! -f "$ETC_DIR/config.yaml" ]' in lib
    assert "install -m 0640" in lib
    assert 'chown root:a4diag "$ETC_DIR/config.yaml"' in lib


def test_installer_verifies_release_before_extraction() -> None:
    lib = INSTALL_LIB.read_text(encoding="utf-8")
    assert "sha256sum -c SHA256SUMS" in lib
    assert "MANIFEST.sig" in lib
    assert "a4diag_verify_release" in lib


def test_installer_has_no_fixed_target_literals() -> None:
    combined = (
        INSTALL_SH.read_text(encoding="utf-8")
        + "\n"
        + INSTALL_LIB.read_text(encoding="utf-8")
    )
    assert "t_11" not in combined
    assert FORBIDDEN_TARGET_IP.search(combined) is None
    assert re.search(r"[A-Za-z0-9_.-]+@[0-9]", combined) is None


def test_install_lib_creates_systemd_identities() -> None:
    """The installer must create the a4diag user/group and runtime directories."""
    lib = INSTALL_LIB.read_text(encoding="utf-8")
    assert "systemd-sysusers" in lib
    assert "systemd-tmpfiles" in lib
    assert "sysusers.d" in lib
    assert "tmpfiles.d" in lib


def test_release_assembly_includes_the_installer(tmp_path: Path) -> None:
    """The assembled release must ship install.sh + tools/install_lib.sh."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "build_release_installer_test", ROOT / "tools" / "build_release.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    project = tmp_path / "project"
    (project / "deploy").mkdir(parents=True)
    (project / "config").mkdir()
    (project / "tools").mkdir()
    for unit_name in EXPECTED_SYSTEMD_UNITS:
        (project / "deploy" / unit_name).write_text("[Unit]\n", encoding="utf-8")
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
    (project / "requirements.lock").write_text("x==1.0 --hash=sha256:" + "1" * 64 + "\n")
    (project / "requirements-build.lock").write_text(
        "y==1.0 --hash=sha256:" + "2" * 64 + "\n"
    )
    (project / "install.sh").write_text("#!/usr/bin/env bash\nset -euo pipefail\n")
    (project / "tools" / "install_lib.sh").write_text("#!/usr/bin/env bash\n")

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    dep = wheelhouse / "dependency-1.0-py3-none-any.whl"
    with zipfile.ZipFile(dep, "w") as archive:
        archive.writestr("dependency-1.0.dist-info/METADATA", "Metadata-Version: 2.1\n")
    digest = hashlib.sha256(dep.read_bytes()).hexdigest()
    (wheelhouse / "SHA256SUMS").write_text(f"{digest}  {dep.name}\n", encoding="utf-8")
    core = tmp_path / module.CORE_WHEEL
    builtin = tmp_path / module.BUILTIN_WHEEL
    for wheel, name, dist in ((core, "a4diag", "a4diag"),
                              (builtin, "a4diag_builtin_plugins", "a4diag-builtin-plugins")):
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                f"{dist}-{module.RELEASE_VERSION}.dist-info/METADATA",
                (
                    f"Metadata-Version: 2.1\nName: {dist}\n"
                    f"Version: {module.RELEASE_VERSION}\n"
                    "Requires-Python: >=3.11,<3.12\n"
                ),
            )
            archive.writestr(
                f"{dist}-{module.RELEASE_VERSION}.dist-info/WHEEL",
                "Wheel-Version: 1.0\nTag: py3-none-any\n",
            )

    output = tmp_path / "release"
    module.assemble_release(project, wheelhouse, (core, builtin), output)
    assert (output / "install.sh").is_file()
    assert (output / "tools" / "install_lib.sh").is_file()
    module.verify_release(output)


def test_self_check_reports_read_only_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from a4diag.cli import main as cli_main

    config = tmp_path / "config.yaml"
    config.write_text(
        "global_mode: read_only\ntargets: []\nplugins: []\nauto_execute_low: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("A4DIAG_CONFIG", str(config))
    code, output = 0, ""
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = cli_main(["self-check", "--offline"])
    output = buffer.getvalue()
    assert code == 0
    payload = json.loads(output)
    assert payload["ok"] is True
    assert payload["version"] == "0.4.0"
    assert payload["global_mode"] == "read_only"
    assert payload["targets"] == []
    assert payload["offline"] is True


def _posix_reason() -> str:
    return (
        "requires POSIX bash/sha256sum; msys2 bash cannot start under the "
        "Windows file sandbox, so the shell harness runs on the Linux CI matrix"
    )


POSIX = pytest.mark.skipif(sys.platform == "win32", reason=_posix_reason())


def write_minimal_wheel(path: Path, distribution: str, version: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{distribution}-{version}.dist-info/METADATA",
            (
                f"Metadata-Version: 2.1\nName: {distribution}\n"
                f"Version: {version}\nRequires-Python: >=3.11,<3.12\n"
            ),
        )
        archive.writestr(
            f"{distribution}-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nTag: py3-none-any\n",
        )


@POSIX
class InstallerSandbox:
    """Fake-root harness that runs install.sh under bash with injected shims."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.log = tmp_path / "pip.log"
        self.os_release = tmp_path / "os-release"
        self.os_release.write_text('ID=rocky\nVERSION_ID="9"\n', encoding="utf-8")
        self._write_shims()

    def _write_shims(self) -> None:
        python = self.bin / "python3.11"
        python.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "-" ]; then
  exec "$A4DIAG_TEST_REAL_PYTHON" "$@"
fi
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  cat > "$3/bin/a4diag" <<'A4DIAG_SHIM'
#!/usr/bin/env bash
echo '{"ok": true, "version": "0.4.0", "global_mode": "read_only", "targets": [], "offline": true}'
exit 0
A4DIAG_SHIM
  chmod +x "$3/bin/a4diag"
  cat > "$3/bin/python" <<'PIP_SHIM'
#!/usr/bin/env bash
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
  echo "${*:3}" >> "${A4DIAG_PIP_LOG:-/dev/null}"
fi
exit 0
PIP_SHIM
  chmod +x "$3/bin/python"
  exit 0
fi
exit 0
""",
            encoding="utf-8",
        )
        python.chmod(0o755)
        (self.bin / "systemctl").write_text(
            "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
        )
        (self.bin / "systemctl").chmod(0o755)

    def make_release(
        self,
        root: Path,
        *,
        version: str = "0.4.0",
        signing_key: bytes | None = None,
    ) -> Path:
        release = root / f"release-{version}"
        release.mkdir()
        (release / "VERSION").write_text(version + "\n", encoding="utf-8")
        (release / "requirements.lock").write_text(
            "x==1.0 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8"
        )
        (release / "requirements-build.lock").write_text(
            "y==1.0 --hash=sha256:" + "2" * 64 + "\n", encoding="utf-8"
        )
        wheelhouse = release / "wheelhouse"
        wheelhouse.mkdir()
        write_minimal_wheel(wheelhouse / "dependency-1.0-py3-none-any.whl", "dependency", "1.0")
        write_minimal_wheel(wheelhouse / f"a4diag-{version}-py3-none-any.whl", "a4diag", version)
        write_minimal_wheel(
            wheelhouse / f"a4diag_builtin_plugins-{version}-py3-none-any.whl",
            "a4diag-builtin-plugins",
            version,
        )
        config = release / "config"
        config.mkdir()
        (config / "config.example.yaml").write_text(
            "global_mode: read_only\ntargets: []\nplugins: []\n", encoding="utf-8"
        )
        systemd = release / "systemd"
        systemd.mkdir()
        for unit in EXPECTED_SYSTEMD_UNITS:
            (systemd / unit).write_text("[Unit]\n", encoding="utf-8")
        (release / "install.sh").write_bytes(INSTALL_SH.read_bytes())
        tools = release / "tools"
        tools.mkdir()
        (tools / "install_lib.sh").write_bytes(INSTALL_LIB.read_bytes())
        # MANIFEST.json + SHA256SUMS + optional signature.
        artifacts = sorted(
            path for path in release.rglob("*")
            if path.is_file() and path.name not in {"SHA256SUMS", "MANIFEST.sig"}
        )
        manifest = {
            "version": version,
            "artifacts": {
                path.relative_to(release).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in artifacts
            },
        }
        (release / "MANIFEST.json").write_bytes(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        )
        if signing_key is not None:
            signature = hmac.new(
                signing_key, (release / "MANIFEST.json").read_bytes(), hashlib.sha256
            ).hexdigest()
            (release / "MANIFEST.sig").write_text(signature + "\n", encoding="utf-8")
        lines = []
        for path in sorted(
            (p for p in release.rglob("*") if p.is_file() and p.name not in {"SHA256SUMS", "MANIFEST.sig"}),
            key=lambda p: p.relative_to(release).as_posix(),
        ):
            lines.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(release).as_posix()}"
            )
        (release / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return release

    def env(self, *, version: str = "0.4.0") -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "A4DIAG_ROOT": str(self.root) + os.sep,
                "A4DIAG_OS_RELEASE": str(self.os_release),
                "A4DIAG_SKIP_ROOT": "1",
                "A4DIAG_SKIP_SYSTEMD": "1",
                "A4DIAG_SKIP_DISK": "1",
                "A4DIAG_EXPECTED_VERSION": version,
                "A4DIAG_ALLOW_UNSIGNED": "1",
                "A4DIAG_PIP_LOG": str(self.log),
                "A4DIAG_TEST_REAL_PYTHON": sys.executable,
                "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            }
        )
        return environment

    def install(
        self,
        release_dir: Path,
        *,
        version: str = "0.4.0",
        inject_failure: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = self.env(version=version)
        if inject_failure is not None:
            environment["A4DIAG_INJECT_FAILURE"] = inject_failure
        return subprocess.run(
            ["bash", str(INSTALL_SH), "--offline", str(release_dir)],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    @property
    def current(self) -> Path:
        return self.root / "opt" / "a4diag" / "current"

    @property
    def pip_argv(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""


@POSIX
def test_offline_install_invokes_pip_without_index(tmp_path: Path) -> None:
    sandbox = InstallerSandbox(tmp_path)
    release = sandbox.make_release(tmp_path)
    result = sandbox.install(release)
    assert result.returncode == 0, result.stderr
    assert "--no-index" in sandbox.pip_argv
    assert "--find-links" in sandbox.pip_argv
    assert "a4diag-0.4.0-py3-none-any.whl" in sandbox.pip_argv


@POSIX
def test_failed_upgrade_keeps_current_symlink(tmp_path: Path) -> None:
    sandbox = InstallerSandbox(tmp_path)
    release_v1 = sandbox.make_release(tmp_path, version="0.4.0")
    release_v2 = sandbox.make_release(tmp_path, version="0.4.1")

    first = sandbox.install(release_v1, version="0.4.0")
    assert first.returncode == 0, first.stderr
    before = sandbox.current.resolve()

    failed = sandbox.install(
        release_v2, version="0.4.1", inject_failure="before_switch"
    )
    assert failed.returncode != 0
    assert sandbox.current.resolve() == before


@POSIX
def test_signature_mismatch_rejects_release(tmp_path: Path) -> None:
    sandbox = InstallerSandbox(tmp_path)
    key = b"k" * 32
    release = sandbox.make_release(tmp_path, signing_key=key)
    (release / "MANIFEST.sig").write_text("0" * 64 + "\n", encoding="utf-8")
    environment = sandbox.env()
    environment["A4DIAG_ALLOW_UNSIGNED"] = "0"
    key_file = tmp_path / "release.key"
    key_file.write_bytes(key)
    environment["A4DIAG_TRUSTED_KEY"] = str(key_file)

    result = subprocess.run(
        ["bash", str(INSTALL_SH), "--offline", str(release)],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "signature mismatch" in result.stderr
    assert not sandbox.current.exists()

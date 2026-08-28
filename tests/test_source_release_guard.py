"""RED contract tests for multi-wheel release assembly and source verification.

The release must require exactly the core and builtin-plugin wheels for
version 0.4.1, verify every artifact hash, and reject fixed-target literals in
the runtime source and default configuration.
"""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILD_RELEASE = ROOT / "tools" / "build_release.py"


def load_build_release():
    spec = importlib.util.spec_from_file_location("build_release_under_test", BUILD_RELEASE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_minimal_wheel(path: Path, distribution: str, version: str) -> None:
    dist_info = f"{distribution}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            (
                f"Metadata-Version: 2.1\nName: {distribution}\n"
                f"Version: {version}\nRequires-Python: >=3.11,<3.12\n"
            ),
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nTag: py3-none-any\n",
        )


def test_release_requires_exact_core_and_plugin_wheels(tmp_path: Path) -> None:
    module = load_build_release()
    project = tmp_path / "project"
    (project / "deploy").mkdir(parents=True)
    (project / "config").mkdir()
    for unit_name in module.EXPECTED_SYSTEMD_UNITS:
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
    (project / "requirements-build.lock").write_text("y==1.0 --hash=sha256:" + "2" * 64 + "\n")
    (project / "install.sh").write_text("#!/usr/bin/env bash\nset -euo pipefail\n")
    (project / "tools").mkdir()
    (project / "tools" / "install_lib.sh").write_text("#!/usr/bin/env bash\n")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    dep = wheelhouse / "dependency-1.0-py3-none-any.whl"
    write_minimal_wheel(dep, "dependency", "1.0")
    import hashlib

    digest = hashlib.sha256(dep.read_bytes()).hexdigest()
    (wheelhouse / "SHA256SUMS").write_text(f"{digest}  {dep.name}\n", encoding="utf-8")
    core = tmp_path / "a4diag-0.4.1-py3-none-any.whl"
    write_minimal_wheel(core, "a4diag", "0.4.1")

    # Only the core wheel provided: the builtin-plugin wheel is missing.
    with pytest.raises(ValueError, match="missing project wheel"):
        module.assemble_release(
            project,
            wheelhouse,
            (core,),
            tmp_path / "out",
        )


def test_verify_source_rejects_fixed_target_literal(tmp_path: Path) -> None:
    module = load_build_release()
    (tmp_path / "src" / "a4diag").mkdir(parents=True)
    (tmp_path / "src" / "a4diag" / "bad.py").write_text(
        'TARGET="192.0.2.141"\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="fixed target literal"):
        module.verify_source(tmp_path)


def test_verify_source_rejects_hardcoded_ssh_user(tmp_path: Path) -> None:
    module = load_build_release()
    (tmp_path / "src" / "a4diag").mkdir(parents=True)
    (tmp_path / "src" / "a4diag" / "bad.py").write_text(
        'SSH = "a4diag-ro@10.0.0.5"\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="fixed target literal"):
        module.verify_source(tmp_path)


def test_verify_release_rejects_undeclared_file(tmp_path: Path) -> None:
    module = load_build_release()
    release = tmp_path / "release"
    release.mkdir()
    (release / "SHA256SUMS").write_text("", encoding="utf-8")
    (release / "stray.bin").write_bytes(b"undeclared")
    with pytest.raises(ValueError, match="undeclared"):
        module.verify_release(release)

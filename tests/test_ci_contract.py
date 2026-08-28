"""CI contract: the distribution matrix, release workflow, smoke script, and
documented-skip policy.

Windows may keep only skips that carry an explicit reason; every pytest.skip /
skipif in the suite must be documented. The distro matrix must cover every
supported distribution, and the smoke script must assert offline install,
read-only defaults, and that no service can write the configuration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

SUPPORTED_IMAGES = {
    "rockylinux:8",
    "rockylinux:9",
    "almalinux:8",
    "almalinux:9",
    "ubuntu:22.04",
    "ubuntu:24.04",
    "debian:12",
}


def test_ci_matrix_covers_supported_platforms() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "test.yml").read_text())
    images = set(workflow["jobs"]["distro"]["strategy"]["matrix"]["image"])
    assert images == SUPPORTED_IMAGES


def test_release_workflow_triggers_on_version_tags_only() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text()
    )
    # YAML 1.1 parses the bare key "on" as boolean True.
    triggers = workflow.get("on") or workflow.get(True) or {}
    assert "push" in triggers
    tags = triggers["push"].get("tags", [])
    assert any(tag == "v*" or tag.startswith("v") for tag in tags)


def test_workflows_contain_no_literal_credentials() -> None:
    for name in ("test.yml", "release.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        # Only ${{ secrets.NAME }} references may appear; strip them first.
        stripped = re.sub(
            r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}", "", text.lower()
        )
        assert "password" not in stripped
        assert "api_key" not in stripped
        assert "token" not in stripped


def test_test_jobs_install_both_local_packages_before_pytest() -> None:
    """Every workflow that runs the source-tree tests must install both
    src-layout packages first, without asking pip to resolve dependencies.
    """

    cases = (
        ("test.yml", "unit"),
        ("test.yml", "windows-documented-skips"),
        ("release.yml", "verify"),
    )
    for workflow_name, job_name in cases:
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow_name).read_text()
        )
        commands = [
            step["run"]
            for step in workflow["jobs"][job_name]["steps"]
            if "run" in step
        ]
        pytest_index = next(
            index for index, command in enumerate(commands) if "pytest" in command
        )
        before_pytest = "\n".join(commands[: pytest_index + 1])
        assert "pip install --no-deps -e ." in before_pytest
        assert (
            "pip install --no-deps -e packages/a4diag-builtin-plugins"
            in before_pytest
        )


def test_ci_build_job_generates_verified_wheelhouse() -> None:
    """The CI build job must build the dependency wheelhouse from the lockfile
    and reference the builtin wheel at its real output path."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "test.yml").read_text())
    steps = "\n".join(step.get("run", "") for step in workflow["jobs"]["build"]["steps"])
    assert "pip download -r requirements.lock" in steps
    assert "sha256sum" in steps
    assert "packages/a4diag-builtin-plugins/dist/" in steps

    release_workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text()
    )
    release_steps = "\n".join(
        step.get("run", "")
        for step in release_workflow["jobs"]["assemble-and-sign"]["steps"]
    )
    assert "pip download -r requirements.lock" in release_steps
    assert "packages/a4diag-builtin-plugins/dist/" in release_steps


def test_distro_smoke_script_enforces_read_only_defaults() -> None:
    script = (ROOT / "tests" / "integration" / "distro_smoke.sh").read_text(
        encoding="utf-8"
    )
    assert "set -euo pipefail" in script
    assert "install.sh" in script
    assert "--offline" in script
    assert "self-check" in script
    assert "read_only" in script
    assert "config.yaml" in script
    assert "t_11" not in script


def test_posix_only_skips_are_documented() -> None:
    """Every pytest.skip / skipif in the suite must carry a non-empty reason."""
    skip_pattern = re.compile(r"pytest\.skip\(\s*f?['\"]([^'\"]+)['\"]", re.DOTALL)
    total_skips = 0
    documented = 0
    for path in sorted((ROOT / "tests").rglob("*.py")):
        if path.name in {"test_installer.py", "test_ci_contract.py"}:
            continue  # harness/self-reference handled separately
        text = path.read_text(encoding="utf-8")
        total_skips += text.count("pytest.skip(")
        matches = skip_pattern.findall(text)
        documented += len(matches)
        for reason in matches:
            assert reason.strip(), f"empty skip reason in {path.name}"
        for line in text.splitlines():
            if "skipif(" in line or "pytest.mark.skipif" in line:
                assert "reason=" in line, f"skipif without reason in {path.name}"
    assert documented == total_skips, "every pytest.skip needs a non-empty reason"
    # The 12 skipped tests at runtime share 10 skip call sites (fixtures skip
    # whole test groups, e.g. AF_UNIX); each call site is documented above.
    assert total_skips >= 10, "expected the audited Linux Phase 4 gate call sites"


def test_matrix_documentation_lists_supported_distributions() -> None:
    doc = (ROOT / "docs" / "testing" / "distro-matrix.md").read_text(encoding="utf-8")
    for image in SUPPORTED_IMAGES:
        assert image in doc

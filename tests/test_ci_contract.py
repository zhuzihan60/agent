"""CI contract: the distribution matrix, release workflow, smoke script, and
documented-skip policy.

Every pytest.skip / skipif in the suite must be documented. The distro matrix
must cover every supported Linux distribution, and the smoke script must
assert offline install, read-only defaults, and that no service can write the
configuration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

ALIBABA_LINUX_CI_IMAGE = (
    "langfarm/alinux3@"
    "sha256:c5c67ed6e33dc967e9a05ec3cec680abaf24bc2ea0fb23ee0d1470750882c6b1"
)

SUPPORTED_IMAGES = {
    ALIBABA_LINUX_CI_IMAGE,
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


def test_distro_jobs_provision_portable_python_311_before_offline_install() -> None:
    for workflow_name, job_name in (
        ("test.yml", "distro"),
        ("release.yml", "distro-smoke"),
    ):
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow_name).read_text()
        )
        steps = workflow["jobs"][job_name]["steps"]
        setup_uv_index = next(
            index
            for index, step in enumerate(steps)
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
        )
        install_python_index = next(
            index
            for index, step in enumerate(steps)
            if "uv python install 3.11" in step.get("run", "")
        )
        smoke_index = next(
            index
            for index, step in enumerate(steps)
            if "distro_smoke.sh" in step.get("run", "")
        )
        assert steps[setup_uv_index]["uses"] == (
            "astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d"
        )
        assert steps[setup_uv_index]["with"]["version"] == "0.12.6"
        assert setup_uv_index < install_python_index < smoke_index


def test_alibaba_linux_ci_image_is_digest_pinned_without_network_bootstrap() -> None:
    for workflow_name, job_name in (
        ("test.yml", "distro"),
        ("release.yml", "distro-smoke"),
    ):
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / workflow_name).read_text()
        )
        job = workflow["jobs"][job_name]
        images = job["strategy"]["matrix"]["image"]
        assert ALIBABA_LINUX_CI_IMAGE in images
        assert "@sha256:" in ALIBABA_LINUX_CI_IMAGE
        assert all(
            step.get("name") != "Bootstrap Alibaba Cloud Linux actions prerequisites"
            for step in job["steps"]
        )


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


def test_production_ci_and_runtime_lock_are_linux_only() -> None:
    requirements = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    assert "pywin32" not in requirements.lower()

    workflow_text = (ROOT / ".github" / "workflows" / "test.yml").read_text(
        encoding="utf-8"
    )
    workflow = yaml.safe_load(workflow_text)
    assert "windows-latest" not in workflow_text.lower()
    assert all("windows" not in name.lower() for name in workflow["jobs"])


def test_distro_smoke_preserves_unsigned_test_and_signed_release_boundaries() -> None:
    test_workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "test.yml").read_text()
    )
    test_smoke = next(
        step
        for step in test_workflow["jobs"]["distro"]["steps"]
        if "distro_smoke.sh" in step.get("run", "")
    )
    assert test_smoke.get("env", {}).get("A4DIAG_ALLOW_UNSIGNED") == "1"

    release_workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text()
    )
    release_job = release_workflow["jobs"]["distro-smoke"]
    assert release_job.get("environment") == "release"
    release_steps = release_job["steps"]
    key_step = next(
        step
        for step in release_steps
        if step.get("name") == "Write the verification key from repository secret material"
    )
    assert "secrets.A4DIAG_RELEASE_PRIVATE_KEY" in key_step.get("run", "")
    release_smoke = next(
        step for step in release_steps if "distro_smoke.sh" in step.get("run", "")
    )
    assert release_smoke.get("env", {}).get("A4DIAG_TRUSTED_KEY") == (
        "/tmp/a4diag-release.key"
    )
    assert "A4DIAG_ALLOW_UNSIGNED" not in release_smoke.get("env", {})


def test_release_workflow_publishes_one_click_assets_after_linux_gates() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text()
    )
    publish = workflow["jobs"]["publish"]
    assert set(publish["needs"]) >= {"verify", "assemble-and-sign", "distro-smoke"}
    commands = "\n".join(
        step.get("run", "") for step in publish["steps"] if "run" in step
    )
    assert "a4diag.tar.gz" in commands
    assert "a4diag.tar.gz.sig" in commands
    assert "install-a4diag.sh" in commands
    release_step = next(
        step for step in publish["steps"] if step.get("name") == "Create GitHub release"
    )
    files = release_step["with"]["files"]
    assert "a4diag.tar.gz" in files
    assert "a4diag.tar.gz.sig" in files
    assert "install-a4diag.sh" in files


def test_release_workflow_runs_the_public_bootstrap_in_linux() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text()
    )
    commands = "\n".join(
        step.get("run", "")
        for step in workflow["jobs"]["distro-smoke"]["steps"]
        if "run" in step
    )
    assert "install-a4diag.sh" in commands
    assert "A4DIAG_RELEASE_URL" in commands
    assert "A4DIAG_RELEASE_SIGNATURE_URL" in commands


def test_ci_build_job_generates_verified_wheelhouse() -> None:
    """The CI build job must build the dependency wheelhouse from the lockfile
    and reference the builtin wheel at its real output path."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "test.yml").read_text())
    steps = "\n".join(step.get("run", "") for step in workflow["jobs"]["build"]["steps"])
    assert "pip download -r requirements.lock" in steps
    assert "sha256sum" in steps
    assert "packages/a4diag-builtin-plugins/dist/" in steps
    for flag in (
        "--only-binary=:all:",
        "--platform manylinux_2_28_x86_64",
        "--platform manylinux2014_x86_64",
        "--python-version 3.11",
        "--implementation cp",
        "--abi cp311",
    ):
        assert flag in steps

    release_workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text()
    )
    release_steps = "\n".join(
        step.get("run", "")
        for step in release_workflow["jobs"]["assemble-and-sign"]["steps"]
    )
    assert "pip download -r requirements.lock" in release_steps
    assert "packages/a4diag-builtin-plugins/dist/" in release_steps
    for flag in (
        "--only-binary=:all:",
        "--platform manylinux_2_28_x86_64",
        "--platform manylinux2014_x86_64",
        "--python-version 3.11",
        "--implementation cp",
        "--abi cp311",
    ):
        assert flag in release_steps


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
    assert "^[[:space:]]*ReadWritePaths=" in script
    assert "grep -q 'ReadWritePaths'" not in script


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

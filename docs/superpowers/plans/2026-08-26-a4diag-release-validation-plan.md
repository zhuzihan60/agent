# A4Diag Release and Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce hardened, atomic, verifiable online/offline releases and prove the Agent's boundaries and recovery behavior across supported Linux/systemd targets.

**Architecture:** Extend the current assembler to consume separately built core/plugin wheels and the verified Python 3.11 dependency wheelhouse, then install into versioned release directories with an atomic `current` symlink. Use templated systemd plugin instances, static release inspection, container/VM distro tests, and privileged local/SSH chaos tests before publication.

**Tech Stack:** Python build/setuptools, POSIX shell, systemd, SHA256/minisign-compatible signatures, pytest, GitHub Actions, Linux VMs/containers.

**Spec:** `docs/superpowers/specs/2026-08-26-a4diag-generic-plugin-agent-design.md`

## Global Constraints

- Apply all master-plan constraints; this phase starts only after Phases 1-3 pass.
- No final release is published merely because assembly succeeds; distro and security acceptance jobs must also pass.
- Installer never overwrites `/etc/a4diag/config.yaml`, secrets, plugin pins, approvals, transactions, audit, or reports.
- Failed install/upgrade leaves the previous `current` release and running services intact.
- Test-only targets use disposable environments; no command targets any existing infrastructure or unregistered real host.

---

### Task 1: Generic Hardened systemd Units

**Files:**
- Create: `deploy/a4diag-core.service`
- Create: `deploy/a4diag-plugin@.service`
- Create: `deploy/a4diag-plugin@.socket`
- Create: `deploy/tmpfiles.d/a4diag.conf`
- Create: `deploy/sysusers.d/a4diag.conf`
- Remove after migration: `deploy/a4diag-controller.service`
- Remove after migration: `deploy/a4diag-executor.service`
- Remove after migration: `deploy/a4diag-executor.socket`
- Modify: `tests/test_release_build.py`
- Create: `tests/test_systemd_units_v3.py`

**Interfaces:**
- Consumes: final core/plugin entrypoints.
- Produces: core service plus one isolated service/socket instance per enabled plugin.

- [ ] **Step 1: Write failing exact-inventory and sandbox tests**

```python
def test_core_cannot_write_configuration(parsed_units) -> None:
    unit = parsed_units["a4diag-core.service"]["Service"]
    assert unit["ProtectSystem"] == "strict"
    assert "/etc/a4diag" not in unit.get("ReadWritePaths", "")
    assert "NoNewPrivileges=yes" in render(unit)

def test_plugin_template_uses_instance_specific_user_and_socket(parsed_units) -> None:
    service = parsed_units["a4diag-plugin@.service"]["Service"]
    assert service["User"] == "a4diag-plugin-%i"
    assert "%i.sock" in parsed_units["a4diag-plugin@.socket"]["Socket"]["ListenStream"]
```

- [ ] **Step 2: Run tests and verify failure on old inventory**

Run: `python -m pytest tests/test_systemd_units_v3.py tests/test_release_build.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement units with least-privilege defaults**

Core gets only state/checkpoint/report/audit paths and plugin sockets. Plugin template uses instance config under `/etc/a4diag/plugins/%i.yaml`, dynamic or sysusers-created identity, private tmp, strict filesystem, restricted address families/capabilities, explicit writable paths, memory/task/time limits, and no configuration write. Capability-specific drop-ins add only their declared helper/socket access.

- [ ] **Step 4: Validate units and commit**

Run on Linux CI: `systemd-analyze verify deploy/a4diag-core.service deploy/a4diag-plugin@.service deploy/a4diag-plugin@.socket`

Expected: exit 0 with no unit errors.

Run: `python -m pytest tests/test_systemd_units_v3.py tests/test_release_build.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add deploy tests/test_systemd_units_v3.py tests/test_release_build.py
git commit -m "feat: harden generic core and plugin services"
```

### Task 2: Multi-Wheel Release Assembly and Static Verification

**Files:**
- Modify: `pyproject.toml`
- Modify: `tools/build_release.py`
- Modify: `tests/test_release_build.py`
- Create: `tests/test_source_release_guard.py`

**Interfaces:**
- Consumes: core wheel, built-in plugin wheel, verified dependency wheelhouse, locks/config/schemas/systemd/install scripts.
- Produces: `assemble`, `verify-source`, and `verify-release` commands for version `0.4.0`.

- [ ] **Step 1: Write failing exact-wheel and forbidden-literal tests**

```python
def test_release_requires_exact_core_and_plugin_wheels(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing project wheel"):
        assemble_release(project_root, dependencies, (core_wheel,), tmp_path / "out")

def test_verify_source_rejects_fixed_target_runtime(tmp_path: Path) -> None:
    (tmp_path / "src/a4diag").mkdir(parents=True)
    (tmp_path / "src/a4diag/bad.py").write_text('TARGET="192.0.2.141"', encoding="utf-8")
    with pytest.raises(ValueError, match="fixed target literal"):
        verify_source(tmp_path)
```

- [ ] **Step 2: Run tests and observe contract failures**

Run: `python -m pytest tests/test_release_build.py tests/test_source_release_guard.py -q`

Expected: FAIL.

- [ ] **Step 3: Extend assembler and verifier**

Require exactly `a4diag-0.4.0-py3-none-any.whl` and `a4diag_builtin_plugins-0.4.0-py3-none-any.whl`; verify wheel ZIP/METADATA, dependency lock coverage, package data manifests, exact systemd inventory, config schemas, installer, licenses, and top-level SHA256 coverage. Reject sdist, extra wheel, duplicate normalized project name, missing compatible tag, malformed manifest, and fixed target/IP/email/integration-key literals in runtime/default config.

- [ ] **Step 4: Preserve atomic staging and test interruption cleanup**

Inject failures after each staging phase; assert final output is absent, staging directory is removed, and source inputs are unchanged. `verify-release` rereads every hash and ensures no undeclared file.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_release_build.py tests/test_source_release_guard.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add pyproject.toml tools/build_release.py tests/test_release_build.py tests/test_source_release_guard.py
git commit -m "build: assemble verified core and plugin release"
```

### Task 3: Atomic Online and Offline Installer

**Files:**
- Create: `install.sh`
- Create: `tools/install_lib.sh`
- Create: `tests/integration/test_installer.py`
- Create: `docs/install.md`

**Interfaces:**
- Consumes: verified release tree or Git checkout/build artifacts.
- Produces: `./install.sh --online` and `./install.sh --offline RELEASE_DIR` with atomic version switch.

- [ ] **Step 1: Write failing shell-harness tests**

```python
def test_failed_upgrade_keeps_current_symlink(installer_sandbox: InstallerSandbox) -> None:
    installer_sandbox.install(release="0.4.0")
    before = installer_sandbox.current.resolve()
    result = installer_sandbox.install(release="0.4.1", inject_failure="before_switch")
    assert result.returncode != 0
    assert installer_sandbox.current.resolve() == before

def test_offline_install_invokes_pip_without_index(installer_sandbox: InstallerSandbox) -> None:
    installer_sandbox.install_offline()
    assert "--no-index" in installer_sandbox.pip_argv
    assert "--find-links" in installer_sandbox.pip_argv
```

- [ ] **Step 2: Run failing installer tests**

Run: `python -m pytest tests/integration/test_installer.py -q`

Expected: FAIL because installer is absent.

- [ ] **Step 3: Implement platform/preflight and atomic release switch**

Use `set -euo pipefail`; require root; parse `/etc/os-release`; require supported distro/version, systemd, Python 3.11, enough disk, and required OS commands. Verify signature/SHA before extraction, build `/opt/a4diag/releases/0.4.0`, create venv, install locked wheels, run `a4diag self-check --offline`, then atomically replace `/opt/a4diag/current`. Create config only if absent and keep it read-only/empty.

- [ ] **Step 4: Implement rollback on service-start failure**

Record the previous symlink, daemon-reload, start/health-check the new core and enabled plugin instances, and restore/restart the previous version if any step fails. Do not delete failed or previous release until an explicit cleanup command.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/integration/test_installer.py -q && python -m pytest -q`

Expected: PASS.

Run on Linux: `shellcheck install.sh tools/install_lib.sh`

Expected: zero findings at configured severity.

```bash
git add install.sh tools/install_lib.sh tests/integration/test_installer.py docs/install.md
git commit -m "feat: add atomic online and offline installer"
```

### Task 4: Supported-Distribution CI Matrix

**Files:**
- Create: `.github/workflows/test.yml`
- Create: `.github/workflows/release.yml`
- Create: `tests/test_ci_contract.py`
- Create: `tests/integration/distro_smoke.sh`
- Create: `docs/testing/distro-matrix.md`

**Interfaces:**
- Consumes: installer and assembled release.
- Produces: unit, build, distro-install, and signed-release gates.

- [ ] **Step 1: Write the failing CI workflow validation test**

```python
def test_ci_matrix_covers_supported_platforms() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/test.yml").read_text())
    images = set(workflow["jobs"]["distro"]["strategy"]["matrix"]["image"])
    assert images == {
        "rockylinux:8", "rockylinux:9", "almalinux:8", "almalinux:9",
        "ubuntu:22.04", "ubuntu:24.04", "debian:12",
    }
```

RHEL uses a separately configured licensed runner and records equivalent major-version evidence; do not publish credentials in workflow YAML.

- [ ] **Step 2: Run test and verify workflow is missing**

Run: `python -m pytest tests/test_ci_contract.py -q`

Expected: FAIL before creating workflows; create `tests/test_ci_contract.py` with the test above as part of this step.

- [ ] **Step 3: Implement test and release workflows**

Test workflow runs unit/contract suites, builds both wheels, verifies release, runs distro smoke containers, and uploads reports. Release workflow triggers only on signed `v*` tags, rebuilds from locks, verifies artifact hashes, signs the top-level manifest using repository secret material, and publishes only after all required jobs succeed.

- [ ] **Step 4: Add distro smoke assertions**

Smoke script performs offline install, confirms default no-target/read-only status, validates systemd units (where container systemd is available), runs model capability failure fallback, and ensures no service can write `/etc/a4diag/config.yaml`.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_ci_contract.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add .github/workflows tests/test_ci_contract.py tests/integration/distro_smoke.sh docs/testing/distro-matrix.md
git commit -m "ci: gate supported Linux distributions"
```

### Task 5: Local/SSH Safety and Chaos Acceptance Suite

**Files:**
- Create: `tests/acceptance/test_local_remediation.py`
- Create: `tests/acceptance/test_ssh_remediation.py`
- Create: `tests/acceptance/test_plugin_chaos.py`
- Create: `tests/acceptance/test_high_risk_gate.py`
- Create: `tests/acceptance/conftest.py`
- Create: `docs/testing/acceptance-runbook.md`

**Interfaces:**
- Consumes: installed release in disposable local/SSH test environments.
- Produces: executable evidence for autonomous LOW, approved HIGH, identity isolation, crash recovery, and rollback.

- [ ] **Step 1: Build disposable target fixtures with explicit opt-in**

Tests skip unless `A4DIAG_ACCEPTANCE=1` and fixture-created target IDs/host keys are present. The harness creates a random target name, temporary SSH key, isolated root prefix or disposable VM, and a canary outside every allowlist; cleanup removes only resources recorded in the fixture ledger.

- [ ] **Step 2: Add LOW and boundary tests**

```python
def test_low_service_fault_is_repaired_and_verified(lab: Lab) -> None:
    lab.break_managed_service()
    result = lab.run_agent()
    assert result.status == "succeeded"
    assert lab.service_is_healthy()
    assert lab.outside_canary_unchanged()

def test_outside_target_is_never_contacted(lab: Lab) -> None:
    result = lab.inject_model_plan(target_id="unregistered")
    assert result.status == "policy_denied"
    assert lab.network_log.connections_to_unregistered == 0
```

- [ ] **Step 3: Add HIGH approval tests**

Assert HIGH without approval has zero executor dispatch; wrong/expired digest remains blocked; correct local CLI approval dispatches once; changed target identity after approval invalidates it; high-risk plugin operation always remains HIGH even when both model responses say LOW.

- [ ] **Step 4: Add crash and rollback tests**

Kill the capability process before dispatch, immediately after marker creation, during apply, and during verify. Restart core/plugin and assert reconcile outcome, `apply_count == 1` for possibly dispatched steps, reverse undo order, truthful `rollback_partial/unknown`, and unchanged outside-allowlist canary.

- [ ] **Step 5: Run privileged acceptance suite and commit**

Run: `sudo A4DIAG_ACCEPTANCE=1 python -m pytest tests/acceptance -q`

Expected: PASS; test report contains generated target IDs and transaction IDs but no secrets.

```bash
git add tests/acceptance docs/testing/acceptance-runbook.md
git commit -m "test: prove isolated remediation and crash recovery"
```

### Task 6: Final Release Candidate and Evidence Bundle

**Files:**
- Create: `docs/release/v0.4.0-checklist.md`
- Create: `docs/release/v0.4.0-known-limitations.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: all prior phase outputs and CI evidence.
- Produces: reviewable release candidate; publishing remains a separate authorized action.

- [ ] **Step 1: Run complete local verification from a clean worktree**

```bash
python -m pytest -q
python -m build --wheel
python -m build --wheel packages/a4diag-builtin-plugins
python tools/build_release.py verify-source --project-root .
python tools/build_release.py assemble --project-root . --dependency-wheelhouse C:/Users/149721/Desktop/ai/.a4diag-v3-wheelhouse --dist-dir dist --output C:/Users/149721/Desktop/ai/.a4diag-v3-final
python tools/build_release.py verify-release --release-root C:/Users/149721/Desktop/ai/.a4diag-v3-final
```

Expected: all tests pass, both exact wheels build, source scan is clean, assembly succeeds atomically, and release manifest coverage is exact.

- [ ] **Step 2: Record external matrix evidence**

The release checklist records immutable CI run IDs for all supported distro jobs, RHEL-equivalent runner, local/SSH acceptance, plugin chaos, HIGH gate, installer rollback, offline install, source scan, and release hash verification. A missing required job leaves the checklist unchecked and blocks publication.

- [ ] **Step 3: Document known limitations without weakening guarantees**

Document no Docker/Kubernetes/non-systemd support, no automatic VM rebuild, administrator trust of installed execution plugins, inability to recover an unreachable/destroyed target remotely, and the requirement for CLI approval of all HIGH operations.

- [ ] **Step 4: Update README install and safety contract**

Show `git clone`, `sudo ./install.sh`, `sudo a4diag init`, safe default behavior, local/SSH examples using documentation-only addresses, plugin pinning, LOW/HIGH behavior, approval commands, notification options, offline verification, and explicit removal/uninstall steps.

- [ ] **Step 5: Run documentation/source checks and commit**

Run: `python tools/build_release.py verify-source --project-root . && python -m pytest -q`

Expected: PASS.

```bash
git add README.md docs/release/v0.4.0-checklist.md docs/release/v0.4.0-known-limitations.md
git commit -m "docs: prepare v0.4.0 release candidate"
```

Do not push, create a GitHub release, deploy to a server, or enable a real target as part of this task. Those actions require explicit user authorization after the evidence bundle is reviewed.

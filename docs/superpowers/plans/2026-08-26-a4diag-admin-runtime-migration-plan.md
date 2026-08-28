# A4Diag Administration and Runtime Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the generic core and bundled plugins through safe administrator commands, digest-bound approval, generic event processing, redacted reporting, and production CLI entrypoints, then retire fixed-target behavior.

**Architecture:** Build deterministic command services behind argparse, with interactive prompts as a thin adapter so the same validation works in CI and automation. Migrate runtime composition only after init, plugin administration, approval, secrets, audit, and event integration pass isolated tests.

**Tech Stack:** Python 3.11, argparse, Pydantic, SQLite, LangGraph, JSON, YAML, getpass, Unix file permissions.

**Spec:** `docs/superpowers/specs/2026-08-26-a4diag-generic-plugin-agent-design.md`

## Global Constraints

- Apply master-plan constraints; require Phase 1 and Phase 2 gates before each commit.
- Administration commands require effective UID 0 or an injected authorizer proving equivalent administrative authority.
- Interactive prompts never relax validators used by non-interactive mode.
- The model/executor service identities cannot write `/etc/a4diag`, plugin pins, target registry, approval actor records, or secret storage.
- This phase does not connect to a real server.

---

### Task 1: Secret References, Recursive Redaction, and Append-Only Audit

**Files:**
- Create: `src/a4diag/secrets.py`
- Create: `src/a4diag/redaction.py`
- Create: `src/a4diag/audit.py`
- Create: `tests/test_secrets_redaction_audit.py`

**Interfaces:**
- Consumes: plugin/target secret reference strings.
- Produces: `SecretResolver.resolve(ref)`, `redact(value, known_secrets)`, and `AuditWriter.append(event)`.

- [ ] **Step 1: Write failing permission, redaction, and hash-chain tests**

```python
def test_secret_file_with_group_or_other_bits_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "model.key"
    path.write_text("secret", encoding="utf-8")
    path.chmod(0o640)
    with pytest.raises(SecretError, match="mode 0600"):
        SecretResolver(tmp_path).resolve("file:model.key")

def test_nested_secret_is_redacted() -> None:
    value = {"headers": {"Authorization": "Bearer abc"}, "text": "token abc"}
    assert "abc" not in json.dumps(redact(value, {"abc"}))

def test_audit_chain_detects_edit(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path / "audit.jsonl")
    writer.append({"event": "prepared"})
    tamper_first_line(tmp_path / "audit.jsonl")
    assert writer.verify().valid is False
```

- [ ] **Step 2: Run failing tests**

Run: `python -m pytest tests/test_secrets_redaction_audit.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement file/env secret references and redaction**

Allow `file:relative-name` beneath `/etc/a4diag/secrets` and an injected test root; allow `env:NAME` only for model-provider compatibility and emit a deprecation audit field. Reject absolute/path-traversal refs, symlinks, non-regular files, owner mismatch, or permissions other than 0600. Redact known secret values plus keys matching password/token/key/authorization/credential patterns.

- [ ] **Step 4: Implement append-only chained JSONL**

Each canonical line contains `sequence`, `timestamp`, `event`, `payload`, `previous_hash`, and `record_hash`. Open with append semantics and mode 0600, fsync each final transaction event, and verify sequence/hash continuity at startup; a broken chain forces read-only mode.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_secrets_redaction_audit.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/secrets.py src/a4diag/redaction.py src/a4diag/audit.py tests/test_secrets_redaction_audit.py
git commit -m "feat: protect secrets and append-only audit"
```

### Task 2: Deterministic Initialization and Generic Target Registration

**Files:**
- Create: `src/a4diag/init_config.py`
- Create: `tests/test_init_config.py`
- Create: `config/schemas/config-v3.json`
- Modify: `src/a4diag/cli.py`

**Interfaces:**
- Consumes: settings validators, plugin registry, secret resolver, transport identity probe.
- Produces: `InitRequest`, `InitService.validate`, `InitService.write_atomic`, and CLI `a4diag init --input request.json` plus interactive `a4diag init`.

- [ ] **Step 1: Write failing no-target/local/SSH initialization tests**

```python
def test_init_without_target_writes_read_only_config(service: InitService, tmp_path: Path) -> None:
    result = service.write_atomic(InitRequest(model=None, targets=()), tmp_path / "config.yaml")
    assert result.settings.targets == ()
    assert result.settings.global_mode == "read_only"

def test_ssh_identity_probe_failure_keeps_write_disabled(service: InitService) -> None:
    request = ssh_request(write_enabled=True)
    service.transport.probe_error = IdentityError("host_key_mismatch")
    with pytest.raises(InitError, match="host_key_mismatch"):
        service.validate(request)
```

- [ ] **Step 2: Run failing tests**

Run: `python -m pytest tests/test_init_config.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement exact request and atomic-write behavior**

```python
class InitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: ModelInit | None
    targets: tuple[TargetInit, ...] = ()
    notifications: tuple[NotificationInit, ...] = ()

class InitService:
    def validate(self, request: InitRequest) -> InitResult: ...
    def write_atomic(self, request: InitRequest, destination: Path) -> InitResult: ...
```

Probe model structured output and target identity before writing. Create a 0600 temporary file in the destination directory, fsync, atomic replace, then read/validate the resulting file. A failed probe or write leaves the previous config byte-for-byte unchanged.

- [ ] **Step 4: Add CLI parsing and final permission summary**

Non-interactive mode reads strict JSON from `--input`. Interactive mode asks model, local/SSH target, identity, capability resources, LOW auto flag, optional notification channels, and notification barrier, then prints canonical effective permissions and requires the literal confirmation `ENABLE` before `write_enabled: true`.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_init_config.py tests/test_cli.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/init_config.py src/a4diag/cli.py tests/test_init_config.py config/schemas/config-v3.json
git commit -m "feat: add safe generic initialization"
```

### Task 3: Administrator Plugin Lifecycle Commands

**Files:**
- Create: `src/a4diag/plugin_admin.py`
- Create: `tests/test_plugin_admin.py`
- Modify: `src/a4diag/cli.py`

**Interfaces:**
- Consumes: manifest verifier and registry pins.
- Produces: `a4diag plugin list`, `verify PACKAGE`, `install PACKAGE`, and `disable NAME`.

- [ ] **Step 1: Write failing authorization/atomic-install tests**

```python
def test_non_admin_cannot_install(admin: PluginAdmin) -> None:
    admin.authorizer.is_admin = False
    with pytest.raises(AdminRequired):
        admin.install(valid_plugin_package())

def test_bad_digest_never_changes_registry(admin: PluginAdmin) -> None:
    before = admin.registry_path.read_bytes()
    with pytest.raises(PluginRegistryError):
        admin.install(tampered_plugin_package())
    assert admin.registry_path.read_bytes() == before
```

- [ ] **Step 2: Run failing tests**

Run: `python -m pytest tests/test_plugin_admin.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement verify/install/disable transactions**

Verification checks archive path safety, manifest schema, signature/SHA, API range, wheel metadata, declared executable/socket, and config migration preflight. Install stages beneath `/opt/a4diag/plugins/.staging`, verifies again, atomically renames to a versioned directory, then atomically updates registry pins. Disable changes only the pin and stops the matching systemd instance through an injected service manager.

- [ ] **Step 4: Add CLI JSON output and tests**

All commands support `--json`; errors go to stderr with exit codes 64 invalid input, 65 verification failure, 69 unavailable dependency, and 77 permission denied. Ensure command output never includes secret values.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_plugin_admin.py tests/test_cli.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/plugin_admin.py src/a4diag/cli.py tests/test_plugin_admin.py
git commit -m "feat: add pinned plugin administration"
```

### Task 4: Local CLI Approval and Notification Barrier

**Files:**
- Create: `src/a4diag/approval_cli.py`
- Create: `tests/test_approval_cli.py`
- Modify: `src/a4diag/cli.py`

**Interfaces:**
- Consumes: `ApprovalStore`, transaction/plan store, notification clients, redaction.
- Produces: `a4diag approvals list`, `show TRANSACTION`, `approve TRANSACTION --digest DIGEST`, and `reject TRANSACTION --reason TEXT`.

- [ ] **Step 1: Write failing full-display/digest/barrier tests**

```python
def test_approve_requires_exact_displayed_digest(cli: CliRunner) -> None:
    tx = cli.seed_pending(high_plan())
    result = cli.run(["approvals", "approve", tx.id, "--digest", "0" * 64])
    assert result.exit_code == 65
    assert cli.approvals.valid_digest(tx.id, now=cli.now) is None

def test_required_notification_failure_blocks_approval(cli: CliRunner) -> None:
    tx = cli.seed_pending(high_plan(), notification_required=True, delivered=False)
    result = cli.run(["approvals", "approve", tx.id, "--digest", tx.digest])
    assert result.exit_code == 69
    assert cli.executor.apply_count == 0
```

- [ ] **Step 2: Run failing tests**

Run: `python -m pytest tests/test_approval_cli.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement non-bypassable approval presentation**

`show` and `approve` render target identity, every typed operation, equivalent fixed command display, core/model/critic risk, affected resource, verify, undo/unreversible warning, digest, expiry, notification receipts, and current identity probe. Approval records effective UID, username, terminal ID, timestamp, and exact digest; stdin/non-TTY approval is rejected unless `--non-interactive-approval-file` is a root-owned 0600 signed request.

- [ ] **Step 4: Implement notification barrier semantics**

When `notification_required: false`, failed optional sends are audited and approval remains possible. When true, every configured required channel needs a valid receipt bound to the plan digest before approval; resend creates a new attempt without changing the plan digest.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/test_approval_cli.py tests/test_core_security_acceptance.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/approval_cli.py src/a4diag/cli.py tests/test_approval_cli.py
git commit -m "feat: add digest-bound CLI approval"
```

### Task 5: Production Runtime Composition and Generic Event Processing

**Files:**
- Create: `src/a4diag/runtime.py`
- Create: `tests/integration/test_runtime_generic.py`
- Modify: `src/a4diag/cli.py`
- Modify: `src/a4diag/alertmanager.py`
- Modify: `src/a4diag/poller.py`
- Modify: `src/a4diag/report.py`

**Interfaces:**
- Consumes: Phase 1 graph, Phase 2 plugin client, Phase 3 admin/security components.
- Produces: `build_runtime(settings_path) -> Runtime`, CLI `controller`, `run-once`, `recover`, and generic alert-to-target resolution.

- [ ] **Step 1: Write failing no-target/model-failure/LOW/HIGH runtime tests**

```python
def test_empty_install_reports_read_only_without_plugin_calls(runtime_factory) -> None:
    runtime = runtime_factory(empty_settings())
    result = runtime.handle(event(target_hint="unknown"))
    assert result.status == "policy_denied"
    assert runtime.plugins.call_count == 0

def test_model_failure_produces_read_only_report(runtime_factory) -> None:
    runtime = runtime_factory(configured_target(), model_error=TimeoutError())
    result = runtime.handle(event(target_hint="lab"))
    assert result.status == "read_only_no_model"
    assert runtime.executor.apply_count == 0
```

- [ ] **Step 2: Run failing integration tests**

Run: `python -m pytest tests/integration/test_runtime_generic.py -q`

Expected: FAIL.

- [ ] **Step 3: Assemble runtime dependencies and migrate events**

Load safe settings, verify audit chain and plugin pins, create socket clients, verify configured target identities, build the LangGraph graph/checkpointer, and recover incomplete transactions before consuming events. Alertmanager labels may select only an existing target ID; IP matching and fallback-to-first-target are removed.

- [ ] **Step 4: Produce complete redacted reports**

Reports include event/transaction IDs, target fingerprint, evidence provenance, diagnosis confidence, typed plan, equivalent command display, risk sources, policy decision, approval/notification status, every apply/verify/undo result, terminal state, residual risk, and manual investigation commands. Secrets and raw credentials are absent.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/integration/test_runtime_generic.py tests/test_alertmanager_store.py tests/test_cli.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/runtime.py src/a4diag/cli.py src/a4diag/alertmanager.py src/a4diag/poller.py src/a4diag/report.py tests/integration/test_runtime_generic.py
git commit -m "feat: migrate runtime to generic plugin workflow"
```

### Task 6: Remove Fixed-Target Runtime and Add Migration Guard

**Files:**
- Modify: `src/a4diag/config.py`
- Modify: `src/a4diag/policy.py`
- Modify: `src/a4diag/orchestrator.py`
- Modify: `src/a4diag/ssh_collector.py`
- Modify: `src/a4diag/tool_router.py`
- Modify: `src/a4diag/mcp_server.py`
- Modify: `tests/test_config_policy.py`
- Modify: `tests/test_collectors_router.py`
- Create: `tests/test_no_fixed_target_runtime.py`
- Create: `docs/migration/v0.3-to-v0.4.md`

**Interfaces:**
- Consumes: v3 runtime from Task 5.
- Produces: one generic runtime with no fixed-target compatibility path.

- [ ] **Step 1: Write the failing source/default-config literal guard before deletion**

```python
FORBIDDEN_RUNTIME_LITERALS = ("t_11", "targets must contain exactly", "fixed-target executor")
FORBIDDEN_FIXED_IP = re.compile(r'(?<![0-9])(?:10|192\.168)(?:\.[0-9]{1,3}){3}(?![0-9])')

def test_runtime_and_default_config_have_no_fixed_target_literals() -> None:
    files = list(Path("src/a4diag").rglob("*.py")) + [Path("config/config.example.yaml")]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
    for literal in FORBIDDEN_RUNTIME_LITERALS:
        assert literal not in combined
    assert FORBIDDEN_FIXED_IP.search(combined) is None
```

- [ ] **Step 2: Run the guard and confirm it fails on legacy code**

Run: `python -m pytest tests/test_no_fixed_target_runtime.py -q`

Expected: FAIL and identify legacy fixed-target literals.

- [ ] **Step 3: Remove or convert legacy fixed-target modules**

Make `config.py` re-export v3 settings only where compatibility is needed; make read-only MCP tools route through registered capability plugins; remove IP target authorization and hardcoded SSH username/units. Delete obsolete functions only after all imports are migrated. Preserve report-reading compatibility for old reports but never import old permissions into new settings automatically.

- [ ] **Step 4: Document explicit migration**

The migration guide instructs administrators to back up v0.3, run `a4diag init`, register each target, verify host key/machine-id, select new allowlists, run read-only acceptance, then explicitly enable writes. State that old frozen target settings are not trusted or auto-converted.

- [ ] **Step 5: Run phase gate and commit**

Run: `python -m pytest tests/test_no_fixed_target_runtime.py tests/integration/test_runtime_generic.py tests/test_core_security_acceptance.py tests/contract -q`

Expected: PASS.

Run: `python -m pytest -q`

Expected: zero failures/errors.

```bash
git add src/a4diag tests config/config.example.yaml docs/migration/v0.3-to-v0.4.md
git commit -m "refactor: remove fixed-target runtime behavior"
```

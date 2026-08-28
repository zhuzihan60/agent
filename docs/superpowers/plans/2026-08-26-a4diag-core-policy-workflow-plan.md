# A4Diag Core Policy and Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the generic, plugin-independent security core that parses safe target configuration, validates plugins, freezes plans, enforces risk/approval, records transactions, and drives recovery through LangGraph.

**Architecture:** Add v3 modules beside the legacy read-only runtime so every task remains independently testable. Use immutable Pydantic domain models, canonical JSON digests, HMAC operation tickets, SQLite transaction state, and dependency-injected fake plugins; do not migrate production CLI entrypoints in this phase.

**Tech Stack:** Python 3.11, Pydantic 2.13.4, LangGraph 1.2.11, langgraph-checkpoint-sqlite 3.1.1, SQLite, PyYAML, hashlib/hmac.

**Spec:** `docs/superpowers/specs/2026-08-26-a4diag-generic-plugin-agent-design.md`

## Global Constraints

- Apply every constraint in `docs/superpowers/plans/2026-08-26-a4diag-plugin-agent-master-plan.md`.
- This phase performs no subprocess, SSH, network, package, file, service, SMTP, or webhook writes.
- New modules may coexist with legacy `config.py`, `policy.py`, `orchestrator.py`, and `store.py`; deleting legacy code belongs to Phase 3.
- All external effects are represented by injected Protocol implementations in tests.

---

### Task 1: Immutable Domain Models and Safe Generic Settings

**Files:**
- Create: `src/a4diag/domain.py`
- Create: `src/a4diag/settings.py`
- Create: `tests/test_settings_v3.py`
- Modify: `config/config.example.yaml`

**Interfaces:**
- Consumes: none.
- Produces: `Risk`, `TargetMode`, `CapabilityGrant`, `TargetConfig`, `Operation`, `Plan`, `StepResult`, `AgentSettings`, and `load_settings(path: Path) -> AgentSettings`.

- [ ] **Step 1: Write failing safe-default and strict-schema tests**

```python
def test_empty_config_is_read_only(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("global_mode: read_only\ntargets: []\nplugins: []\n", encoding="utf-8")
    settings = load_settings(path)
    assert settings.global_mode == "read_only"
    assert settings.targets == ()
    assert settings.auto_execute_low is False

def test_unknown_target_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "global_mode: read_only\ntargets:\n  - id: lab\n    mode: local\n    surprise: true\nplugins: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="surprise"):
        load_settings(path)
```

- [ ] **Step 2: Run the focused test and observe the missing module failure**

Run: `python -m pytest tests/test_settings_v3.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'a4diag.settings'`.

- [ ] **Step 3: Implement exact domain/settings contracts**

```python
class Risk(StrEnum):
    LOW = "low"
    HIGH = "high"

class TargetMode(StrEnum):
    LOCAL = "local"
    SSH = "ssh"

class CapabilityGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    resources: tuple[str, ...]

class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    mode: TargetMode
    identity_ref: str
    write_enabled: bool = False
    auto_execute_low: bool = False
    capabilities: tuple[CapabilityGrant, ...] = ()
    notification_required: bool = False

class AgentSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    global_mode: Literal["read_only", "read_write"] = "read_only"
    targets: tuple[TargetConfig, ...] = ()
    plugins: tuple[str, ...] = ()
    auto_execute_low: bool = False
    max_write_targets: int = Field(default=2, ge=1, le=32)
```

Implement `load_settings` with `yaml.safe_load`, duplicate target-ID rejection, local/SSH identity validation, and rejection of empty resource patterns, `..`, root-only paths, `**` alone, or HIGH-capability auto-write shortcuts.

- [ ] **Step 4: Replace the example configuration with the exact safe default**

```yaml
global_mode: read_only
auto_execute_low: false
max_write_targets: 2
targets: []
plugins: []
```

- [ ] **Step 5: Run focused and full tests**

Run: `python -m pytest tests/test_settings_v3.py -q`

Expected: PASS.

Run: `python -m pytest -q`

Expected: existing tests plus new tests PASS; if legacy tests read `config/config.example.yaml`, move their frozen fixture into the test module without weakening new defaults.

- [ ] **Step 6: Commit**

```bash
git add src/a4diag/domain.py src/a4diag/settings.py tests/test_settings_v3.py config/config.example.yaml
git commit -m "feat: add generic safe-default settings"
```

### Task 2: Plugin Manifest and Pinned Registry

**Files:**
- Create: `src/a4diag/plugin_api/__init__.py`
- Create: `src/a4diag/plugin_api/manifest.py`
- Create: `src/a4diag/plugin_registry.py`
- Create: `tests/test_plugin_registry.py`

**Interfaces:**
- Consumes: `Risk` from Task 1.
- Produces: `PluginType`, `OperationContract`, `PluginManifest`, `PluginPin`, `PluginRegistry.load(...)`, `PluginRegistry.require(name, plugin_type)`.

- [ ] **Step 1: Write failing manifest rejection and pinning tests**

```python
def test_registry_rejects_digest_mismatch(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path, sha256="0" * 64)
    with pytest.raises(PluginRegistryError, match="SHA256"):
        PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")

def test_require_returns_only_enabled_compatible_plugin(tmp_path: Path) -> None:
    manifest_path, pin = write_manifest_fixture(tmp_path)
    registry = PluginRegistry.load((pin,), manifest_path.parent, core_api="1.0")
    assert registry.require("transport-local", PluginType.TRANSPORT).name == "transport-local"
```

- [ ] **Step 2: Verify tests fail before implementation**

Run: `python -m pytest tests/test_plugin_registry.py -q`

Expected: FAIL because `a4diag.plugin_registry` does not exist.

- [ ] **Step 3: Implement strict manifest models**

```python
class PluginType(StrEnum):
    MODEL = "model"
    TRANSPORT = "transport"
    CAPABILITY = "capability"
    NOTIFICATION = "notification"

class OperationContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    risk_floor: Risk
    reversible: bool
    supports_prepare: bool
    supports_verify: bool
    supports_reconcile: bool

class PluginManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    plugin_type: PluginType
    version: str
    api_min: str
    api_max: str
    executable: str
    socket: str
    config_schema: str
    operations: tuple[OperationContract, ...]
```

Parse API versions as numeric `(major, minor)` tuples; reject path traversal, non-absolute sockets, duplicate names, disabled pins, version/API/digest mismatch, and manifests whose external signed-index pin does not cover the installed wheel and manifest bytes. Artifact SHA values live outside the wheel to avoid a self-referential digest.

- [ ] **Step 4: Implement immutable registry lookup**

```python
@dataclass(frozen=True)
class PluginPin:
    name: str
    version: str
    api_version: str
    artifact_path: str
    sha256: str
    enabled: bool

class PluginRegistry:
    @classmethod
    def load(cls, pins: tuple[PluginPin, ...], manifest_root: Path, core_api: str) -> "PluginRegistry": ...
    def require(self, name: str, plugin_type: PluginType) -> PluginManifest: ...
```

- [ ] **Step 5: Run focused and full tests, then commit**

Run: `python -m pytest tests/test_plugin_registry.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/plugin_api src/a4diag/plugin_registry.py tests/test_plugin_registry.py
git commit -m "feat: validate and pin plugin manifests"
```

### Task 3: Canonical Plans, Policy Decisions, Digests, and Tickets

**Files:**
- Modify: `src/a4diag/domain.py`
- Create: `src/a4diag/policy_engine.py`
- Create: `src/a4diag/plugin_api/ticket.py`
- Create: `tests/test_policy_engine_v3.py`
- Create: `tests/test_operation_ticket.py`

**Interfaces:**
- Consumes: `TargetConfig`, `Risk`, `PluginManifest`, `OperationContract`.
- Produces: `canonical_plan_bytes(plan)`, `plan_digest(plan)`, `PolicyEngine.evaluate(...) -> PolicyDecision`, `TicketIssuer.issue(...) -> str`, `TicketVerifier.verify(...) -> OperationTicket`.

- [ ] **Step 1: Write failing boundary, risk-floor, digest, expiry, and replay tests**

```python
def test_out_of_allowlist_is_denied_even_with_high_approval() -> None:
    plan = plan_for_file("/etc/shadow")
    decision = engine.evaluate(
        target, plan, critic_risk=Risk.HIGH, approval_digest=plan_digest(plan)
    )
    assert decision.allowed is False
    assert decision.reason == "resource_not_allowed"

def test_high_risk_manifest_cannot_be_downgraded() -> None:
    plan = firewall_plan(model_risk=Risk.LOW)
    decision = engine.evaluate(
        target, plan, critic_risk=Risk.LOW, approval_digest=None
    )
    assert decision.risk is Risk.HIGH
    assert decision.allowed is False
    assert decision.reason == "approval_required"

def test_ticket_is_single_use() -> None:
    token = issuer.issue(operation, target_fingerprint="machine-1", ttl_seconds=30)
    verifier.verify(token, expected_operation=operation, target_fingerprint="machine-1")
    with pytest.raises(TicketError, match="replay"):
        verifier.verify(token, expected_operation=operation, target_fingerprint="machine-1")
```

- [ ] **Step 2: Run tests and verify missing implementations fail**

Run: `python -m pytest tests/test_policy_engine_v3.py tests/test_operation_ticket.py -q`

Expected: FAIL on missing modules/types.

- [ ] **Step 3: Implement canonical immutable operation and plan models**

```python
class Operation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    capability: str
    action: str
    resource: str
    parameters: dict[str, JsonValue]
    model_risk: Risk
    verify: dict[str, JsonValue]
    undo: dict[str, JsonValue] | None

class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target_id: str
    target_fingerprint: str
    operations: tuple[Operation, ...]
```

Canonicalize with UTF-8 JSON, sorted keys, compact separators, normalized Unicode, and rejection of floats, NaN, bytes, duplicate semantic resources, and more than 20 steps. Compute SHA256 only from canonical bytes.

- [ ] **Step 4: Implement policy evaluation with monotonic risk**

```python
class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    allowed: bool
    risk: Risk
    reason: str
    digest: str

class PolicyEngine:
    def evaluate(self, target: TargetConfig, plan: Plan, *, critic_risk: Risk, approval_digest: str | None) -> PolicyDecision: ...
```

Require exact capability/action/resource membership, write flags, LOW double vote, core HIGH capability set, operation count/output/runtime budgets, reversible metadata, and digest equality. Approval may satisfy only `approval_required`; it may not change any boundary denial.

- [ ] **Step 5: Implement HMAC-SHA256 single-use tickets**

Ticket payload fields are `ticket_id`, `transaction_id`, `step_id`, `target_id`, `target_fingerprint`, `capability`, `action`, `resource`, `parameters_digest`, `plan_digest`, `risk`, `approval_id`, `issued_at`, and `expires_at`. The verifier stores consumed ticket IDs in an injected `ReplayStore.consume(ticket_id) -> bool`.

- [ ] **Step 6: Run tests and commit**

Run: `python -m pytest tests/test_policy_engine_v3.py tests/test_operation_ticket.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/domain.py src/a4diag/policy_engine.py src/a4diag/plugin_api/ticket.py tests/test_policy_engine_v3.py tests/test_operation_ticket.py
git commit -m "feat: enforce plan policy and operation tickets"
```

### Task 4: Digest-Bound Approval and Durable Transaction Store

**Files:**
- Create: `src/a4diag/approvals.py`
- Create: `src/a4diag/transaction_store.py`
- Create: `tests/test_approvals.py`
- Create: `tests/test_transaction_store.py`

**Interfaces:**
- Consumes: canonical plan digest from Task 3.
- Produces: `ApprovalStore.request`, `ApprovalStore.approve`, `ApprovalStore.valid_digest`, `TransactionStore.begin`, `record_prepared`, `record_result`, `mark_unknown`, `next_recovery_action`, `release_target`.

- [ ] **Step 1: Write failing approval expiry and per-target-lock tests**

```python
def test_changed_digest_invalidates_approval(store: ApprovalStore) -> None:
    request = store.request("tx-1", "target-1", "a" * 64, expires_at=200)
    store.approve(request.id, approved_digest="a" * 64, actor="uid:1000", now=100)
    assert store.valid_digest("tx-1", now=101) == "a" * 64
    assert store.valid_digest("tx-1", expected_digest="b" * 64, now=101) is None

def test_second_write_for_same_target_is_rejected(store: TransactionStore) -> None:
    store.begin("tx-1", "target-1", "a" * 64)
    with pytest.raises(TargetBusyError):
        store.begin("tx-2", "target-1", "b" * 64)
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `python -m pytest tests/test_approvals.py tests/test_transaction_store.py -q`

Expected: FAIL on missing modules.

- [ ] **Step 3: Implement SQLite schemas and guarded transitions**

Create tables `approvals`, `transactions`, `transaction_steps`, `plugin_markers`, `target_write_locks`, and `consumed_tickets`. Use `BEGIN IMMEDIATE`, foreign keys, unique active target locks, enumerated CHECK constraints, and compare-and-swap updates of the prior state.

Allowed transaction transitions are encoded in one constant:

```python
ALLOWED_TRANSITIONS = {
    "prepared": {"executing", "failed"},
    "executing": {"verifying", "execution_unknown", "rollback_running"},
    "execution_unknown": {"verifying", "rollback_running", "failed"},
    "verifying": {"succeeded", "rollback_running"},
    "rollback_running": {"rollback_succeeded", "rollback_partial", "rollback_unknown"},
}
```

- [ ] **Step 4: Implement recovery decisions without replay**

```python
class RecoveryAction(StrEnum):
    RECONCILE = "reconcile"
    VERIFY = "verify"
    ROLLBACK = "rollback"
    MANUAL = "manual"

def next_recovery_action(self, transaction_id: str) -> RecoveryAction: ...
```

An `executing` transaction found after restart becomes `execution_unknown` and returns `RECONCILE`; it never returns a direct apply/retry action.

- [ ] **Step 5: Run focused/full tests and commit**

Run: `python -m pytest tests/test_approvals.py tests/test_transaction_store.py -q && python -m pytest -q`

Expected: PASS, including two independent SQLite connections racing for the same target.

```bash
git add src/a4diag/approvals.py src/a4diag/transaction_store.py tests/test_approvals.py tests/test_transaction_store.py
git commit -m "feat: persist approvals and remediation transactions"
```

### Task 5: LangGraph Core with Fake Plugin Ports

**Files:**
- Create: `src/a4diag/workflow.py`
- Create: `tests/test_workflow_v3.py`

**Interfaces:**
- Consumes: settings, registry, policy, approval, ticket and transaction interfaces from Tasks 1-4.
- Produces: `AgentState`, `PluginPorts`, `build_graph(deps: WorkflowDependencies) -> CompiledStateGraph`, `run_event(graph, event) -> AgentState`.

- [ ] **Step 1: Write failing graph-route tests**

```python
def test_low_plan_applies_verifies_and_succeeds(deps: WorkflowDependencies) -> None:
    deps.model.plan_result = low_service_restart_plan()
    state = run_event(build_graph(deps), event_for("target-1"))
    assert state["status"] == "succeeded"
    assert deps.executor.calls == ["prepare", "apply", "verify"]

def test_high_plan_interrupts_before_apply(deps: WorkflowDependencies) -> None:
    deps.model.plan_result = high_firewall_plan()
    state = run_event(build_graph(deps), event_for("target-1"))
    assert state["status"] == "pending_approval"
    assert deps.executor.calls == []

def test_crash_after_dispatch_reconciles_without_replay(deps: WorkflowDependencies) -> None:
    deps.executor.apply_error = TimeoutError()
    first = run_event(build_graph(deps), event_for("target-1"))
    assert first["status"] == "execution_unknown"
    deps.executor.reconcile_result = "applied"
    resumed = run_event(build_graph(deps), resume_for(first["transaction_id"]))
    assert deps.executor.apply_count == 1
    assert resumed["status"] == "succeeded"
```

- [ ] **Step 2: Run tests and verify missing workflow failure**

Run: `python -m pytest tests/test_workflow_v3.py -q`

Expected: FAIL because `a4diag.workflow` is missing.

- [ ] **Step 3: Define strict state and dependency ports**

```python
class AgentState(TypedDict, total=False):
    event_id: str
    target_id: str
    target_fingerprint: str
    evidence: list[dict[str, JsonValue]]
    plan: dict[str, JsonValue]
    digest: str
    risk: str
    transaction_id: str
    next_step: int
    status: str
    error: str

@dataclass(frozen=True)
class PluginPorts:
    model: ModelPort
    collector: CollectorPort
    executor: ExecutorPort
    notifier: NotificationPort
```

- [ ] **Step 4: Implement the exact graph nodes and conditional routes**

Add nodes `ingest`, `resolve_target`, `collect`, `diagnose`, `plan`, `critic`, `policy_gate`, `freeze_plan`, `approval_gate`, `prepare`, `apply_step`, `verify_step`, `next_or_undo`, `final_verify`, `report`, and `close`. Persist after every effect boundary using the injected SQLite checkpointer. Catch model failure only at model nodes and route to `read_only_no_model`; catch executor timeout/crash at apply and route to `execution_unknown`.

- [ ] **Step 5: Add reverse-order rollback assertions**

Add a three-step test where step 3 verification fails and assert executor calls end with `undo:2`, `undo:1`, `undo:0`; when `undo:1` fails, assert final status `rollback_partial` and no claim of success.

- [ ] **Step 6: Run phase gate and commit**

Run: `python -m pytest tests/test_workflow_v3.py tests/test_policy_engine_v3.py tests/test_operation_ticket.py tests/test_transaction_store.py tests/test_approvals.py tests/test_plugin_registry.py tests/test_settings_v3.py -q`

Expected: PASS.

Run: `python -m pytest -q`

Expected: all legacy and v3 tests PASS.

```bash
git add src/a4diag/workflow.py tests/test_workflow_v3.py
git commit -m "feat: add policy-gated LangGraph remediation workflow"
```

### Task 6: Phase 1 Security Acceptance Gate

**Files:**
- Create: `tests/test_core_security_acceptance.py`
- Create: `docs/testing/core-security-matrix.md`

**Interfaces:**
- Consumes: all Phase 1 modules.
- Produces: a single executable acceptance matrix required by every later phase.

- [ ] **Step 1: Write the failing parameterized invariant tests**

Cover empty defaults, unknown target, identity mismatch, missing capability, resource escape, HIGH without approval, changed digest, expired/replayed ticket, same-target concurrent write, unknown execution result, reverse rollback, and model failure.

```python
@pytest.mark.parametrize("mutator,reason", [
    (change_target_identity, "target_identity_mismatch"),
    (escape_file_allowlist, "resource_not_allowed"),
    (remove_write_enable, "target_read_only"),
])
def test_denials_never_call_executor(harness: CoreHarness, mutator, reason: str) -> None:
    mutator(harness)
    state = harness.run()
    assert state["status"] == "policy_denied"
    assert state["error"] == reason
    assert harness.executor.apply_count == 0
```

- [ ] **Step 2: Run the acceptance file and full suite**

Run: `python -m pytest tests/test_core_security_acceptance.py -q`

Expected: PASS with every denial proving `apply_count == 0`.

Run: `python -m pytest -q`

Expected: zero failures/errors.

- [ ] **Step 3: Record the commands and invariant-to-test mapping**

Write `docs/testing/core-security-matrix.md` with one row per invariant, the exact pytest node ID, and the expected terminal state. Do not copy runtime secrets or environment-specific paths.

- [ ] **Step 4: Commit**

```bash
git add tests/test_core_security_acceptance.py docs/testing/core-security-matrix.md
git commit -m "test: lock core security invariants"
```

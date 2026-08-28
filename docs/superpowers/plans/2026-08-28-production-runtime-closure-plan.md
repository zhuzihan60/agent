# A4Diag Production Runtime Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing A4Diag v0.4 production chain executable end to end while preserving fail-closed safety.

**Architecture:** Extend the existing settings, workflow ports and durable stores rather than introducing a parallel runtime. Production CLI commands build one runtime from one settings-v3 document and use explicit typed adapters at external boundaries.

**Tech Stack:** Python 3.11, Pydantic v2, LangGraph, SQLite, AF_UNIX JSON-RPC, Bash/systemd, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-28-production-runtime-closure-design.md`

## Global Constraints

- Do not weaken target-id-only routing, identity pinning, risk floors, approval gates, ticket binding, audit integrity, rollback, or unknown-execution handling.
- Do not use real servers, model APIs, notification endpoints or credentials in tests.
- Treat build, dist, egg-info and __pycache__ as generated output.
- Make each production behavior fail closed when its required plugin or durable state is unavailable.

---

### Task 1: Settings v3 and initialization

**Files:** `src/a4diag/settings.py`, `src/a4diag/domain.py`, `src/a4diag/init_config.py`, `src/a4diag/cli.py`, `config/schemas/config-v3.json`, `config/config.example.yaml`, `README.md`, settings/init/CLI tests.

- [ ] Add failing tests for direct example loading, preserved target transport/model/notification/alert settings and non-interactive ENABLE gating.
- [ ] Extend strict v3 models and serialization; replace production `Config.load` and `UnavailableProbe` paths with typed production adapters.
- [ ] Run focused settings/init/CLI tests.

### Task 2: Plugin RPC execution context

**Files:** `src/a4diag/workflow.py`, `src/a4diag/plugin_ports.py`, plugin protocol/ticket code, built-in plugin host/capability modules, plugin registry/admin code and contract tests.

- [ ] Add failing tests for real transaction id, complete undo payload/digest and socket activation.
- [ ] Thread transaction context through ports and tickets; adopt inherited sockets safely.
- [ ] Canonicalize installed manifest, registry, config, socket and service paths.
- [ ] Run plugin contract and workflow tests.

### Task 3: Approval resume closure

**Files:** `src/a4diag/cli.py`, `src/a4diag/runtime.py`, `src/a4diag/approval_cli.py`, approval/runtime tests.

- [ ] Add failing tests proving shared stores, durable plan display, approve-to-resume and zero HIGH dispatch before approval.
- [ ] Build approvals from the production runtime and add explicit resume command/receipt handling.
- [ ] Run approval and runtime integration tests.

### Task 4: Serve, poll durability and reports

**Files:** `src/a4diag/cli.py`, `src/a4diag/poller.py`, `src/a4diag/alertmanager.py`, `src/a4diag/report.py`, durable store modules and integration tests.

- [ ] Add failing tests for one-shot exit, RuntimeResult persistence, report writing and restart-safe alert dedup.
- [ ] Implement one complete poll transaction and durable alert receipt/result storage.
- [ ] Run serve/poller/report integration tests.

### Task 5: Release and CI

**Files:** `install.sh`, `tools/install_lib.sh`, `tools/build_release.py`, release/installer tests and GitHub workflows.

- [ ] Add failing tests for online archive layout, cross-manifest/signature verification and Windows dependency installation.
- [ ] Make assembly and installer consume one canonical release root and fail before staging on any inconsistency.
- [ ] Run installer/release/CI contract tests.

### Task 6: Full verification

- [ ] Run `python -m compileall -q src packages tests tools`.
- [ ] Run `python -m pytest -q`.
- [ ] Run `python tools/build_release.py verify-source --project-root .`.
- [ ] Report every executed command, exit code, test count and environmental blocker.

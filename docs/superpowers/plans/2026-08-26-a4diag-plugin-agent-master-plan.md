# A4Diag Generic Plugin Agent Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the current fixed-target read-only diagnostic service into a generic LangGraph Agent with administrator-installed out-of-process plugins, safe defaults, LOW autonomous remediation, HIGH local-CLI approval, verified rollback, and online/offline distribution.

**Architecture:** Preserve the existing application while introducing a new v3 core beside it, then migrate the CLI and service entrypoints only after the core and bundled plugins pass contract tests. The core owns policy, digest, approval, transaction, audit, and recovery; plugins communicate through versioned JSON-RPC over Unix sockets and receive only typed requests plus short-lived operation tickets.

**Tech Stack:** Python 3.11, Pydantic 2.13.4, LangGraph 1.2.11, SQLite, httpx 0.28.1, PyYAML 6.0.3, systemd, OpenSSH, unittest/pytest, setuptools.

**Spec:** `docs/superpowers/specs/2026-08-26-a4diag-generic-plugin-agent-design.md`

## Global Constraints

- New installations start with `targets: []`, `global_mode: read_only`, and `auto_execute_low: false`.
- The core and default configuration contain no `t_11`, fixed target IP, fixed SSH username, or fixed target unit allowlist.
- Supported targets in this release are local or SSH Linux hosts running systemd: Rocky/RHEL/AlmaLinux 8/9, Ubuntu 22.04/24.04, and Debian 12.
- Model output is an untrusted proposal; no raw model-generated shell text is executable.
- An operation outside target/capability/resource allowlists is denied and cannot be made valid by approval.
- HIGH is never automatic; local CLI approval is digest-bound and mandatory.
- LOW is automatic only when both model reviews say LOW, the core floor is LOW, the target explicitly enables it, and prepare/verify/recovery requirements pass.
- `network`, `firewall`, `ssh`, `virtualization`, and any future raw-script write operation have a mandatory HIGH floor.
- One write transaction per target; different targets may run concurrently within the configured global limit.
- An unknown execution result is never automatically replayed.
- Plugins are administrator-trusted code, pinned by name/version/API/SHA256, isolated by service identity, and unable to change core policy through the plugin protocol.
- Plugin, target, and model administration remain unavailable to the model and execution identities.
- Online and offline releases use the same locked artifacts; offline installation rejects missing, extra, damaged, sdist, or incompatible wheels.
- Existing tests remain green at every commit; legacy entrypoints are removed only after their v3 replacement tests pass.

---

## Existing Baseline

- Current package: `src/a4diag`; version `0.3.0`; fixed-target read-only behavior remains the regression baseline.
- Current orchestration: `src/a4diag/orchestrator.py`; current model adapter: `src/a4diag/dsh_runner.py`.
- Current config hardcodes a target in `src/a4diag/config.py`; it is not edited until the new generic settings parser is tested independently.
- Current persistence is `src/a4diag/store.py`; new v3 transaction tables are added through an independent store before poller migration.
- Current release assembler in `tools/build_release.py` and verified Python 3.11 wheelhouse are retained and extended.
- Design commit baseline: `261f12b4e7172958dbc12c08575b650a47e772d9`.

## Planned File Structure

```text
src/a4diag/
  domain.py                 immutable target, operation, plan and result types
  settings.py               generic strict configuration and safe defaults
  plugin_api/
    manifest.py             plugin manifest schema and compatibility checks
    protocol.py             JSON-RPC request/response types
    ticket.py               signed single-use operation tickets
  plugin_registry.py        installed/enabled/pinned plugin registry
  policy_engine.py          allowlists, risk floor, budgets and digest gate
  approvals.py              digest-bound local approval records
  transaction_store.py      durable transaction, step, marker and target-lock state
  workflow.py               LangGraph state and graph construction
  plugin_client.py          Unix-socket JSON-RPC client
  runtime.py                production dependency assembly
  init_config.py            deterministic interactive/non-interactive initialization
  secrets.py                secret references and least-privilege resolution
  redaction.py              shared recursive redaction
  audit.py                  append-only audit sink
packages/a4diag-builtin-plugins/
  pyproject.toml
  src/a4diag_builtin_plugins/
    host.py                 common JSON-RPC host and ticket verification
    model_openai.py
    transport_local.py
    transport_ssh.py
    capability_files.py
    capability_services.py
    capability_packages.py
    notification_cli.py
    notification_flashduty.py
    notification_smtp.py
    notification_webhook.py
  manifests/*.json
config/
  config.example.yaml       safe empty default
  schemas/*.json            config and plugin schemas
deploy/
  a4diag-core.service
  a4diag-plugin@.service
  a4diag-plugin@.socket
tools/
  build_release.py          multi-wheel, manifest and offline validation
  install.sh                atomic online/offline installer
tests/
  contract/                 reusable plugin conformance suite
  integration/              local/SSH/crash/approval/rollback integration tests
```

## Ordered Phase Plans

1. `docs/superpowers/plans/2026-08-26-a4diag-core-policy-workflow-plan.md`
   - Deliverable: generic safe-default configuration, plugin manifests/registry, operation tickets, policy/digest/approval, durable transactions and a LangGraph core tested without real plugins.
2. `docs/superpowers/plans/2026-08-26-a4diag-builtin-plugins-plan.md`
   - Deliverable: Unix-socket protocol plus model, local/SSH, files/services/packages and notification plugins passing one conformance suite.
3. `docs/superpowers/plans/2026-08-26-a4diag-admin-runtime-migration-plan.md`
   - Deliverable: `a4diag init`, plugin administration, approval CLI, generic event runtime, audit/reporting, and removal of fixed-target runtime behavior.
4. `docs/superpowers/plans/2026-08-26-a4diag-release-validation-plan.md`
   - Deliverable: hardened systemd services, atomic online/offline install, multi-wheel release assembly, supported-distribution and chaos acceptance gates.

Execute phases in order. Within a phase, execute tasks in order because each task's Interfaces block names the exact dependency supplied to the next task.

## Cross-Phase Acceptance Matrix

| Requirement | First proof | Final proof |
|---|---|---|
| Empty/read-only default | Phase 1 settings tests | Phase 4 clean-install tests |
| No fixed target | Phase 1 source/config scan | Phase 4 release scan |
| Typed plugin protocol | Phase 1 domain tests | Phase 2 conformance suite |
| Boundary cannot be approved | Phase 1 policy tests | Phase 3 CLI integration |
| HIGH needs CLI approval | Phase 1 approval tests | Phase 4 end-to-end test |
| LOW autonomous path | Phase 1 graph tests | Phase 3 local and SSH integration |
| Unknown result not replayed | Phase 1 recovery tests | Phase 4 plugin-kill chaos test |
| Reverse rollback | Phase 1 transaction tests | Phase 2 files/services integration |
| Optional notifications | Phase 2 notification tests | Phase 3 approval integration |
| Plugin pinning/isolation | Phase 1 registry tests | Phase 4 tamper/systemd tests |
| Online/offline GitHub use | Phase 4 installer tests | Phase 4 clean VM matrix |

## Final Verification Commands

Run from the feature worktree after all four plans are complete:

```bash
python -m pytest -q
python -m build
python tools/build_release.py verify-source --project-root .
python tools/build_release.py assemble --project-root . --dependency-wheelhouse C:/Users/149721/Desktop/ai/.a4diag-v3-wheelhouse --dist-dir dist --output C:/Users/149721/Desktop/ai/.a4diag-v3-final
python tools/build_release.py verify-release --release-root C:/Users/149721/Desktop/ai/.a4diag-v3-final
```

Expected evidence:

- pytest reports zero failures and zero errors;
- build creates one core wheel and the bundled-plugin build creates its separate wheel;
- source verification reports zero target-specific literals in runtime/default config;
- release verification reports exact manifest coverage and no sdist/extra artifact;
- supported-distribution CI and privileged SSH/local integration jobs are green.

## Commit Discipline

- One commit per task deliverable, after its focused tests and the full existing suite pass.
- Do not squash across phase acceptance gates; each phase must be independently reviewable.
- Do not amend the approved design commit.
- Do not push, merge, deploy, connect to a real target, or create infrastructure without separate user authorization.

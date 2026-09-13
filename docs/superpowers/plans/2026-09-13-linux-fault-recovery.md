# Linux Fault Recovery Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development task-by-task, with task and final review.

**Goal:** Extend controlled Linux repair with administrator-registered probes and fresh typed recovery checks.
**Architecture:** Shared probe definitions and output contracts live in core; target probes execute fixed bounded reads; transports carry only probe IDs; the core checks typed administrator conditions after repair.
**Tech Stack:** Python 3.11, Pydantic, existing SSH/systemd executor and pytest.
**Spec:** `docs/superpowers/specs/2026-09-13-linux-fault-recovery.md`

## Global constraints

At most 8 diagnostic probes per target; file hashing at most 1048576 bytes; DNS at most 16 addresses.
Existing approvals, tickets, identity checking, managed-root enforcement and recovery-on-failure remain required.

## Tasks

- [x] Core contracts: add `src/a4diag/linux_probes.py` with LinuxProbe, ProbeCondition, output validation and predicate evaluation; test unknown IDs, paths, hosts, fields, types, nonfinite numbers and missing output in `tests/test_linux_probe_config.py and tests/test_linux_probe_recovery.py`.
- [x] Target probes: add `packages/a4diag-target-runtime/src/a4diag_target/linux_probes.py` (`async run_probe(root, probe, runner=None) -> dict`) and `probe_network.py`; bounded filesystem/memory/load/file/package/TCP/DNS reads and real Linux tests in `tests/test_linux_target_probes.py`.
- [x] Target authorization: add `TargetPolicy.diagnostic_probes`, `authorize_probe(id) -> LinuxProbe`; extend installer optional diagnostic_probes input, validate via installed runtime before activation; enable only required network families; test denial and installer configuration.
- [x] Core/transport wiring: add diagnostic_probes to init/domain models, probe evidence/checks to recovery; ReadParams gains probe_id; target read routing and `_RpcCollectorPort` collect and independently re-read probes. Test transported probe IDs and fresh post-repair observations.
- [x] Acceptance/docs: exercise real Linux probes and service/file repair outcomes; document supported predicates, target registration, deployment steps, diagnostic-only domains and unsupported actions.
- [x] Review and ship branch: inspect diffs and safety boundaries, run full CI, fix findings, push feature branch and create a reviewable PR. No new release tag in this task.

For each implementation task: reproduce an appropriate failing behavior first; implement; run focused tests; review against the spec before integration. Complete the full suite after integrating all contracts.

## Validation record

- Code commit `ed3b3005d0af29be22a493f2c49e4b633a7ecaa8`: full Linux CI passed, including production E2E, release assembly and controller/target distro installation checks: https://github.com/zhuzihan60/agent/actions/runs/34745309774
- Focused Windows integration run: 221 passed, 8 skipped, 5 subtests passed. After review fixes: 41 recovery regression tests passed.
- Existing D-drive Ubuntu WSL lab: all seven probe kinds exercised; temporary TCP listener was reachable before close and unreachable after close; temporary file mode 0600 failed the configured predicate and mode 0644 passed after a fresh read.
- WSL validation used source imports and temporary fixtures, without replacing installed services or making model API calls. The WSL permission change was performed by the test harness; automated transport/collector and existing production E2E tests cover separate layers.
- PR: https://github.com/zhuzihan60/agent/pull/3 (stacked on model-budget PR #2). No main merge or release publication performed.

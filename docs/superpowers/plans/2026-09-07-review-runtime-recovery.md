# Review findings remediation plan

> Execution: test-driven implementation of the approved review fixes, using independent workers for file and installer changes and a final integrated review.

**Goal:** Repair the seven findings in the review of affe6f6 and push a tested branch.

**Constraints:** Preserve read-only defaults, identity/approval/digest binding, target resource policy, and no replay of unknown writes. Do not grant blanket filesystem writes. No merge or release. Keep runtime compatibility with Python 3.11.

## Task 1: File effects

- [x] Add regression cases in `tests/test_file_recovery_regressions.py` for chmod reconciliation, unchanged-content replacement, metadata drift and omitted mode; exercise the real local adapter on Linux for metadata preservation.
- [x] Fix `FilesPlugin.reconcile` to compare complete pre/post state, and preserve original metadata on replacement. Atomic replacement receives explicit mode and original ownership before rename.
- [x] Run file capability and target executor tests; self-review the diff.

## Task 2: Deployment

- [x] Exercise installer output for managed filesystem roots with safe characters and protected path rejection.
- [x] Generate a systemd drop-in from validated managed roots, preserving ProtectSystem=strict. Reject unsupported package grants rather than granting blanket filesystem/network access.
- [x] Ensure E2E exercises the released hardened unit rather than a synthetic unprotected unit, and test/write docs for the supported deployment behavior.

## Task 3: Core runtime and production RPC

- [x] Test pending HIGH approval through RuntimePlanSource and ApprovalCli; remove the pre-approval transaction requirement while checking the actual plan digest.
- [x] Test request context reaching the model; append redacted structured request evidence without changing plugin method signatures, and retain alert labels/annotations at event creation.
- [x] Test controller restart recovery with a fresh production RPC executor. Bind read-only recovery context from the checkpoint's validated plan, target identity and approval record. Persisted operations remain immutable; writes still require current policy authorization and a fresh effect ticket.
- [x] Test successful/failed restoration via signed target reads; accept restored only when target proves complete pre-state.
- [x] Run core workflow, approval, RPC and target protocol regression suites.

## Task 4: Integrated verification and delivery

- [x] Use existing Ubuntu WSL/Python 3.11 if available; run compileall, full pytest and verify-source with the locked dependencies.
- [x] Review all changes and amend any defects. Confirm no secrets or test artifacts are included.
- [ ] Commit and push `fix/review-runtime-recovery` to origin. Inspect branch CI where available and report exact evidence and limitations.

## Progress

- Baseline: review demonstrated 5 failing probes; corresponding existing suite had 90 passing tests. Original checkout is clean; dedicated branch created from affe6f6.
- Scope: improve the existing request evidence path; adding a new general telemetry subsystem is outside these bug fixes. Identity verification is not presented as proof that an external alert has cleared.
- Independent review added authenticated persisted-effect digest checks and restoration proof for no-op UNDO recovery. Core regression/workflow suite: 68 passed on Windows; Linux full suite uses the pinned Python 3.11 dependencies.
- Hardened package execution remains unsupported: the installer now rejects package grants explicitly. File grants produce a constrained systemd drop-in; active executor restarts load updated policy and mounts, and the runtime directory group permits the installed relay user.
- Linux full run: 1,048 passed, 2 skipped, 80 subtests passed; two failures were a missing pip in the temporary environment and an old restoration test fixture. After adding pip, installer/systemd verification passed all 28 cases. The fixture now models unavailable restoration evidence and expects the new read-only restoration probe.
- Final Linux security acceptance rerun: 27 passed. Both initial full-suite failures are resolved; compileall, shell syntax and verify-source checks pass.
- The real systemd/SSH production wiring test is restricted to a disposable GitHub runner and remains part of branch CI.

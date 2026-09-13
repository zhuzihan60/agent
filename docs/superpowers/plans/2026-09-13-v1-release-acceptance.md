# v1.0.0 Acceptance and Release Plan

> Use superpowers:subagent-driven-development for independent deployment validation and safety review; root integrates and publishes only after required checks pass.

**Goal:** Comprehensively validate the implemented Linux service/file repair scope and publish a signed v1.0.0 from main.
**Scope:** User explicitly authorized tests, necessary fixes, merge and release on success. Existing D-drive WSL controller/target lab and existing DeepSeek credential may be used; never output secrets. Seven probes are diagnosis/verification, not unrestricted Linux mutations.

- [x] Repair and regress the reproduced target service/socket restart failure; review installer upgrade ordering and preserve least privilege.
- [x] Independently review identity, probe authorization, recovery predicates, fail-closed handling, approvals and rollback; fix reproducible release blockers.
- [x] Prepare consistent 1.0.0 package/manifests/version metadata and release/deployment notes; preserve old release history.
- [x] Run fresh complete Linux CI on the release candidate: unit/contract/integration/acceptance, production SSH wiring, release assembly, controller and target distro smoke tests.
- [x] Run D-drive WSL candidate validation: real model file and service recovery, deliberate recovery failure with rollback, unauthorized operation/probe rejection, restart/upgrade behavior. Capture model usage and target-ledger evidence; restore read-only settings afterwards.
- [ ] Merge prerequisite PR #2, then validated Linux/release PR #3 to main; ensure merged tree equals tested candidate and main checks pass.
- [ ] Tag v1.0.0, run existing signed release pipeline, verify downloaded public archives/signatures/manifests and published release metadata, and report links and supported limits.

No successful release claim until public assets and the signed pipeline are verified. Do not weaken an authorization or recovery gate to make a test pass.

Release gate evidence: [v1.0.0 acceptance record](../../testing/v1.0.0-acceptance.md).

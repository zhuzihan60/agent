# Task F2 report

## Outcome

Implemented protocol 1.1 repair authorization while preserving the protocol 1.0 request and ticket models and their canonical signed representations.

## RED evidence

- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py tests/target_runtime/test_repair_protocol.py`
  - Expected failure: missing `RepairAuthorizationError` and `TargetLifecycleV11` during collection.
  - Result: 2 collection errors.
  - Log: `/opt/a4diag-remediation-test/tests-xs2lxej2/pytest.log`.
- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py`
  - Expected failure: missing protocol 1.1 operation-ticket models.
  - Result: collection error for `OperationTicketExpectationV11`.
  - Log: `/opt/a4diag-remediation-test/tests-v8882c7a/pytest.log`.
- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py::test_rpc_port_dispatches_v11_from_ticket_without_hiding_metadata_in_parameters`
  - Expected failure: the controller port parsed a 1.1 ticket as the legacy ticket model.
  - Result: `ticket_context_invalid` from five strict model mismatches.
  - Log: `/opt/a4diag-remediation-test/tests-zncjxpe1/pytest.log`.
- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py::test_authorize_profile_fails_closed`
  - Expected failure: a profile could authorize a different recovery-check set.
  - Result: one failing parameterized case, `recovery_checks_mismatch` was not raised.
  - Log: `/opt/a4diag-remediation-test/tests-rmyv3ln2/pytest.log`.
- `run-remediation-tests.ps1 -q tests/target_runtime/test_repair_protocol.py::test_job_lifecycles_fail_closed_until_job_handlers_exist`
  - Expected failure: protocol 1.1 did not yet carry a bound `job_id`.
  - Result: two failures because `job_id` was rejected as an extra field.
  - Log: `/opt/a4diag-remediation-test/tests-3wnlqn7d/pytest.log`.
- The same job-lifecycle test was rerun after the schema existed.
  - Expected failure: unimplemented job handlers were reached through `marker_required` instead of the explicit lifecycle fail-closed boundary.
  - Result: two failures, actual `marker_required`, expected `lifecycle_not_wired`.
  - Log: `/opt/a4diag-remediation-test/tests-e5thj1_u/pytest.log`.

## GREEN evidence

- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py tests/target_runtime/test_repair_protocol.py`
  - Result: `30 passed in 0.90s`.
  - Log: `/opt/a4diag-remediation-test/tests-c9hzvv_v/pytest.log`.
- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py tests/target_runtime/test_repair_protocol.py tests/test_operation_ticket.py tests/test_target_protocol.py tests/test_policy_engine_v3.py`
  - Result before the last additive coverage cases: `153 passed in 0.98s`.
  - Log: `/opt/a4diag-remediation-test/tests-ph4oe7xi/pytest.log`.
- `run-remediation-tests.ps1`
  - Final result: `1433 passed, 4 skipped, 80 subtests passed in 122.96s`.
  - Log: `/opt/a4diag-remediation-test/tests-r161z83w/pytest.log`.

## Interfaces delivered

- `authorize_profile(profile, operation, *, now, presented_digest) -> RepairBinding` with stable `RepairAuthorizationError.code` values.
- `RepairPolicyAuthorization`, authenticated with a protocol 1.1-specific domain separator, plus `issue_repair_policy_authorization`, `bind_repair_preconditions`, and authenticity verification.
- Independent `OperationTicketRequestV11`, `OperationTicketExpectationV11`, and `OperationTicketV11` models. Legacy ticket claims remain unchanged and parsing dispatches by explicit version.
- Independent `TargetRequestV11` and `TargetLifecycleV11`, including `query_job`, `confirm_job`, and lifecycle-bound `job_id`. `TargetVerifier` dispatches 1.0 and 1.1 explicitly and can be configured as a 1.0-only verifier.
- Controller RPC dispatch derives 1.1 target envelopes from authenticated 1.1 tickets. Authorization metadata is not inserted into `Operation.parameters`.
- Target policy independently rechecks the local profile ID, digest, expiry, operation, recovery checks, authorization kind, standing authorization ID, and prepare-marker digest on every request. Job handlers remain explicitly fail closed until F3.

## Deviations and concerns

- No F3 job persistence or handler was implemented; `query_job` and `confirm_job` validate their authorization and then return `lifecycle_not_wired`.
- No F5 helper entrypoint was implemented.
- Commit subject: `feat: bind repair authorization across controller and target`; final hash is returned by the worker after the report is committed.

## Production revocation integration follow-up

Ruling: every-stage profile rechecks must take effect in the long-running `TargetSocketServer`; requiring a service restart after policy revocation was not sufficient.

### RED

- `run-remediation-tests.ps1 -q tests/target_runtime/test_server.py`
  - Result: `4 failed, 3 passed`.
  - Evidence: atomically replacing the policy did not revoke apply, missing and malformed policy files did not block prepare, and diagnostics continued using the stale grant.
  - Log: `/opt/a4diag-remediation-test/tests-vmwmzkzn/pytest.log`.
- The first expanded server regression run exposed diagnostic fixtures that bypassed `TargetSocketServer.__init__` and injected the removed `_policy` cache directly.
  - Result: `21 failed, 214 passed, 1 skipped` with `_policy_path` absent from those test-only instances.
  - Log: `/opt/a4diag-remediation-test/tests-ur3wjfr5/pytest.log`.

### GREEN

- `run-remediation-tests.ps1 -q tests/target_runtime/test_server.py`
  - Result: `7 passed in 0.43s` after the live provider was connected.
  - Log: `/opt/a4diag-remediation-test/tests-h87b4muq/pytest.log`.
- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py tests/target_runtime/test_repair_protocol.py tests/target_runtime/test_server.py tests/target_runtime/test_executor.py tests/target_runtime/test_policy.py tests/target_runtime/test_diagnostic_reads.py tests/test_operation_ticket.py tests/test_target_protocol.py tests/test_policy_engine_v3.py`
  - Final result: `236 passed, 1 skipped in 1.49s`.
  - Log: `/opt/a4diag-remediation-test/tests-39rybemp/pytest.log`.

### Integration details

- The server now reopens the policy on every signed execution and policy-authorized diagnostic read; it never falls back to the startup policy.
- Policy reads use `O_NOFOLLOW`, require a regular file, enforce the existing frame-size bound, and fully validate `TargetPolicy` before use.
- Missing, malformed, oversized, non-regular, and symlinked policy paths produce the stable `target_policy_unavailable` denial.
- A real `TargetSocketServer.handle` test signs prepare, atomically replaces the policy with a revoked profile set, signs apply, and verifies `profile_revoked` with zero adapter effects.
- Per the review ruling, the previous full-suite result remains the full-suite evidence; only the affected F2 and server-related regression set was rerun for this follow-up.

## Independent review corrections F2-R1 and F2-R2

### RED

- `run-remediation-tests.ps1 -q tests/contract/test_transport_plugins.py tests/target_runtime/test_server.py`
  - Result: `4 failed, 58 passed in 3.81s`.
  - Evidence: both standing and one-shot V11 prepare tickets failed at the real `PluginHost` verifier with `protocol_mismatch`; the signed profile-metadata mismatch was hidden by the same legacy-only branch; a FIFO policy replacement exceeded the bounded two-second subprocess watchdog.
  - Log: `/opt/a4diag-remediation-test/tests-m8xexcd0/pytest.log`.

### GREEN

- `run-remediation-tests.ps1 -q tests/contract/test_transport_plugins.py tests/target_runtime/test_server.py`
  - Result: `62 passed in 1.69s`.
  - Log: `/opt/a4diag-remediation-test/tests-ws6nsv2n/pytest.log`.
- `run-remediation-tests.ps1 -q tests/contract/test_transport_plugins.py`
  - Result after adding explicit legacy V1.0 relay coverage: `54 passed in 1.33s`.
  - Log: `/opt/a4diag-remediation-test/tests-hb14ethh/pytest.log`.
- `run-remediation-tests.ps1 -q tests/test_repair_authorization.py tests/target_runtime/test_repair_protocol.py tests/target_runtime/test_server.py tests/contract/test_transport_plugins.py tests/test_operation_ticket.py tests/test_target_protocol.py tests/contract/test_plugin_protocol.py`
  - Final focused result: `233 passed in 2.94s`.
  - Log: `/opt/a4diag-remediation-test/tests-7ny94dbe/pytest.log`.

### Correction details

- The plugin host now asks each strict ticketed parameter model for its ticket expectation. The unchanged base implementation constructs the exact legacy V1.0 expectation, while transport effect parameters explicitly parse the signed target-envelope version and construct a V1.1 expectation containing the signed repair binding, authorization kind, and authorization ID.
- Transport envelope validation dispatches `TargetRequest` and `TargetRequestV11` by their explicit protocol version, preserves the absent-version V1.0 default, and validates the common RPC bindings plus the V1.0 approval ID or V1.1 authorization ID before relay.
- The integration test uses the real `TicketIssuer`, `TicketVerifier`, `PluginHost`, and `LocalTransport` relay with signed V1.1 prepare envelopes. It covers successful standing and one-shot authorization and rejects a separately signed profile-binding mismatch before the helper runner is called.
- A parallel signed V1.0 prepare test verifies that the default-version ticket expectation and relay path remain unchanged.
- Policy files are opened with `O_NONBLOCK` in addition to `O_NOFOLLOW`; the existing `fstat` regular-file check therefore rejects a FIFO without waiting for a writer. The bounded forked regression replaces a previously valid live policy with a FIFO and verifies `target_policy_unavailable`, no adapter effect, and no cached fallback.
- Per the review instruction, the previous complete-suite evidence (`1433 passed, 4 skipped, 80 subtests passed`) and the production-revocation focused evidence (`236 passed, 1 skipped`) stand; no complete suite was repeated for this correction.

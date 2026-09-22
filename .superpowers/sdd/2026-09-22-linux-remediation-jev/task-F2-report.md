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
- Target policy hot reload is represented by the executor's policy-provider interface. The current socket server continues to pass a fixed policy instance, so deployed revocation becomes visible when that service is restarted with the updated policy.
- Commit subject: `feat: bind repair authorization across controller and target`; final hash is returned by the worker after the report is committed.

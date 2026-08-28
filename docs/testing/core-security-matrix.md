# Core security acceptance matrix

Run this release gate from the repository root:

```text
python -m pytest tests/test_core_security_acceptance.py -q
```

The test module uses temporary SQLite approval, transaction, and LangGraph checkpoint stores, an in-memory ticket replay store, and typed fake ports. It performs no network, subprocess, or real target operation. “Zero effects” means `prepare == apply == undo == 0`.

| Invariant | Exact pytest node ID | Expected state or error | Effect and lock invariant |
|---|---|---|---|
| Empty configuration is safe | `tests/test_core_security_acceptance.py::test_safe_empty_defaults_expose_no_target_and_no_write` | `policy_denied`; defaults are `read_only`, no targets, no LOW auto-execution | Zero effects; zero transaction rows and zero target locks |
| Unknown target is rejected | `tests/test_core_security_acceptance.py::test_unknown_target_denial_has_zero_effects` | `policy_denied`, `target_resolution_failed:*` | Zero effects |
| Plan identity must match observed identity | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[identity-mismatch]` | `policy_denied`, `target_fingerprint_mismatch` | Zero effects |
| Missing capability grant fails closed | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[missing-capability]` | `policy_denied`, `capability_not_allowed` | Zero effects |
| Missing action grant fails closed | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[missing-action]` | `policy_denied`, `action_not_allowed` | Zero effects |
| Resource outside allowlist fails closed | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[resource-escape]` | `policy_denied`, `resource_not_allowed` | Zero effects |
| Target write disable is authoritative | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[target-read-only]` | `policy_denied`, `target_read_only` | Zero effects |
| Global read-only mode is authoritative | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[global-read-only]` | `policy_denied`, `global_read_only` | Zero effects |
| Lexical path traversal cannot enter a plan | `tests/test_core_security_acceptance.py::test_lexical_resource_traversal_is_rejected_before_workflow` | Pydantic `ValidationError` | Zero effects |
| HIGH requires local approval | `tests/test_core_security_acceptance.py::test_high_without_approval_has_no_ticket_and_no_effects` | `pending_approval` | Zero effects and zero tickets issued |
| Approval is bound to frozen digest | `tests/test_core_security_acceptance.py::test_changed_frozen_digest_is_denied_on_full_high_resume` | `policy_denied`, `approval_mismatch` | Zero effects |
| Approval expiry is rechecked at resume | `tests/test_core_security_acceptance.py::test_expired_approval_is_rejected_on_full_resume` | `approval_expired` | Zero effects |
| Expired operation ticket is rejected | `tests/test_core_security_acceptance.py::test_operation_ticket_boundary_rejects_invalid_use[expired]` | `TicketError(expired)` | Zero executor effects |
| Operation ticket is single-use | `tests/test_core_security_acceptance.py::test_operation_ticket_boundary_rejects_invalid_use[replayed]` | `TicketError(replay)` | Zero executor effects |
| Operation ticket is phase-bound | `tests/test_core_security_acceptance.py::test_operation_ticket_boundary_rejects_invalid_use[wrong-phase]` | `TicketError(phase_mismatch)` | Zero executor effects |
| Same-target exclusivity and global cap | `tests/test_core_security_acceptance.py::test_transaction_locks_enforce_same_target_and_cross_target_cap` | second same-target write is `TargetBusyError`; third target is `GlobalWriteLimitError` at cap 2 | Exactly two different-target locks; never two same-target locks |
| Unknown apply is reconciled, never replayed | `tests/test_core_security_acceptance.py::test_unknown_apply_restart_reconciles_without_second_apply` | first `execution_unknown`, resumed `succeeded` after exactly one `reconcile:apply:0` and one `verify:0` | `apply:0` occurs once; a distinct same-target transaction gets `TargetBusyError` from inside recovered `verify:0`; lock releases only after verify/close |
| Completed effect survives checkpoint crash window | `tests/test_core_security_acceptance.py::test_completed_apply_crash_reconstructs_without_replay` | resumed `succeeded` after exactly one `reconcile:apply:0` and one `verify:0` | `apply:0` occurs once across rebuilt graph; an in-verify same-target probe sees busy; lock releases only after verify/close |
| Rollback order is exact reverse apply order | `tests/test_core_security_acceptance.py::test_rollback_is_exact_reverse_order` | `rollback_succeeded` | Apply is exactly `0,1,2`; undo/restoration are exactly `2,1,0`, interleaved one-for-one |
| Definite rollback failure is truthful | `tests/test_core_security_acceptance.py::test_rollback_failure_is_truthful_and_lock_safe[partial]` | durable `rollback_partial`; undo step `0` is durably `failed` | Apply `0,1`; undo/restoration `1,0`; no reconcile; terminal lock released |
| Ambiguous rollback is truthful | `tests/test_core_security_acceptance.py::test_rollback_failure_is_truthful_and_lock_safe[unknown]` | durable `rollback_unknown`; undo step `0` is durably `unknown` | Apply `0,1`; undo `1,0`; only step `1` restoration; exactly one `reconcile:undo:0`, zero undo replay, lock retained |
| Model outage cannot produce writes | `tests/test_core_security_acceptance.py::test_model_failure_is_read_only_and_has_zero_effects` | `read_only_no_model` | Zero effects |
| Optional notification failure does not replace CLI approval | `tests/test_core_security_acceptance.py::test_optional_notification_failure_is_audited_and_locally_approvable` | first `pending_approval` with `notification_failed`; local approval resumes to `succeeded` | Zero effects before local approval |
| Required notification false acknowledgement blocks approval | `tests/test_core_security_acceptance.py::test_required_notification_failure_is_blocked_and_non_approvable[false]` | `notification_blocked`; approval store rejects local approval | Zero effects |
| Required notification rejects malformed truthy acknowledgement | `tests/test_core_security_acceptance.py::test_required_notification_failure_is_blocked_and_non_approvable[malformed-truthy]` | `notification_blocked`; approval store rejects local approval | Zero effects |
| Current configuration is rechecked on HIGH resume | `tests/test_core_security_acceptance.py::test_current_boundary_revocation_on_high_resume_has_zero_effects[configuration]` | `policy_denied` after read-only revocation | Zero additional effects |
| Current identity is rechecked on HIGH resume | `tests/test_core_security_acceptance.py::test_current_boundary_revocation_on_high_resume_has_zero_effects[identity]` | `policy_denied`, `target_identity_changed` | Zero additional effects |

Any node ID change requires rerunning `pytest --collect-only` and updating this table in the same change.

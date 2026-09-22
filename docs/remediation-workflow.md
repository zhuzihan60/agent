# Registered repair workflow

Repair profiles supplement the existing global `read_write`, target
`write_enabled`, capability/action/resource grants, pinned plugin contracts,
identity checks, and execution budgets. Both controller and target need their
own registered profile. A profile does not lower HIGH repair risk.

The controller currently resolves a unique profile by target, capability and
resource, then validates its action, exact parameters, recovery checks and
expiry. An invalid or ambiguous registered scope is denied rather than falling
back to the legacy protocol. `resolve_repair_profile(..., candidate_id=...)`
also accepts an advisory registered ID for future model selection; it grants
no authority. Canonical V10 `Operation` bytes are unchanged.

Before authorization, the checkpoint freezes each selected profile ID and
digest, the operation's manifest effect kind, and the target's transport and
identity registration. Every repair mutation reloads controller configuration
through the production runtime's settings loader and rechecks these bindings.
One-shot authorization comes from `ApprovalStore.valid_approval` for the exact
transaction, target and plan. A plan entirely covered by explicit standing
profiles can omit one-shot approval. Mixed plans still require normal approval.
Prepared markers are digest-bound into fresh V11 authorization and tickets.

V11 APPLY returns a durable job envelope. Controller and target reservations
retain their locks while execution is prepared, running or unknown. The
controller persists the job against the frozen target/transaction/step/profile
and operation. Pending work reports `execution_unknown`; it does not undo or
repeat an effect on a timeout or cancelled connection.

`Runtime.resume(transaction_id)` (also `a4diag resume`) performs one bounded
signed job observation using the original authenticated durable APPLY ticket
and persisted job reference. That read remains possible after profile expiry,
revocation or controller read-only mode. Original ticket expiry is ignored
only while authenticating this historical observation proof; the new target
request has a fresh bounded expiry and nonce. Query transport methods cannot
relay prepare, apply, undo or confirm requests. If the APPLY response was lost
before a job ID was saved, the controller keeps the transaction unknown for
manual reconciliation rather than guessing or resubmitting.

The production daemon calls `RuntimePoller.heartbeat()` every five seconds
between passes, independently of its 600-second alert fetch thread. The
heartbeat invokes `Runtime.poll_repair_jobs(limit=2)`; callers may choose a
limit from 1 through 32. Durable candidates rotate by transaction ID, with
bounded work per pass and busy transactions skipped. A known successful job
can advance the remaining frozen plan through the same live authorization
checks. These entry points are the S2 scheduler seam for future stable health
samples and total-budget accounting; RPC duration still contributes to the
time between passes. Heartbeats never diagnose or generate a new plan.

`Runtime.cancel_repair(transaction_id)` durably prevents further mutations,
including compensation. Active jobs remain observable until a terminal
result is known. Cancellation neither kills a target worker nor releases an
uncertain resource reservation. A protected per-transaction OS lock serializes
daemon and CLI workflows across processes; it is released on process exit.
The separate durable resource reservation remains locked across crashes.

`Runtime.confirm_repair_job(transaction_id, step_id)` issues a fresh ticket
after current write authorization. It only acknowledges an already terminal,
ownership-bound job and may recover its unreleased reservation. It does not
confirm a network configuration, convert uncertain execution to success, or
prove business recovery. Stable recovery observation belongs to S2 and signed
network nonce/config/deadline confirmation belongs to N2.

Effect kinds come from pinned manifests, never model operation fields. New
service start/restart/stop operations are `compensatable`: checking unit state
after compensation does not restore process memory or application side effects.
Changed irreversible steps are not automatically undone. A full rollback is
reported only when every changed effect is restorable and restoration was
independently verified. Unknown change takes precedence over partial rollback.
Per-step evidence is persisted, reported and included in runtime audit events.
Historical checkpoints without effect declarations preserve their original
classification; loading a new manifest does not reclassify old operations.

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

The production daemon calls `RuntimePoller.heartbeat()` every one second
between passes, independently of its 600-second alert fetch thread. The
heartbeat invokes `Runtime.poll_repair_jobs(limit=2)`; callers may choose a
limit from 1 through 32. Durable candidates rotate by transaction ID, with
bounded work per pass and busy transactions skipped. A known successful job
can advance the remaining frozen plan through the same live authorization
checks. Registered service recovery also uses this scheduler for preflight
failure evidence and sustained health observation. RPC duration contributes
to the time between passes. Heartbeats never diagnose or generate a new plan.

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
prove business recovery. Signed network nonce/config/deadline confirmation
belongs to N2.

## Service recovery

Registered `start`, `restart`, `reset-failed`, `reset-failed-start` and
`reset-failed-restart` plans require at least three consecutive failed business
samples spanning ten seconds before PREPARE. Unknown evidence, healthy units,
and activating/deactivating units do not qualify. A live PID plus failed HTTP
is anomaly evidence; it does not establish why the application stopped
responding. Legacy unprofiled service operations and disk writer stops retain
their existing flow.

A compound action is one exact signed action/marker, detached target job and
resource reservation. Both the compound name and each constituent action must
be explicitly allowed in the registered profile and controller capability
grant. For example, `reset-failed-start` needs actions
`["reset-failed-start", "reset-failed", "start"]`. Target profile authorization
checks the same constituents independently. Reset actions are unavailable in
the legacy unprofiled target protocol. Counters/history and process memory
cannot be restored; resets and restarts are compensatable effects. A failed
recovery never invokes another service start/restart as compensation.

The controller claims the persistent default 600-second cooldown and two
attempts/hour allowance before PREPARE. Subsequent APPLY and queries use that
same attempt; repeated alarms, controller restarts and unknown jobs cannot
reset or bypass it. Unknown execution remains excluded from further mutation.

Success requires actual healthy samples over at least 60 seconds, with no gap
larger than five seconds (or the profile's stricter interval), an unchanged
InvocationID/MainPID, and unchanged restart count. The one-second heartbeat
leaves RPC slack; it is not a guarantee that every concurrent job is sampled
on time. A gap discards the incomplete window. Sampling uses unrounded
monotonic completion times, including HTTP and diagnostic request duration.
Each sampling RPC is bounded; the workflow yields between samples instead of
holding a 60-second RPC open. A relapse stops recovery without another restart.

The total budget starts at the first preflight observation and includes
eligibility, effect execution and post-observation. It defaults to 300 seconds;
explicitly longer configured windows use `max(300, window + 120)`, bounded by
the existing maximum 600-second window to at most 720 seconds. The first
admission freezes the deadline. Process/boot restarts discard sample
continuity, but retain the original deadline and consumed budget. A config
change cannot extend it. Backward/discontinuous clocks fail conservatively.

Accepted work can continue read-only observation after profile revocation,
using its frozen original profile and health-check catalog. Current replacement
checks cannot introduce another endpoint or resource. Unavailable or revoked
target reads/identity produce an unknown/manual outcome; they never establish
recovery. Fresh mutations and confirmations still require current independent
authorization. Success means healthy during the observation period, with the
root cause unproven; reports retain that residual risk and measured samples.

Effect kinds come from pinned manifests, never model operation fields. New
service start/restart/stop operations are `compensatable`: checking unit state
after compensation does not restore process memory or application side effects.
Changed irreversible steps are not automatically undone. A full rollback is
reported only when every changed effect is restorable and restoration was
independently verified. Unknown change takes precedence over partial rollback.
Per-step evidence is persisted, reported and included in runtime audit events.
Historical checkpoints without effect declarations preserve their original
classification; loading a new manifest does not reclassify old operations.

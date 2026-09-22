# Authenticated writer preparation

`PreparationDependency` is trusted core context for the compiled
`services.stop -> disk.cleanup` sequence. It is not an operation parameter or
model grant. The stop and dependent step, profile IDs/digests and operation
digests are frozen before dispatch. The outer HMAC and Ed25519 request bind
controller/target/transaction/plan identity. `stop_job_id` is absent only for
the stop's own PREPARE/APPLY; later requests carry the admitted job ID. An
absent dependency preserves historical canonical serialization, including V10.

For an original stop's read-only job observation, the transport derives its
stop reference from the bound job ID without changing the historical HMAC
claim. A validated APPLY or QUERY response supplies that same reference for
later VERIFY/RECONCILE. A dependent job always retains the original stored
stop ID, which is distinct from the dependent job's own ID.

An administrator must explicitly include `stop` in a services profile's actions.
A disk writer setting cannot grant that action. Ordinary stop operations without
a preparation dependency retain their existing lifecycle.

## Controller integration

The staged workflow must persist its finally obligation and frozen dependency
before invoking `issue_repair_ticket(..., preparation_dependency=dependency)`.
It reserves the existing attempt budget with `reserve_attempt`. Existing graph
service APPLY/UNDO calls already use `controller_mutation_guard`; this guard
persists the exact stop hold before dispatch. `record_job` binds the admitted
job to that hold using the original authenticated durable APPLY ticket.

The finally runner must obtain fresh current authorization for the original
stop's UNDO, use its original marker and operation undo payload, and independently
verify restoration. After each result, call
`record_controller_restoration(deps, state, stop_step_id, phase=..., result=...)`
with `phase='undo'` or `phase='verify_restored'`. This is an internal trusted
result hook, not a tool/model endpoint. It requires the original authenticated
job binding; it cannot be used as authority to dispatch an effect. A successful
UNDO result alone does not release the hold. Cancellation/revocation/expiry and
unknown jobs leave an explicit unresolved obligation for the workflow to report.

The target persists the original signed envelope, establishes the hold before
worker launch, and keeps its reservation through terminal stop success. Both
ordinary V10/V11 service mutation dispatch and independent workers use the same
resource guard for the duration of the mutation. Controller and target guards
are scoped to their respective protected database. The launcher never waits for
worker completion while holding its guard. Generic job confirmation cannot
release a writer hold. Current-authorized signed UNDO followed by successful
independent `verify_restored` releases it; repeating that read after a lost reply
is safe. Installer/uninstaller drain includes ordinary and helper jobs plus
unresolved holds, even when their stop job is terminal.

An independent service worker can briefly wait for its parent's admission
guard, bounded by 15 seconds, its signed request expiry and the existing action
timeout. It reloads authorization and ownership after waiting, and dispatch uses
only the remaining action timeout. A timed-out or newly unauthorized worker
retains unknown ownership; waiting never expires a durable hold.

## Capability preparation integration

The authoritative target disk dispatcher must call
`read_stop_proof(request, verifier=..., current_policy=..., writer_unit=...)`.
The reader uses only `/var/lib/a4diag-target/executor/repair-jobs.sqlite3`, opens
it read-only with bounded queries, and authenticates the original envelope
against the current controller key. It checks the stored request, successful
stop result, exact dependency/context, unreleased hold, and actual stopped unit
and cgroup boundary. Its `StopProof` contains `original`, `marker`, `job_id` and
`writer_snapshot`; the original marker comes from protected history. Missing
historical envelopes are ineligible proof but existing jobs remain queryable.
Historical expiry/replay consumption may be ignored only by this read-only
inspection, never for new execution.

The disk adapter must retain the scanner's bounded before/after writer and
filesystem checks and construct its final marker from this authenticated proof.
The reader is evidence, not authority for deletion or restoration. The staged
prepare frontier, finally scheduling, disk adapter registration and deletion are
the subsequent integrated disk deliverable.

## Unavailable effects

A compiled target adapter may implement synchronous `admit_effect(request)` and
raise `EffectAdmissionRejected` before its effect method is invoked. The worker
then records a normal bound failed job with verified `changed=false`. The hook
must be read-only. Request fields cannot create this evidence. Once effect
invocation begins, failures/exception/default `changed=false` retain the existing
uncertain-result rules. No preparation-only mode or successful cleanup is added.

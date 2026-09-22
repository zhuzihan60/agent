# Registered disk and inode cleanup

This source implementation supports one frozen HIGH-risk plan: an explicitly
granted `services.stop` for the registered writer, followed by `disk.cleanup`
for its exact administrator-owned cache. It prepares/applies/verifies the stop
before preparing candidates. It restores the prior service state through the
original stop's newly authorized signed UNDO and independent verification,
then checks real available bytes/inodes and configured business health.
An already inactive writer remains inactive; its signed no-op stop reports no
change. No separate `services.start` job or quota bypass is used.

Both sides must register these profiles (example values, choose a real expiry):

```json
[
  {"id":"cache-writer","target_id":"target-1","capability":"services",
   "resource":"cache-writer.service","actions":["stop"],"constraints":{},
   "recovery_check_ids":["health"],"expires_at":1798761600,
   "standing_authorization":true},
  {"id":"app-cache","target_id":"target-1","capability":"disk",
   "resource":"/var/cache/demo","actions":["cleanup"],
   "constraints":{"writer_unit":"cache-writer.service","min_age_seconds":3600,
     "max_files":100,"max_bytes":67108864,"min_free_bytes":1048576,"min_free_inodes":10},
   "recovery_check_ids":["health"],"expires_at":1798761600,
   "standing_authorization":true}
]
```

On the controller, set the target's `repair_profiles` to the above array;
retain identity/SSH bindings and explicitly grant both capabilities:

```yaml
capabilities:
  - {name: services, actions: [stop], resources: [cache-writer.service]}
  - {name: disk, actions: [cleanup], resources: [/var/cache/demo]}
recovery_checks:
  - {id: health, kind: http, resource: 'https://app.example.com/health', attempts: 3}
```

The default remains read-only. Actual mutations also require the existing
`global_mode: read_write`, target `write_enabled`, pinned/enabled contracts,
and either exact-plan one-shot approval or explicit standing authorization on
both profiles. Omit standing authorization for approval on each transaction.
Defaults remain one attempt/resource per ten minutes and two per hour.

In the existing target install document, retain public-key/source-CIDR fields,
set `repair_profiles` to the same exact array, and add:

```json
{"repair_helpers":[{"profile_id":"app-cache","adapter":"disk-cache"}],
 "confirm_repair_helpers":"ENABLE"}
```

Use the existing installer with that document. The separately registered
service profile uses the ordinary authorized executor. The disk worker gets
write access only to its exact cache and `/var/lib/a4diag-target/repair-helpers/app-cache`;
it cannot reach the systemd manager. The compiled dispatcher performs fixed
systemd diagnostics; the worker rechecks protected stop/hold evidence, current
grants, unit/drop-in file signatures, cache topology and the pinned cgroup-v2
parent/exact child before each deletion. Only `Slice=system.slice` with an
unambiguous non-instanced unit name is supported. Missing/changed parent or a
populated child is denied. An absent child is valid only under the checked
parent. Persisted identities use device/inode/path, never cross-namespace mount
IDs or raw FD numbers. Units/configuration must be readable inside the worker;
ephemeral `/run` unit fragments are unsupported by its manager-denying sandbox.

See [scanner restrictions](repair-disk-preparation.md): protected root-owned
paths, a declared sole writer, disabled/static unit, no automatic activation,
no delegation, no group/other-writable entries, symlinks, hardlinks or nested
mounts. Root administrators remain trusted; this does not prevent a concurrent
root administrator from starting another writer. Protected Agent/package state
roots and their ancestors cannot be cleanup roots.

Existing invocation remains `Runtime.handle(event)` / `a4diag serve`, followed
by the normal approval flow when required and `a4diag resume TRANSACTION` (or
daemon heartbeat). There is no new cleanup shell command. The deterministic
acceptance entrypoint, with no model/provider calls, is:

```sh
A4DIAG_TEST_DISK=1 python -m pytest -q tests/integration/test_disk_remediation.py
```

Run that opt-in test only in the disposable named D-backed lab: it creates
64 MiB ext4 images and temporary writer services. Production graph, HMAC
PluginHost, signed target/helper admission and independent sandboxed workers
are exercised. Model planning/evidence triggering are deterministic fixtures;
actual bytes, inodes, services and HTTP responses are measured. This is source
and staged-runtime acceptance, not the later built-package/SSH platform matrix
or real-model acceptance, and no release is asserted.

Each PREPARE preallocates a protected per-transaction audit before cleanup.
Each unlink has a durable intent and completion slot. File identities are
rechecked immediately before unlink; changed files are retained. Recovery
uses `statvfs`, not logical bytes unlinked (an open file may retain all blocks).
Audit write failure stops before that unlink. Space reservation is never used
for cache data. Cleanup is irreversible: HTTP failure despite adequate capacity
reports `rollback_partial`, with separate verified writer-restoration evidence.

Cancellation, expiry or revoked authorization permit observation only and
retain the unsatisfied writer obligation for manual recovery. Lost admission
replies without a saved job ID and interrupted UNDO without authenticated
completion remain unknown; neither APPLY nor UNDO is retried. When a claimed
cleanup worker is proven gone, the authenticated audit may terminalize as
partial and allow current-authorized writer restoration. Outstanding intents
retain `changed=null` and an `uncertain` count; absence never invents removed
file/byte counts. Their cleanup reservation remains locked, generic confirmation
is refused and installation requires manual reconciliation. Repeated queries
are stable and never repeat deletion. Audit files are retained as evidence.

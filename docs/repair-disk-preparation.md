# Read-only disk candidate preparation

The target runtime contains the D1a candidate scanner. No production disk
capability or helper adapter is registered yet. This code does not stop a
service, delete files, restore a writer, or claim capacity recovery. Disk
profiles, authenticated stop history, durable writer reservations, staged
execution and finally compensation remain prerequisite integration work.

`prepare_cleanup(DiskLimits, now_ns=...)` checks an already stopped writer,
scans candidates, then checks the writer again. Its `DiskMarker` deliberately
has `writer_stop_marker=None`: diagnostics cannot manufacture authorization or
evidence that this transaction stopped a service. The lower-level
`_scan_candidates` performs filesystem checks only and is not an authorization
entry point. Async integration must call the synchronous diagnostic in a worker
thread.

The supported boundary is deliberately narrow:

- The administrator selects an exact cache root and an exact nonprotected
  `.service` unit. Every root ancestor, cache directory and candidate file is
  root-owned and not writable by group or other users. Privileged administrators
  remain trusted; these checks cannot exclude another root process. Future
  profile integration must establish the registered sole-writer relationship.
- The service must be loaded, inactive/dead, with no process, control process,
  pending systemd job, populated cgroup, delegation or dynamic/nonroot user.
  `KillMode=control-group`, `SendSIGKILL=yes`, `Restart=no` and
  `RemainAfterExit=no` are required. A nonempty cgroup must expose a bounded
  cgroup-v2 `cgroup.events` with `populated 0`.
- Only disabled/static units are accepted. Reported socket/timer/path triggers,
  reverse dependency activation (including `OnFailureOf` and `OnSuccessOf`)
  and upheld units are refused. Unit fragments
  and drop-ins must be protected regular files. Missing, duplicate, oversized
  or unsupported diagnostic properties fail closed. This is not general
  support for all systemd service configurations.

The only diagnostic command is a fixed `/usr/bin/systemctl show` property query,
with a clean environment, a five-second timeout and 16 KiB per output stream.
It issues no mutation. Real systemd formatting was inspected in the disposable
Linux lab; service-state test fixtures represent read-only observations, not
an autonomous stop/cleanup/restoration test.

Directory traversal opens each level with `O_NOFOLLOW`, retains ancestor FDs,
and rechecks names and ownership. The final candidate traversal also checks each
directory against its saved first-pass identity/metadata, ownership, permissions
and mount identity, and rechecks the leaf's mount through an `O_PATH` FD.
Candidates must be singly linked regular
files. Device and Linux mount identities reject nested mounts, including bind
mounts on the same filesystem. Saved inode/device/size/mtime/ctime bindings are
rechecked after scanning; the later apply stage must check them again before
any deletion. FIFOs and symlinks are never opened for content.

Preparation is bounded to 32 root components, 1,024 root-path characters,
eight nested directory levels, 4,096 scanned entries, at most 1,024 candidates,
and 192 KiB of candidate-marker budget. The registered limits further constrain
candidate count and logical bytes. Exceeding a budget raises
`preparation_budget_exceeded`; the scanner never silently truncates a candidate
list. Recently modified regular files are excluded. Initial free bytes and
inodes come from `fstatvfs` on the held root FD and are observations, not proof
that any recovery target has been met.

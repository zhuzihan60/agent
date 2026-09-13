# Linux fault recovery foundation

The user selected Linux as the first environment for a general fault-repair agent.
Extend the existing signed service/file repair workflow with reusable administrator-defined
diagnostics and recovery predicates. Ship working file-permission/configuration recovery
scenarios and explicit diagnostic coverage for capacity, resources, connectivity and packages.

## Contract

`a4diag.linux_probes.LinuxProbe` has `id`, `kind`, `resource`, `max_bytes` (default and maximum 1048576).
Kinds: `filesystem` (canonical absolute directory, including `/`), `memory` and `load`
(resource `host`), `file` (canonical absolute file), `package` (exact package name),
`tcp` (`tcp://host:port` without path, credentials or query), `dns` (exact hostname).
At most 8 probes per target; no duplicate IDs. File probes additionally require existing
target managed-root read authorization. No subprocess accepts model-authored argv.

Output fields:
- filesystem: total_bytes, available_bytes, used_percent, free_inodes (integers).
- memory: total_bytes, available_bytes, used_percent, swap_total_bytes, swap_free_bytes (integers).
- load: load_1_milli, load_5_milli, load_15_milli, cpu_count (integers).
- file: exists (bool), mode, size_bytes (integers), sha256 (string; empty if unavailable).
- package: installed (bool), version (string; empty if not installed).
- tcp: reachable (bool).
- dns: resolved (bool), addresses (list of canonical IP strings, at most 16).

`TargetConfig.diagnostic_probes` and target `TargetPolicy.diagnostic_probes` contain these
definitions independently. The target resolves only an authorized probe ID. Evidence adds
kind `probe`, resource=probe ID. Recovery adds kind `probe`, resource=probe ID, and nonempty
`conditions` with field/operator/value. Operators eq/ge/le/contains are type-checked against
the registered output contract. All conditions and all recovery checks must pass. Results
are recollected after execution and identity is checked before/after; old evidence cannot
prove recovery. File attribute checks require exists=true; package version checks require
installed=true. Unknown IDs, fields, malformed/truncated output and missing probes fail closed.

Target read RPC adds `kind=probe, probe_id=...`; probe definitions never arrive through RPC.
Network probes use bounded subprocesses to avoid uninterruptible resolver threads, and
network families are enabled in the executor only when a target administrator registers
TCP/DNS probes. Existing system service/network configuration protections remain.

## Scope and acceptance

No generic shell execution, broad filesystem deletion, arbitrary process killing or automatic
host-network edits. Package installation remains unavailable in the hardened installer;
package state is now observable and verifiable. Unsupported remediation produces a diagnostic
report rather than invented success. Existing service/file prepare/apply/verify/undo remain
the repair surface for this foundation; new actions can be added as separately verified plugins.

Acceptance: adversarial ID/path/predicate tests, real Linux probe reads, probe evidence over
the production transport interface, after-repair file mode/content verification and failure
handling, legacy suite and distro CI green. Document exact coverage and limitations.

Ruling: first Linux increment prioritizes complete observable, verifiable service/file repairs;
disk cleanup and network mutation require separate operation contracts and are not advertised
as automatically repairable in this increment.

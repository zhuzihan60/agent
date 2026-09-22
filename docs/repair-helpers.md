# Isolated repair helper foundation

The default installation has no repair profiles, no repair helper sockets, and
`new_write_helpers_enabled: []` in its installer output and
`/etc/a4diag-target/repair-self-check.json`. Existing 1.0 install configuration
remains accepted. The production repair adapter registry is deliberately empty:
this foundation does not implement disk, container, APT, or network repairs.

An administrator enables a future registered adapter with `repair_profiles`,
`repair_helpers: [{"profile_id": "...", "adapter": "..."}]`, and literal
`confirm_repair_helpers: "ENABLE"`. Every profile must have exactly one compiled
adapter for a new helper scope; existing service profiles may retain their
ordinary executor path. A helper cannot share a resource with another helper or
legacy profile. Unknown adapter names,
extra fields, duplicate scopes, or caller-specified state paths are rejected.

The installer creates protected profile bindings, a public routing map, private
per-profile state directories, and exact systemd service drop-ins. The relay
uses only a fresh bounded root-owned routing map to choose a fixed Unix socket.
Routing does not grant authority. A missing or invalid registered helper route
fails closed; the ordinary executor socket also rejects helper-owned V11
requests. Existing services V11 with no helper registration retains its current
path. Other capabilities never fall back to that path. V10 uses its existing
path and sandbox.

Each installed helper requires the configured `a4diag-target` peer UID and a
bounded SignedTargetRequest. It reuses TargetVerifier, TargetExecutor, the replay
ledger, RepairStore, and JobStore. Signature, target identity, current target
policy, nonce, operation/profile/marker binding, ownership, and resource budgets
retain their existing checks. Installed bindings remain separate from mutable
policy grants: removing a grant still permits a freshly signed query for the
same existing job, never a new mutation.

## Trust and sandbox boundary

The dispatcher is a trusted root broker. Its only job launch path uses fixed
SystemdJobLauncher argv and unit identity; sandbox properties come from compiled
code and a protected installed profile. Neither requests nor configuration can
import Python modules or supply commands, systemd properties, or socket paths.
Compiled adapter code is trusted; this is not a sandbox for malicious plugins.

The independent worker reloads its installed binding and current policy before
the first effect. Its writable paths come from that same scope. It retains
ProtectSystem=strict, NoNewPrivileges, private devices/home/tmp, empty Linux
capability bounds, and AF_UNIX. Its private read-only `/run` denies the systemd
private socket, system bus, and rootless user buses; only explicitly registered
capability sockets are bound into it. The dispatcher keeps manager access to
launch workers. A worker cannot start an unrelated unrestricted unit.

## Adapter extension API

Concrete capability tasks extend `a4diag_target.repair_install.ADAPTERS` with an
`AdapterSpec(capability, sandbox, plugin)` and add the same ID to
`a4diag.builtin_catalog.REPAIR_ADAPTER_IDS`. This registry is independent of the
ten built-in plugin manifests. The sandbox callback accepts the exact validated
RepairProfile and returns `Sandbox(write_paths, socket_paths, run_uid)`; the
plugin factory returns the bounded lifecycle implementation used in both
dispatcher and worker. Future tasks also extend the currently closed profile
schema. They must test the installed route, worker, and current-policy gates.

Disk adapters must derive only authorized cache and state paths. Container
adapters must bind only registered daemon sockets. APT must have a separately
confirmed adapter and explicitly reviewed package-management write paths;
it cannot borrow the main executor's permissions. Network adapters must derive
only registered configuration/watchdog state and provide an independent
restoration mechanism. No generic command/import/property configuration exists.

Rootless adapters currently fail with `rootless_helper_not_wired`. Their task
must add protected policy/store access for the exact registered UID and prove
that lifecycle reads and worker effects use that UID. There is no fallback to
root or caller-provided XDG/DBus environment. Additional APT/network privileged
operations require a separately reviewed fixed interface; manager access must
not be restored to workers by default.

## Installation and recovery

Installation serializes with a filesystem lock, validates before publication,
stops old helper admission, and rechecks durable jobs. Any prepared, running, or
unknown helper job blocks installation, reconfiguration, or uninstall, even if
the proposed scope is unchanged. Operators must resolve these jobs first; the
installer never kills independent workers or releases uncertain reservations.
State is retained for audit.

A root-only journal snapshots configuration, routes, unit drop-ins, relay,
public keys, and the current release link. Failure restores these artifacts;
the next installer process recovers an interrupted journal before publishing a
new configuration. Recovery also refuses to replace artifacts while an accepted
job remains nonterminal. A filesystem/service failure during recovery is an
operator-visible installation failure, not a claimed successful rollback.

`tests/integration/test_repair_helpers.py` is opt-in with
`A4DIAG_TEST_SYSTEMD=1` in a disposable systemd lab. Its root-installed fixture
registers a bounded test adapter only in the staged test runtime, writes a single
test effect, and checks independent completion and denied outside writes/manager
access. It does not claim real capability repair or historical release upgrade
coverage. The existing release-manifest tests verify the shipped unit inventory.

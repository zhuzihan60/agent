# A4Diag 0.4.0

Generic, fail-closed diagnostics agent with a pinned plugin runtime,
digest-bound CLI approvals, an atomic offline/online installer, and hardened
systemd units. Targets resolve **only by registered id** — never by IP and
never by fallback; HIGH-risk operations always require a human CLI approval;
unknown executions are never replayed.

> Documentation-only addresses (RFC 5737 `192.0.2.x`) are used in examples;
> they are never present in runtime source or the default configuration.

## Install

```bash
git clone <repository> a4diag && cd a4diag
sudo ./install.sh --offline /path/to/verified/release-dir   # or: sudo ./install.sh --online
sudo a4diag self-check --offline
```

See [docs/install.md](docs/install.md) for the full contract (verification,
atomic switch, rollback, uninstall) and
[docs/migration/v0.3-to-v0.4.md](docs/migration/v0.3-to-v0.4.md) to migrate
from v0.3.

## Safe defaults

- `a4diag init` writes `global_mode: read_only`, `targets: []`,
  `plugins: []`; `write_enabled` requires the literal `ENABLE` confirmation.
- Every alert / MCP tool / collector path resolves targets only against
  registered ids; an unregistered label is dropped (`policy_denied` /
  `read_only`), never routed.
- The audit chain is chained, fsynced, and verified at startup; a broken
  chain forces read-only.

## Registering targets (documentation-only addresses)

```bash
sudo a4diag init --input target-request.json   # host/port/user are SSH-only fields
sudo a4diag self-check --offline               # target registered, still read-only
```

Example request (address is documentation-only; never commit a real address):

```json
{"targets": [{"id": "target-1", "mode": "ssh",
 "host": "192.0.2.10", "port": 22122,
 "user": "a4diag", "capabilities": [{"name": "files", "actions": ["replace"],
 "resources": ["/etc/example/**"]}]}]}
```

(`identity_ref` is derived as `target/{id}` by `a4diag init` and is never
accepted from a request.)

## Plugin pinning

```bash
sudo a4diag plugin list
sudo a4diag plugin install capability-services-0.4.0.pkg
sudo a4diag plugin disable capability-services
```

Pins bind name/version/api + artifact/manifest SHA256; the registry refuses
unknown, unverified, or API-incompatible packages.

## Low- and high-risk behavior

- LOW (auto_execute_low): executes and verifies; reports carry typed
  operations, the fixed command display, evidence, and residual risk.
- HIGH: stops at `pending_approval` with zero executor dispatch until a
  digest-bound CLI approval:

  ```bash
  sudo a4diag approvals list --json
  sudo a4diag approvals show <transaction>
  sudo a4diag approvals approve <transaction> --digest <digest>
  ```

- Unknown executions stop as `execution_unknown`; resume reconciles from the
  durable dispatch intent and never re-applies.

## Notifications (optional plugins)

Register one of `notification-cli`, `notification-smtp`, `notification-webhook`,
`notification-flashduty`. Delivery is the plugin's job; the core only records
delivery status and blocks required-notification approvals until delivered.

## Offline verification

```bash
python tools/build_release.py verify-source --project-root .
python tools/build_release.py verify-release --release-root <release-dir> \
  --signing-key /path/to/release.key
```

## Uninstall

```bash
sudo systemctl disable --now a4diag-core.service
sudo rm -rf /opt/a4diag/releases /opt/a4diag/current
```

Keep `/etc/a4diag` and `/var/lib/a4diag` for audit unless you explicitly
decide to remove them.

## Development

```bash
python -m pytest -q          # full suite (documented POSIX skips on Windows)
python -m pytest tests/acceptance -q
```

See [docs/testing/distro-matrix.md](docs/testing/distro-matrix.md) and
[docs/testing/acceptance-runbook.md](docs/testing/acceptance-runbook.md).

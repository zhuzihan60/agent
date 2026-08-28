# Built-in plugin conformance matrix

All built-in plugins are validated by one shared harness
(`tests/contract/test_all_manifests.py`) plus the shared host contract
(`tests/contract/test_plugin_protocol.py`, `test_plugin_crash_matrix.py`) and
the per-family suites (`test_transport_plugins.py`, `test_capability_plugins.py`,
`test_model_plugin.py`, `test_notification_plugins.py`). AF_UNIX, symlink,
permission, and owner capability gates run as mandatory Linux release checks.

## Manifests

| Manifest | Type | Operations / surface | Risk floors | Network | Secret refs |
|---|---|---|---|---|---|
| `transport-local` | transport | `verify_identity`, `read`, `execute_typed` | read low / write high | none | — |
| `transport-ssh` | transport | `verify_identity`, `read`, `execute_typed` | read low / write high | target-ssh | `target:ssh-key`, `target:known-hosts` |
| `capability-files` | capability | `files.replace_managed_file` (low), `files.set_mode` (low) | read low / write high | none | — |
| `capability-services` | capability | `services.restart/start/stop/enable/disable` (low) | read low / write high | none | — |
| `capability-packages` | capability | `packages.install_exact` (high), `packages.remove_exact` (high) | read low / write high | none | — |
| `model-openai-compatible` | model | `diagnose`, `plan`, `critic` | read low / write high | model-provider | `model:api-key` |
| `notification-cli` | notification | `send` | read low / write high | none | — |
| `notification-flashduty` | notification | `send` | read low / write high | notification-endpoint | `notification:flashduty-integration-key` |
| `notification-smtp` | notification | `send` | read low / write high | smtp-server | `notification:smtp-user`, `notification:smtp-password` |
| `notification-webhook` | notification | `send` | read low / write high | notification-endpoint | `notification:webhook-hmac-key` |

## Harness checks (`test_all_manifests.py`)

- Strict manifest schema (`PluginManifest`, `extra="forbid"`, frozen).
- API negotiation: `api_min <= 1.0 <= api_max`, major version 1.
- Absolute Unix socket path with no traversal.
- `executable` resolves to an importable `module:function` in the built-in
  package, and the expected plugin class exists.
- Operation parameter schemas are strict JSON Schema (root `object`,
  `additionalProperties: false`, self-contained) via the same validator the
  registry uses.
- Risk floors: manifest `write_risk_floor >= read_risk_floor`, and every
  capability operation floor is covered by the manifest write floor.
- Claimed surface: capability operations may only claim
  prepare/apply/undo/verify/reconcile that the registered RPC surface
  provides; each manifest's expected RPC method names are fixed per type.
- Declarations: transports must declare permissions; model must declare
  `model-provider` and a `model:` secret ref; notifications must declare
  permissions.
- Wheel consistency (when a wheel exists in `dist/`): exactly one wheel and
  no sdist; every manifest and every plugin module is inside the wheel; the
  entry point is exactly `a4diag-plugin = a4diag_builtin_plugins.host:main`;
  no test fixtures, `.pyc`, secrets, or fixed target IPs are packaged.

## Crash / recovery matrix (`test_plugin_crash_matrix.py`)

- Effect handler crash after dispatch → `execution_unknown`, details redacted
  (an internal secret never reaches the client), and the host quarantines.
- Restart (a fresh host sharing the same replay store) restores `health` and
  `read`; the crashed ticket is never replayed; a freshly issued ticket
  executes normally after restart.
- Invalid ticket → `malformed_token` with zero dispatch.
- Duplicate request → `replay` with zero second dispatch.
- Oversized / malformed frames → stable `payload_too_large`, `multiple_frames`,
  `invalid_json`, `invalid_utf8`, or `duplicate_key`.
- Oversized handler output → `invalid_handler_result` (RPC response bound).
- Effect timeout → `execution_unknown`; reconcile on the same quarantined
  instance stays blocked while a fresh instance serves health.

## Security invariants enforced by the suites

- No generic LOW shell method; every execution is a fixed argv template or
  typed helper action; `shell=True` is absent from the package.
- Identity drift, host-key change, or ticket mismatch blocks writes before
  dispatch (zero operation spawn).
- HIGH operations require a ticket with approval; unknown executions are never
  automatically retried.
- Strict typed schemas reject raw `command`/`shell`/`script`/`argv` fields from
  model output.
- Secrets are secret references resolved per call; they never appear in code,
  logs, URLs, error messages, or delivered notification payloads.
- Notification retries cover only connection errors, 429, and 5xx.

## Phase 4 Linux gates

Six real AF_UNIX host/client/path cases and two symlink-privilege cases are
mandatory Linux Phase 4 gates; no permission, invalid-path, or broad `OSError`
skip is accepted as release evidence.

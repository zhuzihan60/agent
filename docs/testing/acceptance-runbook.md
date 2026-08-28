# Local/SSH safety and chaos acceptance runbook

The acceptance suite (`tests/acceptance/`) proves the agent's boundaries and
recovery behavior **without connecting to any real server, SSH daemon, mail
server, model API, or FlashDuty endpoint**: every "machine" is an injected
fake whose every attempted connection is recorded in a ledger, and the
runtime under test is the real Phase 3 `Runtime`.

## Running

```bash
python -m pytest tests/acceptance -q
```

All scenarios run with fakes and pass locally. The live `t_11` sandbox
scenario is staged with `@pytest.mark.live_t11` and only executes when a real
disposable environment is available:

```bash
sudo A4DIAG_ACCEPTANCE=1 python -m pytest tests/acceptance -q
```

## Coverage

| File | Scenarios |
| --- | --- |
| `test_local_remediation.py` | LOW fault repaired and verified; outside/unregistered target never contacted (zero ledger entries); identity drift blocks write revalidation; unknown execution never replayed; model timeout and network drop fail closed with zero executor calls; a consumed ticket cannot be reused; live t_11 scenario staged. |
| `test_ssh_remediation.py` | host-key change blocks everything (zero apply/undo); SSH username comes from config, never hardcoded; unregistered SSH destinations (IP/hostname/other id) are never contacted; authorization is by registered name only — even a registered target's own IP never authorizes. |
| `test_plugin_chaos.py` | crash before dispatch, after apply, and during prepare — all reconcile from the durable dispatch intent with `apply_count == 1` at most; verify failure triggers reverse-order rollback; undo crash reports `rollback_unknown`/`execution_unknown` truthfully; network loss during apply fails closed and never retries. |
| `test_high_risk_gate.py` | HIGH without approval: zero executor dispatch; wrong digest stays blocked; correct local CLI approval dispatches exactly once; changed target identity after approval invalidates it; a high-risk-floor operation stays HIGH even when the model claims LOW. |

## Evidence discipline

- Every test asserts the outside canary (unregistered destinations) was never
  contacted via the connection ledger.
- Transaction and event ids are the only identifiers reported; no secrets are
  asserted or printed.
- The runbook does not replace the real-environment acceptance: the privileged
  distro matrix and the live t_11 sandbox remain mandatory Linux gates before
  publication.

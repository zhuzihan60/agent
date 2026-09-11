# Service and HTTP recovery loop

User-approved scope: connect diagnostic evidence, reliable model decisions and business recovery verification, prioritizing service failures and HTTP recovery.

Administrators register bounded evidence sources (`id`, `kind`: `service_state`, `service_logs`, `file`; `resource`, `initial`, `max_bytes`) and recovery checks (`id`, `kind`: `service_active`, `http`; `resource`, HTTP expected status and optional body substring). Models never choose arbitrary commands or health URLs. Service diagnostic reads are restricted to target allowed_units; file reads to managed roots, excluding protected paths and symlinks.

Initial collection includes identity and configured initial sources. Models receive the real fingerprint, authorized capabilities, evidence source catalog, recovery criteria and the exact response schema. Missing evidence requests may fetch registered source IDs in at most two additional diagnosis rounds. Unavailable evidence, unknown requests, low confidence, incomplete critic review, or absent recovery checks prevent automatic writes. Existing policy, risk floors, approvals, signed tickets and rollback remain authoritative.

After per-operation verification, independently rerun every administrator recovery check with bounded retries. All checks must pass before success. Failure or unavailable checks enter rollback; rollback success only means restoration of pre-change state, not business recovery. Reports retain diagnostic evidence and separate recovery check results. Default configuration remains read-only; real provider credentials are supplied by the operator, never embedded in examples or tests.

Validate with offline model HTTP fixtures using the actual model plugin, targeted negative-path tests, full locked Linux suite, and the existing production wiring harness. External model reasoning quality is not claimed without a live-provider evaluation.

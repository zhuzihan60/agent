# A4Diag Built-in Plugins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the out-of-process plugin protocol and the initial model, transport, capability, and notification plugins as a separately built, pinned artifact.

**Architecture:** A shared plugin host accepts versioned JSON-RPC over a Unix socket, rejects unknown fields, verifies core-issued operation tickets, and dispatches typed methods. Built-in plugins share packaging and protocol utilities but run as separate processes and service identities; tests use temporary sockets and fake command/network adapters rather than real hosts.

**Tech Stack:** Python 3.11, Pydantic, asyncio Unix sockets, JSON-RPC 2.0, httpx, subprocess argv APIs, smtplib, setuptools.

**Spec:** `docs/superpowers/specs/2026-08-26-a4diag-generic-plugin-agent-design.md`

## Global Constraints

- Apply the master plan constraints and require Phase 1 acceptance tests to pass before every task commit.
- Plugins never receive raw model conversation text when executing an operation.
- No plugin may expose a generic LOW shell method.
- Command execution uses fixed argv arrays, no `shell=True`, and bounded/redacted output.
- Network, firewall, SSH-configuration, virtualization, and script write plugins are not included in the default package.
- Real network/SSH/system modifications are prohibited in unit tests.

---

### Task 1: Versioned JSON-RPC Host, Client, and Conformance Harness

**Files:**
- Create: `src/a4diag/plugin_api/protocol.py`
- Create: `src/a4diag/plugin_client.py`
- Create: `packages/a4diag-builtin-plugins/pyproject.toml`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/__init__.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/host.py`
- Create: `tests/contract/plugin_harness.py`
- Create: `tests/contract/test_plugin_protocol.py`

**Interfaces:**
- Consumes: `TicketVerifier` and plugin manifest types from Phase 1.
- Produces: `RpcRequest`, `RpcResponse`, `PluginClient.call(method, params, ticket=None)`, `PluginHost.serve(socket_path)`, and `PluginContractHarness`.

- [ ] **Step 1: Write failing protocol tests**

```python
async def test_unknown_fields_and_methods_are_rejected(harness: PluginContractHarness) -> None:
    response = await harness.raw({"jsonrpc": "2.0", "id": "1", "method": "unknown", "params": {}, "extra": 1})
    assert response["error"]["code"] == -32600

async def test_write_method_requires_valid_ticket(harness: PluginContractHarness) -> None:
    response = await harness.call("apply", {"operation": service_restart_payload()})
    assert response["error"]["data"]["reason"] == "ticket_required"
```

- [ ] **Step 2: Run tests and observe missing protocol failure**

Run: `python -m pytest tests/contract/test_plugin_protocol.py -q`

Expected: FAIL on missing modules.

- [ ] **Step 3: Implement bounded newline-delimited JSON-RPC**

```python
class RpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jsonrpc: Literal["2.0"]
    id: str
    method: str
    params: dict[str, JsonValue]
    api_version: Literal["1.0"]
    ticket: str | None = None
```

Limit a request to 1 MiB, one JSON object per line, 30-second default call timeout, and one response per ID. Map invalid request/method/params/internal errors to JSON-RPC codes while returning stable A4Diag reasons in `error.data.reason`.

- [ ] **Step 4: Implement host dispatch and shared conformance fixture**

Require `health`, `describe`, and `capability_probe` for every plugin. Require tickets for `prepare`, `apply`, `undo`, and state-changing notification administration; `collect`, `verify`, `reconcile`, and notification `send` remain method-specific typed calls.

- [ ] **Step 5: Run tests and commit**

Run: `python -m pytest tests/contract/test_plugin_protocol.py tests/test_core_security_acceptance.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add src/a4diag/plugin_api/protocol.py src/a4diag/plugin_client.py packages/a4diag-builtin-plugins tests/contract
git commit -m "feat: add isolated plugin RPC protocol"
```

### Task 2: Local and SSH Transport Plugins

**Files:**
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/transport_local.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/transport_ssh.py`
- Create: `packages/a4diag-builtin-plugins/manifests/transport-local.json`
- Create: `packages/a4diag-builtin-plugins/manifests/transport-ssh.json`
- Create: `tests/contract/test_transport_plugins.py`

**Interfaces:**
- Consumes: plugin host and tickets.
- Produces: `verify_identity`, `read`, and `execute_typed` transport methods with `TransportResult`.

- [ ] **Step 1: Write failing identity and argv tests**

```python
def test_ssh_argv_pins_host_key_and_has_no_remote_shell() -> None:
    argv = build_ssh_argv(ssh_target_fixture())
    assert argv[-1] == "a4diag@192.0.2.10"
    assert "StrictHostKeyChecking=yes" in argv
    assert "UserKnownHostsFile=/run/a4diag/secrets/lab.known_hosts" in argv
    assert all(";" not in item for item in argv)

def test_machine_id_change_blocks_write(fake_transport: FakeTransport) -> None:
    fake_transport.machine_id = "changed"
    result = fake_transport.execute_typed(valid_ticket(), service_restart_request())
    assert result.reason == "target_identity_mismatch"
    assert fake_transport.spawn_count == 0
```

- [ ] **Step 2: Verify focused tests fail**

Run: `python -m pytest tests/contract/test_transport_plugins.py -q`

Expected: FAIL on missing transport modules.

- [ ] **Step 3: Implement local/SSH identity contracts**

```python
class TargetIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    machine_id: str
    host_key_sha256: str | None
    os_id: str
    os_version_id: str
    systemd_version: str
```

Local transport reads `/etc/machine-id` and OS release via injected readers. SSH transport invokes `/usr/bin/ssh` with `BatchMode=yes`, `IdentitiesOnly=yes`, fixed port/key/known_hosts, `StrictHostKeyChecking=yes`, `ConnectTimeout=10`, and a fixed remote helper executable; it sends typed JSON on stdin and never appends a model command.

- [ ] **Step 4: Add timeout/output/host-key tests and manifests**

Manifests declare no capability operations, API `1.0`, absolute sockets, exact executable names, required secret references, supported distros, and LOW read/HIGH write transport floors. Test timeout kills the process group and returns `execution_unknown` when dispatch may have occurred.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/contract/test_transport_plugins.py tests/contract/test_plugin_protocol.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/transport_local.py packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/transport_ssh.py packages/a4diag-builtin-plugins/manifests/transport-local.json packages/a4diag-builtin-plugins/manifests/transport-ssh.json tests/contract/test_transport_plugins.py
git commit -m "feat: add identity-pinned local and SSH transports"
```

### Task 3: Files, Services, and Packages Capability Plugins

**Files:**
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_files.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_services.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_packages.py`
- Create: `packages/a4diag-builtin-plugins/manifests/capability-files.json`
- Create: `packages/a4diag-builtin-plugins/manifests/capability-services.json`
- Create: `packages/a4diag-builtin-plugins/manifests/capability-packages.json`
- Create: `tests/contract/test_capability_plugins.py`

**Interfaces:**
- Consumes: typed transport and operation tickets.
- Produces: typed `prepare`, `apply`, `verify`, `undo`, and `reconcile` for managed files, systemd services, and exact packages.

- [ ] **Step 1: Write failing path, rollback, and exact-package tests**

```python
def test_files_rejects_symlink_escape(files_plugin: FilesPlugin, tmp_path: Path) -> None:
    (tmp_path / "managed").symlink_to("/etc")
    with pytest.raises(CapabilityError, match="symlink_escape"):
        files_plugin.prepare(replace_request(tmp_path / "managed/passwd"))

def test_service_undo_restores_prior_state(services_plugin: ServicesPlugin) -> None:
    marker = services_plugin.prepare(restart_request("example.service"))
    services_plugin.apply(marker)
    services_plugin.undo(marker)
    assert services_plugin.transport.calls[-1] == ["systemctl", "stop", "example.service"]

def test_packages_requires_exact_name_and_version(packages_plugin: PackagesPlugin) -> None:
    with pytest.raises(CapabilityError, match="exact_package_required"):
        packages_plugin.prepare(install_request(name="example*", version=None))
```

- [ ] **Step 2: Run tests and verify missing plugin failures**

Run: `python -m pytest tests/contract/test_capability_plugins.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement files operations**

Expose `files.replace_managed_file` and `files.set_mode`. Use `lstat` on every path component, refuse symlinks and device files, save bytes/mode/uid/gid plus SHA256 in the marker, write to a same-directory temporary file with `O_NOFOLLOW`, fsync, atomic replace, verify digest/metadata, and restore the exact prior state on undo.

- [ ] **Step 4: Implement services operations**

Expose `services.restart`, `services.start`, `services.stop`, `services.enable`, and `services.disable`. Accept only complete unit names from the core-validated request; invoke `/usr/bin/systemctl` with argv arrays; marker records `ActiveState`, `SubState`, `UnitFileState`, and invocation ID; verify desired state and undo to the recorded state.

- [ ] **Step 5: Implement packages operations**

Expose `packages.install_exact` and `packages.remove_exact` as HIGH by default. Detect `dnf` or `apt-get` from the verified OS identity, require exact package/version/repository allowlist, capture installed version and package-manager transaction ID, use noninteractive fixed argv, verify installed database state, and undo only when the prior version/artifact remains available.

- [ ] **Step 6: Add partial/crash reconciliation tests and commit**

Test `not_applied`, `applied`, `partial`, and `unknown` for all three plugins. Run:

`python -m pytest tests/contract/test_capability_plugins.py tests/test_core_security_acceptance.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_files.py packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_services.py packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_packages.py packages/a4diag-builtin-plugins/manifests/capability-files.json packages/a4diag-builtin-plugins/manifests/capability-services.json packages/a4diag-builtin-plugins/manifests/capability-packages.json tests/contract/test_capability_plugins.py
git commit -m "feat: add reversible typed capability plugins"
```

### Task 4: OpenAI-Compatible Model Plugin

**Files:**
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/model_openai.py`
- Create: `packages/a4diag-builtin-plugins/manifests/model-openai-compatible.json`
- Create: `tests/contract/test_model_plugin.py`

**Interfaces:**
- Consumes: evidence and strict response schemas from the core.
- Produces: `capability_probe`, `diagnose`, `plan`, and `critic` methods returning typed JSON only.

- [ ] **Step 1: Write failing provider/probe/schema tests**

```python
def test_probe_failure_disables_write(fake_http: FakeHttp) -> None:
    fake_http.response = {"choices": [{"message": {"content": "not-json"}}]}
    result = plugin(fake_http).capability_probe()
    assert result.write_capable is False
    assert result.reason == "structured_output_failed"

def test_plan_rejects_raw_command_field(fake_http: FakeHttp) -> None:
    fake_http.response = response_with_json({"operations": [{"command": "rm -rf /"}]})
    with pytest.raises(ModelProtocolError, match="unknown field"):
        plugin(fake_http).plan(evidence_fixture())
```

- [ ] **Step 2: Run failing tests**

Run: `python -m pytest tests/contract/test_model_plugin.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement provider normalization and structured calls**

Accept `base_url`, `api_key_ref`, `model`, `api_style` (`openai`, `azure`, `ollama`), timeout, and optional headers. Normalize URL construction without logging credentials. Require response models with `extra="forbid"`; keep planner and critic calls separate; treat HTTP, timeout, invalid JSON, schema, and truncation errors as typed failures.

- [ ] **Step 4: Test DeepSeek/OpenAI/Azure/Ollama/vLLM request shapes**

Use fake HTTP transport and assert exact URL, headers, JSON body, response parsing, and redaction. No live provider call is part of the unit suite.

- [ ] **Step 5: Run and commit**

Run: `python -m pytest tests/contract/test_model_plugin.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/model_openai.py packages/a4diag-builtin-plugins/manifests/model-openai-compatible.json tests/contract/test_model_plugin.py
git commit -m "feat: add OpenAI-compatible model plugin"
```

### Task 5: CLI, FlashDuty, SMTP, and Webhook Notification Plugins

**Files:**
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/notification_cli.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/notification_flashduty.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/notification_smtp.py`
- Create: `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/notification_webhook.py`
- Create: `packages/a4diag-builtin-plugins/manifests/notification-cli.json`
- Create: `packages/a4diag-builtin-plugins/manifests/notification-flashduty.json`
- Create: `packages/a4diag-builtin-plugins/manifests/notification-smtp.json`
- Create: `packages/a4diag-builtin-plugins/manifests/notification-webhook.json`
- Create: `tests/contract/test_notification_plugins.py`

**Interfaces:**
- Consumes: redacted `NotificationEvent` with target, digest, typed operations, equivalent command display, risk, verify, undo, and status.
- Produces: `NotificationReceipt(channel, external_id, delivered_at)` or typed failure.

- [ ] **Step 1: Write failing payload/redaction/retry tests**

```python
def test_flashduty_payload_contains_digest_but_not_secret(fake_http: FakeHttp) -> None:
    receipt = flashduty(fake_http).send(notification_event(secret="token-value"))
    body = fake_http.requests[0].json
    assert body["event_status"] == "Warning"
    assert "plan_digest" in body["event_description"]
    assert "token-value" not in json.dumps(body)
    assert receipt.external_id

def test_webhook_5xx_retries_but_4xx_does_not(fake_http: FakeHttp) -> None:
    fake_http.statuses = [503, 200]
    webhook(fake_http).send(notification_event())
    assert len(fake_http.requests) == 2
```

- [ ] **Step 2: Run failing tests**

Run: `python -m pytest tests/contract/test_notification_plugins.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement exact channel behavior**

CLI persists a redacted local event for the approval command. FlashDuty POSTs the standard alert schema to a configured URL with `integration_key` supplied only by secret reference. SMTP uses STARTTLS or implicit TLS with certificate verification and sends text/plain UTF-8. Webhook sends canonical JSON with timestamp, nonce, and optional HMAC signature header. Retry only connection errors, 429, and 5xx using bounded backoff.

- [ ] **Step 4: Run focused/full tests and commit**

Run: `python -m pytest tests/contract/test_notification_plugins.py -q && python -m pytest -q`

Expected: PASS.

```bash
git add packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/notification_*.py packages/a4diag-builtin-plugins/manifests/notification-*.json tests/contract/test_notification_plugins.py
git commit -m "feat: add optional notification plugins"
```

### Task 6: Complete Plugin Conformance and Build Gate

**Files:**
- Create: `tests/contract/test_all_manifests.py`
- Create: `tests/contract/test_plugin_crash_matrix.py`
- Modify: `packages/a4diag-builtin-plugins/pyproject.toml`
- Create: `docs/testing/plugin-conformance-matrix.md`

**Interfaces:**
- Consumes: every Phase 2 plugin.
- Produces: reproducible bundled-plugin wheel and conformance evidence.

- [ ] **Step 1: Write the failing parameterized test that sends every manifest through the same harness**

```python
@pytest.mark.parametrize("manifest_path", sorted(MANIFEST_ROOT.glob("*.json")), ids=lambda p: p.stem)
def test_manifest_contract(manifest_path: Path, contract_harness: PluginContractHarness) -> None:
    result = contract_harness.verify(manifest_path)
    assert result.errors == ()
```

Verify strict schema, API negotiation, socket path, operations, risk floors, timeout, crash, restart, duplicate request, invalid ticket, oversized input, output bound, secret redaction, and claimed reconciliation methods.

- [ ] **Step 2: Configure wheel contents and entrypoints**

Include all manifest JSON files as package data. Define one console entrypoint, `a4diag-plugin = a4diag_builtin_plugins.host:main`; service instance configuration selects a manifest whose wheel SHA and manifest SHA were verified against the external signed release index and administrator pin before service start.

- [ ] **Step 3: Build and inspect the plugin wheel**

Run: `python -m build --wheel packages/a4diag-builtin-plugins`

Expected: exactly one wheel under `packages/a4diag-builtin-plugins/dist` and no sdist.

Run: `python -m zipfile -l packages/a4diag-builtin-plugins/dist/a4diag_builtin_plugins-0.4.0-py3-none-any.whl`

Expected: package modules plus every manifest, with no test fixture or secret.

- [ ] **Step 4: Run phase gate and commit**

Run: `python -m pytest tests/contract tests/test_core_security_acceptance.py -q && python -m pytest -q`

Expected: zero failures/errors.

```bash
git add packages/a4diag-builtin-plugins tests/contract docs/testing/plugin-conformance-matrix.md
git commit -m "test: enforce built-in plugin conformance"
```

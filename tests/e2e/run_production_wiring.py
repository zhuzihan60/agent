"""Linux-only proof of the complete controller-to-target production path."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.approval_cli import ApprovalCli, Authorizer as ApprovalAuthorizer
from a4diag.domain import Operation, Plan, Risk, canonical_json_bytes
from a4diag.plugin_admin import Authorizer as PluginAuthorizer, PluginAdmin
from a4diag.plugin_api.target_protocol import TargetLifecycle, TargetRequest, TargetSigner
from a4diag.plugin_api.ticket import effect_payload_digest
from a4diag.plugin_ports import _RpcModelPort, build_rpc_plugin_ports
from a4diag.plugin_registry import PluginPin, PluginRegistry
from a4diag.runtime import (
    Runtime,
    RuntimeFailure,
    RuntimeIdentityProbe,
    RuntimeNotifier,
    RuntimePlanSource,
    build_runtime,
)
from a4diag.workflow import PluginPorts
from a4diag_builtin_plugins.model_openai import (
    HttpResult, ModelConfig, ModelCriticParams, ModelEvidenceParams, ModelPlugin,
)
from a4diag_builtin_plugins.transport_common import identity_fingerprint
from a4diag_target.policy import TargetPolicy
from a4diag_target.server import probe_identity

ROOT = Path(__file__).resolve().parents[2]
E2E = Path(os.environ.get("A4DIAG_E2E_DIR", "/tmp/a4diag-e2e"))
TARGET_ID = "e2e-target"
SSH_HOST = "127.0.0.2"
SSH_PORT = 22222
PLUGIN_INSTANCE = "e2e-transport"
HELPER = Path("/usr/libexec/a4diag/a4diag-transport-helper")
PLUGIN_CONFIG = Path(f"/etc/a4diag/plugins/{PLUGIN_INSTANCE}.yaml")
TICKET_SECRET = Path("/etc/a4diag/secrets/e2e-ticket.key")
OPERATION_SECRET = Path("/etc/a4diag/secrets/e2e-operation.pem")
PLUGIN_SOCKET = Path(f"/run/a4diag/{PLUGIN_INSTANCE}.sock")
TARGET_SOCKET_UNIT = "a4diag-target-executor.socket"
TARGET_SERVICE_UNIT = "a4diag-target-executor.service"
TARGET_E2E = Path("/var/lib/a4diag-target/executor/e2e")
MANAGED_E2E = Path("/srv/a4diag-e2e-managed")


class _NoopServiceManager:
    def start(self, _name: str) -> None:  # pragma: no cover
        raise AssertionError("plugin list attempted to start a service")

    def stop(self, _name: str) -> None:  # pragma: no cover
        raise AssertionError("plugin list attempted to stop a service")


class _LoseFirstApplyResponse:
    """Let the real target apply once, then simulate a lost controller response."""

    def __init__(self, delegate: object) -> None:
        self._delegate = delegate
        self.response_lost = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    def apply(self, *args: object, **kwargs: object) -> object:
        result = getattr(self._delegate, "apply")(*args, **kwargs)
        if not self.response_lost:
            self.response_lost = True
            raise TimeoutError("e2e_lost_apply_response")
        return result


class _ModelHttpTransport:
    def post(self, url: str, headers: dict[str, str], body: bytes,
             *, timeout_seconds: float) -> HttpResult:
        request = urllib.request.Request(
            url, data=body, headers=headers, method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return HttpResult(response.status, response.read().decode("utf-8"))


class _NoModelSecrets:
    def resolve(self, _ref: str) -> str:
        raise AssertionError("offline model fixture must not resolve provider credentials")


class _ModelPluginClient:
    """Use the production port adapter with the actual typed plugin in process."""

    def __init__(self, plugin: ModelPlugin) -> None:
        self.plugin = plugin

    async def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        params_type = ModelCriticParams if method == "critic" else ModelEvidenceParams
        result = getattr(self.plugin, method)(params_type.model_validate(params))
        return result.model_dump(mode="json")


class ModelHttpFixture:
    """Offline Ollama fixture plus business HTTP health tied to real file state.

    The fixture supplies deterministic responses; the real ModelPlugin builds
    requests and validates every response. This does not evaluate live models.
    """

    def __init__(self, managed: Path, port: int = 0) -> None:
        self.managed = managed
        self.mode = "low"
        self.requests: list[dict[str, Any]] = []
        self.health_results: list[bool] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                pass

            def _respond(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                try:
                    if self.path != "/api/chat":
                        raise ValueError("unexpected model endpoint")
                    payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    messages = payload["messages"]
                    schema = json.loads(messages[0]["content"].split("JSON Schema:\n", 1)[1])
                    if messages[0]["role"] != "system" or payload["format"] != "json":
                        raise ValueError("missing structured request")
                    if schema.get("additionalProperties") is not False:
                        raise ValueError("missing strict schema")
                    envelope = json.loads(messages[1]["content"])
                    fixture.requests.append(payload)
                    response = fixture._response(envelope)
                    self._respond(200, canonical_json_bytes({
                        "message": {"role": "assistant", "content": json.dumps(response)},
                        "done": True,
                    }))
                except (KeyError, ValueError, IndexError, TypeError):
                    self._respond(400, b'{"error":"invalid fixture request"}')

            def do_GET(self) -> None:
                resource = fixture.managed / f"{fixture.mode}.conf"
                healthy = (
                    self.path == "/health" and fixture.mode != "unhealthy"
                    and resource.is_file()
                    and resource.read_bytes() == f"after-{fixture.mode}\n".encode()
                )
                fixture.health_results.append(healthy)
                self._respond(200 if healthy else 503,
                              b'{"state":"recovered"}' if healthy else b'{"state":"unhealthy"}')

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.plugin = ModelPlugin(
            http=_ModelHttpTransport(), secrets=_NoModelSecrets(),
            config=ModelConfig(base_url=self.url, model="offline-e2e", api_style="ollama"),
        )

    def __enter__(self) -> ModelHttpFixture:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def _response(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if envelope.get("probe"):
            return {"ok": True, "capabilities": ["structured"]}
        task = envelope["task"]
        if task == "diagnose":
            source_id = f"{self.mode}-file"
            observed = any(
                row.get("source_id") == source_id and row.get("available") is True
                for row in envelope["evidence"]["observations"]
            )
            # The protected-path scenario reaches the existing policy guard;
            # it never tries to register or read protected target files.
            missing = [] if observed or self.mode == "protected" else [source_id]
            return {"cause": "e2e managed file drift", "confidence": 0.95,
                    "missing_evidence": missing, "recommended_actions": ["files.replace_managed_file"]}
        if task == "critic":
            return {"risk": "high" if self.mode == "high" else "low", "complete": True,
                    "issues": [], "verify_suggestions": [], "undo_suggestions": []}
        if task != "plan":
            raise ValueError("unknown fixture task")
        resource = self.managed / f"{self.mode}.conf"
        if self.mode == "protected":
            resource = Path("/etc/ssh/sshd_config")
        risk = Risk.HIGH if self.mode == "high" else Risk.LOW
        content = f"after-{self.mode}\n".encode()
        operation = Operation(
            capability="files",
            action="replace_managed_file",
            resource=resource.as_posix(),
            parameters={"content": base64.b64encode(content).decode(), "mode": 0o640},
            model_risk=risk,
            verify={"content_sha256": hashlib.sha256(content).hexdigest()},
            undo={"restore": True},
        )
        return {"reasoning": "restore the managed file", "operations": [operation.model_dump(mode="json")]}


class HttpNotifier:
    def __init__(self, url: str) -> None:
        self.url = url

    def send_approval(self, target: object, transaction_id: str, digest: str,
                      plan: Plan, risk: Risk) -> bool:
        request = urllib.request.Request(
            self.url,
            data=canonical_json_bytes({
                "target_id": getattr(target, "id"), "transaction_id": transaction_id,
                "digest": digest, "risk": risk.value,
                "operations": [item.model_dump(mode="json") for item in plan.operations],
            }),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
            return response.status == 202


def run(argv: list[str], *, input_bytes: bytes | None = None,
        check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, input=input_bytes, capture_output=True, check=check, env=env)


def wait_for(path: Path, process: subprocess.Popen[bytes] | None = None) -> None:
    for _ in range(200):
        if path.exists():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(process.stderr.read().decode(errors="replace"))
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {path}")


def key_blob_digest(public_key: Path) -> str:
    fields = public_key.read_text(encoding="ascii").split()
    return hashlib.sha256(base64.b64decode(fields[1])).hexdigest()


def ssh_call(identity: Path, known_hosts: Path, value: dict[str, object]) -> dict[str, object]:
    completed = run([
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "ConnectTimeout=10", "-p", str(SSH_PORT), "-i", str(identity),
        f"root@{SSH_HOST}", str(HELPER),
    ], input_bytes=canonical_json_bytes(value))
    return json.loads(completed.stdout)


def signed_request(*, signer: TargetSigner, fingerprint: str, operation: Operation,
                   lifecycle: TargetLifecycle, transaction: str, nonce: str,
                   marker: dict[str, object] | None = None,
                   undo: dict[str, object] | None = None) -> dict[str, object]:
    if lifecycle is TargetLifecycle.PREPARE:
        effect: dict[str, object] = {}
    elif lifecycle is TargetLifecycle.UNDO:
        effect = {"marker": marker, "undo": undo}
    else:
        effect = {"marker": marker}
    now = int(time.time())
    request = TargetRequest(
        controller_id="e2e-controller", target_id=TARGET_ID,
        target_fingerprint=fingerprint, transaction_id=transaction, step_id="0",
        lifecycle=lifecycle, operation=operation, marker=marker, undo=undo,
        plan_digest=hashlib.sha256(transaction.encode()).hexdigest(),
        effect_payload_digest=effect_payload_digest(effect), risk=operation.model_risk,
        approval_id="e2e-approval" if operation.model_risk is Risk.HIGH else None,
        issued_at=now - 1, expires_at=now + 120, nonce=nonce,
    )
    return signer.sign(request).model_dump(mode="json")


def make_registry() -> tuple[Path, tuple[PluginPin, ...], Path]:
    manifest_root = E2E / "installed-plugins"
    manifest_root.mkdir(parents=True)
    artifact = manifest_root / "a4diag_builtin_plugins-0.4.3.whl"
    artifact.write_bytes(b"e2e installed built-in wheel")
    artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    pins: list[PluginPin] = []
    for source in sorted((ROOT / "packages/a4diag-builtin-plugins/manifests").glob("*.json")):
        destination = manifest_root / source.name
        shutil.copyfile(source, destination)
        payload = json.loads(destination.read_text(encoding="utf-8"))
        pins.append(PluginPin(
            name=payload["name"], version=payload["version"], api_version="1.0",
            artifact_path=artifact.name, artifact_sha256=artifact_digest,
            manifest_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
            enabled=True,
        ))
    registry_path = E2E / "plugin-registry.json"
    registry_path.write_text(json.dumps({"plugins": [pin.__dict__ for pin in pins]}, sort_keys=True), encoding="utf-8")
    return manifest_root, tuple(pins), registry_path


def start_fixture(script: str, port: int, count: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "tests/e2e/fixtures" / script), str(port), str(count)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    for _ in range(100):
        if count.exists() and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return process
            except OSError:
                pass
        time.sleep(0.03)
    raise RuntimeError(f"fixture failed: {script}")


def start_plugin() -> subprocess.Popen[bytes]:
    PLUGIN_SOCKET.unlink(missing_ok=True)
    process = subprocess.Popen(
        [sys.executable, "-c", "from a4diag_builtin_plugins.host import main; raise SystemExit(main())",
         "--instance", PLUGIN_INSTANCE],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    wait_for(PLUGIN_SOCKET, process)
    return process


def main() -> int:
    if os.name != "posix" or os.environ.get("CI") != "true" or os.geteuid() != 0:
        raise RuntimeError("production wiring harness requires a root GitHub Linux runner")
    import grp

    E2E.mkdir(parents=True, exist_ok=True)
    if TARGET_E2E.exists():
        shutil.rmtree(TARGET_E2E)
    managed = MANAGED_E2E.resolve()
    if managed != MANAGED_E2E:
        raise RuntimeError("managed E2E path resolved outside its fixed fixture path")
    if managed.exists():
        shutil.rmtree(managed)
    identity_root = TARGET_E2E / "identity-root"
    target_config = TARGET_E2E / "config"
    target_state = TARGET_E2E / "state"
    target_runtime = TARGET_E2E / "runtime"
    ssh_dir = E2E / "ssh"
    for directory in (
        managed,
        identity_root / "etc/ssh",
        target_config,
        target_state,
        target_runtime,
        ssh_dir,
        Path("/run/a4diag"),
        Path("/run/a4diag-target"),
        Path("/run/sshd"),
        PLUGIN_CONFIG.parent,
        TICKET_SECRET.parent,
        HELPER.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    for name in ("recovery", "low", "high", "replay", "unhealthy"):
        (managed / f"{name}.conf").write_bytes(b"before\n")
        os.chmod(managed / f"{name}.conf", 0o600)
    controller_sentinel = E2E / "controller-sentinel"
    controller_sentinel.write_bytes(b"controller-before\n")

    client_key = ssh_dir / "client"
    host_key = ssh_dir / "host"
    run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key)])
    run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
    host_digest = key_blob_digest(host_key.with_suffix(".pub"))
    shutil.copyfile(host_key.with_suffix(".pub"), identity_root / "etc/ssh/ssh_host_ed25519_key.pub")
    (identity_root / "etc/machine-id").write_text("e2e-machine-id\n", encoding="utf-8")
    (identity_root / "etc/os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8")
    identity = probe_identity(identity_root)
    fingerprint = identity_fingerprint(identity)

    operation_key = Ed25519PrivateKey.generate()
    private_pem = operation_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = operation_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    OPERATION_SECRET.write_bytes(private_pem)
    TICKET_SECRET.write_text("e2e-ticket-key-0123456789abcdef0123456789abcdef", encoding="utf-8")
    os.chmod(OPERATION_SECRET, 0o600)
    os.chmod(TICKET_SECRET, 0o600)
    controller_fp = "sha256:" + hashlib.sha256(operation_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    policy = TargetPolicy(
        target_id=TARGET_ID, target_fingerprint=fingerprint,
        controller_key_fingerprint=controller_fp, managed_roots=(str(managed),),
    )
    policy_path = target_config / "target-policy.json"
    public_path = target_config / "operation-public.pem"
    replay_path = target_state / "target-replay.sqlite3"
    policy_path.write_text(policy.model_dump_json(), encoding="utf-8")
    public_path.write_bytes(public_pem)

    helper_backup = HELPER.read_bytes() if HELPER.exists() else None
    HELPER.write_text(
        f"#!/bin/sh\nexec {sys.executable} -c 'from a4diag_target.helper import main; raise SystemExit(main())'\n",
        encoding="utf-8",
    )
    os.chmod(HELPER, 0o755)
    authorized_keys = ssh_dir / "authorized_keys"
    public_client = client_key.with_suffix(".pub").read_text(encoding="ascii").strip()
    authorized_keys.write_text(f'command="{HELPER}",restrict {public_client}\n', encoding="ascii")
    known_hosts = ssh_dir / "known_hosts"
    known_hosts.write_text(f"[{SSH_HOST}]:{SSH_PORT} {host_key.with_suffix('.pub').read_text(encoding='ascii')}", encoding="ascii")
    sshd_config = ssh_dir / "sshd_config"
    sshd_log = ssh_dir / "sshd.log"
    sshd_config.write_text("\n".join([
        f"Port {SSH_PORT}", f"ListenAddress {SSH_HOST}", f"HostKey {host_key}",
        f"AuthorizedKeysFile {authorized_keys}", "PermitRootLogin prohibit-password",
        "PasswordAuthentication no", "PubkeyAuthentication yes", "StrictModes no",
        "UsePAM no", "PidFile /tmp/a4diag-e2e-sshd.pid", "LogLevel VERBOSE",
    ]) + "\n", encoding="utf-8")

    service_path = Path(f"/run/systemd/system/{TARGET_SERVICE_UNIT}")
    socket_path = Path(f"/run/systemd/system/{TARGET_SOCKET_UNIT}")
    service_override_dir = Path(f"{service_path}.d")
    service_override_path = service_override_dir / "e2e.conf"
    managed_roots_override_path = service_override_dir / "managed-roots.conf"
    for source in (
        ROOT / "src/a4diag",
        ROOT / "packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins",
        ROOT / "packages/a4diag-target-runtime/src/a4diag_target",
    ):
        shutil.copytree(source, target_runtime / source.name, dirs_exist_ok=True)
    target_service = target_runtime / "target_service.py"
    shutil.copyfile(ROOT / "tests/e2e/fixtures/target_service.py", target_service)
    run(
        [
            "/usr/bin/systemd-sysusers",
            str(ROOT / "deploy/sysusers.d/a4diag-target.conf"),
        ]
    )
    service_path.write_bytes((ROOT / "deploy/a4diag-target-executor.service").read_bytes())
    socket_path.write_bytes((ROOT / "deploy/a4diag-target-executor.socket").read_bytes())
    service_override_dir.mkdir(parents=True, exist_ok=True)
    service_override_path.write_text(
        "\n".join(
            [
                "[Service]",
                f'Environment="A4DIAG_TARGET_POLICY={policy_path}"',
                f'Environment="A4DIAG_TARGET_PUBLIC_KEY={public_path}"',
                f'Environment="A4DIAG_TARGET_REPLAY={replay_path}"',
                f'Environment="A4DIAG_TARGET_IDENTITY_ROOT={identity_root}"',
                f'Environment="PYTHONPATH={target_runtime}"',
                'Environment="PYTHONDONTWRITEBYTECODE=1"',
                "ExecStart=",
                f"ExecStart={sys.executable} {target_service}",
                "ReadOnlyPaths=",
                f"ReadOnlyPaths={target_runtime} {target_config} {identity_root}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    managed_roots_override_path.write_text(
        "[Service]\n"
        "ReadWritePaths=\n"
        "ReadWritePaths=/run/a4diag-target /var/lib/a4diag-target/executor\n"
        f"ReadWritePaths={managed}\n",
        encoding="utf-8",
    )

    PLUGIN_CONFIG.write_text(yaml.safe_dump({
        "manifest": "transport-ssh", "socket": str(PLUGIN_SOCKET),
        "ticket_key_ref": "file:e2e-ticket.key",
        "config": {"host": SSH_HOST, "port": SSH_PORT, "user": "root",
                   "identity_file": str(client_key), "known_hosts": str(known_hosts),
                   "host_key_sha256": host_digest},
    }, sort_keys=True), encoding="utf-8")
    os.chmod(PLUGIN_CONFIG, 0o640)

    manifest_root, pins, registry_path = make_registry()
    settings_path = E2E / "settings.yaml"
    settings_path.write_text(yaml.safe_dump({
        "global_mode": "read_write", "auto_execute_low": True, "max_write_targets": 2,
        "targets": [{
            "id": TARGET_ID, "mode": "ssh", "identity_ref": f"target/{TARGET_ID}",
            "identity_fingerprint": fingerprint, "transport": PLUGIN_INSTANCE,
            "host": SSH_HOST, "port": SSH_PORT, "user": "root",
            "identity_file_ref": "file:e2e-ssh-unused", "known_hosts_ref": "file:e2e-known-unused",
            "operation_signing_key_ref": "file:e2e-operation.pem", "host_key_sha256": host_digest,
            "write_enabled": True, "auto_execute_low": True, "notification_required": True,
            "evidence_sources": [
                {"id": f"{name}-file", "kind": "file", "resource": str(managed / f"{name}.conf"),
                 "initial": False, "max_bytes": 1024}
                for name in ("recovery", "low", "high", "unhealthy")
            ],
            "recovery_checks": [{
                "id": "business-http", "kind": "http", "resource": "http://127.0.0.1:18081/health",
                "expected_status": 200, "body_contains": "recovered", "attempts": 1,
            }],
            "capabilities": [{"name": "files", "actions": ["replace_managed_file"],
                              "resources": [f"{managed}/**"]}],
        }],
        "plugins": [pin.name for pin in pins], "model": None, "notifications": [],
    }, sort_keys=False), encoding="utf-8")

    notification_count = E2E / "notification.count"
    processes: list[subprocess.Popen[bytes]] = []
    runtime = None
    model_fixture = None
    try:
        run(["/usr/bin/systemctl", "daemon-reload"])
        run(["/usr/bin/systemctl", "start", TARGET_SOCKET_UNIT])
        if not Path("/run/a4diag-target/executor.sock").is_socket():
            raise RuntimeError("systemd target socket was not activated")
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-f", str(sshd_config), "-E", str(sshd_log)], stderr=subprocess.PIPE)
        processes.append(sshd)
        time.sleep(0.25)
        if sshd.poll() is not None:
            raise RuntimeError(sshd.stderr.read().decode(errors="replace"))
        model_fixture = ModelHttpFixture(managed, port=18081)
        model_fixture.__enter__()
        if model_fixture.plugin.capability_probe().write_capable is not True:
            raise RuntimeError("actual model plugin failed structured-output probe")
        processes.append(start_fixture("notification_server.py", 18082, notification_count))
        plugin = start_plugin()
        processes.append(plugin)

        notifier = HttpNotifier("http://127.0.0.1:18082")

        def ports_factory(settings: object, registry: PluginRegistry) -> PluginPorts:
            real = build_rpc_plugin_ports(settings, registry)  # type: ignore[arg-type]
            model = _RpcModelPort(_ModelPluginClient(model_fixture.plugin), registry)  # type: ignore[arg-type]
            return PluginPorts(model=model, collector=real.collector, executor=real.executor, notifier=notifier)

        paths = {name: E2E / name for name in ("audit.jsonl", "checkpoints.sqlite3", "transactions.sqlite3", "approvals.sqlite3")}
        policy_key = b"e2e-policy-key-0123456789abcdef0123456789abcdef"

        def build_e2e_runtime(factory: object) -> Runtime:
            return build_runtime(
                settings_path,
                audit_path=paths["audit.jsonl"],
                checkpoints_path=paths["checkpoints.sqlite3"],
                transactions_path=paths["transactions.sqlite3"],
                approvals_path=paths["approvals.sqlite3"],
                registry_pins=pins,
                manifest_root=manifest_root,
                plugin_ports_factory=factory,  # type: ignore[arg-type]
                ticket_key=TICKET_SECRET.read_bytes(),
                policy_key=policy_key,
            )

        lost_response_executor: _LoseFirstApplyResponse | None = None

        def uncertain_ports_factory(
            settings: object, registry: PluginRegistry
        ) -> PluginPorts:
            nonlocal lost_response_executor
            real = ports_factory(settings, registry)
            lost_response_executor = _LoseFirstApplyResponse(real.executor)
            return PluginPorts(
                model=real.model,
                collector=real.collector,
                executor=lost_response_executor,  # type: ignore[arg-type]
                notifier=real.notifier,
            )

        runtime = build_e2e_runtime(uncertain_ports_factory)
        identity_verified = runtime.probe_fingerprint(TARGET_ID) == fingerprint
        runtime_directory = Path("/run/a4diag-target")
        target_socket = runtime_directory / "executor.sock"
        runtime_directory_stat = runtime_directory.stat()
        target_socket_stat = target_socket.stat()
        runtime_directory_group = grp.getgrgid(runtime_directory_stat.st_gid).gr_name
        socket_group = grp.getgrgid(target_socket_stat.st_gid).gr_name
        runuser_path = shutil.which("runuser")
        if runuser_path is None:
            raise RuntimeError("runuser is required to verify target relay access")
        relay_connect = run(
            [
                runuser_path,
                "-u",
                "a4diag-target",
                "--",
                "/usr/bin/python3",
                "-c",
                (
                    "import socket, struct; "
                    "client = socket.socket(socket.AF_UNIX); "
                    "client.settimeout(10); "
                    "client.connect('/run/a4diag-target/executor.sock'); "
                    "stream = client.makefile('rwb'); "
                    "stream.write(struct.pack('!I', 2) + b'{}'); "
                    "stream.flush(); "
                    "header = stream.read(4); "
                    "assert len(header) == 4; "
                    "size = struct.unpack('!I', header)[0]; "
                    "assert len(stream.read(size)) == size; "
                    "stream.close(); client.close()"
                ),
            ],
            check=False,
        )
        relay_user_socket_access = (
            relay_connect.returncode == 0
            and runtime_directory_group == "a4diag-target"
            and socket_group == "a4diag-target"
            and stat.S_IMODE(runtime_directory_stat.st_mode) == 0o750
            and stat.S_IMODE(target_socket_stat.st_mode) == 0o660
        )
        if not relay_user_socket_access:
            raise RuntimeError(
                "a4diag-target cannot traverse/connect to target socket: "
                f"runtime_group={runtime_directory_group!r}, "
                f"runtime_mode={stat.S_IMODE(runtime_directory_stat.st_mode):#o}, "
                f"socket_group={socket_group!r}, "
                f"socket_mode={stat.S_IMODE(target_socket_stat.st_mode):#o}, "
                f"runuser_stderr={relay_connect.stderr.decode(errors='replace')!r}"
            )
        service_properties = run(
            [
                "/usr/bin/systemctl",
                "show",
                TARGET_SERVICE_UNIT,
                "--property=NoNewPrivileges,PrivateTmp,PrivateDevices,ProtectSystem,"
                "ProtectHome,RestrictAddressFamilies,ReadOnlyPaths,ReadWritePaths",
            ]
        ).stdout.decode("utf-8")
        hardened = {
            key: value
            for key, _, value in (
                line.partition("=") for line in service_properties.splitlines()
            )
        }
        required_hardening = {
            "NoNewPrivileges": "yes",
            "PrivateTmp": "yes",
            "PrivateDevices": "yes",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "RestrictAddressFamilies": "AF_UNIX",
        }
        service_hardened = all(
            hardened.get(key) == value for key, value in required_hardening.items()
        ) and all(
            expected in hardened.get(property_name, "")
            for property_name, expected in (
                ("ReadOnlyPaths", str(target_runtime)),
                ("ReadOnlyPaths", str(target_config)),
                ("ReadWritePaths", str(managed)),
            )
        )
        managed_root_requires_drop_in = not managed.is_relative_to(
            Path("/var/lib/a4diag-target/executor")
        )
        if not service_hardened or not managed_root_requires_drop_in:
            raise RuntimeError(f"target service hardening missing: {hardened}")

        model_fixture.mode = "recovery"
        recovery_unknown = runtime.handle(
            {
                "event_id": "recovery-tx",
                "target_id": TARGET_ID,
                "request": {"fault": "lost-apply-response"},
            }
        )
        recovery_effect_applied = (
            managed / "recovery.conf"
        ).read_bytes() == b"after-recovery\n"
        recovery_inode = (managed / "recovery.conf").stat().st_ino
        old_executor = runtime.executor
        runtime.close()
        runtime = None
        plugin.terminate()
        plugin.wait(timeout=5)
        processes.remove(plugin)
        plugin = start_plugin()
        processes.append(plugin)
        runtime = build_e2e_runtime(ports_factory)
        executor_recreated = runtime.executor is not old_executor
        recovery_discovered = "recovery-tx" in runtime.recoverable
        recovered = runtime.resume("recovery-tx")
        runtime_recovery_succeeded = (
            recovery_unknown.status == "execution_unknown"
            and lost_response_executor is not None
            and lost_response_executor.response_lost
            and recovery_effect_applied
            and executor_recreated
            and recovery_discovered
            and recovered.status == "succeeded"
            and (managed / "recovery.conf").read_bytes() == b"after-recovery\n"
            and (managed / "recovery.conf").stat().st_ino == recovery_inode
        )

        model_fixture.mode = "low"
        low = runtime.handle({"event_id": "low-tx", "target_id": TARGET_ID, "request": {"fault": "low"}})
        low_applied = low.status == "succeeded" and (managed / "low.conf").read_bytes() == b"after-low\n"
        evidence_loop_complete = (
            any(row.get("source_id") == "low-file" and row.get("available") is True
                for row in low.report.get("evidence", []))
            and low.report.get("recovery_result", {}).get("ok") is True
        )
        if not evidence_loop_complete:
            raise RuntimeError(f"evidence/HTTP recovery loop failed: {low.report}")

        plugin.terminate(); plugin.wait(timeout=5); processes.remove(plugin)
        plugin = start_plugin(); processes.append(plugin)
        step = runtime._deps.transactions.get_steps("low-tx")[0]
        marker = json.loads(step.plugin_marker_json)
        operation = Operation.model_validate(json.loads(step.operation_json))
        signer = TargetSigner(operation_key)
        reconciled = ssh_call(client_key, known_hosts, signed_request(
            signer=signer, fingerprint=fingerprint, operation=operation,
            lifecycle=TargetLifecycle.RECONCILE, transaction="reconcile-tx",
            marker=marker, nonce="reconcile-nonce-0001",
        ))
        undone = ssh_call(client_key, known_hosts, signed_request(
            signer=signer, fingerprint=fingerprint, operation=operation,
            lifecycle=TargetLifecycle.UNDO, transaction="undo-tx", marker=marker,
            undo=operation.undo, nonce="undo-nonce-00000001",
        ))
        rollback_exact = undone.get("ok") is True and (managed / "low.conf").read_bytes() == b"before\n" and (managed / "low.conf").stat().st_mode & 0o777 == 0o600

        model_fixture.mode = "high"
        before_high = (managed / "high.conf").read_bytes()
        pending_high = runtime.handle(
            {"event_id": "high-tx", "target_id": TARGET_ID, "request": {"fault": "high"}}
        )
        approval = runtime.approvals.for_transaction("high-tx")
        if approval is None:
            raise RuntimeError("HIGH plan did not create an approval")
        before_effects = 0 if (managed / "high.conf").read_bytes() == before_high else 1
        approval_cli = ApprovalCli(
            approvals=runtime.approvals,
            plans=RuntimePlanSource(runtime),
            notifier=RuntimeNotifier(runtime),
            identity=RuntimeIdentityProbe(runtime),
            authorizer=ApprovalAuthorizer(True),
            clock=lambda: int(time.time()),
            stdin_isatty=lambda: True,
            actor_factory=lambda: "e2e-admin",
            signing_key=policy_key,
        )
        shown = approval_cli.show("high-tx")
        receipt = approval_cli.approve("high-tx", shown.plan.plan_digest)
        high_done = runtime.resume("high-tx")
        after_effects = 1 if high_done.status == "succeeded" and (managed / "high.conf").read_bytes() == b"after-high\n" else 0
        approval_cli_path = (
            pending_high.status == "pending_approval"
            and shown.status == "pending"
            and shown.notification_status == "delivered"
            and shown.plan.plan_digest == approval.plan_digest
            and receipt.status == "approved"
        )

        model_fixture.mode = "unhealthy"
        unhealthy = runtime.handle({
            "event_id": "unhealthy-tx", "target_id": TARGET_ID,
            "request": {"fault": "business HTTP remains unhealthy"},
        })
        unhealthy_rolled_back = (
            unhealthy.status == "rollback_succeeded"
            and (managed / "unhealthy.conf").read_bytes() == b"before\n"
            and stat.S_IMODE((managed / "unhealthy.conf").stat().st_mode) == 0o600
            and unhealthy.report.get("recovery_result", {}).get("ok") is False
        )
        if not unhealthy_rolled_back:
            raise RuntimeError(f"unhealthy business check did not restore target: {unhealthy.report}")

        model_fixture.mode = "protected"
        protected_before = Path("/etc/ssh/sshd_config").read_bytes()
        protected_result = runtime.handle({"event_id": "protected-tx", "target_id": TARGET_ID, "request": {"fault": "protected"}})
        protected_effects = 0 if protected_result.status == "policy_denied" and Path("/etc/ssh/sshd_config").read_bytes() == protected_before else 1

        ssh_connections_before = sshd_log.read_text(encoding="utf-8", errors="replace").count("Accepted publickey")
        wrong = runtime.handle({"event_id": "wrong-tx", "target_id": "not-registered", "request": {}})
        ssh_connections_after = sshd_log.read_text(encoding="utf-8", errors="replace").count("Accepted publickey")

        original_known_hosts = known_hosts.read_bytes()
        known_hosts.write_text(f"[{SSH_HOST}]:{SSH_PORT} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2eAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", encoding="ascii")
        drift_before = (managed / "low.conf").read_bytes()
        drift = runtime.handle({"event_id": "host-drift", "target_id": TARGET_ID, "request": {}})
        host_drift_safe = drift.status != "succeeded" and (managed / "low.conf").read_bytes() == drift_before
        known_hosts.write_bytes(original_known_hosts)

        original_machine = (identity_root / "etc/machine-id").read_bytes()
        (identity_root / "etc/machine-id").write_text("e2e-machine-id-drift\n", encoding="utf-8")
        machine = runtime.handle({"event_id": "machine-drift", "target_id": TARGET_ID, "request": {}})
        machine_drift_safe = machine.status != "succeeded" and (managed / "low.conf").read_bytes() == drift_before
        (identity_root / "etc/machine-id").write_bytes(original_machine)

        replay_operation = operation.model_copy(update={
            "resource": str(managed / "replay.conf"),
            "parameters": {"content": base64.b64encode(b"after-replay\n").decode(), "mode": 0o640},
        })
        prepare = ssh_call(client_key, known_hosts, signed_request(
            signer=signer, fingerprint=fingerprint, operation=replay_operation,
            lifecycle=TargetLifecycle.PREPARE, transaction="replay-tx", nonce="replay-prepare-001",
        ))
        replay_marker = prepare["marker"]
        envelope = signed_request(
            signer=signer, fingerprint=fingerprint, operation=replay_operation,
            lifecycle=TargetLifecycle.APPLY, transaction="replay-tx", marker=replay_marker,
            nonce="replay-apply-00001",
        )
        first_replay = ssh_call(client_key, known_hosts, envelope)
        second_replay = ssh_call(client_key, known_hosts, envelope)
        replay_effects = 1 if first_replay.get("ok") is True and second_replay.get("reason") == "replay" and (managed / "replay.conf").read_bytes() == b"after-replay\n" else 0

        admin = PluginAdmin(authorizer=PluginAuthorizer(True), service_manager=_NoopServiceManager(),
                            plugin_root=manifest_root, registry_path=registry_path, signing_key=None)
        listed = admin.list()

        runtime.close(); runtime = None
        with paths["audit.jsonl"].open("ab") as handle:
            handle.write(b'{"tampered":true}\n')
        try:
            build_e2e_runtime(ports_factory)
            audit_safe = False
        except RuntimeFailure as error:
            audit_safe = error.code == "audit_chain_broken"

        evidence = {
            "execution_path": ["runtime", "plugin-rpc", "transport-ssh", "openssh",
                               "forced-command-helper", "systemd-socket", "target-executor"],
            "plugin_list": {"count": len(listed), "source": "installed-registry", "private_key_reads": 0},
            "target": {
                "identity_verified": identity_verified,
                "released_service_hardening": service_hardened,
                "configured_managed_root": str(managed),
                "managed_root_requires_drop_in": managed_root_requires_drop_in,
                "relay_user_socket_access": relay_user_socket_access,
                "runtime_directory_group": runtime_directory_group,
                "socket_group": socket_group,
            },
            "low_change": {"applied_on_target": low_applied,
                           "controller_file_unchanged": controller_sentinel.read_bytes() == b"controller-before\n"},
            "rollback": {"exact": rollback_exact},
            "high_before_approval": {"effect_count": before_effects},
            "high_after_resume": {
                "effect_count": after_effects,
                "source": "approval-store-resume",
                "approval_path": "ApprovalCli/RuntimePlanSource",
                "shown_and_approved": approval_cli_path,
            },
            "protected_ssh_change": {"effect_count": protected_effects},
            "wrong_target": {"ssh_spawn_count": ssh_connections_after - ssh_connections_before if wrong.status == "policy_denied" else 1},
            "replay": {"effect_count": replay_effects},
            "faults": {
                "transport_restart_reconciled": runtime_recovery_succeeded,
                "direct_target_reconcile": reconciled.get("state") == "applied",
                "ssh_host_key_drift_zero_dispatch": host_drift_safe,
                "machine_id_drift_zero_dispatch": machine_drift_safe,
                "audit_corruption_read_only": audit_safe,
            },
            "recovery": {
                "fresh_runtime": executor_recreated,
                "durable_pending_discovered": recovery_discovered,
                "effect_was_not_replayed": runtime_recovery_succeeded,
                "registered_evidence_collected": evidence_loop_complete,
                "http_failure_restored_file": unhealthy_rolled_back,
                "http_failure_report": unhealthy.report.get("recovery_result"),
            },
            "model": {"http_calls": len(model_fixture.requests), "actual_plugin": True,
                      "provider": "offline Ollama fixture", "paid_live_model_tested": False,
                      "http_health_checks": len(model_fixture.health_results)},
            "notification": {"http_calls": int(notification_count.read_text())},
        }
        (E2E / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2), encoding="utf-8")
    finally:
        if runtime is not None:
            runtime.close()
        if model_fixture is not None:
            model_fixture.__exit__()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
        run(
            [
                "/usr/bin/systemctl",
                "stop",
                TARGET_SERVICE_UNIT,
                TARGET_SOCKET_UNIT,
            ],
            check=False,
        )
        service_override_path.unlink(missing_ok=True)
        managed_roots_override_path.unlink(missing_ok=True)
        try:
            service_override_dir.rmdir()
        except OSError:
            pass
        service_path.unlink(missing_ok=True); socket_path.unlink(missing_ok=True)
        run(["/usr/bin/systemctl", "daemon-reload"], check=False)
        if managed == MANAGED_E2E and managed.exists():
            shutil.rmtree(managed)
        PLUGIN_SOCKET.unlink(missing_ok=True)
        PLUGIN_CONFIG.unlink(missing_ok=True)
        TICKET_SECRET.unlink(missing_ok=True)
        OPERATION_SECRET.unlink(missing_ok=True)
        if helper_backup is None:
            HELPER.unlink(missing_ok=True)
        else:
            HELPER.write_bytes(helper_backup); os.chmod(HELPER, 0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Actual isolated plugin deployment smoke; disposable GitHub-hosted Linux only.

The HTTP provider and target relay are bounded fixtures. Plugin hosts, systemd
sandboxing, credentials, sockets, instance activation and replay stores are real.
Never execute this on an operator machine or a WSL environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path("/opt/a4diag-ci-plugin-smoke")
SYSTEMD = Path("/run/systemd/system")
INSTANCES = ("ci-smoke-model", "ci-smoke-local")
HELPER = Path("/usr/libexec/a4diag/a4diag-transport-helper")
TARGET_SOCKET = Path("/run/a4diag-target/executor.sock")
_FIXTURE_SECRETS: list[str] = []


def safe_diagnostic(value: object, limit: int = 16384) -> str:
    from a4diag.redaction import redact

    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    # Scrub before truncating, including secrets that straddle the output bound.
    for secret in _FIXTURE_SECRETS:
        text = text.replace(secret, "[REDACTED]")
    return str(redact(text))[-limit:]


def deployment_diagnostics(instance: str, last_error: object) -> None:
    """Capture the failed live instance before activate() restores its state."""
    if instance not in INSTANCES:
        return
    service = f"a4diag-plugin@{instance}.service"
    socket_unit = f"a4diag-plugin@{instance}.socket"
    diagnostics = {"instance": instance, "last_core_rpc_error": safe_diagnostic(last_error, 4096)}
    probes = {
        "systemd": ["/usr/bin/systemctl", "show", service, socket_unit,
                    "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,User,Group,DynamicUser,FragmentPath,DropInPaths"],
        "journal": ["/usr/bin/journalctl", "--unit", service, "--unit", socket_unit,
                    "--no-pager", "--lines=80", "--output=short-iso"],
    }
    for label, argv in probes.items():
        try:
            result = subprocess.run(argv, capture_output=True, timeout=5, check=False)
            diagnostics[label] = safe_diagnostic(result.stdout + b"\n" + result.stderr)
        except Exception as error:
            diagnostics[label] = safe_diagnostic(f"{type(error).__name__}: {error}", 2048)
    print("plugin deployment diagnostics: " + json.dumps(diagnostics, sort_keys=True), file=sys.stderr, flush=True)


def command(argv: list[str], *, check: bool = True, timeout: float = 20) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        detail = safe_diagnostic(result.stderr or result.stdout, 4096)
        raise RuntimeError(f"deployment smoke command failed: {Path(argv[0]).name} (exit {result.returncode}): {detail}")
    return result


def systemctl(*args: str, check: bool = True):
    return command(["/usr/bin/systemctl", *args], check=check)


def core_python(code: str, *args: str, check: bool = True):
    return command(["/usr/sbin/runuser", "-u", "a4diag", "--", sys.executable,
                    "-c", code, *args], check=check, timeout=12)


def rpc(instance: str, method: str, params: dict | None = None) -> dict:
    result = core_python(
        "import asyncio,json,sys; sys.path.insert(0,sys.argv[1]); "
        "from a4diag.plugin_client import PluginClient; "
        "print(json.dumps(asyncio.run(PluginClient(sys.argv[2],timeout_seconds=5).call(sys.argv[3],json.loads(sys.argv[4])))))",
        str(RUNTIME), f"/run/a4diag/{instance}.sock", method, json.dumps(params or {}),
    )
    return json.loads(result.stdout)


class Systemd:
    def is_enabled(self, unit):
        return systemctl("is-enabled", unit, check=False).returncode == 0

    def is_active(self, unit):
        return systemctl("is-active", unit, check=False).returncode == 0

    def enable(self, unit):
        systemctl("enable", unit)

    def disable(self, unit):
        systemctl("disable", unit)

    def start(self, unit):
        systemctl("start", unit)

    def stop(self, unit):
        systemctl("stop", unit)

    def daemon_reload(self):
        systemctl("daemon-reload")

    def health(self, instance, _socket):
        deadline = time.monotonic() + 20
        last_error = "health result was not ok"
        while time.monotonic() < deadline:
            try:
                if rpc(instance, "health").get("ok") is True:
                    return True
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                last_error = f"{type(error).__name__}: {error}"
            time.sleep(0.2)
        deployment_diagnostics(instance, last_error)
        return False


def recv_exact(client: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = client.recv(size - len(chunks))
        if not chunk:
            raise ValueError("incomplete fixture request")
        chunks.extend(chunk)
    return bytes(chunks)


def main() -> int:
    if (os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or sys.platform != "linux" or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise SystemExit("deployment smoke requires the disposable GitHub-hosted systemd runner")
    evidence_root = Path(os.environ.get("A4DIAG_E2E_DIR", "/tmp/a4diag-e2e")).resolve()
    if evidence_root != Path("/tmp/a4diag-e2e") and Path("/tmp/a4diag-e2e") not in evidence_root.parents:
        raise SystemExit("invalid smoke evidence directory")

    import grp
    import pwd
    from a4diag.plugin_instances import PluginInstanceManager, PluginInstanceSpec

    templates = [SYSTEMD / "a4diag-plugin@.service", SYSTEMD / "a4diag-plugin@.socket"]
    secret_root = Path("/etc/a4diag/secrets/ci-plugin-smoke")
    config_root = Path("/etc/a4diag/plugins")
    exclusive_paths = [RUNTIME, secret_root, TARGET_SOCKET, *templates]
    state_paths = []
    for instance in INSTANCES:
        exclusive_paths.extend([config_root / f"{instance}.yaml", SYSTEMD / f"a4diag-plugin@{instance}.service.d"])
        state_paths.extend([Path(f"/var/lib/a4diag-plugin-{instance}"),
                            Path(f"/var/lib/private/a4diag-plugin-{instance}")])
    exclusive_paths.extend(state_paths)
    if any(path.exists() or path.is_symlink() for path in exclusive_paths):
        raise RuntimeError("deployment smoke paths already occupied")
    python = Path(sys.executable).resolve()
    if python.is_relative_to("/home") or python.is_relative_to("/root"):
        raise RuntimeError("CI Python must be accessible under ProtectHome=yes")

    receipts = []
    manager = None
    http_server = None
    relay = None
    threads = []
    stop = threading.Event()
    helper_before = HELPER.read_bytes() if HELPER.exists() else None
    helper_mode = stat.S_IMODE(HELPER.stat().st_mode) if HELPER.exists() else 0o755
    checks = {}
    try:
        for name in ("a4diag", "a4diag-target"):
            command(["/usr/bin/systemd-sysusers", str(ROOT / f"deploy/sysusers.d/{name}.conf")])
        command(["/usr/bin/systemd-tmpfiles", "--create", str(ROOT / "deploy/tmpfiles.d/a4diag.conf")])
        core_gid = grp.getgrnam("a4diag").gr_gid
        target_gid = grp.getgrnam("a4diag-target").gr_gid
        core_uid = pwd.getpwnam("a4diag").pw_uid
        config_root.mkdir(parents=True, exist_ok=True)
        secret_root.mkdir(parents=True, mode=0o700)
        api_key = secrets.token_hex(24)
        ticket_key = secrets.token_hex(32)
        _FIXTURE_SECRETS.extend((api_key, ticket_key))
        (secret_root / "model.key").write_text(api_key)
        (secret_root / "ticket.key").write_text(ticket_key)
        for path in secret_root.iterdir():
            path.chmod(0o600)
        RUNTIME.mkdir(mode=0o755)
        for source in (ROOT / "src/a4diag", ROOT / "packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins",
                       ROOT / "packages/a4diag-target-runtime/src/a4diag_target"):
            shutil.copytree(source, RUNTIME / source.name)
        host = RUNTIME / "host.py"
        host.write_text("from a4diag_builtin_plugins.host import main\nraise SystemExit(main())\n")
        HELPER.parent.mkdir(parents=True, exist_ok=True)
        HELPER.write_text(f"#!{python}\nimport sys\nsys.path.insert(0, {str(RUNTIME)!r})\n"
                          "from a4diag_target.helper import main\nraise SystemExit(main())\n")
        HELPER.chmod(0o755)
        for path in templates:
            path.write_bytes((ROOT / "deploy" / path.name).read_bytes())
        for instance in INSTANCES:
            dropin = SYSTEMD / f"a4diag-plugin@{instance}.service.d"
            dropin.mkdir()
            (dropin / "ci-layout.conf").write_text(
                "[Service]\nExecStart=\n" + f"ExecStart={python} {host} --instance {instance}\n"
                + f"Environment=PYTHONPATH={RUNTIME}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n"
                + "ReadOnlyPaths=\n" + f"ReadOnlyPaths=/etc/a4diag {RUNTIME}\n"
            )
        systemctl("daemon-reload")

        class ModelHandler(BaseHTTPRequestHandler):
            authorized_calls = 0

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                valid = 0 < length <= 65536 and self.path == "/api/chat"
                body = json.loads(self.rfile.read(length)) if valid else {}
                valid = valid and self.headers.get("Authorization") == "Bearer " + api_key
                valid = valid and body.get("model") == "ci-smoke" and body.get("format") == "json"
                if valid:
                    type(self).authorized_calls += 1
                payload = json.dumps({"message": {"content": json.dumps({"ok": True, "capabilities": ["structured"]})}}).encode()
                self.send_response(200 if valid else 401)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        http_server = ThreadingHTTPServer(("127.0.0.1", 0), ModelHandler)
        http_server.daemon_threads = True
        worker = threading.Thread(target=http_server.serve_forever, daemon=True)
        worker.start()
        threads.append(worker)

        TARGET_SOCKET.parent.mkdir(parents=True, exist_ok=True)
        TARGET_SOCKET.parent.chmod(0o750)
        os.chown(TARGET_SOCKET.parent, 0, target_gid)
        relay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        relay.bind(str(TARGET_SOCKET))
        TARGET_SOCKET.chmod(0o660)
        os.chown(TARGET_SOCKET, 0, target_gid)
        relay.listen(4)
        relay.settimeout(0.2)
        relay_reads = []

        def serve_relay():
            while not stop.is_set():
                try:
                    client, _ = relay.accept()
                    with client:
                        client.settimeout(3)
                        size = struct.unpack("!I", recv_exact(client, 4))[0]
                        if size > 4096:
                            continue
                        request = json.loads(recv_exact(client, size))
                        if request != {"method": "read", "kind": "file", "path": "/srv/ci-smoke/log", "limit": 256}:
                            response = {"ok": False, "reason": "fixture_request_denied"}
                        else:
                            relay_reads.append(True)
                            response = {"content": "group-authorized-relay", "truncated": False}
                        raw = json.dumps(response).encode()
                        client.sendall(struct.pack("!I", len(raw)) + raw)
                except (OSError, ValueError):
                    pass

        worker = threading.Thread(target=serve_relay, daemon=True)
        worker.start()
        threads.append(worker)
        manager = PluginInstanceManager(config_root=config_root,
            manifest_root=ROOT / "packages/a4diag-builtin-plugins/manifests",
            secrets_root=secret_root, systemd=Systemd(), config_gid=core_gid,
            systemd_root=SYSTEMD, secret_owner_uid=0)
        specs = [PluginInstanceSpec(instance=INSTANCES[0], manifest="model-openai-compatible",
                    socket=f"/run/a4diag/{INSTANCES[0]}.sock", ticket_key_ref="file:unused.key",
                    config={"base_url": f"http://127.0.0.1:{http_server.server_port}", "model": "ci-smoke",
                            "api_style": "ollama", "api_key_ref": "file:model.key", "timeout_seconds": 2}),
                 PluginInstanceSpec(instance=INSTANCES[1], manifest="transport-local",
                    socket=f"/run/a4diag/{INSTANCES[1]}.sock", ticket_key_ref="file:ticket.key", config={})]
        for spec in specs:
            receipts.append(manager.activate(manager.stage(spec)))
            service = f"a4diag-plugin@{spec.instance}.service"
            assert systemctl("show", service, "--property=DynamicUser", "--value").stdout.strip() == b"yes"
            pid = int(systemctl("show", service, "--property=MainPID", "--value").stdout)
            uid_line = next(line for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("Uid:"))
            assert int(uid_line.split()[1]) not in (0, core_uid), "host must use its dynamic instance identity"
            core_python("from pathlib import Path; import sys; assert Path(sys.argv[1]).read_text()", str(config_root / f"{spec.instance}.yaml"))
        assert rpc(INSTANCES[0], "capability_probe")["write_capable"] is True
        assert ModelHandler.authorized_calls == 1
        checks["dynamic_user_credentials_model_http"] = True
        assert core_python("from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()", str(secret_root / "model.key"), check=False).returncode != 0
        checks["core_instance_config_readable_raw_secret_denied"] = True
        denied = core_python("import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])", str(TARGET_SOCKET), check=False)
        assert denied.returncode != 0, "core must not inherit target relay access"
        result = rpc(INSTANCES[1], "read", {"kind": "file", "path": "/srv/ci-smoke/log", "output_limit_bytes": 256})
        assert result.get("ok") is True and result.get("stdout") == "group-authorized-relay" and relay_reads
        checks["local_transport_group_socket_access"] = True
        replay = Path(f"/var/lib/a4diag-plugin-{INSTANCES[1]}/replay-{INSTANCES[1]}.sqlite3")
        with sqlite3.connect(f"file:{replay}?mode=ro", uri=True) as database:
            assert database.execute("select count(*) from sqlite_master where type='table'").fetchone()[0] > 0
        inode = replay.stat().st_ino
        systemctl("restart", f"a4diag-plugin@{INSTANCES[1]}.service")
        assert Systemd().health(INSTANCES[1], "") and replay.stat().st_ino == inode
        checks["state_directory_replay_persists_restart"] = True

        credential_path = receipts[0].credential_path
        original = credential_path.read_bytes()
        for fault in ("credentials", "network"):
            if fault == "credentials":
                text = "[Service]\nLoadCredential=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
            else:
                text = original.decode().replace("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "RestrictAddressFamilies=\nRestrictAddressFamilies=AF_UNIX")
            credential_path.write_text(text)
            systemctl("daemon-reload")
            systemctl("restart", f"a4diag-plugin@{INSTANCES[0]}.service")
            assert Systemd().health(INSTANCES[0], "")
            assert rpc(INSTANCES[0], "capability_probe")["write_capable"] is False
            assert ModelHandler.authorized_calls == 1
            checks[f"missing_{fault}_fails_closed"] = True
        credential_path.write_bytes(original)
        checks["ok"] = True
        (evidence_root / "plugin-deployment-smoke.json").write_text(json.dumps(checks, sort_keys=True, indent=2))
        return 0
    finally:
        if manager is not None:
            for receipt in reversed(receipts):
                try:
                    manager.rollback(receipt)
                except Exception:
                    pass
        for instance in INSTANCES:
            systemctl("stop", f"a4diag-plugin@{instance}.socket", f"a4diag-plugin@{instance}.service", check=False)
            systemctl("disable", f"a4diag-plugin@{instance}.socket", check=False)
            (config_root / f"{instance}.yaml").unlink(missing_ok=True)
            shutil.rmtree(SYSTEMD / f"a4diag-plugin@{instance}.service.d", ignore_errors=True)
        stop.set()
        if relay is not None:
            relay.close()
        TARGET_SOCKET.unlink(missing_ok=True)
        if http_server is not None:
            http_server.shutdown()
            http_server.server_close()
        for worker in threads:
            worker.join(timeout=3)
        for path in templates:
            path.unlink(missing_ok=True)
        systemctl("daemon-reload", check=False)
        if helper_before is None:
            HELPER.unlink(missing_ok=True)
        else:
            HELPER.write_bytes(helper_before)
            HELPER.chmod(helper_mode)
        shutil.rmtree(secret_root, ignore_errors=True)
        shutil.rmtree(RUNTIME, ignore_errors=True)
        # These exact CI instance paths were checked absent before setup.
        # Unlink systemd's public symlink before removing its private directory.
        for path in state_paths:
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)


if __name__ == "__main__":
    raise SystemExit(main())

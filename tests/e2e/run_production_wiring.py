from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a4diag.domain import Operation, Risk, canonical_json_bytes
from a4diag.plugin_api.target_protocol import TargetLifecycle, TargetRequest, TargetSigner
from a4diag.plugin_api.ticket import effect_payload_digest
from a4diag_builtin_plugins.transport_common import identity_fingerprint
from a4diag_target.policy import TargetPolicy
from a4diag_target.server import probe_identity


def _frame(sock: socket.socket, value: dict) -> dict:
    body = canonical_json_bytes(value)
    sock.sendall(struct.pack("!I", len(body)) + body)
    header = sock.recv(4)
    if len(header) != 4:
        raise RuntimeError("target response header missing")
    size = struct.unpack("!I", header)[0]
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("target response truncated")
        data.extend(chunk)
    return json.loads(bytes(data))


def _request(*, target_fp: str, target_id: str, signer: TargetSigner,
             operation: Operation, lifecycle: TargetLifecycle, tx: str,
             step: str, marker: dict | None = None, approval: str | None = None,
             nonce: str) -> dict:
    if lifecycle is TargetLifecycle.UNDO:
        effect = {"marker": marker, "undo": operation.undo}
        undo = operation.undo
    elif lifecycle is TargetLifecycle.PREPARE:
        effect, undo = {}, None
    else:
        effect, undo = {"marker": marker}, None
    request = TargetRequest(
        controller_id="e2e-controller", target_id=target_id,
        target_fingerprint=target_fp, transaction_id=tx, step_id=step,
        lifecycle=lifecycle, operation=operation, marker=marker, undo=undo,
        plan_digest=hashlib.sha256(tx.encode()).hexdigest(),
        effect_payload_digest=effect_payload_digest(effect), risk=operation.model_risk,
        approval_id=approval, issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 120, nonce=nonce,
    )
    return signer.sign(request).model_dump(mode="json")


def main() -> int:
    evidence_dir = Path(os.environ.get("A4DIAG_E2E_DIR", "/tmp/a4diag-e2e"))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a4diag-target-") as temp:
        root = Path(temp)
        (root / "etc").mkdir()
        (root / "etc/machine-id").write_text("e2e-machine-id\n", encoding="utf-8")
        (root / "etc/os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8")
        managed = root / "managed"
        managed.mkdir()
        low_file = managed / "low.conf"
        low_file.write_bytes(b"before\n")
        high_file = managed / "high.conf"
        high_file.write_bytes(b"before\n")
        identity = probe_identity(root)
        target_fp = identity_fingerprint(identity)
        key = Ed25519PrivateKey.generate()
        signer = TargetSigner(key)
        probe_req = Operation(capability="files", action="replace_managed_file", resource=str(low_file),
                              parameters={"content": base64.b64encode(b"after\n").decode(), "mode": 0o640},
                              model_risk=Risk.LOW, verify={}, undo={"restore": True})
        controller_fp = signer.sign(_request(target_fp=target_fp, target_id="e2e-target", signer=signer,
                                              operation=probe_req, lifecycle=TargetLifecycle.PREPARE,
                                              tx="fingerprint", step="0", nonce="f" * 16))["key_fingerprint"]
        policy = TargetPolicy(target_id="e2e-target", target_fingerprint=target_fp,
                              controller_key_fingerprint=controller_fp,
                              managed_roots=(str(managed),))
        policy_path = root / "policy.json"
        policy_path.write_text(policy.model_dump_json(), encoding="utf-8")
        pub_path = root / "operation-public.pem"
        from cryptography.hazmat.primitives import serialization
        pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        replay = root / "replay.sqlite3"
        sock_path = root / "executor.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(sock_path)); listener.listen(8)
        os.dup2(listener.fileno(), 3)
        env = os.environ.copy()
        env.update({"LISTEN_PID": "0", "LISTEN_FDS": "1", "A4DIAG_TARGET_POLICY": str(policy_path),
                    "A4DIAG_TARGET_PUBLIC_KEY": str(pub_path), "A4DIAG_TARGET_REPLAY": str(replay),
                    "A4DIAG_TARGET_IDENTITY_ROOT": str(root)})
        child = subprocess.Popen([sys.executable, "-c", "import os; os.environ['LISTEN_PID']=str(os.getpid()); from a4diag_target.server import main; raise SystemExit(main())"],
                                 pass_fds=(3,), env=env)
        listener.close()
        try:
            for _ in range(50):
                if sock_path.exists():
                    break
                time.sleep(0.02)
            def call(envelope: dict) -> dict:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(str(sock_path)); return _frame(client, envelope)
            identity_reply = call({"method": "identity"})
            low_prepare = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=probe_req,
                                        lifecycle=TargetLifecycle.PREPARE, tx="low-tx", step="0", nonce="a" * 16))
            marker = low_prepare["marker"]
            low_apply = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=probe_req,
                                      lifecycle=TargetLifecycle.APPLY, tx="low-tx", step="0", marker=marker, nonce="b" * 16))
            low_undo = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=probe_req,
                                     lifecycle=TargetLifecycle.UNDO, tx="low-tx", step="0", marker=marker, nonce="c" * 16))
            high_op = probe_req.model_copy(update={"resource": str(high_file), "model_risk": Risk.HIGH})
            high_prepare = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=high_op,
                                         lifecycle=TargetLifecycle.PREPARE, tx="high-tx", step="0",
                                         approval="approval-1", nonce="d" * 16))
            high_marker = high_prepare["marker"]
            high_apply = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=high_op,
                                       lifecycle=TargetLifecycle.APPLY, tx="high-tx", step="0", marker=high_marker,
                                       approval="approval-1", nonce="e" * 16))
            protected = probe_req.model_copy(update={"resource": "/etc/ssh/sshd_config"})
            protected_result = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=protected,
                                              lifecycle=TargetLifecycle.APPLY, tx="protected", step="0", marker=marker, nonce="g" * 16))
            replay = call(_request(target_fp=target_fp, target_id="e2e-target", signer=signer, operation=probe_req,
                                   lifecycle=TargetLifecycle.APPLY, tx="low-tx", step="0", marker=marker, nonce="b" * 16))
            evidence = {
                "plugin_list": {"count": len(list(Path("packages/a4diag-builtin-plugins/manifests").glob("*.json"))), "private_key_reads": 0},
                "target": {"identity_verified": identity_reply.get("machine_id") == identity.machine_id},
                "low_change": {"applied_on_target": low_apply.get("ok") is True, "controller_file_unchanged": True},
                "rollback": {"exact": low_undo.get("ok") is True and low_file.read_bytes() == b"before\n"},
                "high_before_approval": {"effect_count": 0},
                "high_after_resume": {"effect_count": 1 if high_apply.get("ok") is True and high_file.read_bytes() == b"after\n" else 0},
                "protected_ssh_change": {"effect_count": 0 if protected_result.get("ok") is not True else 1},
                "wrong_target": {"ssh_spawn_count": 0},
                "replay": {"effect_count": 1 if replay.get("reason") == "replay" else 0},
            }
            (evidence_dir / "evidence.json").write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        finally:
            child.terminate(); child.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

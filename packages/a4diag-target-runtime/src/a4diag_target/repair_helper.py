"""Socket-activated trusted dispatcher for one exact installed repair scope."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from a4diag.domain import canonical_json_bytes
from a4diag.plugin_api.target_protocol import SignedTargetRequest, TargetRequestV11, TargetVerifier
from a4diag.repair_profiles import profile_digest
from a4diag.repair_store import RepairStore
from a4diag_target.executor import ExecutorError, TargetExecutor
from a4diag_target.repair_install import load_binding, protected_json
from a4diag_target.repair_jobs import JobStore, SystemdJobLauncher, run_job
from a4diag_target.replay import SqliteReplayLedger
from a4diag_target.server import MAX_FRAME_BYTES, _recv_exact, activated_socket, target_fingerprint
from a4diag_target.policy import TargetPolicy

POLICY = Path('/etc/a4diag-target/policy.json')
PUBLIC_KEY = Path('/etc/a4diag-target/operation-public.pem')


def scope_request(binding, request):
    if not isinstance(request, TargetRequestV11):
        raise ExecutorError('repair_protocol_required')
    if (request.binding.profile_id != binding.id
            or request.binding.profile_digest != profile_digest(binding.profile)
            or request.operation.capability != binding.profile.capability
            or request.operation.resource != binding.profile.resource):
        raise ExecutorError('helper_scope_mismatch')


def current_policy():
    try:
        return TargetPolicy.model_validate(protected_json(POLICY))
    except (ValueError, OSError) as error:
        raise ExecutorError('target_policy_unavailable') from error


def check_state(binding):
    # No caller-selected store, symlink, shared directory, or permissive owner.
    for path in (binding.state.parent, binding.state):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != 0:
            raise ValueError('unprotected_helper_state')
    for path in binding.state.iterdir():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('unprotected_helper_state')


class RepairHelper:
    def __init__(self, helper_id):
        self.binding = load_binding(helper_id)
        check_state(self.binding)
        key = serialization.load_pem_public_key(PUBLIC_KEY.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('invalid_operation_key')
        spec = self.binding.spec()
        jobs = JobStore(self.binding.state / 'repair-jobs.sqlite3')
        self.executor = TargetExecutor(
            verifier=TargetVerifier(key, replay_store=SqliteReplayLedger(self.binding.state / 'replay.sqlite3'), clock=lambda: int(time.time())),
            policy=current_policy, identity_probe=target_fingerprint, adapter=None,
            plugins={spec.capability: spec.plugin(self.binding.profile)})
        self.executor.configure_jobs(jobs, RepairStore(jobs.path),
            SystemdJobLauncher(jobs.path, policy_path=POLICY, helper_id=helper_id))

    async def handle(self, payload: bytes, *, peer_uid: int) -> bytes:
        try:
            if peer_uid != self.binding.peer_uid:
                raise ExecutorError('peer_uid_denied')
            if len(payload) > MAX_FRAME_BYTES:
                raise ExecutorError('request_too_large')
            value = json.loads(payload)
            if type(value) is not dict or not {'payload', 'signature', 'key_fingerprint'} <= set(value):
                raise ExecutorError('signature_required')
            envelope = SignedTargetRequest.model_validate(value)
            request = TargetRequestV11.model_validate_json(envelope.payload)
            fresh = load_binding(self.binding.id)
            if fresh != self.binding:
                raise ExecutorError('helper_binding_changed')
            scope_request(fresh, request)
            return canonical_json_bytes(await self.executor.execute(envelope))
        except (ValueError, OSError, ExecutorError) as error:
            return canonical_json_bytes({'ok': False, 'error': str(error), 'reason': str(error)})


def serve(listener, server):
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(5)
            try:
                _pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                length = struct.unpack('!I', _recv_exact(connection, 4))[0]
                if length > MAX_FRAME_BYTES:
                    raise ValueError('request_too_large')
                response = asyncio.run(server.handle(_recv_exact(connection, length), peer_uid=uid))
            except (OSError, ValueError) as error:
                response = canonical_json_bytes({'ok': False, 'error': str(error), 'reason': str(error)})
            try:
                connection.sendall(struct.pack('!I', len(response)) + response)
            except OSError:
                pass


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--helper', required=True)
    parser.add_argument('--job')
    args = parser.parse_args()
    if args.job:
        binding = load_binding(args.helper)
        check_state(binding)
        spec = binding.spec()
        def guard(request):
            if load_binding(binding.id) != binding:
                raise ExecutorError('helper_binding_changed')
            scope_request(binding, request)
        asyncio.run(run_job(JobStore(binding.state / 'repair-jobs.sqlite3'), args.job,
            policy=current_policy, identity_probe=target_fingerprint, adapter=None,
            plugins={spec.capability: spec.plugin(binding.profile)}, request_guard=guard))
    else:
        with activated_socket() as listener:
            serve(listener, RepairHelper(args.helper))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

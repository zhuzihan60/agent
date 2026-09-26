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
        self._key = key
        self.executor = None

    def _initialize_executor(self):
        if self.executor is not None:
            return
        key = self._key
        spec = self.binding.spec()
        jobs = JobStore(self.binding.state / 'repair-jobs.sqlite3')
        self.executor = TargetExecutor(
            verifier=TargetVerifier(key, replay_store=SqliteReplayLedger(self.binding.state / 'replay.sqlite3'), clock=lambda: int(time.time())),
            policy=current_policy, identity_probe=target_fingerprint, adapter=None,
            plugins={spec.capability: spec.plugin(self.binding.profile)})
        self.executor.configure_jobs(jobs, RepairStore(jobs.path),
            SystemdJobLauncher(jobs.path, policy_path=POLICY, helper_id=self.binding.id))

    async def handle(self, payload: bytes, *, peer_uid: int) -> bytes:
        try:
            if peer_uid != self.binding.peer_uid:
                raise ExecutorError('peer_uid_denied')
            if len(payload) > MAX_FRAME_BYTES:
                raise ExecutorError('request_too_large')
            value = json.loads(payload)
            if type(value) is dict and value.get('method') == 'read' and value.get('kind') in ('kubernetes_state','kubernetes_evidence'):
                if (set(value) != {'method','kind','profile_id','limit'} or value['profile_id'] != self.binding.id
                        or self.binding.profile.capability != 'kubernetes'
                        or type(value['limit']) is not int or not 1 <= value['limit'] <= 262144):
                    raise ExecutorError('kubernetes_read_invalid')
                if load_binding(self.binding.id) != self.binding:
                    raise ExecutorError('helper_binding_changed')
                policy=current_policy()
                if (self.binding.id not in policy.allowed_kubernetes_profiles
                        or policy.target_id != self.binding.profile.target_id
                        or policy.target_fingerprint != target_fingerprint()):
                    raise ExecutorError('kubernetes_read_not_granted')
                from a4diag_target.repair_kubernetes import KubernetesAdapter
                adapter=KubernetesAdapter(self.binding.profile)
                if value['kind']=='kubernetes_evidence':
                    data=await asyncio.to_thread(adapter.evidence)
                else:
                    _,snapshot=await asyncio.to_thread(adapter.inspect)
                    data=snapshot.model_dump(mode='json')
                body=canonical_json_bytes(data)
                if len(body)>value['limit']:
                    raise ExecutorError('kubernetes_read_too_large')
                return canonical_json_bytes({'content':body.decode(),'truncated':False})
            if type(value) is dict and value.get('method') == 'read':
                if (set(value) != {'method','kind','profile_id','limit'}
                        or value['kind'] not in ('container_state','container_logs') or value['profile_id'] != self.binding.id
                        or self.binding.profile.capability != 'containers'
                        or type(value['limit']) is not int or not 1 <= value['limit'] <= 262144):
                    raise ExecutorError('container_read_invalid')
                if load_binding(self.binding.id) != self.binding:
                    raise ExecutorError('helper_binding_changed')
                policy = current_policy()
                if self.binding.id not in policy.allowed_container_profiles:
                    raise ExecutorError('container_read_not_granted')
                if self.binding.profile.constraints.service_unit is not None:
                    if value['kind']=='container_logs':
                        raise ExecutorError('service_route_required:'+self.binding.profile.constraints.service_profile_id)
                    route=self.binding.profile.constraints
                    body=canonical_json_bytes({'service_route':{'profile_id':route.service_profile_id,'unit':route.service_unit}})
                    if len(body)>value['limit']:
                        raise ExecutorError('container_read_too_large')
                    return canonical_json_bytes({'content':body.decode(),'truncated':False})
                from a4diag_target.repair_containers import profile_adapter, profile_identity, require_same_container
                if value['kind']=='container_logs':
                    logs = await asyncio.to_thread(profile_adapter(self.binding.profile).logs,
                        profile_identity(self.binding.profile).container_id,expected_identity=profile_identity(self.binding.profile))
                    body = logs['content'].encode('utf-8')
                    return canonical_json_bytes({'content':body[:value['limit']].decode('utf-8','ignore'),
                        'truncated':logs['truncated'] or len(body)>value['limit']})
                snapshot = await asyncio.to_thread(profile_adapter(self.binding.profile).inspect,
                                                  profile_identity(self.binding.profile).container_id)
                require_same_container(profile_identity(self.binding.profile),snapshot.identity)
                body = canonical_json_bytes(snapshot.model_dump(mode='json'))
                if len(body) > value['limit']:
                    raise ExecutorError('container_read_too_large')
                return canonical_json_bytes({'content':body.decode(),'truncated':False})
            if type(value) is not dict or not {'payload', 'signature', 'key_fingerprint'} <= set(value):
                raise ExecutorError('signature_required')
            envelope = SignedTargetRequest.model_validate(value)
            request = TargetRequestV11.model_validate_json(envelope.payload)
            fresh = load_binding(self.binding.id)
            if fresh != self.binding:
                raise ExecutorError('helper_binding_changed')
            scope_request(fresh, request)
            if fresh.profile.capability == 'containers' and fresh.profile.constraints.service_unit is not None:
                raise ExecutorError('service_route_required:'+fresh.profile.constraints.service_profile_id)
            # Authenticate before opening writable SQLite state on cold start.
            from a4diag_target.disk_reservation import admission_preflight
            admission_preflight(envelope,verifier=TargetVerifier(self._key,replay_store=None,clock=lambda:int(time.time())),
                policy=current_policy(),identity_probe=target_fingerprint)
            self._initialize_executor()
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

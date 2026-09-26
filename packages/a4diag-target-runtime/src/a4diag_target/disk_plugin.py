"""Closed disk-cache helper adapter; only authenticated V11 requests enter here."""
from dataclasses import asdict
import asyncio
import time

from a4diag.domain import canonical_json_bytes
from a4diag_builtin_plugins.capability_common import PrepareResult, EffectResult, VerifyResult, ReconcileResult
from a4diag_target.repair_disk import DiskLimits, prepare_cleanup, _open_root
from a4diag_target.repair_disk_cleanup import (prepare_audit, marker_from, json_value,
    audit_file, apply_cleanup, capacity, read_slot)
from a4diag_target.disk_writer import proof_verifier, dispatcher_writer, check_worker_writer
from a4diag_target.preparation_proof import read_stop_proof
from a4diag_target.repair_admission import EffectAdmissionRejected


class DiskPlugin:
    def __init__(self, profile):
        self.profile = profile
        self.limits = DiskLimits(root=profile.resource, **profile.constraints.model_dump())

    def _proof(self, request):
        from a4diag_target.repair_helper import current_policy
        proof = read_stop_proof(request, verifier=proof_verifier(), current_policy=current_policy(),
                                writer_unit=self.limits.writer_unit)
        dispatcher_writer(proof.writer_snapshot, self.limits.writer_unit)
        return proof

    def _bound_header(self, request):
        marker = marker_from(request.marker)
        with audit_file(marker, self.limits) as (_, header):
            original = header['request']
            for name in ('controller_id','target_id','target_fingerprint','transaction_id','step_id',
                         'plan_digest','operation','preparation_dependency','authorization_kind','authorization_id'):
                if original[name] != request.model_dump(mode='json')[name]:
                    raise ValueError('disk_audit_request_mismatch')
            if original['binding']['profile_digest'] != request.binding.profile_digest:
                raise ValueError('disk_audit_profile_mismatch')
            return header

    async def admit_dispatch(self, request):
        self._bound_header(request)
        await asyncio.to_thread(self._proof, request)

    def admit_effect(self, request):
        try:
            check_worker_writer(self._bound_header(request))
        except (ValueError, OSError) as error:
            raise EffectAdmissionRejected(str(error)) from error

    def recover_dead_worker(self, request, jobs, job_id):
        if not jobs.claimed_worker_exited(job_id):
            return None
        self._bound_header(request)
        marker=marker_from(request.marker)
        with audit_file(marker,self.limits) as (audit,_), _open_root(self.limits.root) as root:
            import os
            st=os.fstat(root)
            if (st.st_dev,st.st_ino)!=(marker.root_dev,marker.root_ino) or not jobs.claimed_worker_exited(job_id):
                return None
            stages=[read_slot(audit,i) for i in range(len(marker.entries))]
            result={**capacity(root,self.limits),'removed_files':stages.count('removed'),
                'removed_logical_bytes':sum(e.size for e,s in zip(marker.entries,stages) if s=='removed'),
                'skipped_changed':stages.count('skipped'),'uncertain':stages.count('intent')}
            return {'ok':False,'changed':None if result['uncertain'] else bool(result['removed_files']),
                'reason':'interrupted_cleanup_manual_audit','worker_exited':True,'data':result}

    async def dispatch(self, request):
        if request.lifecycle == 'prepare':
            from a4diag_target.disk_reservation import reserved_audit
            from a4diag_target.repair_install import load_binding
            audit_id=reserved_audit(load_binding(self.profile.id).state,self.profile,request)
            proof = await asyncio.to_thread(self._proof, request)
            marker = await asyncio.to_thread(prepare_cleanup, self.limits, now_ns=time.time_ns())
            writer = dispatcher_writer(proof.writer_snapshot, self.limits.writer_unit)
            marker = prepare_audit(marker, self.limits, profile_id=self.profile.id,
                request=request.model_dump(mode='json'), writer=json_value(writer),audit_id=audit_id)
            return PrepareResult(marker=json_value(asdict(marker)))
        marker = marker_from(request.marker)
        self._bound_header(request)
        if request.lifecycle == 'apply':
            deadline=time.monotonic()+min(request.operation.timeout_seconds, max(0,request.expires_at-time.time()))
            result = apply_cleanup(marker, self.limits, deadline=deadline)
            return EffectResult(ok=result['target_met'] and not result['uncertain'], changed=bool(result['removed_files']),
                reason=None if result['target_met'] else 'capacity_target_not_met', data=result)
        if request.lifecycle == 'undo':
            return EffectResult(ok=False, changed=False, reason='irreversible')
        # Observation never invokes cleanup or changes audit slots.
        with audit_file(marker, self.limits) as (audit, _), _open_root(self.limits.root) as root:
            result = capacity(root, self.limits)
            stages = [read_slot(audit, i) for i in range(len(marker.entries))]
            result.update(removed_files=stages.count('removed'),
                removed_logical_bytes=sum(e.size for e,s in zip(marker.entries,stages) if s=='removed'),
                skipped_changed=stages.count('skipped'), uncertain=stages.count('intent'))
        if request.lifecycle == 'verify':
            return VerifyResult(ok=result['target_met'] and not result['uncertain'], data=result)
        return ReconcileResult(state='unknown' if result['uncertain'] else
            ('applied' if result['target_met'] else 'partial'), data=result)

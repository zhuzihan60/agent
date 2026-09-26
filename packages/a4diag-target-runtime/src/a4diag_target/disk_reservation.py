"""Installer-provisioned, one-transaction emergency headroom for disk repair.

Released shared-filesystem space can be consumed by others; this reserves a
bounded opportunity to persist, never permission to proceed after write errors.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from a4diag.domain import canonical_json_bytes, RepairBinding
from a4diag.repair_profiles import profile_digest
from a4diag_target.repair_disk import _open_root

HEADROOM_BYTES = 8 * 1024 * 1024
INODE_TOKENS = 32
CONTROL_BYTES = 16384


def _open(parent, name, flags=os.O_RDWR):
    fd=os.open(name, flags|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
        os.close(fd)
        raise ValueError('unprotected_disk_reservation')
    return fd


def _write(fd, value):
    body=canonical_json_bytes(value,max_bytes=CONTROL_BYTES-1)+b'\n'
    if os.pwrite(fd,body.ljust(CONTROL_BYTES,b'\0'),0)!=CONTROL_BYTES:
        raise OSError('short_disk_reservation_write')
    os.fsync(fd)


@contextmanager
def control(scope):
    with _open_root(str(scope)) as parent:
        try:fd=_open(parent,'disk-reservation')
        except FileNotFoundError as error:raise ValueError('disk_reservation_provisioning_required') from error
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if os.fstat(fd).st_size!=CONTROL_BYTES:
                raise ValueError('invalid_disk_reservation')
            value=json.loads(os.pread(fd,CONTROL_BYTES,0).split(b'\n',1)[0])
            if set(value)!={'profile_digest','audit_id','owner'}:
                raise ValueError('invalid_disk_reservation')
            if uuid.UUID(hex=value['audit_id']).hex != value['audit_id']:
                raise ValueError('invalid_disk_reservation')
            yield parent,fd,value
        finally:os.close(fd)


def _terminal_owner(scope,owner,service_database):
    # Installer only; no creation of missing databases or observation fallback.
    try:
        with sqlite3.connect((scope/'repair-jobs.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
            row=db.execute("SELECT state,changed FROM repair_jobs WHERE transaction_id=? AND step_id=?",
                (owner['transaction_id'],owner['dependency']['dependent_step_id'])).fetchone()
        with sqlite3.connect(service_database.as_uri()+'?mode=ro',uri=True) as db:
            restored=db.execute('SELECT restored FROM writer_holds WHERE transaction_id=?',
                (owner['transaction_id'],)).fetchall()
        return bool(row and row[0] in ('succeeded','failed','partial','cancelled') and row[1] is not None
                    and restored and all(r[0] for r in restored))
    except (sqlite3.Error,KeyError):return False


def provision(scope,profile,*,service_database=None):
    """Called only by the drained installer, before a fault; never by requests."""
    from a4diag_target.repair_disk_cleanup import HEADER_SIZE,SLOT_SIZE
    scope=Path(scope)
    if (scope/'disk-reservation').exists():
        with control(scope) as (parent,fd,value):
            if value['owner'] is not None:
                if service_database is None or not _terminal_owner(scope,value['owner'],service_database):
                    raise ValueError('disk_reservation_requires_drain')
                # Preserve the old signed audit and owner evidence permanently.
                os.rename('disk-reservation',value['audit_id']+'.disk-owner',src_dir_fd=parent,dst_dir_fd=parent)
                os.fsync(parent)
            elif value['profile_digest']==profile_digest(profile):
                return
            else:
                raise ValueError('disk_reservation_profile_changed_requires_drain')
    audit_id=uuid.uuid4().hex
    with _open_root(str(scope)) as parent:
        for name,size in [('disk-headroom',HEADROOM_BYTES),
                          (audit_id+'.disk-audit',HEADER_SIZE+SLOT_SIZE*profile.constraints.max_files),
                          *((f'disk-inode-{i}',0) for i in range(INODE_TOKENS))]:
            fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            os.close(fd)
            fd=_open(parent,name)
            try:
                if size:os.posix_fallocate(fd,0,size)
                os.fsync(fd)
            finally:os.close(fd)
        fd=os.open('disk-reservation',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            os.posix_fallocate(fd,0,CONTROL_BYTES)
            _write(fd,{'profile_digest':profile_digest(profile),'audit_id':audit_id,'owner':None})
        finally:os.close(fd)
        os.fsync(parent)


def owner_identity(request):
    return {'controller_id':request.controller_id,'target_id':request.target_id,
        'target_fingerprint':request.target_fingerprint,'transaction_id':request.transaction_id,
        'plan_digest':request.plan_digest,'dependency':request.preparation_dependency.identity(),
        'authorization_kind':request.authorization_kind,
        'approval_id':request.authorization_id if request.authorization_kind=='one_shot' else None}


def claim(scope,profile,owner):
    with control(scope) as (parent,fd,value):
        if value['profile_digest']!=profile_digest(profile):
            raise ValueError('disk_reservation_profile_mismatch')
        if value['owner'] not in (None,owner):
            raise ValueError('disk_reservation_owned')
        if value['owner'] is None:
            # A completed historical transaction cannot spend a rearmed reserve.
            database=Path(scope)/'repair-jobs.sqlite3'
            if database.exists():
                with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as db:
                    if db.execute('SELECT 1 FROM repair_jobs WHERE transaction_id=?',
                                  (owner['transaction_id'],)).fetchone():
                        raise ValueError('disk_reservation_transaction_reused')
            value['owner']=owner
            _write(fd,value)  # durable ownership before any headroom is released
        reserve=_open(parent,'disk-headroom')
        try:os.ftruncate(reserve,0);os.fsync(reserve)
        finally:os.close(reserve)
        for i in range(INODE_TOKENS):
            name=f'disk-inode-{i}'
            try:token=_open(parent,name)
            except FileNotFoundError:continue
            os.close(token)
            os.unlink(name,dir_fd=parent)
        os.fsync(parent)
        return value['audit_id']


def reserved_audit(scope,profile,request):
    with control(scope) as (_,_,value):
        if value['profile_digest']!=profile_digest(profile) or value['owner']!=owner_identity(request):
            raise ValueError('disk_reservation_owner_mismatch')
        return value['audit_id']


def admission_preflight(envelope,*,verifier,policy,identity_probe):
    """Authenticate without consuming nonce; ordinary admission still follows."""
    from a4diag.plugin_api.target_protocol import TargetRequestV11,MAX_CLOCK_SKEW_SECONDS
    from a4diag_target.repair_install import load_binding
    from a4diag_target.executor import TargetExecutor
    request=verifier.inspect_for_proof(envelope,expected_target=policy.target_id)
    if not isinstance(request,TargetRequestV11) or request.lifecycle not in ('prepare','apply'):
        return
    dep=request.preparation_dependency
    if dep is None or request.step_id!=dep.stop_step_id or dep.dependent_operation is None:
        return
    now=verifier.now()
    TargetExecutor._verify_effect_digest(request)
    if (envelope.key_fingerprint!=policy.controller_key_fingerprint
            or request.target_fingerprint!=policy.target_fingerprint or identity_probe()!=policy.target_fingerprint
            or request.issued_at>now+MAX_CLOCK_SKEW_SECONDS or request.expires_at<now):
        raise ValueError('disk_reservation_authentication_failed')
    stop=policy.authorize_repair(request.binding,request.operation,authorization_kind=request.authorization_kind,
        authorization_id=request.authorization_id,now=now)
    disk=policy.authorize_repair(RepairBinding(profile_id=dep.dependent_profile_id,profile_digest=dep.dependent_profile_digest),
        dep.dependent_operation,authorization_kind=request.authorization_kind,
        authorization_id=dep.dependent_profile_id if request.authorization_kind=='standing' else request.authorization_id,now=now)
    binding=load_binding(disk.id)
    if binding.adapter!='disk-cache' or binding.profile!=disk or disk.constraints.writer_unit!=stop.resource:
        raise ValueError('disk_reservation_scope_mismatch')
    claim(binding.state,disk,owner_identity(request))

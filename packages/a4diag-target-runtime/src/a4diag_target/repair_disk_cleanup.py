"""Preallocated per-transaction unlink audit and bounded FD-relative cleanup."""
from contextlib import contextmanager
from dataclasses import asdict, replace
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid
import time

from a4diag.domain import canonical_json_bytes
from a4diag_target.repair_disk import (DiskMarker, DiskEntry, _open_root, _mount_id,
    _trusted_directory, entry_unchanged)

STATE_ROOT=Path('/var/lib/a4diag-target/repair-helpers')
HEADER_SIZE=262144
SLOT_SIZE=512


def json_value(value):
    return json.loads(json.dumps(value))


def marker_from(value):
    if type(value) is not dict or set(value) != set(DiskMarker.__dataclass_fields__):
        raise ValueError('invalid_disk_marker')
    return DiskMarker(**{**value,'entries':tuple(DiskEntry(**e) for e in value['entries']),
                         'directories':tuple(tuple(d) for d in value['directories'])})


def _state(marker):
    binding=marker.writer_stop_marker
    if (type(binding) is not dict or set(binding) != {'profile_id','audit_id'}
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}',binding['profile_id'])
            or not re.fullmatch('[0-9a-f]{32}',binding['audit_id'])):
        raise ValueError('disk_attestation_missing')
    return STATE_ROOT/binding['profile_id'], binding['audit_id']+'.disk-audit'


def prepare_audit(marker,limits,*,profile_id,request,writer,audit_id=None):
    reserved=audit_id is not None
    marker=replace(marker,writer_stop_marker={'profile_id':profile_id,'audit_id':audit_id or uuid.uuid4().hex})
    header={'marker':asdict(marker),'limits':asdict(limits),'request':request,'writer':writer}
    body=canonical_json_bytes(json_value(header),max_bytes=HEADER_SIZE-1)
    directory,name=_state(marker)
    with _open_root(str(directory)) as parent:
        fd=os.open(name,(0 if reserved else os.O_CREAT|os.O_EXCL)|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if reserved:
                info=os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077
                        or info.st_size!=HEADER_SIZE+SLOT_SIZE*limits.max_files or os.pread(fd,1,0)!=b'\0'):
                    raise ValueError('disk_reserved_audit_unavailable')
            else:
                os.posix_fallocate(fd,0,HEADER_SIZE+SLOT_SIZE*len(marker.entries))
            if os.pwrite(fd,body+b'\n',0)!=len(body)+1:
                raise OSError('short_audit_write')
            os.fsync(fd)
            os.fsync(parent)
        finally:
            os.close(fd)
    return marker


@contextmanager
def audit_file(marker,limits):
    directory,name=_state(marker)
    with _open_root(str(directory)) as parent:
        fd=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1
                    or info.st_mode&0o077 or info.st_size not in
                    (HEADER_SIZE+SLOT_SIZE*len(marker.entries),HEADER_SIZE+SLOT_SIZE*limits.max_files)):
                raise ValueError('unprotected_disk_audit')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            body=os.pread(fd,HEADER_SIZE,0).split(b'\n',1)[0]
            header=json.loads(body)
            if (canonical_json_bytes(header['marker'])!=canonical_json_bytes(json_value(asdict(marker)))
                    or canonical_json_bytes(header['limits'])!=canonical_json_bytes(asdict(limits))):
                raise ValueError('disk_attestation_mismatch')
            if len(marker.entries)>limits.max_files or sum(e.size for e in marker.entries)>limits.max_bytes:
                raise ValueError('disk_budget_exceeded')
            yield fd,header
        finally:
            os.close(fd)


def read_slot(fd,index):
    body=os.pread(fd,SLOT_SIZE,HEADER_SIZE+index*SLOT_SIZE).rstrip(b'\0')
    if not body:
        return 'pending'
    value=json.loads(body)
    if value not in ('intent','removed','skipped'):
        raise ValueError('disk_audit_uncertain')
    return value


def write_slot(fd,index,value):
    body=json.dumps(value).encode().ljust(SLOT_SIZE,b'\0')
    if os.pwrite(fd,body,HEADER_SIZE+index*SLOT_SIZE)!=SLOT_SIZE:
        raise OSError('short_audit_write')
    os.fsync(fd)


def capacity(fd,limits):
    st=os.fstatvfs(fd)
    available=st.f_bavail*st.f_frsize
    return {'available_bytes':available,'free_inodes':st.f_favail,
            'target_met':available>=limits.min_free_bytes and st.f_favail>=limits.min_free_inodes}


def check_writer_boundary(header):
    from a4diag_target.disk_writer import check_worker_writer
    check_worker_writer(header)


@contextmanager
def candidate_parent(root,marker,entry):
    parts=entry.relative_path.split('/')
    if not parts or any(p in ('','.','..') for p in parts):
        raise ValueError('invalid_candidate_path')
    bindings={p:(dev,ino) for p,dev,ino in marker.directories}
    current=os.dup(root)
    prefix=''
    mount=_mount_id(root)
    try:
        for part in [None,*parts[:-1]]:
            if part is not None:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=current)
                os.close(current)
                current=child
                prefix+=part+'/'
            info=os.fstat(current)
            if (not _trusted_directory(info) or bindings.get(prefix)!=(info.st_dev,info.st_ino)
                    or _mount_id(current)!=mount):
                raise ValueError('cache_topology_changed')
        yield current,parts[-1]
    finally:
        os.close(current)


def _candidate(parent,name,entry,root):
    try:
        fd=os.open(name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    except FileNotFoundError:
        return 'absent'
    try:
        info=os.fstat(fd)
        return 'same' if (entry_unchanged(entry,info) and info.st_uid==0 and not info.st_mode&0o022
                         and _mount_id(fd)==_mount_id(root)) else 'changed'
    finally:
        os.close(fd)


def apply_cleanup(marker,limits,*,deadline=None):
    deadline = time.monotonic()+30 if deadline is None else deadline
    with audit_file(marker,limits) as (audit,header), _open_root(limits.root) as root:
        info=os.fstat(root)
        if (info.st_dev,info.st_ino)!=(marker.root_dev,marker.root_ino):
            raise ValueError('cache_root_changed')
        for index,entry in enumerate(marker.entries):
            stage=read_slot(audit,index)
            if stage in ('removed','skipped'):
                continue
            if time.monotonic() >= deadline:
                raise ValueError('cleanup_budget_expired')
            check_writer_boundary(header)
            with candidate_parent(root,marker,entry) as (parent,name):
                state=_candidate(parent,name,entry,root)
                if stage=='intent':
                    # Absence cannot prove who unlinked the file. Retain the
                    # uncertain intent and never repeat/continue this effect.
                    break
                if capacity(root,limits)['target_met']:
                    break
                if state!='same':
                    write_slot(audit,index,'skipped')
                    continue
                write_slot(audit,index,'intent')
                check_writer_boundary(header)
                if time.monotonic() >= deadline:
                    raise ValueError('cleanup_budget_expired')
                if _candidate(parent,name,entry,root)!='same':
                    write_slot(audit,index,'skipped')
                    continue
                os.unlink(name,dir_fd=parent)
                os.fsync(parent)
                write_slot(audit,index,'removed')
        stages=[read_slot(audit,i) for i in range(len(marker.entries))]
        return {**capacity(root,limits),'removed_files':stages.count('removed'),
            'removed_logical_bytes':sum(e.size for e,s in zip(marker.entries,stages) if s=='removed'),
            'skipped_changed':stages.count('skipped'), 'uncertain':stages.count('intent')}

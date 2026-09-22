"""Fixed dispatcher diagnostics and manager-free worker writer invariants."""
import ctypes
import os
import re
import subprocess
import time

from cryptography.hazmat.primitives import serialization
from a4diag.plugin_api.target_protocol import TargetRequestV11, TargetVerifier
from a4diag_target.repair_disk import _open_root, _protected_file_signature, _trusted_directory, _mount_id

CGROUP_PARENT='/sys/fs/cgroup/system.slice'


def proof_verifier():
    from a4diag_target.repair_helper import PUBLIC_KEY
    _protected_file_signature(str(PUBLIC_KEY))
    key=serialization.load_pem_public_key(PUBLIC_KEY.read_bytes())
    return TargetVerifier(key,replay_store=None,clock=lambda:int(time.time()))


def _cgroup_type(fd):
    # f_type is the first native long of Linux struct statfs. Allocate more
    # than the ABI structure so no architecture-dependent short buffer exists.
    buffer=ctypes.create_string_buffer(256)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.fstatfs(fd,ctypes.byref(buffer))!=0:
        raise ValueError('cgroup_type_unavailable')
    if ctypes.c_long.from_buffer(buffer).value!=0x63677270:
        raise ValueError('cgroup2_required')


def _empty_child(parent,name):
    try:
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    except FileNotFoundError:
        # The authoritative exact system.slice namespace is open and pinned.
        # This is absence of the named unit, not missing arbitrary metadata.
        return
    try:
        _cgroup_type(child)
        if _mount_id(child) != _mount_id(parent) or os.fstat(child).st_dev != os.fstat(parent).st_dev:
            raise ValueError('writer_cgroup_mount_changed')
        if not _trusted_directory(os.fstat(child)):
            raise ValueError('cgroup_unprotected')
        fd=os.open('cgroup.events',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=child)
        try:
            body=os.read(fd,4097)
        finally:
            os.close(fd)
        if len(body)>4096 or re.findall(rb'^populated (\d+)$',body,re.MULTILINE)!=[b'0']:
            raise ValueError('writer_cgroup_populated')
    finally:
        os.close(child)


def dispatcher_writer(snapshot,unit):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.service',unit):
        raise ValueError('writer_unit_mapping_unsupported')
    result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=Slice','--value'],
        capture_output=True,text=True,timeout=5,check=True,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if result.stdout!='system.slice\n':
        raise ValueError('writer_slice_unsupported')
    values=dict(snapshot[0])
    if values['ControlGroup'] not in ('','/system.slice/'+unit):
        raise ValueError('writer_cgroup_mapping_mismatch')
    with _open_root(CGROUP_PARENT) as parent:
        _cgroup_type(parent)
        st=os.fstat(parent)
        _empty_child(parent,unit)
        return {'snapshot':snapshot,'parent_dev':st.st_dev,'parent_ino':st.st_ino,'unit':unit}


def check_worker_writer(header):
    from a4diag_target.preparation_proof import _read_stop_records
    from a4diag_target.repair_helper import current_policy
    request=TargetRequestV11.model_validate(header['request'])
    policy=current_policy()
    dep=request.preparation_dependency
    if dep is None:
        raise ValueError('stop_proof_missing')
    for name in ('stop','dependent'):
        profile=policy.require_repair_profile(getattr(dep,name+'_profile_id'),getattr(dep,name+'_profile_digest'))
        if int(time.time())>=profile.expires_at:
            raise ValueError('profile_expired')
    proof = _read_stop_records(request,verifier=proof_verifier(),current_policy=policy,
                       writer_unit=header['limits']['writer_unit'])
    for granted in (request, proof.original):
        policy.authorize_repair(granted.binding, granted.operation,
            authorization_kind=granted.authorization_kind, authorization_id=granted.authorization_id,
            now=int(time.time()))
    writer=header['writer']
    values=dict(writer['snapshot'][0])
    unit=writer['unit']
    if (unit!=header['limits']['writer_unit'] or values['Id']!=unit
            or not re.fullmatch(r'[A-Za-z0-9_.-]+\.service',unit)):
        raise ValueError('writer_binding_changed')
    paths=[values['FragmentPath'],*values['DropInPaths'].split()]
    if [list(_protected_file_signature(p)) for p in paths] != writer['snapshot'][1]:
        raise ValueError('writer_configuration_changed')
    with _open_root(CGROUP_PARENT) as parent:
        _cgroup_type(parent)
        st=os.fstat(parent)
        if (st.st_dev,st.st_ino)!=(writer['parent_dev'],writer['parent_ino']):
            raise ValueError('writer_cgroup_parent_changed')
        _empty_child(parent,unit)

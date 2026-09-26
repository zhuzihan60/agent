from dataclasses import replace
import os

import pytest
from tests.target_runtime.test_repair_disk import cache_root


def test_installer_provisions_exclusive_prefault_reserve(cache_root):
    tmp_path=cache_root
    from a4diag_target.disk_reservation import provision, claim, HEADROOM_BYTES, INODE_TOKENS
    from test_disk_workflow import disk_profile
    scope=tmp_path/'scope';scope.mkdir(mode=0o700)
    profile=disk_profile()
    provision(scope,profile)
    assert (scope/'disk-headroom').stat().st_size==HEADROOM_BYTES
    owner={'transaction_id':'first','plan_digest':'a'*64}
    claim(scope,profile,owner)
    assert (scope/'disk-headroom').stat().st_size==0
    assert not list(scope.glob('disk-inode-*'))
    claim(scope,profile,owner)
    with pytest.raises(ValueError,match='owned'):
        claim(scope,profile,{**owner,'transaction_id':'second'})
    with pytest.raises(ValueError,match='drain'):
        provision(scope,profile)


def test_claim_commits_owner_before_releasing_space_and_retries_only_same_budget(cache_root,monkeypatch):
    tmp_path=cache_root
    from a4diag_target import disk_reservation as reserve
    from test_disk_workflow import disk_profile
    scope=tmp_path/'scope';scope.mkdir(mode=0o700)
    profile=disk_profile();reserve.provision(scope,profile)
    owner={'transaction_id':'first','plan_digest':'a'*64}
    original=os.ftruncate
    monkeypatch.setattr(reserve.os,'ftruncate',lambda *a:(_ for _ in ()).throw(OSError('release_failed')))
    with pytest.raises((OSError,ValueError)):reserve.claim(scope,profile,owner)
    assert (scope/'disk-headroom').stat().st_size==reserve.HEADROOM_BYTES
    with pytest.raises(ValueError,match='owned'):reserve.claim(scope,profile,{'transaction_id':'other'})
    monkeypatch.setattr(reserve.os,'ftruncate',original)
    reserve.claim(scope,profile,owner)
    assert (scope/'disk-headroom').stat().st_size==0


def test_historical_dependency_omits_new_operation_and_rejects_digest_mismatch():
    from tests.target_runtime.test_preparation_dependency import dependency,disk_operation
    from tests.target_runtime.test_repair_protocol import _profile,_operation
    from a4diag.preparation import PreparationDependency
    old=dependency(_profile(),_operation(action='stop'))
    assert 'dependent_operation' not in old.model_dump(mode='json')
    value=old.model_dump();value['dependent_operation']=disk_operation()
    assert PreparationDependency.model_validate(value).dependent_operation is not None
    value['dependent_operation_digest']='0'*64
    with pytest.raises(ValueError,match='operation_mismatch'):PreparationDependency.model_validate(value)


def test_owner_persist_failure_releases_no_headroom(cache_root,monkeypatch):
    from a4diag_target import disk_reservation as reserve
    from test_disk_workflow import disk_profile
    profile=disk_profile();reserve.provision(cache_root,profile)
    monkeypatch.setattr(reserve,'_write',lambda *a:(_ for _ in ()).throw(OSError('audit_full')))
    with pytest.raises((ValueError,OSError)):
        reserve.claim(cache_root,profile,{'transaction_id':'tx'})
    assert (cache_root/'disk-headroom').stat().st_size==reserve.HEADROOM_BYTES
    assert len(list(cache_root.glob('disk-inode-*')))==reserve.INODE_TOKENS


def test_rearm_requires_actual_restored_terminal_owner_and_preserves_audit(cache_root):
    import sqlite3
    from a4diag_target import disk_reservation as reserve
    from test_disk_workflow import disk_profile
    from a4diag_target.repair_jobs import JobStore
    profile=disk_profile();reserve.provision(cache_root,profile)
    owner={'transaction_id':'tx','dependency':{'dependent_step_id':'1'}}
    audit=reserve.claim(cache_root,profile,owner)
    jobs=JobStore(cache_root/'repair-jobs.sqlite3')
    job=jobs.ensure('tx','1','a'*64,profile_digest='b'*64);jobs.start(job.id,now=1)
    jobs.complete(job.id,state='partial',changed=None,result={},now=2)
    service=cache_root/'service.sqlite3'
    with sqlite3.connect(service) as db:
        db.execute('CREATE TABLE writer_holds(transaction_id TEXT, restored INTEGER)')
        db.execute("INSERT INTO writer_holds VALUES ('tx',1)")
    with pytest.raises(ValueError,match='drain'):reserve.provision(cache_root,profile,service_database=service)
    with sqlite3.connect(jobs.path) as db:db.execute("UPDATE repair_jobs SET state='succeeded',changed=1")
    reserve.provision(cache_root,profile,service_database=service)
    assert (cache_root/(audit+'.disk-audit')).exists() and (cache_root/(audit+'.disk-owner')).exists()
    with pytest.raises(ValueError,match='reused'):reserve.claim(cache_root,profile,owner)
    assert (cache_root/'disk-headroom').stat().st_size==reserve.HEADROOM_BYTES


@pytest.mark.parametrize('denial',[None,'forged','revoked','expired','wrong_writer','not_standing'])
def test_signed_preflight_requires_both_grants_before_claim(cache_root,monkeypatch,denial):
    tmp_path=cache_root
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from a4diag.plugin_api.target_protocol import TargetSigner,TargetVerifier,TargetLifecycleV11,_public_fingerprint
    from a4diag.repair_profiles import profile_digest
    from a4diag_target import repair_install as install
    from a4diag_target.disk_reservation import provision,admission_preflight,HEADROOM_BYTES
    from a4diag_target.policy import TargetPolicy
    from tests.target_runtime.test_preparation_dependency import dependency,disk_operation
    from tests.target_runtime.test_repair_protocol import _profile,_operation,_request,FINGERPRINT
    from test_disk_workflow import disk_profile
    stop=_profile(actions=('stop',));disk=disk_profile().model_copy(update={'id':'cache','target_id':'demo'})
    if denial=='expired':disk=disk.model_copy(update={'expires_at':149})
    if denial=='wrong_writer':disk=disk.model_copy(update={'constraints':disk.constraints.model_copy(update={'writer_unit':'other.service'})})
    if denial=='not_standing':disk=disk.model_copy(update={'standing_authorization':False})
    operation=_operation(action='stop')
    dep=dependency(stop,operation,dependent_profile_digest=profile_digest(disk),dependent_operation=disk_operation())
    request=_request(stop,TargetLifecycleV11.PREPARE,'r'*32,operation=operation).model_copy(update={'preparation_dependency':dep})
    key=Ed25519PrivateKey.generate();signer=TargetSigner(key)
    policy=TargetPolicy(target_id='demo',target_fingerprint=FINGERPRINT,controller_key_fingerprint=_public_fingerprint(key.public_key()),
        repair_profiles=(stop,) if denial=='revoked' else (stop,disk))
    binding=install.HelperBinding(adapter='disk-cache',profile=disk,peer_uid=0)
    monkeypatch.setattr(install,'STATE_ROOT',tmp_path)
    monkeypatch.setattr(install,'load_binding',lambda _:binding)
    binding.state.mkdir(mode=0o700);provision(binding.state,disk)
    envelope=signer.sign(request)
    if denial=='forged':envelope=TargetSigner(Ed25519PrivateKey.generate()).sign(request)
    verifier=TargetVerifier(key.public_key(),replay_store=None,clock=lambda:150)
    def run():admission_preflight(envelope,verifier=verifier,policy=policy,identity_probe=lambda:FINGERPRINT)
    if denial:
        with pytest.raises(Exception):run()
        assert (binding.state/'disk-headroom').stat().st_size==HEADROOM_BYTES
    else:
        run();run()
        assert (binding.state/'disk-headroom').stat().st_size==0

import os
from dataclasses import replace
import time

import pytest

from tests.target_runtime.test_repair_disk import cache_root, limits, old_file, scan


def staged(cache_root, monkeypatch):
    from a4diag_target import repair_disk_cleanup as cleanup
    marker=scan(cache_root)
    bound=limits(cache_root, min_free_bytes=1 << 50)
    state=cache_root.parent/'disk-test-state'
    state.mkdir(exist_ok=True)
    monkeypatch.setattr(cleanup,'STATE_ROOT',state)
    monkeypatch.setattr(cleanup,'check_writer_boundary',lambda header:None)
    (state/'test-cache').mkdir(exist_ok=True)
    return cleanup.prepare_audit(marker,bound,profile_id='test-cache',request={},writer={}),bound


def test_cleanup_unlinks_only_unchanged_frozen_candidates_and_accounts_actual_space(cache_root, monkeypatch):
    from a4diag_target.repair_disk import apply_cleanup
    old_file(cache_root/'old', b'old bytes')
    old_file(cache_root/'replaced', b'keep original')
    marker,bound=staged(cache_root,monkeypatch)
    (cache_root/'replaced').rename(cache_root/'saved')
    (cache_root/'replaced').write_bytes(b'new value')
    result=apply_cleanup(marker,bound)
    assert not (cache_root/'old').exists()
    assert (cache_root/'replaced').read_bytes()==b'new value'
    assert (cache_root/'saved').read_bytes()==b'keep original'
    assert result['removed_files']==1 and result['removed_logical_bytes']==9
    assert result['skipped_changed']==1 and result['target_met'] is False
    st=os.statvfs(cache_root)
    assert result['available_bytes']==st.f_bavail*st.f_frsize
    again=apply_cleanup(marker,bound)
    assert again['removed_files']==1 and again['removed_logical_bytes']==9


def test_failed_audit_intent_cannot_delete(cache_root,monkeypatch):
    from a4diag_target import repair_disk_cleanup as cleanup
    old_file(cache_root/'old')
    marker,bound=staged(cache_root,monkeypatch)
    monkeypatch.setattr(cleanup,'write_slot',lambda *a: (_ for _ in ()).throw(OSError('ENOSPC')))
    with pytest.raises(ValueError, match='unsafe_cache_path'):
        cleanup.apply_cleanup(marker,bound)
    assert (cache_root/'old').read_bytes()==b'old'


def test_writer_drift_before_delete_keeps_candidates(cache_root,monkeypatch):
    from a4diag_target import repair_disk_cleanup as cleanup
    old_file(cache_root/'old')
    marker,bound=staged(cache_root,monkeypatch)
    monkeypatch.setattr(cleanup,'check_writer_boundary',lambda *a: (_ for _ in ()).throw(ValueError('writer_drift')))
    with pytest.raises(ValueError,match='writer_drift'):
        cleanup.apply_cleanup(marker,bound)
    assert (cache_root/'old').exists()


@pytest.mark.parametrize('after_unlink',[False,True])
def test_uncertain_intent_never_invents_counts_or_repeats_delete(cache_root,monkeypatch,after_unlink):
    from a4diag_target import repair_disk_cleanup as cleanup
    old_file(cache_root/'old')
    marker,bound=staged(cache_root,monkeypatch)
    with cleanup.audit_file(marker,bound) as (fd,_):cleanup.write_slot(fd,0,'intent')
    if after_unlink:(cache_root/'old').unlink()
    result=cleanup.apply_cleanup(marker,bound)
    assert result['removed_files']==0 and result['removed_logical_bytes']==0 and result['uncertain']==1
    assert (cache_root/'old').exists() is (not after_unlink)
    assert cleanup.apply_cleanup(marker,bound)==result


def test_audit_preallocation_failure_has_no_cache_effect(cache_root,monkeypatch):
    from a4diag_target import repair_disk_cleanup as cleanup
    old_file(cache_root/'old')
    monkeypatch.setattr(cleanup.os,'posix_fallocate',lambda *a:(_ for _ in ()).throw(OSError('ENOSPC')))
    with pytest.raises(ValueError):staged(cache_root,monkeypatch)
    assert (cache_root/'old').exists()

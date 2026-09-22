import os
from pathlib import Path

import pytest

from a4diag_target.repair_jobs import JobStore


@pytest.mark.parametrize('failure',['permission','io','malformed','boot_missing'])
def test_live_claimed_worker_unavailable_identity_before_audit_stays_unknown(tmp_path,monkeypatch,failure):
    from a4diag_target.disk_plugin import DiskPlugin
    store=JobStore(tmp_path/'jobs.db')
    job=store.ensure('tx','1','a'*64,profile_digest='b'*64)
    store.start(job.id,now=1)
    assert store.claim(job.id)
    store.complete(job.id,state='unknown',changed=None,result={},now=2)
    read=Path.read_text
    def unavailable(path,*args,**kwargs):
        if str(path)==f'/proc/{os.getpid()}/stat':
            if failure=='permission':raise PermissionError('EACCES')
            if failure=='io':raise OSError('EIO')
            if failure=='malformed':return 'unreadable stat'
        if failure=='boot_missing' and str(path)=='/proc/sys/kernel/random/boot_id':
            raise FileNotFoundError('boot identity unavailable')
        return read(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',unavailable)
    # The live worker has claimed its job but has not acquired the audit lock.
    plugin=object.__new__(DiskPlugin)
    plugin._bound_header=lambda _:pytest.fail('must not enter audit or terminalize live worker')
    assert store.claimed_worker_exited(job.id) is False
    assert plugin.recover_dead_worker(None,store,job.id) is None
    assert store.get(job.id).state=='unknown'
    assert store.get(job.id).changed is None


@pytest.mark.parametrize('observation',['absent','zombie','different','same'])
def test_exit_requires_positive_proc_evidence(monkeypatch,observation):
    from a4diag_target.repair_jobs import process_identity,process_exited
    saved=process_identity(os.getpid())
    read=Path.read_text
    record=Path(f'/proc/{os.getpid()}/stat').read_text()
    def observed(path,*args,**kwargs):
        if str(path)==f'/proc/{os.getpid()}/stat':
            if observation=='absent':raise FileNotFoundError()
            prefix,tail=record.rsplit(')',1);fields=tail.split()
            if observation=='zombie':fields[0]='Z'
            if observation=='different':fields[19]=str(int(fields[19])+1)
            return prefix+') '+' '.join(fields)
        return read(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',observed)
    assert process_exited(os.getpid(),saved)==(observation!='same')

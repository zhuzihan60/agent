import os
from types import SimpleNamespace
import pytest
from tests.target_runtime.test_repair_disk import cache_root


def test_exact_child_absence_uses_existing_pinned_parent(cache_root,monkeypatch):
    from a4diag_target import disk_writer as writer
    monkeypatch.setattr(writer,'CGROUP_PARENT',str(cache_root))
    monkeypatch.setattr(writer,'_cgroup_type',lambda fd:None)
    monkeypatch.setattr(writer.subprocess,'run',lambda *a,**k:SimpleNamespace(stdout='system.slice\n'))
    snapshot=((('ControlGroup',''),('Id','demo.service')),())
    result=writer.dispatcher_writer(snapshot,'demo.service')
    assert (result['parent_dev'],result['parent_ino'])==(cache_root.stat().st_dev,cache_root.stat().st_ino)
    monkeypatch.setattr(writer,'CGROUP_PARENT',str(cache_root/'missing'))
    with pytest.raises(ValueError):writer.dispatcher_writer(snapshot,'demo.service')


@pytest.mark.parametrize('events',['populated 1\n','populated 0\npopulated 0\n','invalid\n'])
def test_populated_or_ambiguous_child_denied(cache_root,monkeypatch,events):
    from a4diag_target import disk_writer as writer
    monkeypatch.setattr(writer,'_cgroup_type',lambda fd:None)
    child=cache_root/'demo.service';child.mkdir()
    (child/'cgroup.events').write_text(events)
    with writer._open_root(str(cache_root)) as parent:
        with pytest.raises(ValueError,match='writer_cgroup_populated'):writer._empty_child(parent,'demo.service')


@pytest.mark.parametrize('unit,slice_', [('demo@x.service','system.slice\n'),('demo.service','other.slice\n')])
def test_unsupported_systemd_mapping_is_denied(monkeypatch,unit,slice_):
    from a4diag_target import disk_writer as writer
    monkeypatch.setattr(writer.subprocess,'run',lambda *a,**k:SimpleNamespace(stdout=slice_))
    with pytest.raises(ValueError,match='unsupported'):writer.dispatcher_writer((),unit)

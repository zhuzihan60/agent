"""Actual owner-bound Podman helper lifecycle, rootful and rootless."""
import os
import pytest
from tests.integration.test_docker_repair import run_signed_container_recovery
pytestmark=pytest.mark.skipif(os.environ.get("A4DIAG_TEST_PODMAN")!="1",reason="requires disposable Podman lab")
@pytest.mark.parametrize("uid",[0,22001])
def test_signed_podman_recovery(tmp_path,uid):
    run_signed_container_recovery(tmp_path,"podman",uid)

from test_workflow_v3 import deps_factory
@pytest.mark.parametrize('uid',[0,22001])
def test_podman_daemon_recovery(deps_factory,tmp_path,uid):
    run_signed_container_recovery(tmp_path,'podman',uid,deps_factory=deps_factory,fault='exited')

@pytest.mark.parametrize('fault',['managed','managed-relapse','managed-unready'])
def test_managed_podman_transfers_to_signed_service(deps_factory,tmp_path,fault):
    run_signed_container_recovery(tmp_path,'podman',0,deps_factory=deps_factory,fault=fault)


def test_actual_rootless_socket_wrong_uid_symlink_and_absence_fail_closed(tmp_path):
    from pathlib import Path
    from a4diag_target.repair_podman import PodmanAdapter
    from a4diag_target.repair_containers import ContainerIdentityError
    path=Path('/run/user/22001/podman/podman.sock')
    from a4diag_target.repair_install import attest_runtime_socket
    attestation=attest_runtime_socket(path,22001)
    assert path.stat().st_uid==22001
    with pytest.raises(ContainerIdentityError):
        PodmanAdapter(0,path).inspect('a'*64)
    link=tmp_path/'forged.sock';link.symlink_to(path)
    with pytest.raises(ContainerIdentityError):attest_runtime_socket(link,22001)
    with pytest.raises(ContainerIdentityError):
        PodmanAdapter(22001,link).inspect('a'*64)
    with pytest.raises(FileNotFoundError):
        PodmanAdapter(22001,path.with_name('missing-a4diag.sock')).inspect('a'*64)
    forged=attestation.model_copy(update={'inode':attestation.inode+1})
    with pytest.raises(ContainerIdentityError,match='re_registration_required'):
        PodmanAdapter(22001,path,attestation=forged).inspect('a'*64)

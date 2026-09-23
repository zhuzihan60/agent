import pytest


def test_rootless_socket_cannot_be_used_as_another_user():
    from a4diag_target.repair_podman import validate_runtime_owner
    from a4diag_target.repair_containers import ContainerIdentityError
    for peer, owner in ((1002,1002),(1001,1002),(1002,1001),(0,0)):
        with pytest.raises(ContainerIdentityError):
            validate_runtime_owner(expected_uid=1001, peer_uid=peer, path_owner_uid=owner)
    validate_runtime_owner(expected_uid=1001, peer_uid=1001, path_owner_uid=1001)


@pytest.mark.privileged_linux
def test_socket_registration_rejects_symlink_and_changed_endpoint(tmp_path):
    import socket
    from a4diag_target.repair_install import attest_runtime_socket
    from a4diag_target.repair_podman import PodmanAdapter
    path=tmp_path/'api.sock'
    with socket.socket(socket.AF_UNIX) as channel:
        channel.bind(str(path))
        attestation=attest_runtime_socket(path,0)
        link=tmp_path/'alias.sock';link.symlink_to(path)
        with pytest.raises(ValueError,match='symlink'):attest_runtime_socket(link,0)
        path.unlink()
        with socket.socket(socket.AF_UNIX) as replacement:
            replacement.bind(str(path))
            adapter=PodmanAdapter(0,path,attestation=attestation)
            with pytest.raises(ValueError,match='re_registration_required'):adapter.inspect('a'*64)

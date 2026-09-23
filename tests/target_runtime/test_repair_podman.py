import pytest


def owner_runtime(monkeypatch):
    import json
    from types import SimpleNamespace
    from tests.target_runtime.test_container_lifecycle import profile,Runtime,CID
    from a4diag_target.repair_install import HelperBinding,SocketAttestation
    from a4diag_target.repair_podman import OwnerBoundPodman
    selected=profile(resource='podman/22001/'+CID,standing_authorization=True)
    binding=HelperBinding(adapter='podman',profile=selected,peer_uid=0,
        socket_attestation=SocketAttestation(device=1,inode=2,owner_uid=22001))
    monkeypatch.setattr('a4diag_target.repair_install.load_binding',lambda _:binding)
    monkeypatch.setattr('a4diag_target.repair_docker.socket_identity',lambda *args:(1,2))
    runtime=OwnerBoundPodman(selected)
    snapshot=Runtime().snapshot.model_copy(update={'identity':runtime.identity})
    reply=SimpleNamespace(returncode=0,stdout=json.dumps({'euid':22001,'execution':{'peer_uid':22001},'snapshot':snapshot.model_dump(mode='json')}))
    return selected,runtime,reply


@pytest.mark.privileged_linux
def test_owner_child_timeout_is_structured_and_helper_serves_next_read(monkeypatch):
    import json,socket,struct,subprocess,threading
    from a4diag_target import repair_helper
    from a4diag_target.policy import TargetPolicy
    from tests.target_runtime.test_repair_protocol import FINGERPRINT
    selected,runtime,reply=owner_runtime(monkeypatch)
    from a4diag_target.repair_install import load_binding
    helper=object.__new__(repair_helper.RepairHelper);helper.binding=load_binding(selected.id)
    monkeypatch.setattr(repair_helper,'load_binding',load_binding)
    policy=TargetPolicy(target_id='demo',target_fingerprint=FINGERPRINT,controller_key_fingerprint='sha256:'+'e'*64,
                         allowed_container_profiles=(selected.id,))
    monkeypatch.setattr(repair_helper,'current_policy',lambda:policy)
    attempts=[]
    def child(*args,**kwargs):
        attempts.append(1)
        if len(attempts)==1:raise subprocess.TimeoutExpired(args[0],kwargs['timeout'])
        return reply
    monkeypatch.setattr(subprocess,'run',child)
    pairs=[socket.socketpair(),socket.socketpair()];pending=[pair[1] for pair in pairs];errors=[]
    class Listener:
        def accept(self):
            if not pending:raise StopIteration
            return pending.pop(0),None
    def serve():
        try:repair_helper.serve(Listener(),helper)
        except StopIteration:pass
        except Exception as error:errors.append(error)
    thread=threading.Thread(target=serve);thread.start();responses=[]
    try:
        for client,_ in pairs:
            client.settimeout(3)
            body=json.dumps({'method':'read','kind':'container_state','profile_id':selected.id,'limit':8192}).encode()
            client.sendall(struct.pack('!I',len(body))+body)
            size=struct.unpack('!I',repair_helper._recv_exact(client,4))[0]
            responses.append(json.loads(repair_helper._recv_exact(client,size)))
    finally:
        for pair in pairs:
            for channel in pair:channel.close()
        thread.join(4)
    assert not thread.is_alive() and errors==[]
    assert responses[0]['ok'] is False and 'timeout' in responses[0]['reason']
    assert json.loads(responses[1]['content'])['identity']['owner_uid']==22001


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

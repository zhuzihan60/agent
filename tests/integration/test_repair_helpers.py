"""Opt-in checks of the installed, socket-activated repair boundary."""
import os
from pathlib import Path
import json
import hashlib
import shutil
import site
import socket
import struct
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('A4DIAG_TEST_SYSTEMD') != '1', reason='requires disposable systemd lab')


def test_repair_helper_installation_entrypoint_exists():
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    root = Path(__file__).resolve().parents[2]
    assert (root / 'deploy/a4diag-repair-helper@.service').is_file(), 'isolated helper installation entrypoint missing'
    assert (root / 'deploy/a4diag-repair-helper@.socket').is_file()


@pytest.fixture(scope='module')
def installed_helper():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from a4diag.plugin_api.target_protocol import TargetSigner
    from a4diag_target.server import target_fingerprint
    from tests.target_runtime.test_repair_protocol import _profile, _request
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11
    assert os.uname().nodename == 'a4diag-remediation-test'
    repo = Path(__file__).resolve().parents[2]
    token = uuid.uuid4().hex[:12]
    base = Path('/opt/a4diag-target')
    stage = base / 'releases/1.0.0'
    current = base / 'current'
    assert not current.exists() and not current.is_symlink()
    assert not stage.exists()
    etc = Path('/etc/a4diag-target')
    saved = {p: p.read_bytes() for p in etc.glob('*') if p.is_file()}
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    profile = _profile(id='f5-'+token, expires_at=int(time.time())+600)
    state = Path('/var/lib/a4diag-target/repair-helpers') / profile.id
    units = Path('/etc/systemd/system')
    helper_unit = f'a4diag-repair-helper@{profile.id}'
    workers = []
    run = repo.parent
    release = run / 'helper-release'
    release.mkdir()
    stage.mkdir(parents=True)
    subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(stage/'venv')], check=True)
    packages = stage/'venv/lib/python3.11/site-packages'
    shutil.copytree(repo/'packages/a4diag-target-runtime/src/a4diag_target', packages/'a4diag_target')
    shutil.copytree(repo/'src/a4diag', packages/'a4diag')
    shutil.copytree(repo/'packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins', packages/'a4diag_builtin_plugins')
    (packages/'lab.pth').write_text('\n'.join(site.getsitepackages())+'\n')
    # This module exists ONLY in the disposable root-installed test runtime.
    # Production registry stays empty and has no config-driven import hook.
    fixture_code = '''from pathlib import Path
import json, subprocess, time
from a4diag_builtin_plugins.capability_common import CommandOutcome
from a4diag_builtin_plugins.capability_services import ServicesPlugin
from a4diag_target.repair_install import AdapterSpec, Sandbox, ADAPTERS
class BoundedAdapter:
    def __init__(self, profile): self.profile=profile
    async def run_command(self, argv, **kwargs):
        if argv[1] == 'show':
            return CommandOutcome(returncode=0, stdout='ActiveState=active\\nSubState=running\\nUnitFileState=enabled\\nInvocationID=fixture\\n')
        root=Path('/var/lib/a4diag-target/repair-helpers')/self.profile.id
        evidence={}
        for name, command in {
            'system_bus':['/usr/bin/systemd-run','--quiet','--unit=a4diag-f5-escape','/usr/bin/true'],
            'private_socket':['/usr/bin/systemctl','--system','start','a4diag-f5-escape.service'],
            'user_bus':['/usr/bin/systemctl','--user','start','a4diag-f5-escape.service'],
        }.items():
            result=subprocess.run(command,capture_output=True,timeout=5)
            evidence[name]=result.returncode
        try:
            Path('/var/lib/a4diag-target/f5-outside').write_text('escaped')
            evidence['outside_write']=True
        except OSError: evidence['outside_write']=False
        (root/'sandbox-evidence.json').write_text(json.dumps(evidence))
        if (root/'hold-worker').exists():
            (root/'worker-paused').touch()
            deadline=time.monotonic()+45
            while not (root/'release-worker').exists():
                if time.monotonic()>deadline: raise RuntimeError('fixture release timeout')
                time.sleep(.05)
        time.sleep(3)
        (root/'effect').write_text('bounded fixture effect')
        return CommandOutcome(returncode=0)
ADAPTERS['lab-bounded']=AdapterSpec('services',lambda p:Sandbox(),lambda p:ServicesPlugin(transport=BoundedAdapter(p)))
'''
    (packages/'f5_fixture.py').write_text(fixture_code)
    registry = packages/'a4diag_target/repair_install.py'
    # Append before module-main to cover installer subprocess and runtime alike.
    code = registry.read_text()
    code = code.replace("if __name__ == '__main__':", "import f5_fixture\nfrom a4diag_target.repair_install import ADAPTERS as ADAPTERS\n\nif __name__ == '__main__':")
    registry.write_text(code)
    for name, module in [('a4diag-repair-helper','repair_helper'),('a4diag-transport-helper','helper'),('a4diag-target-executor','server')]:
        executable = stage/'venv/bin'/name
        executable.write_text(f'#!{stage}/venv/bin/python\nfrom a4diag_target.{module} import main\nraise SystemExit(main())\n')
        executable.chmod(0o755)
    (stage/'.runtime-ready').touch()
    shutil.copytree(repo/'deploy', release/'systemd')
    (release/'VERSION').write_text('1.0.0\n')
    for path in (release/'systemd').iterdir():
        if path.is_file() and not path.name.startswith(('a4diag-target','a4diag-repair-helper')):
            path.unlink()
    shutil.copytree(release/'systemd', stage/'systemd')
    artifacts = {p.relative_to(release).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in release.rglob('*') if p.is_file()}
    (release/'MANIFEST.json').write_text(json.dumps({'version':'1.0.0','artifacts':artifacts}))
    artifacts['MANIFEST.json']=hashlib.sha256((release/'MANIFEST.json').read_bytes()).hexdigest()
    (release/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name,digest in sorted(artifacts.items())))
    from tests.integration.test_target_installer import configuration
    config = run/'helper-install.json'
    config.write_text(json.dumps(configuration(
        target_id='demo', operation_public_key=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        controller_key_fingerprint=signer.sign(_request(profile,TargetLifecycleV11.PREPARE,'nonce-key-probe-1234')).key_fingerprint,
        repair_profiles=[profile.model_dump(mode='json')], repair_helpers=[{'profile_id':profile.id,'adapter':'lab-bounded'}], confirm_repair_helpers='ENABLE')))
    env={**os.environ,'A4DIAG_TARGET_ALLOW_UNSIGNED':'1'}
    env.pop('PYTHONPATH', None)
    command=['bash',str(repo/'tools/install_target_lib.sh'),'install',str(release),str(config)]
    try:
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=40)
        assert result.returncode == 0, result.stdout+result.stderr
        # Root client is deliberately NOT the configured a4diag-target peer.
        import pwd
        peer=pwd.getpwnam('a4diag-target').pw_uid
        class Installed:
            def send(self, payload, *, uid=peer, oversized=False, legacy=False):
                script='''import socket,struct,json,sys,os
os.setgroups([]);os.setgid(int(sys.argv[2]));os.setuid(int(sys.argv[2]))
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
 client.settimeout(10);client.connect(sys.argv[1]);body=sys.stdin.buffer.read();client.sendall(struct.pack('!I',1048577 if sys.argv[3]=='1' else len(body))+body)
 header=client.recv(4);size=struct.unpack('!I',header)[0];data=b''
 while len(data)<size:data+=client.recv(size-len(data))
 print(data.decode())
'''
                destination='/run/a4diag-target/executor.sock' if legacy else f'/run/a4diag-target/repair-{profile.id}.sock'
                call=subprocess.run([sys.executable,'-c',script,destination,str(uid),'1' if oversized else '0'],input=json.dumps(payload),capture_output=True,text=True,timeout=15)
                assert call.returncode == 0, call.stderr
                return json.loads(call.stdout)
            def relay(self, payload, *, denied=False):
                script="import os,sys;os.setgroups([]);os.setgid(int(sys.argv[1]));os.setuid(int(sys.argv[1]));os.execv(sys.argv[2],[sys.argv[2]])"
                call=subprocess.run([sys.executable,'-c',script,str(peer),'/usr/libexec/a4diag/a4diag-transport-helper'],env=env,input=json.dumps(payload),capture_output=True,text=True,timeout=15)
                if denied:
                    assert call.returncode != 0 and 'repair_route_unavailable' in call.stderr
                    return None
                assert call.returncode == 0, call.stderr
                return json.loads(call.stdout)
            def effects(self): return list(state.glob('effect'))
            def signed(self, lifecycle, **changes):
                req=_request(profile,lifecycle,'nonce-'+uuid.uuid4().hex,authorization_id=profile.id,**changes)
                req=req.model_copy(update={'issued_at':int(time.time()),'expires_at':int(time.time())+120,'target_fingerprint':target_fingerprint()})
                return signer.sign(req).model_dump(mode='json')
        installed=Installed()
        installed.profile=profile;installed.signer=signer;installed.state=state;installed.workers=workers
        installed.command=command;installed.env=env;installed.config=config
        yield installed
    finally:
        for unit in workers+[helper_unit+'.socket',helper_unit+'.service','a4diag-target-executor.socket','a4diag-target-executor.service']:
            subprocess.run(['systemctl','stop',unit],capture_output=True)
        subprocess.run(['systemctl','disable',helper_unit+'.socket','a4diag-target-executor.socket'],capture_output=True)
        for path in [units/(helper_unit+'.service.d'),etc/'repair-helpers']:
            if path.exists():shutil.rmtree(path)
        for name in ['a4diag-repair-helper@.service','a4diag-repair-helper@.socket','a4diag-target-executor.service','a4diag-target-executor.socket']:
            (units/name).unlink(missing_ok=True)
        for path in etc.glob('*'):
            if path.is_file() and path not in saved:path.unlink()
        for path,body in saved.items():path.write_bytes(body)
        if current.is_symlink() and current.resolve()==stage:current.unlink()
        journal=base/'.repair-install-journal.json'
        if journal.exists():
            assert set(json.loads(journal.read_text())['ids']) <= {profile.id}
            journal.unlink()
        shutil.rmtree(stage)
        if state.exists():shutil.rmtree(state)
        subprocess.run(['systemctl','daemon-reload'],check=True)


def test_unsigned_local_helper_call_is_denied(installed_helper):
    response=installed_helper.send({'action':'restart'})
    assert response['error']=='signature_required'
    assert installed_helper.effects()==[]


def test_wrong_peer_and_oversized_direct_socket_are_denied(installed_helper):
    assert installed_helper.send({'action':'restart'},uid=0)['error']=='peer_uid_denied'
    assert installed_helper.send({},oversized=True)['error']=='request_too_large'
    assert installed_helper.effects()==[]


def test_installed_configuration_failures_preserve_authorization(installed_helper):
    helper = installed_helper
    original = helper.config.read_bytes()
    paths = [Path('/etc/a4diag-target/policy.json'), Path('/etc/a4diag-target/repair-routes.json'), Path('/etc/a4diag-target/repair-helpers')/(helper.profile.id+'.json')]
    before = {p:p.read_bytes() for p in paths}
    try:
        source = json.loads(original)
        source.update(managed_resources=[{'capability':'services','resource':helper.profile.resource}],confirm_managed_resources='ENABLE')
        helper.config.write_text(json.dumps(source))
        denied = subprocess.run(helper.command,env=helper.env,capture_output=True,text=True,timeout=30)
        assert denied.returncode != 0 and 'duplicate_helper_scope' in denied.stderr
        assert all(p.read_bytes()==body for p,body in before.items())
        source = json.loads(original)
        source['repair_helpers'][0]['adapter'] = 'unknown'
        helper.config.write_text(json.dumps(source))
        denied = subprocess.run(helper.command,env=helper.env,capture_output=True,text=True,timeout=30)
        assert denied.returncode != 0 and 'adapter_not_registered' in denied.stderr
        assert all(p.read_bytes()==body for p,body in before.items())
        source = json.loads(original)
        source['repair_helpers'] *= 2
        helper.config.write_text(json.dumps(source))
        denied = subprocess.run(helper.command,env=helper.env,capture_output=True,text=True,timeout=30)
        assert denied.returncode != 0 and 'duplicate_helper_scope' in denied.stderr
        assert all(p.read_bytes()==body for p,body in before.items())
        source = json.loads(original)
        source.update(repair_profiles=[],repair_helpers=[])
        helper.config.write_text(json.dumps(source))
        interrupted = subprocess.run(helper.command,env={**helper.env,'A4DIAG_TARGET_INJECT_FAILURE':'after_configuration'},capture_output=True,text=True,timeout=30)
        assert interrupted.returncode != 0 and 'after configuration' in interrupted.stderr
        assert all(p.read_bytes()==body for p,body in before.items())
        assert helper.send({'action':'restart'})['error']=='signature_required'
        assert helper.effects()==[]
    finally:
        helper.config.write_bytes(original)


def test_live_uninstall_excludes_install_after_second_drain(installed_helper):
    helper = installed_helper
    gate = helper.config.parent/'uninstall-race'
    gate.mkdir()
    unit = f'a4diag-repair-helper@{helper.profile.id}.socket'
    shim = gate/'systemctl'
    shim.write_text(f'''#!{sys.executable}
import os,sys,time
from pathlib import Path
gate=Path({str(gate)!r})
if sys.argv[1:]==['disable',{unit!r}]:
 (gate/'ready').touch()
 deadline=time.monotonic()+30
 while not (gate/'release').exists():
  if time.monotonic()>deadline:raise SystemExit(91)
  time.sleep(.02)
os.execv('/usr/bin/systemctl',['/usr/bin/systemctl',*sys.argv[1:]])
''')
    shim.chmod(0o755)
    policy = Path('/etc/a4diag-target/policy.json')
    before = policy.read_bytes()
    uninstalling = subprocess.Popen(helper.command[:2]+['uninstall'],
        env={**helper.env,'PATH':str(gate)+':'+helper.env['PATH'],'A4DIAG_TARGET_CONFIRM_UNINSTALL':'REMOVE'},
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+15
        while not (gate/'ready').exists() and time.monotonic()<deadline:time.sleep(.02)
        assert (gate/'ready').exists(), 'uninstall did not reach disable after its second drain'
        competing = subprocess.run(helper.command,env=helper.env,capture_output=True,text=True,timeout=15)
        assert competing.returncode != 0 and 'another target installation is running' in competing.stderr
        assert policy.read_bytes() == before
        (gate/'release').touch()
        out,err=uninstalling.communicate(timeout=15)
        assert uninstalling.returncode == 0, out+err
        assert subprocess.run(['systemctl','is-active',unit],capture_output=True).returncode != 0
    finally:
        (gate/'release').touch()
        if uninstalling.poll() is None:uninstalling.communicate(timeout=15)
        restored=subprocess.run(helper.command,env=helper.env,capture_output=True,text=True,timeout=30)
        assert restored.returncode == 0, restored.stdout+restored.stderr


def test_installed_helper_reloads_missing_invalid_symlink_and_fifo_policy(installed_helper):
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11 as L
    helper = installed_helper
    policy = Path('/etc/a4diag-target/policy.json')
    original = policy.read_bytes()
    alternate = policy.with_suffix('.f5-alternate')
    try:
        for mutation in ('missing', 'invalid', 'symlink', 'fifo'):
            policy.unlink(missing_ok=True)
            if mutation == 'invalid':
                policy.write_text('{invalid')
            elif mutation == 'symlink':
                alternate.write_bytes(original)
                policy.symlink_to(alternate)
            elif mutation == 'fifo':
                os.mkfifo(policy)
            response = helper.send(helper.signed(L.PREPARE))
            assert response['error'] == 'target_policy_unavailable', response
            policy.unlink(missing_ok=True)
            policy.write_bytes(original);policy.chmod(0o600)
        assert helper.effects() == []
    finally:
        policy.unlink(missing_ok=True)
        policy.write_bytes(original);policy.chmod(0o600)
        alternate.unlink(missing_ok=True)


def test_registered_scope_never_falls_back_on_route_damage(installed_helper):
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11 as L
    helper = installed_helper
    routes = Path('/etc/a4diag-target/repair-routes.json')
    original = routes.read_bytes()
    try:
        for damage in ('missing', 'foreign_socket', 'writable'):
            if damage == 'missing': routes.unlink()
            elif damage == 'foreign_socket': routes.write_text(json.dumps({helper.profile.id:'/run/docker.sock'}))
            else: routes.write_bytes(original);routes.chmod(0o666)
            envelope = helper.signed(L.PREPARE)
            helper.relay(envelope, denied=True)
            assert helper.send(envelope,legacy=True)['reason'] == 'repair_route_unavailable'
            routes.write_bytes(original);routes.chmod(0o644)
        assert helper.effects() == []
    finally:
        routes.write_bytes(original);routes.chmod(0o644)


def test_signed_scope_replay_revocation_and_independent_sandbox(installed_helper):
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11 as L, TargetRequestV11
    from a4diag.domain import canonical_json_bytes
    helper=installed_helper
    envelope=helper.signed(L.PREPARE)
    # Cross-helper profile binding is denied before an effect.
    wrong=TargetRequestV11.model_validate_json(envelope['payload'])
    wrong=wrong.model_copy(update={'binding':wrong.binding.model_copy(update={'profile_id':'other'})})
    assert helper.send(helper.signer.sign(wrong).model_dump(mode='json'))['error']=='helper_scope_mismatch'
    assert helper.send(envelope,legacy=True)['reason']=='repair_helper_required'
    prepared=helper.relay(envelope)
    assert 'marker' in prepared, prepared
    assert helper.send(envelope)['ok'] is False
    marker=prepared['marker']
    wrong=TargetRequestV11.model_validate_json(helper.signed(L.APPLY,marker=marker)['payload'])
    wrong=wrong.model_copy(update={'binding':wrong.binding.model_copy(update={'preconditions_digest':'f'*64})})
    assert helper.send(helper.signer.sign(wrong).model_dump(mode='json'))['error']=='preconditions_digest_mismatch'
    invalid=helper.signed(L.PREPARE)
    invalid['signature']='A'*88
    assert helper.send(invalid)['ok'] is False
    assert helper.effects()==[]
    request=helper.signed(L.APPLY,marker=marker)
    # Pause the actual installer immediately before its first helper stop:
    # the first drain passed, but a real signed job can still be admitted.
    gate = helper.config.parent/'drain-race'
    gate.mkdir()
    shim = gate/'systemctl'
    stop_args = ['stop',f'a4diag-repair-helper@{helper.profile.id}.socket',f'a4diag-repair-helper@{helper.profile.id}.service']
    shim.write_text(f'''#!{sys.executable}
import os,sys,time
from pathlib import Path
gate=Path({str(gate)!r})
if sys.argv[1:]=={stop_args!r}:
 (gate/'ready').touch()
 deadline=time.monotonic()+30
 while not (gate/'release').exists():
  if time.monotonic()>deadline:raise SystemExit(91)
  time.sleep(.02)
os.execv('/usr/bin/systemctl',['/usr/bin/systemctl',*sys.argv[1:]])
''')
    shim.chmod(0o755)
    paths = [Path('/etc/a4diag-target/policy.json'), Path('/etc/a4diag-target/repair-routes.json'), Path('/etc/a4diag-target/repair-helpers')/(helper.profile.id+'.json')]
    before = {p:p.read_bytes() for p in paths}
    (helper.state/'hold-worker').touch()
    (helper.state/'hold-worker').chmod(0o600)
    installer = subprocess.Popen(helper.command,env={**helper.env,'PATH':str(gate)+':'+helper.env['PATH']},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+15
        while not (gate/'ready').exists() and time.monotonic()<deadline:time.sleep(.02)
        assert (gate/'ready').exists(), 'installer did not reach first-drain/stop boundary'
        response=helper.send(request)
        assert 'job' in response, response
        job_id=response['job']['id'];helper.workers.append(f'a4diag-repair-{job_id}.service')
        deadline=time.monotonic()+10
        while not (helper.state/'worker-paused').exists() and time.monotonic()<deadline:time.sleep(.02)
        assert (helper.state/'worker-paused').exists()
        (gate/'release').touch()
        out,err=installer.communicate(timeout=20)
        assert installer.returncode != 0 and 'repair_helpers_require_drain' in err, out+err
        assert all(p.read_bytes()==body for p,body in before.items())
        assert helper.relay(helper.signed(L.QUERY_JOB,job_id=job_id))['job']['state']=='running'
        # A new installer process encounters the retained journal while the
        # same worker remains active. Recovery must also preserve observation.
        blocked=subprocess.run(helper.command,env=helper.env,capture_output=True,text=True,timeout=20)
        assert blocked.returncode != 0 and 'repair_helpers_require_drain' in blocked.stderr
        assert all(p.read_bytes()==body for p,body in before.items())
        assert helper.relay(helper.signed(L.QUERY_JOB,job_id=job_id))['job']['state']=='running'
    finally:
        (gate/'release').touch()
        (helper.state/'release-worker').touch()
        (helper.state/'release-worker').chmod(0o600)
        if installer.poll() is None:installer.communicate(timeout=20)
    deadline=time.monotonic()+15
    from a4diag_target.repair_jobs import JobStore
    jobs=JobStore(helper.state/'repair-jobs.sqlite3')
    while jobs.get(job_id).state=='running' and time.monotonic()<deadline:time.sleep(.1)
    assert jobs.get(job_id).state=='succeeded',jobs.get(job_id)
    evidence=json.loads((helper.state/'sandbox-evidence.json').read_text())
    assert evidence['outside_write'] is False
    assert all(evidence[name]!=0 for name in ('system_bus','private_socket','user_bus'))
    assert helper.effects()
    # Route/binding remains installed while target grant is revoked.
    policy=Path('/etc/a4diag-target/policy.json')
    body=json.loads(policy.read_text());body['repair_profiles']=[];policy.write_text(json.dumps(body))
    query=helper.relay(helper.signed(L.QUERY_JOB,job_id=job_id))
    assert query['job']['state']=='succeeded',query
    assert helper.send(helper.signed(L.PREPARE))['error']=='profile_revoked'
    (Path(__file__).resolve().parents[3]/'helper-sandbox-evidence.json').write_text(json.dumps({'worker':evidence,'job':query['job']},indent=2))

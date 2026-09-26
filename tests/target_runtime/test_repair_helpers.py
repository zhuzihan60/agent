import json
import subprocess
import sys

import pytest

from tests.test_linux_probe_policy import installation_config, installer_script


def test_empty_profiles_install_no_write_helpers(tmp_path):
    config = tmp_path / 'install.json'
    config.write_text(json.dumps(installation_config(repair_profiles=[], repair_helpers=[])))
    result = subprocess.run([sys.executable, '-c', installer_script('validate_config'), str(config)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_registry_defaults_closed():
    from a4diag_target.repair_install import ADAPTERS, plan_helpers
    assert set(ADAPTERS) == {'disk-cache', 'docker', 'podman', 'kubernetes'}
    assert plan_helpers([], [], peer_uid=123) == ()
    with pytest.raises(ValueError, match='adapter_not_registered'):
        plan_helpers([], [{'profile_id': 'web', 'adapter': 'shell'}], peer_uid=123)


def test_installer_unknown_adapter_cannot_grant_write_access(tmp_path):
    config = tmp_path / 'install.json'
    config.write_text(json.dumps(installation_config(repair_profiles=[], repair_helpers=[{'profile_id':'web', 'adapter':'shell'}], confirm_repair_helpers='ENABLE')))
    result = subprocess.run([sys.executable, '-c', installer_script('validate_config'), str(config)], capture_output=True, text=True)
    assert result.returncode != 0


def test_scope_and_sandbox_are_derived_from_registered_code(monkeypatch):
    from a4diag_target import repair_install as install
    from tests.target_runtime.test_repair_protocol import _profile
    profile = _profile()
    monkeypatch.setitem(install.ADAPTERS, 'bounded', install.AdapterSpec('services', lambda p: install.Sandbox(write_paths=('/var/cache/demo',)), lambda p: object()))
    binding, = install.plan_helpers([profile], [{'profile_id':'web', 'adapter':'bounded'}], peer_uid=123)
    assert str(binding.state) == '/var/lib/a4diag-target/repair-helpers/web'
    assert binding.socket == '/run/a4diag-target/repair-web.sock'
    assert 'ProtectSystem=strict' in install.render_drop_in(binding)
    assert 'ReadWritePaths=/var/lib/a4diag-target/repair-helpers/web /var/cache/demo' in install.render_drop_in(binding)
    with pytest.raises(ValueError, match='duplicate_helper_scope'):
        install.plan_helpers([profile], [{'profile_id':'web','adapter':'bounded'}]*2, peer_uid=123)
    with pytest.raises(ValueError):
        install.HelperBinding(adapter='bounded', profile=profile, peer_uid=123, state_directory='/tmp/shared')


def test_installer_rejects_helper_overlap_with_v10_managed_resources(monkeypatch):
    from a4diag_target import repair_install as install
    from tests.target_runtime.test_repair_protocol import _profile
    profile = _profile()
    monkeypatch.setitem(install.ADAPTERS, 'bounded', install.AdapterSpec('services', lambda p: install.Sandbox(), lambda p: object()))
    source = installation_config(repair_profiles=[profile.model_dump(mode='json')],
        repair_helpers=[{'profile_id':profile.id,'adapter':'bounded'}],
        confirm_repair_helpers='ENABLE', confirm_managed_resources='ENABLE',
        managed_resources=[{'capability':'services','resource':profile.resource}])
    with pytest.raises(ValueError, match='duplicate_helper_scope'):
        install.installation_plan(source, peer_uid=123)
    source['managed_resources'][0]['resource'] = 'other.service'
    assert len(install.installation_plan(source, peer_uid=123)) == 1


@pytest.mark.parametrize('path', ['/tmp/x y', '/tmp/%i', '/tmp/../etc', '/'])
def test_sandbox_paths_reject_systemd_expansion(path):
    from a4diag_target.repair_install import Sandbox
    with pytest.raises(ValueError):
        Sandbox(write_paths=(path,))


def test_v11_missing_route_never_uses_executor(monkeypatch, tmp_path):
    from a4diag_target import helper
    from tests.target_runtime.test_repair_protocol import _profile, _request
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11, TargetSigner
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import io
    request = TargetSigner(Ed25519PrivateKey.generate()).sign(_request(_profile(), TargetLifecycleV11.PREPARE, 'nonce-routing-1234'))
    calls = []
    from a4diag_target import repair_install
    config_root = tmp_path/'bindings'
    config_root.mkdir()
    (config_root/'web.json').write_text('{}')
    (config_root/'web.json').chmod(0o600)
    monkeypatch.setattr(repair_install, 'CONFIG_ROOT', config_root)
    monkeypatch.setattr(helper, 'REPAIR_ROUTES', tmp_path / 'missing')
    with pytest.raises(helper.HelperError, match='repair_route_unavailable'):
        helper.run_helper(io.BytesIO(request.model_dump_json().encode()), io.BytesIO(), env={}, connector=lambda *args: calls.append(args))
    assert calls == []


def test_ordinary_socket_cannot_bypass_isolated_helper(monkeypatch):
    import asyncio
    from a4diag_target.server import TargetSocketServer
    from tests.target_runtime.test_repair_protocol import _profile, _request
    from a4diag.plugin_api.target_protocol import TargetLifecycleV11, TargetSigner
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    server = object.__new__(TargetSocketServer)
    calls = []
    class Executor:
        async def execute(self, envelope):
            calls.append(envelope)
            return {'ok': True}
    server._executor = Executor()
    monkeypatch.setattr('a4diag_target.repair_install.helper_route', lambda profile_id: f'/run/a4diag-target/repair-{profile_id}.sock')
    request = TargetSigner(Ed25519PrivateKey.generate()).sign(_request(_profile(), TargetLifecycleV11.PREPARE, 'nonce-bypass-1234'))
    response = json.loads(asyncio.run(server.handle(request.model_dump_json().encode())))
    assert response.get('reason') == 'repair_helper_required'
    assert calls == []


@pytest.mark.privileged_linux
def test_interrupted_install_journal_survives_process_exit(tmp_path):
    from a4diag_target.repair_install import install_transaction
    root = tmp_path / 'root'
    policy = root / 'etc/a4diag-target/policy.json'
    policy.parent.mkdir(parents=True)
    policy.write_text('old policy')
    policy.chmod(0o600)
    install_transaction('begin', root, {})
    policy.write_text('half-written policy')
    # A new interpreter recovers the old file without the original installer.
    result = subprocess.run([sys.executable,'-m','a4diag_target.repair_install','rollback',str(root)],capture_output=True,text=True)
    assert result.returncode == 0, result.stderr
    assert policy.read_text() == 'old policy'
    assert policy.stat().st_mode & 0o777 == 0o600

import pytest
from test_disk_workflow import disk_profile


def test_disk_registration_has_exact_cache_write_scope_and_denies_manager():
    from a4diag_target.repair_install import plan_helpers, sandbox_properties
    profile = disk_profile()
    # A separate stop grant is mandatory, even during installation.
    with pytest.raises(ValueError, match='disk_writer_stop_profile_required'):
        plan_helpers([profile], [{'profile_id':profile.id, 'adapter':'disk-cache'}], peer_uid=123)
    from tests.target_runtime.test_repair_protocol import _profile
    stop = _profile().model_copy(update={'resource':'demo.service','actions':('stop',)})
    binding, = plan_helpers([profile, stop], [{'profile_id':profile.id, 'adapter':'disk-cache'}], peer_uid=123)
    properties = sandbox_properties(binding)
    assert 'ReadWritePaths=/var/lib/a4diag-target/repair-helpers/demo-cache /var/cache/demo' in properties
    assert 'TemporaryFileSystem=/run:ro' in properties
    assert not binding.spec().sandbox(profile).socket_paths


@pytest.mark.parametrize('root',['/var/lib','/var/lib/a4diag-target/executor','/opt/a4diag-target','/root','/etc/cache','/var/cache/../lib'])
def test_disk_profile_rejects_protected_or_ambiguous_roots(root):
    with pytest.raises(ValueError):disk_profile(root)


def test_installer_validates_real_disk_registration(tmp_path):
    import json,subprocess,sys
    from tests.test_linux_probe_policy import installation_config,installer_script
    from tests.target_runtime.test_repair_protocol import _profile
    disk=disk_profile().model_copy(update={'target_id':'node-1'})
    stop=_profile().model_copy(update={'target_id':'node-1','resource':'demo.service','actions':('stop',)})
    config=tmp_path/'disk-install.json'
    config.write_text(json.dumps(installation_config(repair_profiles=[p.model_dump(mode='json') for p in (disk,stop)],
        repair_helpers=[{'profile_id':disk.id,'adapter':'disk-cache'}],confirm_repair_helpers='ENABLE')))
    run=subprocess.run([sys.executable,'-c',installer_script('validate_config'),str(config)],capture_output=True,text=True)
    assert run.returncode==0,run.stderr


def test_controller_disk_contract_does_not_claim_local_write_authority():
    import asyncio
    from a4diag_builtin_plugins.host import build_plugin
    plugin=build_plugin('capability-disk')
    probe=asyncio.run(plugin.capability_probe(None))
    assert not probe.write_capable and probe.reason=='exact_target_disk_helper_required'
    with pytest.raises(Exception,match='disk_helper_required'):asyncio.run(plugin.prepare(None))

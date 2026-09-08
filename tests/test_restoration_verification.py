from __future__ import annotations

import asyncio

import pytest

from a4diag_builtin_plugins.capability_common import CapabilityError, CommandOutcome
from a4diag_builtin_plugins.capability_packages import PackagesPlugin
from a4diag_builtin_plugins.capability_services import ServicesPlugin
from contract.test_capability_plugins import (
    FakeTarget, operation, prepare_params, verify_params, service_state,
)


def test_service_restoration_checks_prior_runtime_state_not_invocation_id():
    target = FakeTarget()
    target.service_state['example.service'] = service_state(
        active='active', sub='running', file_state='enabled', invocation='before')
    plugin = ServicesPlugin(transport=target)
    op = operation(capability='services', action='restart', resource='example.service',
                   parameters={'unit': 'example.service'})
    marker = asyncio.run(plugin.prepare(prepare_params(op))).marker
    target.service_state['example.service'] = service_state(
        active='active', sub='running', file_state='enabled', invocation='after-undo')
    assert asyncio.run(plugin.verify_restored(verify_params(op, marker))).ok
    target.service_state['example.service'] = service_state(
        active='inactive', sub='dead', file_state='enabled', invocation='after-undo')
    assert not asyncio.run(plugin.verify_restored(verify_params(op, marker))).ok


@pytest.mark.parametrize('prior', [None, '1.0'])
def test_package_restoration_proves_prior_version_or_absence(prior):
    target = FakeTarget()
    if prior is not None:
        target.installed['example'] = prior
    plugin = PackagesPlugin(transport=target)
    op = operation(capability='packages', action='install_exact', resource='example',
                   parameters={'name': 'example', 'version': '2.0'})
    marker = asyncio.run(plugin.prepare(prepare_params(op))).marker
    assert asyncio.run(plugin.verify_restored(verify_params(op, marker))).ok
    target.installed['example'] = '2.0'
    assert not asyncio.run(plugin.verify_restored(verify_params(op, marker))).ok


def test_package_restoration_does_not_treat_query_failure_as_absence():
    target = FakeTarget()
    plugin = PackagesPlugin(transport=target)
    op = operation(capability='packages', action='install_exact', resource='example',
                   parameters={'name': 'example', 'version': '2.0'})
    marker = asyncio.run(plugin.prepare(prepare_params(op))).marker
    async def failed(*args, **kwargs):
        raise CapabilityError('command_timeout')
    target.run_command = failed
    result = asyncio.run(plugin.verify_restored(verify_params(op, marker)))
    assert not result.ok and result.reason == 'state_unavailable'


def test_package_database_error_is_not_evidence_of_restoration():
    target = FakeTarget()
    plugin = PackagesPlugin(transport=target)
    op = operation(capability='packages', action='install_exact', resource='example',
                   parameters={'name': 'example', 'version': '2.0'})
    marker = asyncio.run(plugin.prepare(prepare_params(op))).marker
    async def database_error(*args, **kwargs):
        return CommandOutcome(returncode=1, stdout='', stderr='error: cannot open Packages database')
    target.run_command = database_error
    assert not asyncio.run(plugin.verify_restored(verify_params(op, marker))).ok


def test_target_executor_checks_restored_state_instead_of_desired_state():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from a4diag.domain import Operation, Risk
    from a4diag.plugin_api.target_protocol import TargetRequest, TargetSigner, TargetVerifier
    from a4diag.plugin_api.ticket import effect_payload_digest
    from a4diag_target.executor import TargetExecutor
    from a4diag_target.policy import TargetPolicy
    from test_target_protocol import ReplayStore

    adapter = FakeTarget()
    adapter.add_file('/srv/lab/config', b'before', mode=0o100640)
    key = Ed25519PrivateKey.generate()
    signer = TargetSigner(key)
    fingerprint = 'sha256:' + 'a' * 64
    op = Operation(capability='files', action='replace_managed_file', resource='/srv/lab/config',
                   parameters={'content': 'YWZ0ZXI='}, model_risk=Risk.LOW, verify={}, undo={'restore': True})
    def request(phase, nonce, marker=None, restored=False):
        effect = {} if phase == 'prepare' else {'marker': marker}
        if phase == 'undo':
            effect['undo'] = op.undo
        return TargetRequest(controller_id='controller', target_id='lab', target_fingerprint=fingerprint,
                             transaction_id='tx-1', step_id='0', lifecycle=phase, operation=op,
                             marker=marker, undo=op.undo if phase == 'undo' else None,
                             plan_digest='d' * 64, effect_payload_digest=effect_payload_digest(effect),
                             risk=Risk.LOW, approval_id=None, issued_at=100, expires_at=200,
                             nonce=nonce * 16, verify_restored=restored)
    first = signer.sign(request('prepare', 'a'))
    executor = TargetExecutor(
        verifier=TargetVerifier(key.public_key(), replay_store=ReplayStore(), clock=lambda: 110),
        policy=TargetPolicy(target_id='lab', target_fingerprint=fingerprint,
                            controller_key_fingerprint=first.key_fingerprint, managed_roots=('/srv/lab',)),
        identity_probe=lambda: fingerprint, adapter=adapter)
    marker = asyncio.run(executor.execute(first))['marker']
    asyncio.run(executor.execute(signer.sign(request('apply', 'b', marker))))
    assert not asyncio.run(executor.execute(signer.sign(request('verify', 'c', marker, True))))['ok']
    asyncio.run(executor.execute(signer.sign(request('undo', 'd', marker))))
    assert asyncio.run(executor.execute(signer.sign(request('verify', 'e', marker, True))))['ok']
    assert adapter.files['/srv/lab/config'] == b'before'

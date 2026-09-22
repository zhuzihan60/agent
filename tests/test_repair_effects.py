import pytest


@pytest.mark.parametrize('effects, expected', [
    ([('irreversible', True, False)], 'rollback_partial'),
    ([('compensatable', True, True)], 'rollback_partial'),
    ([('restorable', True, True)], 'rollback_succeeded'),
    ([('restorable', True, False)], 'rollback_partial'),
    ([('irreversible', False, False)], 'rollback_succeeded'),
    ([('restorable', None, False), ('irreversible', True, False)], 'rollback_unknown'),
    ([('restorable', True, True), ('irreversible', True, False)], 'rollback_partial'),
    ([], 'rollback_succeeded'),
])
def test_effect_rollback_truth(effects, expected):
    from a4diag.repair_effects import RepairEffect, rollback_outcome
    assert rollback_outcome([
        RepairEffect(kind=kind, changed=changed, restoration_verified=verified)
        for kind, changed, verified in effects
    ]) == expected


def test_manifest_legacy_effects_and_explicit_compensation():
    from a4diag.plugin_api.manifest import OperationContract
    common = dict(name='services.restart', risk_floor='high', supports_prepare=True,
                  supports_verify=True, supports_reconcile=True, parameters_schema={})
    assert OperationContract(**common, reversible=True).effect_kind == 'restorable'
    assert OperationContract(**common, reversible=False).effect_kind == 'irreversible'
    assert OperationContract(**common, reversible=False,
                             effect_kind='compensatable').effect_kind == 'compensatable'


def test_effect_evidence_is_durable_and_cannot_change_kind(tmp_path):
    from a4diag.transaction_store import TransactionStore, TransactionStoreError
    from a4diag.repair_effects import RepairEffect
    store = TransactionStore(tmp_path/'transactions.db')
    store.begin('tx', 'target', 'a'*64, now=100)
    effect = RepairEffect(kind='irreversible', changed=True, restoration_verified=False)
    store.record_effect('tx', '0', effect)
    assert TransactionStore(store.path).repair_effects('tx') == {'0': effect}
    with pytest.raises(TransactionStoreError, match='effect_kind_changed'):
        store.record_effect('tx', '0', effect.model_copy(update={'kind': 'restorable'}))


def test_audit_refuses_untruthful_full_rollback(tmp_path):
    from a4diag.audit import AuditWriter, AuditError
    writer = AuditWriter(tmp_path/'audit.jsonl')
    with pytest.raises(AuditError, match='effect_outcome_mismatch'):
        writer.append({'event': 'rollback_finished', 'result': 'rollback_succeeded',
                       'effects': [{'kind': 'irreversible', 'changed': True, 'restoration_verified': False}]})


def test_terminal_job_without_change_evidence_remains_unknown():
    from a4diag.repair_jobs import RepairJob
    from a4diag.repair_workflow import job_result
    job = RepairJob(id='job', transaction_id='tx', step_id='0', profile_digest='a'*64,
        operation_digest='b'*64, state='partial', changed=None, started_at=100, finished_at=101)
    assert job_result(job).status == 'unknown'

from __future__ import annotations

import multiprocessing
import sqlite3

import pytest


def _reserve_process(path, gate, results, tx):
    from a4diag.repair_store import RepairStore, RepairLimitError
    store = RepairStore(path)
    gate.wait()
    try:
        results.put(store.reserve('demo', 'web.service', tx, 1000, 600, 2))
    except RepairLimitError as error:
        results.put(error.code)


def test_resource_lock_survives_restart_and_never_expires(tmp_path):
    from a4diag.repair_store import RepairStore, RepairLimitError
    path = tmp_path / 'repair.db'
    reservation = RepairStore(path).reserve('demo', 'web.service', 'tx1', 1000, 600, 2)
    RepairStore(path).mark_started(reservation, 1001)
    for now in (2000, 999999):
        with pytest.raises(RepairLimitError, match='resource_busy'):
            RepairStore(path).reserve('demo', 'web.service', 'tx2', now, 600, 2)
    with pytest.raises(RepairLimitError, match='job_not_terminal'):
        RepairStore(path).finish(reservation, 'succeeded')


def test_reserved_attempts_count_across_restart_and_clock_rollback(tmp_path):
    from a4diag.repair_store import RepairStore, RepairLimitError
    path = tmp_path / 'repair.db'
    store = RepairStore(path)
    first = store.reserve('demo', 'web.service', 'tx1', 1000, 600, 2)
    store.finish(first, 'cancelled')
    for now, code in ((999, 'clock_rollback'), (1599, 'cooldown')):
        with pytest.raises(RepairLimitError, match=code):
            RepairStore(path).reserve('demo', 'web.service', 'tx2', now, 600, 2)
    second = RepairStore(path).reserve('demo', 'web.service', 'tx2', 1600, 600, 2)
    store.finish(second, 'cancelled')
    with pytest.raises(RepairLimitError, match='hourly_limit'):
        RepairStore(path).reserve('demo', 'web.service', 'tx3', 2200, 600, 2)
    assert RepairStore(path).reserve('demo', 'web.service', 'tx3', 4600, 600, 2)


def test_two_processes_cannot_reserve_same_resource(tmp_path):
    from a4diag.repair_store import RepairStore
    path = tmp_path / 'repair.db'
    RepairStore(path)
    ctx = multiprocessing.get_context('spawn')
    gate, results = ctx.Event(), ctx.Queue()
    workers = [ctx.Process(target=_reserve_process, args=(path, gate, results, f'tx{i}')) for i in range(2)]
    for worker in workers:
        worker.start()
    gate.set()
    values = [results.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(20)
        assert worker.exitcode == 0
    assert values.count('resource_busy') == 1


def test_database_full_fails_closed_without_reservation(tmp_path, monkeypatch):
    from a4diag.repair_store import RepairStore, RepairLimitError
    store = RepairStore(tmp_path / 'repair.db')
    original = store._connect
    def limited():
        connection = original()
        pages = connection.execute('PRAGMA page_count').fetchone()[0]
        connection.execute(f'PRAGMA max_page_count={pages}')
        return connection
    monkeypatch.setattr(store, '_connect', limited)
    with pytest.raises(RepairLimitError, match='store_unavailable'):
        store.reserve('demo', 'r' * 100000, 'tx1', 1000, 600, 2)


def test_controller_job_references_persist_and_reject_foreign_or_stale_result(tmp_path):
    from a4diag.transaction_store import TransactionStore, PreparedStep, TransactionStoreError
    from a4diag.repair_jobs import RepairJob
    from a4diag.policy_engine import canonical_operation_digest
    from a4diag.domain import Operation, canonical_json_bytes
    operation = Operation(capability='services', action='restart', resource='web.service',
        parameters={'unit':'web.service'}, model_risk='high', verify={}, undo=None)
    digest = canonical_operation_digest(operation)
    path = tmp_path / 'controller.db'
    store = TransactionStore(path)
    store.begin('tx1', 'demo', 'd'*64, now=100)
    store.record_prepared('tx1', [PreparedStep('0', canonical_json_bytes(operation.model_dump(mode='json')).decode(), '{}', '{}')], now=100)
    job = RepairJob(id='job1', transaction_id='tx1', step_id='0', profile_digest='b'*64,
        operation_digest=digest, state='running', started_at=100)
    store.record_repair_job(job, target_id='demo', profile_digest='b'*64, now=101)
    assert TransactionStore(path).repair_jobs('tx1') == (job,)
    assert TransactionStore(path).pending_repair_jobs() == (('demo', job),)
    for changes in ({'id':'foreign'}, {'profile_digest':'e'*64}, {'operation_digest':'f'*64}):
        with pytest.raises(TransactionStoreError):
            store.record_repair_job(job.model_copy(update=changes), target_id='demo', profile_digest='b'*64, now=102)
    with pytest.raises(TransactionStoreError):
        store.record_repair_job(job, target_id='other', profile_digest='b'*64, now=102)
    terminal = job.model_copy(update={'state':'partial', 'changed':True, 'finished_at':103})
    store.record_repair_job(terminal, target_id='demo', profile_digest='b'*64, now=103)
    assert store.pending_repair_jobs() == ()
    with pytest.raises(TransactionStoreError):
        store.record_repair_job(job, target_id='demo', profile_digest='b'*64, now=104)

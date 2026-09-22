"""Controller/store protection independent of target transport behavior."""
import multiprocessing
from types import SimpleNamespace

import pytest


def _occupy_resource(path, ready, finish):
    from a4diag.repair_store import RepairStore
    from a4diag.writer_holds import WriterHolds
    with WriterHolds(RepairStore(path)).resource_guard('demo', 'demo.service'):
        ready.set()
        assert finish.wait(20)


def test_guard_excludes_other_process_for_whole_mutation(tmp_path):
    from a4diag.repair_store import RepairStore, RepairLimitError
    from a4diag.writer_holds import WriterHolds
    store = RepairStore(tmp_path/'state.db')
    ctx = multiprocessing.get_context('spawn')
    ready, finish = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_occupy_resource, args=(store.path, ready, finish))
    process.start()
    try:
        assert ready.wait(10)
        with pytest.raises(RepairLimitError, match='resource_busy'):
            with WriterHolds(store).resource_guard('demo', 'demo.service'):
                pytest.fail('overlapping mutation admitted')
        finish.set()
        process.join(10)
        assert process.exitcode == 0
        with WriterHolds(store).resource_guard('demo', 'demo.service'):
            pass
    finally:
        finish.set()
        if process.is_alive():
            process.terminate()
        process.join(10)


def test_controller_legacy_dispatch_rejects_persisted_hold(tmp_path):
    from a4diag.repair_store import RepairStore, RepairLimitError
    from a4diag.writer_holds import WriterHolds, controller_mutation_guard
    from tests.test_repair_authorization import _operation
    store = RepairStore(tmp_path/'state.db')
    store.reserve('demo', 'demo.service', 'owner', 100, 600, 2)
    binding = dict(target_id='demo', resource='demo.service', transaction_id='owner')
    WriterHolds(store).protect(binding)
    deps = SimpleNamespace(transactions=SimpleNamespace(path=store.path),
        tickets=SimpleNamespace(inspect_for_recovery=lambda _:SimpleNamespace(preparation_dependency=None)))
    with pytest.raises(RepairLimitError, match='resource_busy'):
        with controller_mutation_guard(deps, {'transaction_id':'other'}, SimpleNamespace(id='demo'),
                _operation(), '0', {}, 'signed-ticket'):
            pytest.fail('legacy dispatcher ran while writer held')

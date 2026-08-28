from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from a4diag.alertmanager import AlertmanagerClient, dedup_key
from a4diag.config import Config
from a4diag.poller import Poller
from a4diag.store import Store

from tests.test_config_policy import CONFIG_TEXT, write_config


def raw_alert(
    fingerprint: str = "fp-001",
    starts_at: str = "2026-08-24T09:00:00+08:00",
    instance: str = "10.3.12.131:9100",
    target_id: str = "t_01",
    state: str = "active",
) -> dict[str, object]:
    return {
        "annotations": {"summary": "CPU usage is high"},
        "endsAt": "0001-01-01T00:00:00Z",
        "fingerprint": fingerprint,
        "receivers": [{"name": "default"}],
        "startsAt": starts_at,
        "status": {"inhibitedBy": [], "silencedBy": [], "state": state},
        "updatedAt": "2026-08-24T09:01:00+08:00",
        "generatorURL": "http://10.3.7.5:9090/graph",
        "labels": {
            "alertname": "HostHighCpu",
            "instance": instance,
            "target_id": target_id,
            "severity": "warning",
        },
    }


class AlertmanagerStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config = Config.load(write_config(self.root, CONFIG_TEXT))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_normalizes_only_active_registered_targets(self) -> None:
        client = AlertmanagerClient(self.config)

        alert = client.normalize(raw_alert())

        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.target, "t_01")
        self.assertEqual(alert.name, "HostHighCpu")
        self.assertEqual(alert.severity, "warning")
        self.assertIsNone(client.normalize(raw_alert(state="suppressed")))
        # An IP/instance label never routes; only a registered target_id label does.
        self.assertIsNone(client.normalize(raw_alert(target_id="10.3.12.99")))
        self.assertIsNone(client.normalize(raw_alert(target_id="unknown")))

    def test_dedup_key_includes_alert_generation(self) -> None:
        client = AlertmanagerClient(self.config)
        first = client.normalize(raw_alert())
        recurrent = client.normalize(
            raw_alert(starts_at="2026-08-25T09:00:00+08:00")
        )
        assert first is not None and recurrent is not None

        self.assertEqual(dedup_key(first), "fp-001:2026-08-24T09:00:00+08:00")
        self.assertNotEqual(dedup_key(first), dedup_key(recurrent))

    def test_store_claims_same_alert_once_and_persists_queue(self) -> None:
        alert = AlertmanagerClient(self.config).normalize(raw_alert())
        assert alert is not None
        database = self.root / "state.db"

        first_store = Store(database)
        self.assertTrue(first_store.claim_alert(alert))
        self.assertFalse(first_store.claim_alert(alert))

        reopened = Store(database)
        queued = reopened.next_queued(limit=2)
        self.assertEqual([item.fingerprint for item in queued], ["fp-001"])

    def test_worker_batch_never_exceeds_two_and_leaves_third_queued(self) -> None:
        store = Store(self.root / "state.db")
        client = AlertmanagerClient(self.config)
        for index in range(3):
            alert = client.normalize(raw_alert(fingerprint=f"fp-{index}"))
            assert alert is not None
            self.assertTrue(store.claim_alert(alert))

        lock = threading.Lock()
        active = 0
        maximum_active = 0

        def diagnose(alert):
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return f"/reports/{alert.fingerprint}.yaml"

        poller = Poller(store=store, diagnose=diagnose, max_concurrency=2)

        self.assertEqual(poller.process_queued_batch(), 2)
        self.assertEqual(maximum_active, 2)
        self.assertEqual(store.count_by_status("completed"), 2)
        self.assertEqual(store.count_by_status("queued"), 1)

        self.assertEqual(poller.process_queued_batch(), 1)
        self.assertEqual(store.count_by_status("completed"), 3)
        self.assertEqual(store.count_by_status("queued"), 0)

    def test_poll_once_claims_each_alert_generation_only_once(self) -> None:
        client = AlertmanagerClient(self.config)
        first = client.normalize(raw_alert(fingerprint="fp-1"))
        second = client.normalize(raw_alert(fingerprint="fp-2"))
        assert first is not None and second is not None

        class AlertSource:
            def active_alerts(self):
                return [first, second]

        store = Store(self.root / "state.db")
        poller = Poller(
            store=store,
            diagnose=lambda alert: f"/{alert.fingerprint}.yaml",
            max_concurrency=2,
            alert_source=AlertSource(),
        )

        self.assertEqual(poller.poll_once(), 2)
        self.assertEqual(poller.poll_once(), 0)
        self.assertEqual(store.count_by_status("queued"), 2)

    def test_interrupted_job_is_requeued_once_then_failed(self) -> None:
        alert = AlertmanagerClient(self.config).normalize(raw_alert())
        assert alert is not None
        store = Store(self.root / "state.db")
        self.assertTrue(store.claim_alert(alert))

        store.mark_running(alert)
        self.assertEqual(store.recover_interrupted(), {"requeued": 1, "failed": 0})
        self.assertEqual(store.count_by_status("queued"), 1)

        store.mark_running(alert)
        self.assertEqual(store.recover_interrupted(), {"requeued": 0, "failed": 1})
        self.assertEqual(store.count_by_status("failed"), 1)

    def test_atomic_reservation_enforces_global_concurrency_two(self) -> None:
        database = self.root / "state.db"
        first_store = Store(database)
        second_store = Store(database)
        client = AlertmanagerClient(self.config)
        for index in range(3):
            alert = client.normalize(raw_alert(fingerprint=f"fp-{index}"))
            assert alert is not None
            self.assertTrue(first_store.claim_alert(alert))

        barrier = threading.Barrier(2)
        reservations: list[list[str]] = []
        lock = threading.Lock()

        def reserve(store: Store) -> None:
            barrier.wait()
            alerts = store.reserve_queued(max_concurrency=2)
            with lock:
                reservations.append([item.fingerprint for item in alerts])

        threads = [
            threading.Thread(target=reserve, args=(first_store,)),
            threading.Thread(target=reserve, args=(second_store,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        flattened = [item for reservation in reservations for item in reservation]
        self.assertEqual(len(flattened), 2)
        self.assertEqual(len(set(flattened)), 2)
        self.assertEqual(first_store.count_by_status("running"), 2)
        self.assertEqual(first_store.count_by_status("queued"), 1)


if __name__ == "__main__":
    unittest.main()

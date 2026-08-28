from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from a4diag.process_lock import AlreadyRunningError, SingleInstanceLock


class ProcessLockTests(unittest.TestCase):
    def test_second_poll_process_cannot_acquire_live_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "poller.lock"
            with SingleInstanceLock(path):
                with self.assertRaises(AlreadyRunningError):
                    with SingleInstanceLock(path):
                        self.fail("second process lock unexpectedly acquired")

            with SingleInstanceLock(path):
                pass


if __name__ == "__main__":
    unittest.main()

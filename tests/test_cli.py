from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import a4diag.cli as cli
from a4diag.models import Alert
from a4diag.store import Store


class CliTests(unittest.TestCase):
    def test_removed_dsh_profile_command_is_not_exposed(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                cli._parser().parse_args(["verify-profile"])
        self.assertEqual(raised.exception.code, 2)

    def test_cleanup_does_not_recover_or_change_running_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "config.yaml"
            config_path.write_text(
                "global_mode: read_only\nauto_execute_low: false\n"
                "max_write_targets: 2\ntargets: []\nplugins: []\n"
                "retention:\n  normal_days: 1\n  abnormal_days: 14\n",
                encoding="utf-8",
            )
            database = root / "state.db"
            store = Store(database)
            alert = Alert(
                fingerprint="fp-cleanup",
                starts_at="2026-08-24T09:00:00+08:00",
                name="cleanup-test",
                severity="warning",
                target="target-1",
                labels={"target_id": "target-1"},
                annotations={},
            )
            self.assertTrue(store.claim_alert(alert))
            store.mark_running(alert)

            with (
                patch.object(cli, "REPORT_ROOT", root / "reports"),
                patch.dict(os.environ, {"A4DIAG_CONFIG": str(config_path)}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cli.main(["cleanup"]), 0)

            self.assertEqual(store.count_by_status("running"), 1)
            self.assertEqual(store.count_by_status("queued"), 0)


if __name__ == "__main__":
    unittest.main()

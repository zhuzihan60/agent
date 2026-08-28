from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from a4diag.report import classify_report, cleanup_expired


UTC = timezone.utc
NOW = datetime(2026, 8, 24, 2, 0, 0, tzinfo=UTC)


def write_report(
    root: Path,
    name: str,
    *,
    status: str,
    conclusion: str,
    evidence_complete: bool,
    age: timedelta,
) -> Path:
    path = root / "2026-08-24" / f"{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {
                "task_id": name,
                "status": status,
                "conclusion": conclusion,
                "evidence_complete": evidence_complete,
                "finished_at": (NOW - age).isoformat(),
            },
            allow_unicode=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


class ReportRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_only_complete_diagnosed_normal_report_is_normal(self) -> None:
        self.assertEqual(
            classify_report(
                {
                    "status": "diagnosed",
                    "conclusion": "normal",
                    "evidence_complete": True,
                }
            ),
            "normal",
        )
        for report in (
            {
                "status": "insufficient_evidence",
                "conclusion": "normal",
                "evidence_complete": False,
            },
            {
                "status": "collection_failed",
                "conclusion": "normal",
                "evidence_complete": False,
            },
            {
                "status": "model_failed",
                "conclusion": "normal",
                "evidence_complete": False,
            },
            {
                "status": "diagnosed",
                "conclusion": "abnormal",
                "evidence_complete": True,
            },
        ):
            with self.subTest(report=report):
                self.assertEqual(classify_report(report), "abnormal")

    def test_cleanup_uses_one_day_for_normal_and_fourteen_for_abnormal(self) -> None:
        expired_normal = write_report(
            self.root,
            "normal-old",
            status="diagnosed",
            conclusion="normal",
            evidence_complete=True,
            age=timedelta(hours=25),
        )
        current_normal = write_report(
            self.root,
            "normal-current",
            status="diagnosed",
            conclusion="normal",
            evidence_complete=True,
            age=timedelta(hours=23),
        )
        current_failed = write_report(
            self.root,
            "failed-current",
            status="collection_failed",
            conclusion="abnormal",
            evidence_complete=False,
            age=timedelta(days=2),
        )
        expired_failed = write_report(
            self.root,
            "failed-old",
            status="collection_failed",
            conclusion="abnormal",
            evidence_complete=False,
            age=timedelta(days=15),
        )

        deleted = cleanup_expired(
            self.root,
            normal_days=1,
            abnormal_days=14,
            now=NOW,
        )

        self.assertEqual(set(deleted), {expired_normal, expired_failed})
        self.assertFalse(expired_normal.exists())
        self.assertFalse(expired_failed.exists())
        self.assertTrue(current_normal.exists())
        self.assertTrue(current_failed.exists())


if __name__ == "__main__":
    unittest.main()

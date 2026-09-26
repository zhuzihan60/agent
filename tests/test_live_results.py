from pathlib import Path

import pytest

from tests.ci.assert_live_results import validate_results


@pytest.mark.parametrize("body", ["", '<testcase name="not-run"><skipped /></testcase>', '<testcase name="broken"><failure /></testcase>', '<testcase name="crashed"><error /></testcase>'])
def test_live_gate_rejects_empty_skipped_or_failed_results(tmp_path: Path, body: str) -> None:
    report = tmp_path / "results.xml"
    report.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>")
    with pytest.raises(ValueError):
        validate_results(report)


def test_live_gate_counts_executed_tests(tmp_path: Path) -> None:
    report = tmp_path / "results.xml"
    report.write_text('<testsuites><testsuite><testcase name="a"/><testcase name="b"/></testsuite></testsuites>')
    assert validate_results(report) == 2

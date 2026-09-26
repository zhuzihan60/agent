"""A successful opt-in acceptance job must have executed tests, not skips."""
from __future__ import annotations

from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def validate_results(path: Path) -> int:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    if not cases:
        raise ValueError("live acceptance did not execute any tests")
    for case in cases:
        if any(case.find(tag) is not None for tag in ("skipped", "failure", "error")):
            raise ValueError(f"live acceptance was skipped or failed: {case.get('name')}")
    return len(cases)


if __name__ == "__main__":
    print(f"Executed {validate_results(Path(sys.argv[1]))} live acceptance tests without skips")

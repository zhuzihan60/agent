from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pytest

import a4diag.cli as cli


def test_target_is_chosen_automatically_only_when_unambiguous() -> None:
    assert cli._choose_target(None, ["local"]) == "local"
    assert cli._choose_target("web", ["local", "web"]) == "web"
    with pytest.raises(ValueError, match="setup"):
        cli._choose_target(None, [])
    with pytest.raises(ValueError, match="--target"):
        cli._choose_target(None, ["local", "web"])
    with pytest.raises(ValueError, match="not registered"):
        cli._choose_target("other", ["local"])


def test_diagnosis_is_printed_in_plain_language(tmp_path: Path) -> None:
    report = {
        "diagnosis": {"cause": "nginx stopped", "confidence": 0.9,
                      "recommended_actions": ["start nginx"], "missing_evidence": ["http check"]},
    }
    text = cli._format_diagnosis("read_only", report, tmp_path / "r.yaml")
    assert "只读模式" in text and "nginx stopped" in text
    assert "1. start nginx" in text and "- http check" in text
    assert str(tmp_path / "r.yaml") in text


def test_diagnose_without_registered_targets_points_to_setup(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("global_mode: read_only\ntargets: []\nplugins: []\n", encoding="utf-8")
    monkeypatch.setenv("A4DIAG_CONFIG", str(config))
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        assert cli.main(["diagnose", "website is down"]) == 64
    assert "a4diag setup" in stderr.getvalue()


def test_diagnose_rejects_blank_or_oversized_descriptions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("A4DIAG_CONFIG", str(tmp_path / "missing.yaml"))
    with contextlib.redirect_stderr(io.StringIO()):
        assert cli.main(["diagnose", "   "]) == 64
        assert cli.main(["diagnose", "x" * (cli.MAX_DESCRIPTION_CHARS + 1)]) == 64

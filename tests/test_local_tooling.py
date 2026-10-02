#!/usr/bin/env python3
"""Deterministic tests for local security and dependency tooling."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.dependency_review import compare  # noqa: E402
from scripts.dependencies import version_key  # noqa: E402
import scripts.sast as sast  # noqa: E402
from scripts.sast import sarif_document  # noqa: E402


def test_integrity_loss_is_visible_to_review() -> None:
    result = compare(
        [{"key": "pin:X", "value": "abc", "immutable": True, "source": "base", "kind": "pin"}],
        [{"key": "pin:X", "value": "abc", "immutable": False, "source": "candidate", "kind": "pin"}],
    )
    assert result["changed"][0]["before"]["immutable"] is True
    assert result["changed"][0]["after"]["immutable"] is False


def test_update_versions_are_ordered_without_mutation() -> None:
    assert version_key("5.29.6") > version_key("5.28.2")
    assert (ROOT / "requirements.txt").is_file()


def test_sast_report_converts_to_machine_readable_sarif() -> None:
    document = sarif_document(
        {
            "results": [
                {
                    "test_id": "B999",
                    "test_name": "test-rule",
                    "issue_text": "unsafe test fixture",
                    "filename": "tests/example.py",
                    "line_number": 7,
                }
            ]
        }
    )
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "B999"


def test_sast_bootstrap_failure_cannot_pass() -> None:
    original = sast.bootstrap_bandit
    try:
        sast.bootstrap_bandit = lambda: (_ for _ in ()).throw(sast.SastError("tool unavailable"))
        with tempfile.TemporaryDirectory(prefix="sast-failure-") as temporary:
            report_dir = Path(temporary)
            try:
                sast.run_sast(report_dir)
            except sast.SastError:
                pass
            else:
                raise AssertionError("SAST bootstrap failure was accepted")
            report = json.loads((report_dir / "sast-bandit.json").read_text(encoding="utf-8"))
            assert report["gate_decision"] == "FAIL"
    finally:
        sast.bootstrap_bandit = original


def test_sast_incomplete_tool_directory_is_retained() -> None:
    original = sast.tool_directory
    try:
        with tempfile.TemporaryDirectory(prefix="sast-owned-state-") as temporary:
            target = Path(temporary) / "bandit"
            target.mkdir()
            sentinel = target / "foreign-marker"
            sentinel.write_text("retain", encoding="utf-8")
            sast.tool_directory = lambda: target
            try:
                sast.bootstrap_bandit()
            except sast.SastError as error:
                assert "retained unchanged" in str(error)
            else:
                raise AssertionError("incomplete pre-existing tool directory was overwritten")
            assert sentinel.read_text(encoding="utf-8") == "retain"
    finally:
        sast.tool_directory = original


def main() -> None:
    test_integrity_loss_is_visible_to_review()
    test_update_versions_are_ordered_without_mutation()
    test_sast_report_converts_to_machine_readable_sarif()
    test_sast_bootstrap_failure_cannot_pass()
    test_sast_incomplete_tool_directory_is_retained()
    print("PASS local security and dependency tooling tests")


if __name__ == "__main__":
    main()

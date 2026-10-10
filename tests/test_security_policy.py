#!/usr/bin/env python3
"""Deterministic tests for the provider-independent vulnerability policy."""

from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from ci import (  # noqa: E402
    ValidationError,
    enforce_vulnerability_policy,
    load_vulnerability_exceptions,
    vulnerability_exception_match,
)


KNOWN = {
    "VulnerabilityID": "CVE-2024-23342",
    "PkgName": "ecdsa",
    "InstalledVersion": "0.19.1",
    "Severity": "HIGH",
    "FixedVersion": "",
}


def test_exact_known_exception_is_accepted() -> None:
    exceptions = load_vulnerability_exceptions(today=dt.date(2026, 10, 9))
    assert vulnerability_exception_match(KNOWN, "source", exceptions) is not None
    with tempfile.TemporaryDirectory(prefix="security-policy-") as temporary:
        report_dir = Path(temporary)
        manifest = {"report_dir": str(report_dir)}
        enforce_vulnerability_policy([("source", [KNOWN])], exceptions, report_dir, manifest)
        report = json.loads((report_dir / "vulnerability-dispositions.json").read_text())
        assert report["overall"] == "PASS"
        assert report["findings"][0]["disposition"] == "PASS_WITH_DOCUMENTED_EXCEPTION"


def test_changed_version_and_scope_do_not_match() -> None:
    exceptions = load_vulnerability_exceptions(today=dt.date(2026, 10, 9))
    changed = dict(KNOWN, InstalledVersion="0.19.0")
    assert vulnerability_exception_match(changed, "source", exceptions) is None
    assert vulnerability_exception_match(KNOWN, "image:tor", exceptions) is None


def test_unknown_no_fix_and_fixable_findings_fail() -> None:
    exceptions = load_vulnerability_exceptions(today=dt.date(2026, 10, 9))
    unknown = dict(KNOWN, VulnerabilityID="CVE-2099-0001")
    fixed = dict(KNOWN, FixedVersion="0.20.0")
    for finding in (unknown, fixed):
        with tempfile.TemporaryDirectory(prefix="security-policy-") as temporary:
            try:
                enforce_vulnerability_policy(
                    [("source", [finding])],
                    exceptions,
                    Path(temporary),
                    {"report_dir": temporary},
                )
            except ValidationError:
                pass
            else:
                raise AssertionError("unsafe vulnerability disposition was accepted")


def test_expired_and_malformed_authority_fails() -> None:
    with tempfile.TemporaryDirectory(prefix="security-policy-") as temporary:
        path = Path(temporary) / "exceptions.json"
        document = json.loads((ROOT / "security/vulnerability-exceptions.json").read_text())
        document["exceptions"][0]["review_by"] = "2026-09-14"
        path.write_text(json.dumps(document), encoding="utf-8")
        try:
            load_vulnerability_exceptions(today=dt.date(2026, 9, 15), path=path)
        except ValidationError:
            pass
        else:
            raise AssertionError("expired exception authority was accepted")

        path.write_text("{}", encoding="utf-8")
        try:
            load_vulnerability_exceptions(today=dt.date(2026, 9, 15), path=path)
        except ValidationError:
            pass
        else:
            raise AssertionError("malformed exception authority was accepted")


def main() -> None:
    test_exact_known_exception_is_accepted()
    test_changed_version_and_scope_do_not_match()
    test_unknown_no_fix_and_fixable_findings_fail()
    test_expired_and_malformed_authority_fails()
    print("PASS machine-enforced vulnerability exception policy")


if __name__ == "__main__":
    main()

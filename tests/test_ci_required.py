#!/usr/bin/env python3
"""Required acceptance registration and nonzero-child propagation contracts."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ci
import test_support


def main() -> None:
    assert ci.acceptance_failure_kind(
        "test_first_install.py", "command failed: DEFAULT_BUILDER_STATUS=INFRA_FAILURE_DEFAULT_BUILDKIT_LEASE"
    ) == "INFRA_FAILURE"
    assert ci.acceptance_failure_kind(
        "test_compose_build_policy.py",
        "command failed: DEFAULT_BUILDER_STATUS=INFRA_FAILURE_DEFAULT_BUILDER_PREFLIGHT",
    ) == "INFRA_FAILURE"
    assert ci.acceptance_failure_kind(
        "test_first_install.py", "command failed: FAIL_PRODUCT_FIRST_BUILD"
    ) == "TEST_FAILURE"
    assert test_support.default_builder_infrastructure_category(
        "failed to get lease sha256:broken: not found") == "DEFAULT_BUILDKIT_LEASE"
    assert test_support.default_builder_infrastructure_category(
        "failed to solve: Dockerfile process apt-get returned exit code 100") is None
    required_product_paths = {
        "test_first_install.py", "test_network_lifecycle_e2e.py", "test_linux_gui.py",
        "test_persistence.py", "test_ledger.py", "test_mac_gui.py",
        "test_integrity_pins.py", "test_compose_build_policy.py",
    }
    assert required_product_paths <= set(ci.MANDATORY_ACCEPTANCE_TESTS)
    ci.validate_mandatory_acceptance_registration()
    for required in ("test_first_install.py", "test_network_lifecycle_e2e.py", "test_linux_gui.py",
                     "test_persistence.py", "test_ledger.py", "test_mac_gui.py"):
        missing = [name for name in ci.ACCEPTANCE_TESTS if name != required]
        try:
            ci.validate_mandatory_acceptance_registration(missing)
        except ci.ValidationError as error:
            assert required in str(error)
        else:
            raise AssertionError(f"removing the required test {required} was accepted")

    passed = [{"test": name, "status": "PASS"} for name in ci.MANDATORY_ACCEPTANCE_TESTS]
    ci.validate_mandatory_acceptance_results(passed)
    not_run = [dict(result) for result in passed]
    next(result for result in not_run if result["test"] == "test_network_lifecycle_e2e.py")["status"] = "NOT_RUN"
    try:
        ci.validate_mandatory_acceptance_results(not_run)
    except ci.ValidationError as error:
        assert "test_network_lifecycle_e2e.py" in str(error)
    else:
        raise AssertionError("a mandatory NOT_RUN result was accepted as complete")

    for required in ("test_first_install.py", "test_network_lifecycle_e2e.py", "test_linux_gui.py",
                     "test_persistence.py"):
        not_run = [dict(result) for result in passed]
        next(result for result in not_run if result["test"] == required)["status"] = "NOT_RUN"
        try:
            ci.validate_mandatory_acceptance_results(not_run)
        except ci.ValidationError as error:
            assert required in str(error)
        else:
            raise AssertionError(f"mandatory skipped coverage for {required} was accepted")

    try:
        ci.record_acceptance_skip(None, "test_linux_gui.py", "synthetic non-Linux host")
    except ci.ValidationError as error:
        assert "mandatory acceptance is NOT_RUN" in str(error)
    else:
        raise AssertionError("a skipped mandatory Linux GUI product test was accepted")
    ci.record_acceptance_skip(None, "test_optional_auxiliary.py", "synthetic optional platform limitation")
    assert ci.gate_overall_status({"acceptance_test_results": [
        {"test": "test_first_install.py", "failure_kind": "INFRA_FAILURE"}]}, 1) == "BLOCKED"
    assert ci.gate_failure_kind("unable to download Trivy 0.74.0: HTTP Error 500") == "INFRA_FAILURE"
    assert ci.gate_failure_kind("unable to download Trivy 0.74.0: HTTP Error 404") is None
    assert ci.gate_overall_status({"failure_kind": "INFRA_FAILURE"}, 1) == "BLOCKED"
    assert ci.gate_overall_status({"acceptance_test_results": [
        {"test": "test_network_lifecycle_e2e.py", "failure_kind": "TEST_FAILURE"}]}, 1) == "FAIL"

    failed_child = subprocess.CompletedProcess(["python3", "child"], 17, "", "synthetic child failure")
    with patch.object(ci, "run", return_value=failed_child):
        try:
            ci.checked(["python3", "child"], timeout=5)
        except ci.ValidationError:
            pass
        else:
            raise AssertionError("a failed required child command was reported as PASS")
    wrapper = (ROOT / "scripts/ci.sh").read_text(encoding="utf-8")
    assert 'exec python3 "${SCRIPT_DIR}/ci.py" "$@"' in wrapper
    assert 'exec python3 "${SCRIPT_DIR}/platform_runner.py" "$@"' in wrapper
    print("PASS mandatory test registration, NOT_RUN rejection, and child-error propagation")


if __name__ == "__main__":
    main()

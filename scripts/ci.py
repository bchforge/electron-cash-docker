#!/usr/bin/env python3
"""Canonical provider-independent validation for Electron Cash Docker."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import glob
import hashlib
import json
import os
import platform
import re
import signal
import shutil
import stat
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from compose_guard import UnsafeComposeModel, validate_resolved_model
import docker_ownership
import release_security
from dependency_review import run_dependency_review
from sast import default_report_directory as sast_report_directory
from sast import run_sast


ROOT = Path(__file__).resolve().parents[1]
TASK_BUILDKIT_IMAGE = "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
ENV_FILE = ROOT / ".env.example"
EXCEPTION_FILE = ROOT / "security" / "vulnerability-exceptions.json"
TRIVY_VERSION = "0.74.0"
TRIVY_ARCHIVE_SHA256 = "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
TRIVY_ARCHIVE = f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz"
TRIVY_ARCHIVE_PINS = {
    ("Linux", "x86_64"): (TRIVY_ARCHIVE, TRIVY_ARCHIVE_SHA256),
    ("Linux", "aarch64"): (f"trivy_{TRIVY_VERSION}_Linux-ARM64.tar.gz",
                             "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"),
    ("Darwin", "arm64"): (f"trivy_{TRIVY_VERSION}_macOS-ARM64.tar.gz",
                            "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11"),
    ("Darwin", "x86_64"): (f"trivy_{TRIVY_VERSION}_macOS-64bit.tar.gz",
                            "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485"),
}
HIGH_SEVERITIES = {"HIGH", "CRITICAL"}
BASELINE_HEAD = "a342e623a491390321b7bd44fab5166ee84c14f5"
CADDY_BASE_IMAGE = "caddy@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f"
ACCEPTANCE_TESTS = (
    "test_caddy_version.py",
    "test_login_locale_runtime.py",
    "test_language_browser.py",
    "test_auth_recovery.py",
    "test_campaign_controls.py",
    "test_theme_runtime.py",
    "test_gui_session_lifecycle.py",
    "test_runtime.py",
    "test_compose_build_policy.py",
    "test_electron_cash_version.py",
    "test_cve_2024_23342.py",
    "test_product_version.py",
    "test_cloudflare_cidrs.py",
    "test_client_ip.py",
    "test_fail2ban_filter.py",
    "test_fail2ban_dummy.py",
    "test_caddy_ban_semantics.py",
    "test_caddy_ban_failures.py",
    "test_adapter_failures.py",
    "test_auth_config.py",
    "test_auth_browser.py",
    "test_published_client_ip.py",
    "test_proxy_client_ban.py",
    "test_canonical_startup.py",
    "test_plugin_distribution.py",
    "test_flipstarter_plugin.py",
    "test_novnc_sharing.py",
    "test_novnc_websocket_heartbeat.py",
    "test_persistence.py",
    "test_cashfusion_defaults.py",
    "test_cashfusion_states.py",
    "test_headless.py",
    "test_rpc.py",
    "test_ledger.py",
    "test_platform_runner.py",
    "test_mac_gui.py",
    "test_docker_ownership.py",
    "test_network_lifecycle_e2e.py",
    "test_linux_gui.py",
    "test_tor_proxy.py",
    "test_backup_restore.py",
    "test_backup_wrapper.py",
    "test_backup_acceptance.py",
    "test_first_install.py",
)
REMOTE_ACCEPTANCE_TEST = "test_remote_access.py"
PUBLIC_ACCEPTANCE_TEST = "test_public_access.py"
MANDATORY_ACCEPTANCE_TESTS = (
    "test_caddy_version.py",
    "test_login_locale_runtime.py",
    "test_language_browser.py",
    "test_auth_recovery.py",
    "test_campaign_controls.py",
    "test_theme_runtime.py",
    "test_gui_session_lifecycle.py",
    "test_runtime.py",
    "test_integrity_pins.py",
    "test_compose_build_policy.py",
    "test_electron_cash_version.py",
    "test_cve_2024_23342.py",
    "test_product_version.py",
    "test_cloudflare_cidrs.py",
    "test_client_ip.py",
    "test_fail2ban_filter.py",
    "test_fail2ban_dummy.py",
    "test_caddy_ban_semantics.py",
    "test_caddy_ban_failures.py",
    "test_adapter_failures.py",
    "test_auth_config.py",
    "test_auth_browser.py",
    "test_published_client_ip.py",
    "test_proxy_client_ban.py",
    "test_canonical_startup.py",
    "test_plugin_distribution.py",
    "test_flipstarter_plugin.py",
    "test_novnc_sharing.py",
    "test_novnc_websocket_heartbeat.py",
    "test_persistence.py",
    "test_cashfusion_defaults.py",
    "test_cashfusion_states.py",
    "test_headless.py",
    "test_rpc.py",
    "test_ledger.py",
    "test_platform_runner.py",
    "test_mac_gui.py",
    "test_docker_ownership.py",
    "test_network_lifecycle_e2e.py",
    "test_linux_gui.py",
    "test_tor_proxy.py",
    "test_backup_restore.py",
    "test_backup_wrapper.py",
    "test_backup_acceptance.py",
    "test_first_install.py",
    REMOTE_ACCEPTANCE_TEST,
)


class ValidationError(RuntimeError):
    """A validation check failed."""


def validate_mandatory_acceptance_registration(tests: list[str] | tuple[str, ...] | None = None) -> None:
    registered = list(ACCEPTANCE_TESTS if tests is None else tests)
    duplicates = sorted({name for name in registered if registered.count(name) > 1})
    dispatched = set(registered) | {"test_integrity_pins.py", REMOTE_ACCEPTANCE_TEST}
    missing = sorted(set(MANDATORY_ACCEPTANCE_TESTS) - dispatched)
    absent = sorted(name for name in MANDATORY_ACCEPTANCE_TESTS
                    if not (ROOT / "tests" / name).is_file())
    if duplicates or missing or absent:
        raise ValidationError(f"mandatory acceptance registration invalid: duplicates={duplicates}, "
                              f"missing={missing}, absent_files={absent}")


def validate_mandatory_acceptance_results(results: list[dict[str, Any]]) -> None:
    statuses: dict[str, list[str]] = {}
    for result in results:
        name = result.get("test")
        if isinstance(name, str):
            statuses.setdefault(name, []).append(str(result.get("status", "NOT_RUN")))
    failures = {name: statuses.get(name, ["NOT_RUN"]) for name in MANDATORY_ACCEPTANCE_TESTS
                if statuses.get(name) != ["PASS"]}
    if failures:
        raise ValidationError(f"mandatory acceptance did not PASS exactly once: {failures}")


def acceptance_failure_kind(test: str, error: BaseException | str) -> str:
    message = str(error)
    if (test in {"test_compose_build_policy.py", "test_first_install.py"} and
            re.search(r"DEFAULT_BUILDER_STATUS=INFRA_FAILURE_[A-Z0-9_]+", message)):
        return "INFRA_FAILURE"
    return "TEST_FAILURE"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_run_id() -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"local-{timestamp}-{uuid.uuid4().hex[:12]}"


def report_directory(run_id: str) -> Path:
    configured = os.environ.get("CI_REPORT_DIR")
    if configured:
        directory = Path(configured).expanduser()
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        directory = state_home / "electron-cash-docker" / "ci" / run_id
    resolved = directory.resolve()
    if resolved == ROOT.resolve() or ROOT.resolve() in resolved.parents:
        raise ValidationError('CI_REPORT_DIR must be outside the source repository')
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def trivy_cache_directory() -> Path:
    configured = os.environ.get("TRIVY_CACHE_DIR")
    if configured:
        cache = Path(configured).expanduser()
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        cache = state_home / "electron-cash-docker" / "trivy-cache"
    cache.mkdir(parents=True, exist_ok=True)
    return cache.resolve()


def json_write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_text(command: list[str], *, timeout: int = 120) -> str:
    result = run(command, timeout=timeout)
    if result.returncode != 0:
        raise ValidationError(f"command failed ({result.returncode}):\n{sanitize(result.stdout + result.stderr)}")
    return result.stdout.strip()


def source_file_paths(report_dir: Path) -> list[str]:
    output = git_text(["git", "ls-files", "--cached", "--others", "--exclude-standard"])
    report_root = None
    try:
        report_root = report_dir.resolve().relative_to(ROOT.resolve())
    except ValueError:
        pass
    paths = []
    for raw_path in output.splitlines():
        path = Path(raw_path)
        if report_root is not None and (path == report_root or report_root in path.parents):
            continue
        paths.append(raw_path)
    return sorted(set(paths))


def source_manifest(report_dir: Path) -> tuple[dict[str, Any], str, str]:
    records: list[dict[str, Any]] = []
    deleted = set(git_text(["git", "diff", "--name-only", "--diff-filter=D", "HEAD"]).splitlines())
    deleted.update(git_text(["git", "diff", "--name-only", "--diff-filter=D"]).splitlines())
    for raw_path in source_file_paths(report_dir):
        path = ROOT / raw_path
        if not path.exists() and not path.is_symlink():
            if raw_path in deleted:
                continue  # the worktree, not the index, is the source authority
            raise ValidationError(f"source manifest path disappeared: {raw_path}")
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            file_type = "file"
            digest = sha256_file(path)
            size = metadata.st_size
        elif stat.S_ISLNK(metadata.st_mode):
            file_type = "symlink"
            digest = sha256_bytes(os.readlink(path).encode("utf-8"))
            size = len(os.readlink(path).encode("utf-8"))
        else:
            file_type = "other"
            digest = None
            size = metadata.st_size
        records.append(
            {
                "path": raw_path,
                "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                "type": file_type,
                "size": size,
                "sha256": digest,
            }
        )
    document = {
        "schema_version": 1,
        "root": str(ROOT),
        "files": records,
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    source_hash = sha256_bytes(serialized)
    json_write(report_dir / "effective-source-manifest.json", document)

    untracked_paths = set(git_text(["git", "ls-files", "--others", "--exclude-standard"]).splitlines())
    untracked = [record for record in records if record["path"] in untracked_paths]
    untracked_document = {"schema_version": 1, "files": untracked}
    untracked_serialized = json.dumps(
        untracked_document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    untracked_hash = sha256_bytes(untracked_serialized)
    json_write(report_dir / "untracked-source-manifest.json", untracked_document)
    return document, source_hash, untracked_hash


def working_tree_diff_hash() -> str:
    result = subprocess.run(
        ["git", "diff", "--binary", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValidationError(f"unable to capture working-tree diff: {result.stderr.decode(errors='replace')}")
    return sha256_bytes(result.stdout)


def candidate_identity(report_dir: Path) -> dict[str, Any]:
    status = git_text(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    manifest, source_hash, untracked_hash = source_manifest(report_dir)
    head = git_text(["git", "rev-parse", "HEAD"])
    try:
        baseline = git_text(["git", "rev-parse", "v0.4^{commit}"])
    except ValidationError:
        baseline = BASELINE_HEAD
    branch = git_text(["git", "branch", "--show-current"])
    identity = {
        "identity": "UNCOMMITTED_CANDIDATE" if status else "COMMITTED_CANDIDATE",
        "baseline_head": baseline,
        "head": head,
        "branch": branch,
        "dirty": bool(status),
        "status": status.splitlines(),
        "source_fingerprint": source_hash,
        "working_tree_diff_sha256": working_tree_diff_hash(),
        "untracked_source_manifest_sha256": untracked_hash,
        "effective_source_file_count": len(manifest["files"]),
    }
    if identity["dirty"]:
        identity["baseline_head"] = BASELINE_HEAD
    return identity


def tool_snapshot() -> dict[str, str | None]:
    values: dict[str, str | None] = {"python": sys.version.split()[0]}
    for name, command in (
        ("docker", ["docker", "version", "--format", "{{.Server.Version}}"]),
        ("docker_compose", ["docker", "compose", "version"]),
    ):
        result = run(command, timeout=60)
        values[name] = result.stdout.strip() if result.returncode == 0 else None
    return values


def require_frozen_candidate(initial: dict[str, Any], final: dict[str, Any]) -> None:
    fields = ("head", "source_fingerprint", "working_tree_diff_sha256",
              "untracked_source_manifest_sha256")
    changed = [field for field in fields if not initial.get(field) or initial.get(field) != final.get(field)]
    if changed:
        raise ValidationError(f"candidate source changed during validation: {changed}; rerun frozen gate")


def persist_manifest(manifest: dict[str, Any]) -> None:
    json_write(Path(manifest["report_dir"]) / "gate-manifest.json", manifest)


def finalize_manifest(manifest: dict[str, Any]) -> None:
    acceptance_results = manifest.get("acceptance_test_results", [])
    result_by_test = {
        result.get("test"): result.get("status")
        for result in acceptance_results
        if isinstance(result, dict)
    }
    requirement_tests = {
        "integrity_and_supply_chain": ["test_integrity_pins.py", "test_cloudflare_cidrs.py"],
        "v021_regression_acceptance": [
            "test_electron_cash_version.py",
            "test_cve_2024_23342.py",
            "test_plugin_distribution.py",
            "test_flipstarter_plugin.py",
            "test_novnc_sharing.py",
            "test_novnc_websocket_heartbeat.py",
            "test_persistence.py",
            "test_cashfusion_defaults.py",
            "test_cashfusion_states.py",
            "test_headless.py",
            "test_rpc.py",
            "test_tor_proxy.py",
            "test_backup_restore.py",
            "test_backup_wrapper.py",
            "test_backup_acceptance.py",
        ],
        "canonical_gateway": ["test_product_version.py", "test_canonical_startup.py", "test_auth_browser.py"],
        "network_lifecycle": ["test_electron_cash_version.py", "test_network_lifecycle_e2e.py", "test_backup_restore.py"],
        "v04_native_linux_gui_synthetic": ["test_linux_gui.py"],
        "v04_ledger_capability": ["test_ledger.py"],
        "platform_launcher_regressions": ["test_platform_runner.py", "test_mac_gui.py"],
        "client_ip_normalization": ["test_client_ip.py", "test_published_client_ip.py"],
        "fail2ban_caddy_enforcement": [
            "test_fail2ban_filter.py",
            "test_fail2ban_dummy.py",
            "test_caddy_ban_semantics.py",
            "test_caddy_ban_failures.py",
            "test_adapter_failures.py",
            "test_proxy_client_ban.py",
            REMOTE_ACCEPTANCE_TEST,
        ],
        "public_cloudflare_acceptance": [PUBLIC_ACCEPTANCE_TEST],
    }
    requirements: dict[str, dict[str, Any]] = {}
    for name, tests in requirement_tests.items():
        statuses = [result_by_test.get(test, "NOT_RUN") for test in tests]
        status = (
            "PASS"
            if all(value == "PASS" for value in statuses)
            else "FAIL"
            if any(value not in {"PASS", "NOT_RUN"} for value in statuses) or "FAIL" in statuses
            else "NOT_RUN"
        )
        requirements[name] = {"status": status, "tests": tests, "test_statuses": statuses}
    manifest["requirements"] = requirements
    test_statuses = list(result_by_test.values())
    vulnerability_dispositions = manifest.get("_vulnerability_dispositions", [])
    manifest["totals"] = {
        "acceptance_tests": {
            "total": len(test_statuses),
            "passed": test_statuses.count("PASS"),
            "failed": test_statuses.count("FAIL"),
            "not_run": test_statuses.count("NOT_RUN"),
        },
        "requirements": {
            "total": len(requirements),
            "passed": sum(value["status"] == "PASS" for value in requirements.values()),
            "failed": sum(value["status"] == "FAIL" for value in requirements.values()),
            "not_run": sum(value["status"] == "NOT_RUN" for value in requirements.values()),
        },
        "vulnerabilities": {
            "total": len(vulnerability_dispositions),
            "passed": sum(value.get("gate_decision") == "PASS" for value in vulnerability_dispositions),
            "exceptions": sum(value.get("disposition") == "PASS_WITH_DOCUMENTED_EXCEPTION" for value in vulnerability_dispositions),
            "failed": sum(value.get("gate_decision") == "FAIL" for value in vulnerability_dispositions),
        },
        "cleanup": {
            "failures": len((manifest.get("cleanup") or {}).get("failures", [])),
            "status": (manifest.get("cleanup") or {}).get("overall", "NOT_RUN"),
        },
    }
    report_dir = Path(manifest["report_dir"])
    manifest["artifact_hashes"] = {
        str(path.relative_to(report_dir)): sha256_file(path)
        for path in sorted(report_dir.rglob("*"))
        if path.is_file() and path.name not in {"gate-manifest.json", "gate-manifest.sha256"}
    }
    persist_manifest(manifest)
    manifest_path = Path(manifest["report_dir"]) / "gate-manifest.json"
    digest = sha256_file(manifest_path)
    (Path(manifest["report_dir"]) / "gate-manifest.sha256").write_text(
        f"{digest}  gate-manifest.json\n", encoding="utf-8"
    )


def acceptance_skip_reason(test: str, host_system: str | None = None) -> str | None:
    system = host_system or platform.system()
    if test == "test_linux_gui.py" and system != "Linux":
        return "requires a Linux host with Xvfb/X11 tools; kept in the Linux integration profile"
    return None


def record_acceptance_skip(manifest: dict[str, Any] | None, test: str, reason: str) -> None:
    mandatory = test in MANDATORY_ACCEPTANCE_TESTS
    if manifest is not None:
        manifest.setdefault("acceptance_test_results", []).append(
            {"test": test, "status": "FAIL" if mandatory else "NOT_RUN", "reason": reason}
        )
        persist_manifest(manifest)
    print(f"[ci] NOT RUN {test}: {reason}")
    if mandatory:
        raise ValidationError(f"mandatory acceptance is NOT_RUN: {test}: {reason}")


def gate_overall_status(manifest: dict[str, Any], exit_code: int) -> str:
    if exit_code == 0:
        required_steps = {"fast", "official-advisory-source-preflight", "local-sast",
            "source-scans-and-vulnerability-policy", "component-inventory-and-official-advisory-assessment",
            "acceptance", "dependency-review", "final-resource-postcondition"}
        steps = manifest.get("steps", [])
        complete = all([s.get("status") for s in steps if s.get("name") == name] == ["PASS"]
                       for name in required_steps)
        try:
            validate_mandatory_acceptance_results(manifest.get("acceptance_test_results", []))
        except ValidationError:
            complete = False
        return "PASS" if (complete and manifest.get("release_security", {}).get("status") == "PASS"
            and manifest.get("cleanup", {}).get("overall") == "PASS") else "FAIL"
    if (manifest.get("failure_kind") == "INFRA_FAILURE" or
            any(result.get("failure_kind") == "INFRA_FAILURE"
           for result in manifest.get("acceptance_test_results", [])
           if isinstance(result, dict))):
        return "BLOCKED"
    return "FAIL"


def gate_failure_kind(error: BaseException | str) -> str | None:
    message = str(error).lower()
    if ("unable to download trivy" in message and
            re.search(r"http error (?:429|5\d\d)", message)):
        return "INFRA_FAILURE"
    return None


def record_step(
    manifest: dict[str, Any],
    name: str,
    function: Callable[[], Any],
) -> Any:
    step = {"name": name, "status": "RUNNING", "started_at": utc_now()}
    manifest.setdefault("steps", []).append(step)
    persist_manifest(manifest)
    try:
        result = function()
    except Exception as error:
        step.update(
            {
                "status": "FAIL",
                "finished_at": utc_now(),
                "error": sanitize(str(error)),
            }
        )
        persist_manifest(manifest)
        raise
    step.update({"status": "PASS", "finished_at": utc_now()})
    persist_manifest(manifest)
    return result


def sanitize(text: str) -> str:
    patterns = (
        (r"(?i)(JSONRPC_PASSWORD|TEST_WALLET_PASSWORD)([=: ]+)\S+", r"\1\2[REDACTED]"),
        (r"(?i)(password)([=: ]+)\S+", r"\1\2[REDACTED]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text[-16000:]


def parse_iso_date(value: Any, field: str) -> dt.date:
    if not isinstance(value, str):
        raise ValidationError(f"security exception field {field!r} must be an ISO date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise ValidationError(f"security exception field {field!r} is not an ISO date") from error


def load_vulnerability_exceptions(
    *, today: dt.date | None = None, path: Path | None = None
) -> list[dict[str, Any]]:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    path = path or EXCEPTION_FILE
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValidationError(f"security exception authority is missing: {path}") from error
    except json.JSONDecodeError as error:
        raise ValidationError(f"security exception authority is invalid JSON: {error}") from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValidationError("security exception authority has an unsupported schema")
    exceptions = document.get("exceptions")
    if not isinstance(exceptions, list):
        raise ValidationError("security exception authority must contain an exceptions list")

    required = {
        "vulnerability_id",
        "package_name",
        "installed_version",
        "severity",
        "expected_fixed_version",
        "scopes",
        "reviewed_on",
        "review_by",
        "status",
        "rationale",
        "mitigation_reference",
        "owner",
        "advisory_url",
    }
    seen: set[tuple[Any, ...]] = set()
    validated: list[dict[str, Any]] = []
    for exception in exceptions:
        if not isinstance(exception, dict) or not required.issubset(exception):
            raise ValidationError("security exception is missing required fields")
        if not all(isinstance(exception[field], str) and exception[field] for field in (
            "vulnerability_id",
            "package_name",
            "installed_version",
            "severity",
            "status",
            "rationale",
            "mitigation_reference",
            "owner",
            "advisory_url",
        )):
            raise ValidationError("security exception contains an empty or invalid text field")
        if exception["severity"].upper() not in HIGH_SEVERITIES:
            if (exception["severity"] != "UNKNOWN" or exception.get("applicability") != "not-linked" or
                    exception.get("vulnerability_id") != "GO-2026-5932" or
                    exception.get("package_name") != "golang.org/x/crypto" or
                    exception.get("scopes") != ["image:caddy"] or
                    exception.get("proof_report") != "caddy-package-deps.txt" or
                    exception.get("absent_go_package_prefix") != "golang.org/x/crypto/openpgp"):
                raise ValidationError("UNKNOWN exception requires exact scoped, machine-enforced absence proof")
        if exception["status"] != "active":
            raise ValidationError("inactive security exceptions are not permitted in the authority")
        scopes = exception["scopes"]
        if not isinstance(scopes, list) or not scopes or not all(isinstance(scope, str) and scope for scope in scopes):
            raise ValidationError("security exception scopes must be a non-empty string list")
        reviewed_on = parse_iso_date(exception["reviewed_on"], "reviewed_on")
        review_by = parse_iso_date(exception["review_by"], "review_by")
        if reviewed_on > today or review_by < reviewed_on or review_by < today:
            raise ValidationError("security exception is future-dated or past its review-by date")
        if exception["expected_fixed_version"] is not None:
            raise ValidationError("this release only supports explicit no-fix exceptions")
        identity = (
            exception["vulnerability_id"],
            exception["package_name"],
            exception["installed_version"],
            exception["severity"].upper(),
            tuple(sorted(scopes)),
        )
        if identity in seen:
            raise ValidationError("duplicate security exception identity")
        seen.add(identity)
        normalized = dict(exception)
        normalized["severity"] = exception["severity"].upper()
        normalized["scopes"] = sorted(scopes)
        validated.append(normalized)
    return validated


def vulnerability_exception_match(
    finding: dict[str, Any], scope: str, exceptions: list[dict[str, Any]]
) -> dict[str, Any] | None:
    vulnerability_id = finding.get("VulnerabilityID")
    package_name = finding.get("PkgName")
    installed_version = finding.get("InstalledVersion")
    severity = str(finding.get("Severity", "")).upper()
    fixed_version = str(finding.get("FixedVersion") or "").strip()
    if fixed_version:
        return None
    for exception in exceptions:
        if (
            exception["vulnerability_id"] == vulnerability_id
            and exception["package_name"] == package_name
            and exception["installed_version"] == installed_version
            and exception["severity"] == severity
            and scope in exception["scopes"]
            and exception["expected_fixed_version"] is None
        ):
            return exception
    return None


def vulnerability_exception_identity(exception: dict[str, Any]) -> str:
    return "|".join(
        (
            exception["vulnerability_id"],
            exception["package_name"],
            exception["installed_version"],
            exception["severity"],
            ",".join(exception["scopes"]),
        )
    )


def extract_vulnerabilities(document: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in document.get("Results", []):
        findings.extend(result.get("Vulnerabilities") or [])
    return findings


def extract_secrets(document: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in document.get("Results", []):
        findings.extend(result.get("Secrets") or [])
    return findings


def sanitized_secret_document(document: dict[str, Any]) -> dict[str, Any]:
    sensitive_keys = {"Match", "Secret", "SecretMatch", "Raw", "Data"}

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if key in sensitive_keys else redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return redact(document)


def enforce_vulnerability_policy(
    findings_by_scope: list[tuple[str, list[dict[str, Any]]]],
    exceptions: list[dict[str, Any]],
    report_dir: Path,
    manifest: dict[str, Any],
) -> None:
    dispositions: list[dict[str, Any]] = []
    failures: list[str] = []
    for scope, findings in findings_by_scope:
        for finding in findings:
            severity = str(finding.get("Severity", "")).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                exception = vulnerability_exception_match(finding, scope, exceptions)
                proof = report_dir / "caddy-package-deps.txt"
                packages = proof.read_text().splitlines() if proof.is_file() else []
                required = {"github.com/caddyserver/caddy/v2/cmd/caddy", "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"}
                if (severity == "UNKNOWN" and not finding.get("FixedVersion") and exception and
                        exception.get("applicability") == "not-linked" and required <= set(packages) and
                        not any(p == exception["absent_go_package_prefix"] or
                            p.startswith(exception["absent_go_package_prefix"] + "/") for p in packages)):
                    disposition = "PASS_WITH_DOCUMENTED_NOT_APPLICABLE_PROOF"
                    used = manifest.setdefault("_used_exception_authority", [])
                    identity = vulnerability_exception_identity(exception)
                    if identity not in used:
                        used.append(identity)
                else:
                    disposition = "FAIL_UNCLASSIFIED_FINDING"
                    exception = None
                    failures.append(f"{scope}:{finding.get('VulnerabilityID')} has unsupported/unknown severity")
            elif severity not in HIGH_SEVERITIES:
                disposition = "LOWER_SEVERITY_NOT_IN_RELEASE_POLICY"
                exception = None
            else:
                fixed_version = str(finding.get("FixedVersion") or "").strip()
                exception = vulnerability_exception_match(finding, scope, exceptions)
                if fixed_version:
                    disposition = "FAIL_FIXABLE_HIGH_OR_CRITICAL"
                    failures.append(
                        f"{scope}:{finding.get('VulnerabilityID')}:{finding.get('PkgName')} has fix {fixed_version}"
                    )
                elif exception:
                    disposition = "PASS_WITH_DOCUMENTED_EXCEPTION"
                    used = manifest.setdefault("_used_exception_authority", [])
                    identity = vulnerability_exception_identity(exception)
                    if identity not in used:
                        used.append(identity)
                else:
                    disposition = "FAIL_UNREVIEWED_NO_FIX_HIGH_OR_CRITICAL"
                    failures.append(
                        f"{scope}:{finding.get('VulnerabilityID')}:{finding.get('PkgName')} has no active exact exception"
                    )
            dispositions.append(
                {
                    "scope": scope,
                    "vulnerability_id": finding.get("VulnerabilityID"),
                    "package_name": finding.get("PkgName"),
                    "installed_version": finding.get("InstalledVersion"),
                    "severity": severity,
                    "fixed_version": finding.get("FixedVersion") or None,
                    "disposition": disposition,
                    "exception_match": exception["vulnerability_id"] if exception else None,
                    "gate_decision": "FAIL" if disposition.startswith("FAIL_") else "PASS",
                }
            )
    all_dispositions = manifest.setdefault("_vulnerability_dispositions", [])
    all_dispositions.extend(dispositions)
    all_failures = manifest.setdefault("_vulnerability_failures", [])
    all_failures.extend(failures)
    policy = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "exception_authority": str(EXCEPTION_FILE),
        "findings": all_dispositions,
        "overall": "FAIL" if all_failures else "PASS",
        "failures": all_failures,
    }
    policy_path = report_dir / "vulnerability-dispositions.json"
    json_write(policy_path, policy)
    manifest["vulnerability_dispositions"] = str(policy_path)
    manifest["vulnerability_finding_count"] = len(all_dispositions)
    manifest["vulnerability_policy"] = policy["overall"]
    persist_manifest(manifest)
    if failures:
        raise ValidationError("vulnerability policy failed: " + "; ".join(failures))


def validate_exception_usage(
    exceptions: list[dict[str, Any]], manifest: dict[str, Any], report_dir: Path
) -> None:
    used = set(manifest.get("_used_exception_authority", []))
    unused = [
        vulnerability_exception_identity(exception)
        for exception in exceptions
        if vulnerability_exception_identity(exception) not in used
    ]
    if not unused:
        return
    policy_path = report_dir / "vulnerability-dispositions.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8")) if policy_path.is_file() else {}
    failures = list(policy.get("failures") or [])
    failures.extend(f"unused security exception authority: {identity}" for identity in unused)
    policy["overall"] = "FAIL"
    policy["failures"] = failures
    policy["unused_exceptions"] = unused
    json_write(policy_path, policy)
    manifest["unused_security_exceptions"] = unused
    manifest["vulnerability_policy"] = "FAIL"
    persist_manifest(manifest)
    raise ValidationError("unused security exception authority: " + "; ".join(unused))


def run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=timeout,
    )


DISK_FLOOR_BYTES = 5 * 1024**3
DISK_CANCEL_TRIGGER_BYTES = 6 * 1024**3
DISK_CANCELLATION_HEADROOM_BYTES = DISK_CANCEL_TRIGGER_BYTES - DISK_FLOOR_BYTES
DISK_DEFAULT_PHASE_PEAK_BYTES = 1 * 1024**3
DISK_BUILDKIT_BOOTSTRAP_PEAK_BYTES = 2 * 1024**3
# Observed free-space drops in local-20260927T002405Z-257785a85600; these
# workset bounds round above measured high-water deltas instead of multiplying
# by every image/test phase in advance.
DISK_NORMAL_WALLET_PEAK_BYTES = 5 * 1024**3
DISK_HW_WALLET_INCREMENTAL_PEAK_BYTES = 2 * 1024**3
DISK_TOR_IMAGE_PEAK_BYTES = (1 * 1024**3) + (512 * 1024**2)
DISK_AUTH_SESSION_PEAK_BYTES = 512 * 1024**2
DISK_CADDY_IMAGE_PEAK_BYTES = 3 * 1024**3
DISK_FAIL2BAN_IMAGE_PEAK_BYTES = 512 * 1024**2
DISK_IMAGE_SCAN_PEAK_BYTES = 1 * 1024**3
DISK_RUNTIME_PEAK_BYTES = 2 * 1024**3
DISK_SAST_PEAK_BYTES = 1 * 1024**3


def disk_phase_admission(peak_bytes: int) -> int:
    """Require the operational floor, phase workset, and cancellation headroom."""
    return DISK_FLOOR_BYTES + peak_bytes + DISK_CANCELLATION_HEADROOM_BYTES


DISK_PHASE_PEAKS_BYTES = {
    "builder_bootstrap": DISK_BUILDKIT_BOOTSTRAP_PEAK_BYTES,
    "normal_wallet": DISK_NORMAL_WALLET_PEAK_BYTES,
    "hardware_wallet_incremental": DISK_HW_WALLET_INCREMENTAL_PEAK_BYTES,
    "tor": DISK_TOR_IMAGE_PEAK_BYTES,
    "auth_session": DISK_AUTH_SESSION_PEAK_BYTES,
    "caddy": DISK_CADDY_IMAGE_PEAK_BYTES,
    "fail2ban": DISK_FAIL2BAN_IMAGE_PEAK_BYTES,
    "image_scans": DISK_IMAGE_SCAN_PEAK_BYTES,
    "runtime_acceptance": DISK_RUNTIME_PEAK_BYTES,
    "sast": DISK_SAST_PEAK_BYTES,
}
DISK_DEFAULT_PHASE_ADMISSION_BYTES = disk_phase_admission(DISK_DEFAULT_PHASE_PEAK_BYTES)
DISK_PHASE_ADMISSIONS_BYTES = {
    name: max(DISK_DEFAULT_PHASE_ADMISSION_BYTES, disk_phase_admission(peak))
    for name, peak in DISK_PHASE_PEAKS_BYTES.items()
}
DISK_BUILDKIT_BOOTSTRAP_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["builder_bootstrap"]
DISK_NORMAL_WALLET_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["normal_wallet"]
DISK_HW_WALLET_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["hardware_wallet_incremental"]
DISK_TOR_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["tor"]
DISK_AUTH_SESSION_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["auth_session"]
DISK_CADDY_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["caddy"]
DISK_FAIL2BAN_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["fail2ban"]
DISK_IMAGE_SCAN_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["image_scans"]
DISK_RUNTIME_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["runtime_acceptance"]
DISK_SAST_ADMISSION_BYTES = DISK_PHASE_ADMISSIONS_BYTES["sast"]


def configure_disk_storage_paths(docker_root: str) -> list[str]:
    """Monitor the checkout filesystem and local Docker storage filesystem."""
    paths = [ROOT.resolve()]
    docker_path = Path(docker_root).expanduser()
    if docker_path.is_dir():
        paths.append(docker_path.resolve())
    elif sys.platform.startswith("linux"):
        raise ValidationError(f"local Docker storage path is not accessible for disk admission: {docker_path}")
    unique = list(dict.fromkeys(str(path) for path in paths))
    os.environ["CI_DISK_PATHS"] = os.pathsep.join(unique)
    return unique


def disk_storage_samples() -> list[dict[str, Any]]:
    configured = os.environ.get("CI_DISK_PATHS")
    paths = [Path(item) for item in configured.split(os.pathsep) if item] if configured else [ROOT]
    samples = []
    for path in paths:
        try:
            free_bytes = shutil.disk_usage(path).free
        except OSError as error:
            raise ValidationError(f"unable to measure free space for required storage path {path}: {error}") from error
        samples.append({"path": str(path), "free_bytes": free_bytes})
    if not samples:
        raise ValidationError("no storage paths are configured for disk admission")
    return samples


def disk_checkpoint(stage: str, manifest: dict[str, Any] | None = None, *, persist: bool = True) -> int:
    storage_samples = disk_storage_samples()
    free = min(item["free_bytes"] for item in storage_samples)
    if manifest is not None:
        observations = manifest.setdefault("disk_observations", [])
        observations.append({"at": utc_now(), "stage": stage, "free_bytes": free,
                            "storage_paths": storage_samples,
                            "floor_bytes": DISK_FLOOR_BYTES,
                            "cancel_trigger_bytes": DISK_CANCEL_TRIGGER_BYTES})
        manifest["minimum_observed_free_bytes"] = min(
            [free, *(item["free_bytes"] for item in observations)])
        if persist:
            persist_manifest(manifest)
    return free


def require_disk_floor(stage: str, manifest: dict[str, Any] | None = None) -> int:
    free = disk_checkpoint(stage, manifest)
    if free <= DISK_FLOOR_BYTES:
        raise ValidationError(
            f"disk safety floor reached before {stage}: {free} bytes free, "
            f"minimum is {DISK_FLOOR_BYTES} bytes"
        )
    return free


def require_build_capacity(
    stage: str,
    manifest: dict[str, Any] | None = None,
    *,
    initial: bool = False,
    minimum_free_bytes: int | None = None,
) -> int:
    free = require_disk_floor(f"before-build: {stage}", manifest)
    required = max(DISK_DEFAULT_PHASE_ADMISSION_BYTES, minimum_free_bytes or 0)
    if initial:
        required = max(required, DISK_BUILDKIT_BOOTSTRAP_ADMISSION_BYTES)
    if free < required:
        raise ValidationError(
            f"insufficient measured scratch capacity before {stage}: {free} bytes free; "
            f"requires {required} bytes; {DISK_FLOOR_BYTES} bytes is the hard floor"
        )
    return free


def checked(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
    log_path: Path | None = None,
    disk_floor_bytes: int | None = None,
    disk_cancel_bytes: int | None = None,
    manifest: dict[str, Any] | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"[ci] {shutil.which(command[0]) or command[0]} {' '.join(command[1:])}")
    docker_build = bool(command and command[0] == "docker" and (
        (len(command) > 1 and command[1] == "build") or
        (len(command) > 2 and command[1:3] == ["image", "build"]) or
        (len(command) > 1 and command[1] == "compose" and "build" in command[2:])
    ))
    execution_env = env if env is not None else os.environ
    if docker_build and execution_env.get("CI_DOCKER_OWNER_SHIM") != "1":
        raise ValidationError("Docker builds require the task-owned owner/disk-guard shim")
    # The owner shim supervises Docker build subprocesses itself so it can
    # record and stop the exact Docker CLI process before the host floor.
    if disk_floor_bytes is None or (docker_build and execution_env.get("CI_DOCKER_OWNER_SHIM") == "1"):
        result = run(command, env=env, timeout=timeout)
    else:
        if disk_floor_bytes < DISK_FLOOR_BYTES:
            raise ValidationError("requested disk floor may not be lower than the hard acceptance floor")
        cancel_at = disk_cancel_bytes if disk_cancel_bytes is not None else (
            DISK_CANCEL_TRIGGER_BYTES if disk_floor_bytes == DISK_FLOOR_BYTES else disk_floor_bytes)
        if cancel_at < disk_floor_bytes:
            raise ValidationError("disk cancellation trigger may not be lower than the hard floor")
        free = require_disk_floor(f"start: {Path(command[0]).name} {command[1] if len(command) > 1 else ''}", manifest)
        if free <= cancel_at:
            raise ValidationError(
                f"insufficient cancellation headroom before phase: {free} bytes free; "
                f"cancellation trigger is {cancel_at} bytes"
            )
        process = subprocess.Popen(
            command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        )
        output = ""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    output, _ = process.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    output, _ = process.communicate()
                raise subprocess.TimeoutExpired(command, timeout, output=output)
            try:
                output, _ = process.communicate(timeout=min(0.5, remaining))
                break
            except subprocess.TimeoutExpired:
                current_free = disk_checkpoint(
                    f"during: {Path(command[0]).name} {command[1] if len(command) > 1 else ''}",
                    manifest, persist=False)
                if current_free <= cancel_at:
                    disk_checkpoint("disk-cancel-trigger-abort", manifest)
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        output, _ = process.communicate(timeout=20)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        output, _ = process.communicate()
                    raise ValidationError(
                        f"cancelled phase at the early disk trigger: {current_free} bytes free, "
                        f"trigger {cancel_at} bytes, hard floor {disk_floor_bytes} bytes"
                    )
        result = subprocess.CompletedProcess(command, process.returncode, output or "", "")
        require_disk_floor(f"complete: {Path(command[0]).name} {command[1] if len(command) > 1 else ''}", manifest)
        end_free = disk_checkpoint(
            f"after:{Path(command[0]).name} {command[1] if len(command) > 1 else ''}", manifest, persist=False)
        if end_free <= cancel_at:
            raise ValidationError(
                f"phase completed at/below the early disk trigger: {end_free} bytes free, "
                f"trigger {cancel_at} bytes"
            )
    if log_path is not None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {shlex.join(command)}\n")
            handle.write(sanitize(result.stdout + result.stderr) + "\n")
    if result.returncode != 0:
        raise ValidationError(
            f"command failed ({result.returncode}):\n{sanitize(result.stdout + result.stderr)}"
        )
    return result


def write_docker_owner_shim(directory: Path) -> Path:
    if not shutil.which("docker"):
        raise ValidationError("Docker CLI is unavailable for the acceptance resource-owner shim")
    shim = directory / "docker"
    content = ("#!/usr/bin/env python3\n"
               f"import sys; sys.path.insert(0, {json.dumps(str(ROOT / 'scripts'))})\n"
               "from docker_ownership import docker_shim_main\n"
               "raise SystemExit(docker_shim_main())\n")
    shim.write_text(content, encoding="utf-8")
    shim.chmod(0o700)
    return shim


def _reported_size_bytes(value: str) -> int:
    match = re.fullmatch(r"\s*([0-9.]+)\s*([A-Za-z]+)\s*", str(value))
    if not match:
        return 0
    units = {"B": 1, "kB": 1000, "KB": 1000, "MB": 1000**2,
             "GB": 1000**3, "TB": 1000**4}
    return int(float(match.group(1)) * units.get(match.group(2), 1))


def _root_filesystem_capacity(df_output: str) -> dict[str, Any]:
    lines = df_output.splitlines()
    if len(lines) < 2:
        raise ValidationError("root filesystem capacity output is incomplete")
    fields = lines[1].split()
    if len(fields) < 5:
        raise ValidationError("root filesystem capacity fields are invalid")
    try:
        total, used, free = (int(fields[index]) * 1024 for index in (1, 2, 3))
    except ValueError as error:
        raise ValidationError("root filesystem capacity is not numeric") from error
    return {"device": fields[0], "total_bytes": total, "used_bytes": used,
            "free_bytes": free, "capacity_percent": fields[4]}


def _buildx_protection_metadata(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    driver = next((line.split(":", 1)[1].strip() for line in lines
                   if line.strip().startswith("Driver:")), "")
    last_activity = [line.strip().partition(":")[2].strip() for line in lines
                     if line.strip().startswith("Last Activity:")]
    statuses = [line.strip().partition(":")[2].strip() for line in lines
                if line.strip().startswith("Status:")]
    configuration_lines = [line.rstrip() for line in lines
                           if line.strip() and not line.strip().startswith(("Last Activity:", "Status:"))]
    nodes: list[dict[str, str]] = []
    in_nodes = False
    for line in lines:
        stripped = line.strip()
        if stripped == "Nodes:":
            in_nodes = True
            continue
        if not in_nodes:
            continue
        if stripped.startswith("Name:"):
            nodes.append({"name": stripped.partition(":")[2].strip()})
        elif nodes and stripped.startswith("Endpoint:"):
            nodes[-1]["endpoint"] = stripped.partition(":")[2].strip()
    return {"driver": driver, "nodes": nodes,
            "configuration": "\n".join(configuration_lines),
            "inspect_telemetry": {"last_activity": last_activity, "statuses": statuses}}


def capture_buildx_protection_state() -> list[dict[str, Any]]:
    """Snapshot every Buildx builder without assuming it uses the active context."""
    listing = run(["docker", "buildx", "ls", "--format", "{{json .}}"])
    if listing.returncode:
        raise ValidationError("unable to enumerate Buildx builders for protection baseline")
    contexts_result = run(["docker", "context", "ls", "--format", "{{json .}}"])
    if contexts_result.returncode:
        raise ValidationError("unable to enumerate Docker contexts for Buildx protection baseline")
    context_names: set[str] = set()
    contexts_by_endpoint: dict[str, str] = {}
    try:
        for line in contexts_result.stdout.splitlines():
            if not line.strip():
                continue
            context = json.loads(line)
            name = str(context.get("Name", ""))
            endpoint = str(context.get("DockerEndpoint", ""))
            if name:
                context_names.add(name)
                if endpoint:
                    contexts_by_endpoint[endpoint] = name
        builders: dict[str, dict[str, Any]] = {}
        for line in listing.stdout.splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            name = str(item.get("Name", ""))
            if not name:
                raise ValueError("Buildx listing row has no builder name")
            record = builders.setdefault(name, {
                "driver": str(item.get("Driver", "")),
                "dynamic": bool(item.get("Dynamic", False)),
                "nodes_by_name": {},
                "unavailable": False,
                "error_digest": None,
            })
            if item.get("Err"):
                record["unavailable"] = True
                record["error_digest"] = sha256_bytes(str(item["Err"]).encode("utf-8"))
            for node in item.get("Nodes", []) or []:
                node_name = str(node.get("Name", ""))
                endpoint = str(node.get("Endpoint", ""))
                if node_name or endpoint:
                    record["nodes_by_name"][node_name or endpoint] = {
                        "name": node_name, "endpoint": endpoint}
        result: list[dict[str, Any]] = []
        for name, record in sorted(builders.items()):
            nodes = sorted(record["nodes_by_name"].values(), key=lambda node: (node["name"], node["endpoint"]))
            if record["unavailable"]:
                # Retain the inaccessible foreign builder's stable listed identity and
                # availability state. Never contact, bootstrap, or remove its backend.
                configuration = json.dumps({"unavailable": True, "dynamic": record["dynamic"]},
                                            sort_keys=True, separators=(",", ":"))
                result.append({"name": name, "driver": record["driver"], "nodes": nodes,
                               "configuration": configuration, "cache_items": None,
                               "cache_total_bytes": None, "cache_status": "UNAVAILABLE",
                               "inspect": "unavailable",
                               "inspect_telemetry": {"status": "unavailable",
                                                     "error_digest": record["error_digest"]}})
                continue
            endpoints = sorted({node["endpoint"] for node in nodes if node["endpoint"]})
            if not endpoints:
                raise ValidationError(f"Buildx builder {name} has no inspectable Docker context endpoint")
            endpoint = endpoints[0]
            context = endpoint if endpoint in context_names else contexts_by_endpoint.get(endpoint)
            if not context:
                raise ValidationError(f"unable to map Buildx builder {name} endpoint to a Docker context")
            prefix = ["docker", f"--context={context}", "buildx"]
            builder_info = run([*prefix, "inspect", name], timeout=120)
            if builder_info.returncode:
                raise ValidationError(f"unable to snapshot Buildx nodes for builder {name}")
            inspected = run([*prefix, "du", "--builder", name, "--format", "json"], timeout=240)
            if inspected.returncode:
                raise ValidationError(f"unable to snapshot Buildx cache for builder {name}")
            cache_items = []
            for cache_line in inspected.stdout.splitlines():
                if not cache_line.strip():
                    continue
                item = json.loads(cache_line)
                cache_items.append({key: item.get(key) for key in
                                    ("ID", "Parent", "Type", "CreatedAt", "LastUsedAt", "Size", "Shared",
                                     "Mutable", "Reclaimable", "UsageCount")})
            metadata = _buildx_protection_metadata(builder_info.stdout)
            result.append({"name": name, **metadata,
                           "cache_items": sorted(cache_items, key=lambda item: str(item.get("ID"))),
                           "cache_total_bytes": sum(_reported_size_bytes(str(item.get("Size", "0B")))
                                                     for item in cache_items),
                           "cache_status": "AVAILABLE",
                           "inspect": builder_info.stdout})
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValidationError(f"Buildx or Docker context inventory is invalid: {error}") from error
    return result


def capture_docker_protection_state() -> dict[str, Any]:
    image_lines = run(["docker", "image", "ls", "--all", "--digests", "--no-trunc", "--format", "{{json .}}"])
    if image_lines.returncode:
        raise ValidationError("unable to snapshot Docker images before acceptance")
    image_rows = [json.loads(line) for line in image_lines.stdout.splitlines() if line.strip()]
    image_ids = sorted({item.get("ID") for item in image_rows if item.get("ID")})
    if image_ids:
        inspected_images = run(["docker", "image", "inspect", *image_ids], timeout=180)
        if inspected_images.returncode:
            raise ValidationError("Docker image inventory changed while taking the protection snapshot")
        image_details = {item.get("Id"): {
            "created": item.get("Created"),
            "parent": item.get("Parent"),
            "architecture": item.get("Architecture"),
            "os": item.get("Os"),
            "size": item.get("Size"),
            "labels": (item.get("Config") or {}).get("Labels") or {},
            "repo_tags": sorted(item.get("RepoTags") or []),
            "repo_digests": sorted(item.get("RepoDigests") or []),
            "rootfs_layers": (item.get("RootFS") or {}).get("Layers") or [],
        } for item in json.loads(inspected_images.stdout)}
    else:
        image_details = {}
    images = [{"repository": item.get("Repository"), "tag": item.get("Tag"),
               "ID": item.get("ID"), "Digest": item.get("Digest"),
               "created_at": item.get("CreatedAt"), "size": item.get("Size"),
               "metadata": image_details.get(item.get("ID"))}
              for item in image_rows]

    container_ids = run(["docker", "ps", "-aq"])
    if container_ids.returncode:
        raise ValidationError("unable to enumerate containers for protection baseline")
    if container_ids.stdout.strip():
        container_inspection = run(["docker", "inspect", *container_ids.stdout.split()], timeout=180)
        if container_inspection.returncode:
            raise ValidationError("Docker container inventory changed while taking the protection snapshot")
        raw_containers = json.loads(container_inspection.stdout)
    else:
        raw_containers = []
    containers = []
    for item in raw_containers:
        state = item.get("State", {})
        health = state.get("Health") or {}
        config = item.get("Config", {})
        host = item.get("HostConfig", {})
        network_settings = item.get("NetworkSettings", {})
        config_identity = {key: config.get(key) for key in
                           ("Image", "Hostname", "Domainname", "User", "WorkingDir", "ExposedPorts",
                            "Tty", "OpenStdin", "StdinOnce", "StopSignal", "Labels")}
        config_identity["environment_sha256"] = sha256_bytes(
            json.dumps(config.get("Env") or [], sort_keys=True, separators=(",", ":")).encode())
        config_identity["launch_sha256"] = sha256_bytes(json.dumps(
            {key: config.get(key) for key in ("Entrypoint", "Cmd", "Healthcheck")},
            sort_keys=True, separators=(",", ":")).encode())
        containers.append({"id": item.get("Id"), "name": item.get("Name", "").lstrip("/"),
                           "configured_image": config.get("Image"), "image_id": item.get("Image"),
                           "created": item.get("Created"), "status": state.get("Status"),
                           "running": state.get("Running"), "health": health.get("Status"),
                           "health_details": {"failing_streak": health.get("FailingStreak"),
                                              "log": [{key: entry.get(key) for key in ("Start", "End", "ExitCode")}
                                                      for entry in health.get("Log", [])]},
                           "state_details": {key: state.get(key) for key in
                                             ("StartedAt", "FinishedAt", "ExitCode", "OOMKilled", "Dead")},
                           "restart_count": item.get("RestartCount"),
                           "config_identity": config_identity,
                           "labels": config.get("Labels") or {},
                           "mounts": sorted(
                               [{"type": mount.get("Type"), "name": mount.get("Name"),
                                 "source": mount.get("Source"), "destination": mount.get("Destination"),
                                 "mode": mount.get("Mode"), "rw": mount.get("RW"),
                                 "propagation": mount.get("Propagation")}
                                for mount in item.get("Mounts", [])],
                               key=lambda mount: (mount.get("destination") or "", mount.get("type") or "",
                                                  mount.get("name") or "", mount.get("source") or "")),
                           "networks": {name: {key: endpoint.get(key) for key in
                                                ("NetworkID", "EndpointID", "Gateway", "IPAddress",
                                                 "GlobalIPv6Address", "MacAddress", "Aliases", "DriverOpts")}
                                        for name, endpoint in sorted((network_settings.get("Networks") or {}).items())},
                           "ports": network_settings.get("Ports") or {},
                           "host_config": {key: host.get(key) for key in
                                           ("NetworkMode", "PortBindings", "Privileged", "ReadonlyRootfs",
                                            "RestartPolicy", "CapAdd", "CapDrop", "SecurityOpt", "Runtime",
                                            "CgroupnsMode", "Devices", "DeviceRequests", "GroupAdd", "AutoRemove",
                                            "Init", "Tmpfs", "IpcMode", "PidMode", "UsernsMode", "StorageOpt",
                                            "ReadonlyPaths", "MaskedPaths", "Dns", "DnsSearch", "DnsOptions",
                                            "ExtraHosts")}})

    volume_list = run(["docker", "volume", "ls", "-q"])
    if volume_list.returncode:
        raise ValidationError("unable to enumerate volumes for protection baseline")
    volume_names = volume_list.stdout.split()
    if volume_names:
        volume_inspection = run(["docker", "volume", "inspect", *volume_names], timeout=180)
        if volume_inspection.returncode:
            raise ValidationError("Docker volume inventory changed while taking the protection snapshot")
        raw_volumes = json.loads(volume_inspection.stdout)
    else:
        raw_volumes = []
    system_df_verbose = run(["docker", "system", "df", "-v"])
    if system_df_verbose.returncode:
        raise ValidationError("unable to capture Docker volume and cache disk usage")
    volume_sizes = {}
    volume_section = False
    for line in system_df_verbose.stdout.splitlines():
        if line.startswith("Local Volumes space usage:"):
            volume_section = True
            continue
        if volume_section and (line.startswith("Build cache usage:") or line.startswith("Images space usage:")):
            volume_section = False
        if volume_section:
            parts = line.split()
            if len(parts) == 3 and parts[1].isdigit():
                volume_sizes[parts[0]] = parts[2]
    volumes = [{"name": item.get("Name"), "driver": item.get("Driver"), "scope": item.get("Scope"),
                "created_at": item.get("CreatedAt"), "mountpoint": item.get("Mountpoint"),
                "options": item.get("Options") or {}, "labels": item.get("Labels") or {},
                "usage_data": item.get("UsageData") or {},
                "size": volume_sizes.get(item.get("Name"), "unknown")}
               for item in raw_volumes]

    network_list = run(["docker", "network", "ls", "-q"])
    if network_list.returncode:
        raise ValidationError("unable to enumerate networks for protection baseline")
    network_ids = network_list.stdout.split()
    if network_ids:
        network_inspection = run(["docker", "network", "inspect", *network_ids], timeout=180)
        if network_inspection.returncode:
            raise ValidationError("Docker network inventory changed while taking the protection snapshot")
        raw_networks = json.loads(network_inspection.stdout)
    else:
        raw_networks = []
    networks = [{"id": item.get("Id"), "name": item.get("Name"), "driver": item.get("Driver"),
                 "scope": item.get("Scope"), "internal": item.get("Internal"),
                 "attachable": item.get("Attachable"), "ingress": item.get("Ingress"),
                 "labels": item.get("Labels") or {}, "ipam": item.get("IPAM") or {},
                 "subnets": [config.get("Subnet") for config in ((item.get("IPAM") or {}).get("Config") or [])
                             if config.get("Subnet")],
                 "options": item.get("Options") or {}, "config_only": item.get("ConfigOnly"),
                 "config_from": item.get("ConfigFrom") or {}, "containers": item.get("Containers") or {}}
                for item in raw_networks]

    builders = capture_buildx_protection_state()

    daemon_info = run(["docker", "info", "--format",
                       "{{.ID}}|{{.DockerRootDir}}|{{.Driver}}|{{.ServerVersion}}|{{.OperatingSystem}}|{{.OSType}}|{{.Architecture}}"])
    if daemon_info.returncode:
        raise ValidationError("unable to identify Docker daemon for the protection snapshot")

    # POSIX-compatible 1 KiB blocks work on macOS and Linux; GNU df's -B1 is
    # not available on the physical Mac validation host.
    df_result = run(["df", "-Pk", "/"])
    if df_result.returncode or len(df_result.stdout.splitlines()) < 2:
        raise ValidationError("unable to capture root filesystem capacity")
    root_filesystem = _root_filesystem_capacity(df_result.stdout)
    system_df = run(["docker", "system", "df"])
    if system_df.returncode:
        raise ValidationError("unable to capture Docker disk usage summary")
    state = {"snapshot_schema": 2, "captured_at": utc_now(), "daemon": daemon_info.stdout.strip(),
             "root_filesystem": root_filesystem,
             "docker_system_df": system_df.stdout,
              "images": sorted(images, key=lambda item: (item.get("repository", ""), item.get("tag", ""), item.get("ID", ""))),
             "containers": sorted(containers, key=lambda item: item.get("id", "")),
             "volumes": sorted(volumes, key=lambda item: item.get("name", "")),
              "networks": sorted(networks, key=lambda item: item.get("id", "")),
              "builders": builders}
    state["telemetry_policy"] = docker_ownership.TELEMETRY_ONLY_FIELD_POLICY
    state["telemetry"] = {
        "filesystem_usage": {key: state["root_filesystem"].get(key)
                             for key in ("used_bytes", "free_bytes", "capacity_percent")},
        "docker_system_df": system_df.stdout,
        "volume_usage": {item["name"]: {"size": item.get("size"),
                                          "usage_data": item.get("usage_data")}
                         for item in volumes},
        "container_runtime": {item["id"]: {key: item.get(key) for key in
                                             ("status", "running", "health", "health_details",
                                              "state_details", "restart_count")}
                              for item in containers},
        "container_network_runtime": {
            item["id"]: {name: {key: endpoint.get(key) for key in
                                ("Gateway", "IPAddress", "GlobalIPv6Address", "MacAddress")}
                         for name, endpoint in (item.get("networks") or {}).items()}
            for item in containers},
        "builder_usage": {item["name"]: {"cache_items": item.get("cache_items"),
                                          "cache_total_bytes": item.get("cache_total_bytes"),
                                          **(item.get("inspect_telemetry") or {})}
                          for item in builders},
    }
    state["strict_protection_fingerprint"] = docker_ownership.strict_protection_fingerprint(state)
    return state


def write_private_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def write_immutable_private_json(path: Path, document: dict[str, Any]) -> str:
    """Create a private snapshot exactly once; existing evidence is never replaced."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValidationError("immutable Docker snapshot is not a private regular file owned by this user")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(descriptor)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(descriptor)
    return sha256_bytes(payload)


def read_immutable_private_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or
                stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValidationError(f"immutable Docker snapshot is not private operator-owned evidence: {path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read()
    finally:
        os.close(descriptor)


def verify_gate_protection_state(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    task_builder: dict[str, Any],
    baseline_path: Path | None = None,
    baseline_sha256: str | None = None,
    immutable_snapshots: list[tuple[Path, str]] | None = None,
) -> list[str]:
    failures = docker_ownership.compare_preexisting_state(before, after, task_builder=task_builder)
    protected_files = list(immutable_snapshots or [])
    if baseline_path is not None and baseline_sha256 is not None:
        protected_files.append((baseline_path, baseline_sha256))
    for path, expected_sha256 in protected_files:
        try:
            if sha256_bytes(read_immutable_private_bytes(path)) != expected_sha256:
                failures.append(f"immutable Docker protection snapshot integrity changed: {path.name}")
        except (OSError, ValidationError) as error:
            failures.append(f"immutable Docker protection snapshot is unavailable ({path.name}): {error}")
    return [f"FOREIGN_STATE_DRIFT: {failure}" for failure in failures]


def read_immutable_docker_snapshot(path: Path, expected_sha256: str) -> dict[str, Any]:
    try:
        payload = read_immutable_private_bytes(path)
    except (OSError, ValidationError) as error:
        raise ValidationError(f"unable to read immutable Docker protection snapshot: {error}") from error
    if sha256_bytes(payload) != expected_sha256:
        raise ValidationError(f"immutable Docker protection snapshot integrity changed: {path.name}")
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValidationError(f"immutable Docker protection snapshot is invalid JSON: {error}") from error
    required = ("images", "containers", "volumes", "networks", "builders", "root_filesystem", "daemon")
    if (not isinstance(document, dict) or any(key not in document for key in required) or
            any(not isinstance(document.get(key), list)
                for key in ("images", "containers", "volumes", "networks", "builders")) or
            not isinstance(document.get("root_filesystem"), dict) or
            not isinstance(document["root_filesystem"].get("free_bytes"), int) or
            not isinstance(document.get("daemon"), str)):
        raise ValidationError(f"immutable Docker protection snapshot has an invalid structure: {path.name}")
    return document


def refresh_task_builder_record(record_path: Path, name: str) -> dict[str, Any]:
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"task-owned builder ownership record is unreadable: {error}") from error
    container_name = f"buildx_buildkit_{name}0"
    inspected = run(["docker", "inspect", container_name], timeout=60)
    builder_running = False
    if inspected.returncode == 0:
        container = json.loads(inspected.stdout)[0]
        builder_running = bool(container.get("State", {}).get("Running"))
        resources = {"container_id": container.get("Id"), "container_name": container_name,
                     "configured_image": container.get("Config", {}).get("Image"),
                     "image_id": container.get("Image"),
                     "container_status": container.get("State", {}).get("Status"),
                     "volumes": sorted(mount.get("Name") for mount in container.get("Mounts", [])
                                          if mount.get("Type") == "volume" and mount.get("Name"))}
        if resources["configured_image"] != TASK_BUILDKIT_IMAGE:
            raise ValidationError("task-owned BuildKit container uses an image outside the task's pinned reference")
        pinned_image = run(["docker", "image", "inspect", "--format", "{{.Id}}", TASK_BUILDKIT_IMAGE])
        if pinned_image.returncode or resources["image_id"] != pinned_image.stdout.strip():
            raise ValidationError("task-owned BuildKit container does not match the task's pinned image reference")
        previous = record.get("resources", {})
        if previous.get("container_id") and previous["container_id"] != resources["container_id"]:
            raise ValidationError("task-owned BuildKit container identity changed; refusing to reassign ownership")
        if previous.get("volumes") and previous["volumes"] != resources["volumes"]:
            raise ValidationError("task-owned BuildKit volume identity changed; refusing to reassign ownership")
        record["resources"] = resources
    elif "no such object" in inspected.stderr.lower():
        record.setdefault("resources", {})
    else:
        raise ValidationError(f"unable to inspect task-owned BuildKit container: {inspected.stderr}")
    if builder_running:
        du = run(["docker", "buildx", "du", "--builder", name, "--format", "json"], timeout=240)
        if du.returncode:
            raise ValidationError(f"unable to inspect task-owned BuildKit cache: {du.stderr}")
        items = [json.loads(line) for line in du.stdout.splitlines() if line.strip()]
    else:
        items = []
    record["cache"] = {"entry_count": len(items),
                       "reported_total_bytes": sum(_reported_size_bytes(str(item.get("Size", "0B")))
                                                    for item in items),
                       "items": [{key: item.get(key) for key in
                                  ("ID", "Type", "Size", "Mutable", "Reclaimable", "UsageCount")}
                                 for item in sorted(items, key=lambda value: str(value.get("ID")))]}
    record["last_verified_at"] = utc_now()
    write_private_json(record_path, record)
    return record


def _task_builder_record_for_gate(record_path: Path, name: str) -> dict[str, Any]:
    if record_path.is_symlink() or not record_path.is_file():
        raise ValidationError("task-owned Buildx record is missing during cleanup")
    metadata = record_path.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValidationError("task-owned Buildx record permissions changed during cleanup")
    document = json.loads(record_path.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or document.get("schema_version") != 1 or
            document.get("owner") != "electron-cash-docker-v0.4-task" or
            document.get("repository_root") != str(ROOT) or document.get("builder") != name or
            document.get("driver_image") != TASK_BUILDKIT_IMAGE or
            document.get("state") != "ready"):
        raise ValidationError("task-owned Buildx record identity changed during cleanup")
    return document


def task_builder_record_path() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")).expanduser()
    return state_home / "electron-cash-docker" / "owned-builders" / "ecd-v04-task-acceptance.json"


def ensure_task_buildx_builder(*, report_dir: Path, manifest: dict[str, Any] | None,
                               log_path: Path | None) -> tuple[str, int, Path]:
    """Claim one stable task-owned Buildx builder without changing the default."""
    record_path = task_builder_record_path()
    directory = record_path.parent
    if directory.exists() or directory.is_symlink():
        if (directory.is_symlink() or not directory.is_dir() or
                directory.stat().st_uid != os.geteuid() or stat.S_IMODE(directory.stat().st_mode) & 0o077):
            raise ValidationError("task-owned Buildx state directory is not a private operator-owned directory")
    else:
        directory.mkdir(parents=True, mode=0o700)
    lock_path = directory / "ecd-v04-task-acceptance.lock"
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | nofollow, 0o600)
    lock_stat = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.geteuid() or
            stat.S_IMODE(lock_stat.st_mode) & 0o077):
        os.close(lock_fd)
        raise ValidationError("task-owned builder lock is not a private regular file")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        os.close(lock_fd)
        raise ValidationError("the task-owned acceptance Buildx builder is in use by another session") from error

    def save(record: dict[str, Any]) -> None:
        temporary = record_path.with_name(f".{record_path.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(record, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, record_path)

    try:
        existing: dict[str, Any] | None = None
        if record_path.exists():
            record_stat = record_path.lstat()
            if (stat.S_ISLNK(record_stat.st_mode) or not stat.S_ISREG(record_stat.st_mode) or
                    record_stat.st_uid != os.geteuid() or stat.S_IMODE(record_stat.st_mode) & 0o077):
                raise ValidationError("task-owned builder record permissions are unsafe")
            loaded = json.loads(record_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValidationError("task-owned Buildx record is not a JSON object")
            existing = loaded
            name = str(existing.get("builder", ""))
            if (existing.get("schema_version") != 1 or not name.startswith("ecd-v04-task-acceptance-") or
                    existing.get("owner") != "electron-cash-docker-v0.4-task" or
                    existing.get("repository_root") != str(ROOT) or
                    existing.get("driver_image") != TASK_BUILDKIT_IMAGE):
                raise ValidationError("task-owned Buildx record does not match this repository")
            requested = os.environ.get("CI_PRUNE_TASK_BUILDER")
            if requested and requested != name:
                raise ValidationError("requested Buildx builder does not match the durable task ownership record")
        else:
            if os.environ.get("CI_PRUNE_TASK_BUILDER"):
                raise ValidationError("caller-selected Buildx builder has no durable task ownership record")
            name = "ecd-v04-task-acceptance-" + uuid.uuid4().hex
        listed = checked(["docker", "buildx", "ls"], log_path=log_path).stdout.splitlines()
        present = any(line.split() and line.split()[0].rstrip("*") == name for line in listed)
        if not existing and present:
            raise ValidationError(f"Buildx builder name is already present without a task ownership record: {name}")
        if not existing:
            container_name = f"buildx_buildkit_{name}0"
            stale_container = run(["docker", "ps", "-aq", "--filter", f"name=^{container_name}$"], timeout=60)
            stale_volume = run(["docker", "volume", "inspect", f"{container_name}_state"], timeout=60)
            if stale_container.returncode or stale_volume.returncode == 0:
                raise ValidationError("an unclaimed Docker resource collides with the task Buildx name")
            if "no such volume" not in stale_volume.stderr.lower():
                raise ValidationError("unable to verify task Buildx state volume is absent")
            free = require_build_capacity("task-owned Buildx builder reservation", manifest)
            record = {"schema_version": 1, "owner": "electron-cash-docker-v0.4-task",
                      "repository_root": str(ROOT), "builder": name, "driver": "docker-container",
                      "driver_image": TASK_BUILDKIT_IMAGE,
                      "state": "creating", "created_at": utc_now(),
                      "disk_free_bytes_before_create": free}
            save(record)
        else:
            assert existing is not None
            record = existing
        if not present:
            require_build_capacity("task-owned BuildKit bootstrap", manifest, initial=True)
            buildkit_image = checked(["docker", "image", "inspect", TASK_BUILDKIT_IMAGE])
            inspected_buildkit = json.loads(buildkit_image.stdout)[0]
            if not inspected_buildkit.get("Id"):
                raise ValidationError("task BuildKit image reference did not resolve to an immutable local image ID")
            checked(["docker", "buildx", "create", "--name", name, "--driver", "docker-container",
                     "--driver-opt", f"image={TASK_BUILDKIT_IMAGE}", "--bootstrap"],
                    timeout=300, log_path=log_path, disk_floor_bytes=DISK_FLOOR_BYTES, manifest=manifest)
        inspect_result = checked(["docker", "buildx", "inspect", name], timeout=60, log_path=log_path)
        inspect = inspect_result.stdout
        if _buildx_protection_metadata(inspect)["driver"] != "docker-container":
            raise ValidationError(f"task-owned builder has an unexpected driver: {name}")
        if record.get("resources", {}).get("container_id"):
            current_container = run(["docker", "inspect", f"buildx_buildkit_{name}0"], timeout=60)
            if current_container.returncode:
                raise ValidationError("previously claimed task BuildKit container is missing; refusing to recreate it")
            current_item = json.loads(current_container.stdout)[0]
            current_id = current_item.get("Id")
            if current_id != record["resources"]["container_id"]:
                raise ValidationError("task-owned BuildKit container identity changed; refusing to reuse the name")
            if current_item.get("State", {}).get("Status") != "running":
                raise ValidationError("task-owned BuildKit container is not running; refusing to reuse it")
            current_volumes = sorted(mount.get("Name") for mount in current_item.get("Mounts", [])
                                     if mount.get("Type") == "volume" and mount.get("Name"))
            if current_volumes != record["resources"].get("volumes", []):
                raise ValidationError("task-owned BuildKit state-volume identity changed")
        record.update({"state": "ready", "last_verified_at": utc_now(),
                       "inspect_sha256": sha256_bytes(inspect.encode())})
        save(record)
        record = refresh_task_builder_record(record_path, name)
        if manifest is not None:
            manifest["task_owned_builder"] = {"name": name, "driver": "docker-container",
                                               "record": str(record_path), "created_or_reused": True}
            persist_manifest(manifest)
        return name, lock_fd, record_path
    except Exception:
        os.close(lock_fd)
        raise


def assert_safe_docker_endpoint(*, log_path: Path | None = None) -> None:
    for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        if os.environ.get(key):
            raise ValidationError(f"unsafe Docker environment variable is set: {key}")
    context = os.environ.get("DOCKER_CONTEXT", "default")
    if context != "default":
        raise ValidationError(f"unexpected Docker context: {context}")

    context_result = checked(
        ["docker", "context", "inspect", "default", "--format", "{{json .Endpoints.docker}}"],
        log_path=log_path,
    )
    try:
        endpoint = json.loads(context_result.stdout)
    except json.JSONDecodeError as error:
        raise ValidationError("Docker context endpoint was not valid JSON") from error
    host = endpoint.get("Host") if isinstance(endpoint, dict) else None
    if not isinstance(host, str) or not host.startswith("unix:///"):
        raise ValidationError(f"Docker endpoint is not local Unix-socket transport: {host}")
    if "production" in host.lower():
        raise ValidationError("Docker endpoint references production")
    checked(["docker", "version", "--format", "{{.Server.Version}}"], log_path=log_path)
    checked(["docker", "compose", "version"], log_path=log_path)

    existing = checked(
        ["docker", "ps", "-a", "--format", "{{.Labels}}"], timeout=60, log_path=log_path
    ).stdout.lower()
    if "com.docker.compose.project=electron-cash-docker" in existing:
        raise ValidationError("Docker daemon already contains the production Compose project")
    volumes = checked(
        ["docker", "volume", "ls", "--format", "{{.Name}}"],
        timeout=60,
        log_path=log_path,
    ).stdout.splitlines()
    if (
        {"bchforge-electron-cash-data", "bchforge-electron-cash-tor-data"}.intersection(volumes)
        and os.environ.get("CI_PRESERVE_EXISTING_WALLET_TOR_VOLUMES") != "1"
    ):
        raise ValidationError("Docker daemon already contains the production wallet/Tor volumes")


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def candidate_names() -> tuple[str, str, str, str]:
    suffix = f"{os.environ.get('CI_RUN_ID', 'local')}-{uuid.uuid4().hex}".lower()
    return (
        f"electron-cash-ci:{suffix}",
        f"bchforge/electron-cash-docker-tor-ci:{suffix}",
        f"electron-cash-auth-session-ci:{suffix}",
        f"bchforge-v021-{suffix}",
    )


IMAGE_CONSUMERS = {
    "electron-cash-normal": ["shared acceptance runtime suites", "test_canonical_startup.py",
                             "tests/test_linux_gui.py", "tests/test_mac_gui.py"],
    "electron-cash-hw": ["tests/test_ledger.py", "ledger-linux platform runner"],
    "tor-proxy": ["network/Tor acceptance suites", "canonical startup", "Linux GUI", "platform runners"],
    "auth-session": ["authentication/browser and remote-access acceptance suites"],
    "caddy": ["gateway, Caddy-ban, browser, and published-client acceptance suites"],
    "fail2ban": ["ban, remote-access, and published-client acceptance suites"],
}


def _dockerfile_copy_sources(dockerfile: Path) -> list[str]:
    """Extract local COPY/ADD inputs; external BuildKit stages are not context inputs."""
    logical_lines: list[str] = []
    pending = ""
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        part = line.rstrip()
        if pending:
            pending += " " + part.lstrip()
        else:
            pending = part
        if pending.endswith("\\"):
            pending = pending[:-1]
            continue
        logical_lines.append(pending)
        pending = ""
    if pending:
        logical_lines.append(pending)

    sources: set[str] = set()
    for line in logical_lines:
        match = re.match(r"\s*(COPY|ADD)\s+(.+)$", line, re.IGNORECASE)
        if not match:
            continue
        payload = match.group(2).strip()
        if payload.startswith("["):
            try:
                tokens = json.loads(payload)
            except json.JSONDecodeError as error:
                raise ValidationError(f"invalid JSON COPY/ADD in {dockerfile}: {error}") from error
            if not isinstance(tokens, list) or len(tokens) < 2:
                raise ValidationError(f"invalid COPY/ADD source list in {dockerfile}")
            copy_sources = tokens[:-1]
        else:
            tokens = shlex.split(payload)
            if any(token == "--from" or token.startswith("--from=") for token in tokens):
                continue
            while tokens and tokens[0].startswith("--"):
                option = tokens.pop(0)
                if "=" not in option and tokens:
                    tokens.pop(0)
            if len(tokens) < 2:
                raise ValidationError(f"COPY/ADD has no source in {dockerfile}")
            copy_sources = tokens[:-1]
        for source in copy_sources:
            if not isinstance(source, str) or source.startswith(("http://", "https://", "git@")):
                continue
            sources.add(source.lstrip("/"))
    return sorted(sources)


def _context_input_manifest(context: Path, dockerfile: Path) -> dict[str, Any]:
    context = context.resolve()
    dockerfile = dockerfile.resolve()
    if not dockerfile.is_file():
        raise ValidationError(f"Dockerfile is missing from the resolved build configuration: {dockerfile}")
    inputs: dict[str, dict[str, Any]] = {}

    def include(path: Path) -> None:
        if path.is_dir() and not path.is_symlink():
            for child in sorted(path.rglob("*")):
                if child.is_file() or child.is_symlink():
                    include(child)
            return
        if not path.is_file() and not path.is_symlink():
            raise ValidationError(f"Docker build input is missing: {path}")
        try:
            relative = path.relative_to(context).as_posix()
        except ValueError as error:
            raise ValidationError(f"Docker build input escapes its context: {path}") from error
        if path.is_symlink():
            payload = os.readlink(path).encode()
            kind = "symlink"
        else:
            payload = path.read_bytes()
            kind = "file"
        inputs[relative] = {"kind": kind, "sha256": sha256_bytes(payload), "size": len(payload)}

    include(dockerfile)
    ignore_candidates = [context / f"{dockerfile.name}.dockerignore", context / ".dockerignore"]
    ignore_file = next((path for path in ignore_candidates if path.is_file()), None)
    ignore_sha256 = None
    if ignore_file is not None:
        include(ignore_file)
        ignore_sha256 = sha256_file(ignore_file)
    for source in _dockerfile_copy_sources(dockerfile):
        matches = sorted(Path(path) for path in glob.glob(str(context / source), recursive=True))
        if not matches:
            raise ValidationError(f"Docker COPY/ADD input pattern matched no files: {source}")
        for match in matches:
            include(match)
    return {"inputs": inputs, "dockerignore": str(ignore_file) if ignore_file else None,
            "dockerignore_sha256": ignore_sha256}


def image_build_configuration(model: dict[str, Any], service_name: str, image_ref: str,
                              *, variant: str, compose_files: list[Path]) -> dict[str, Any]:
    services = model.get("services") or {}
    service = services.get(service_name)
    if not isinstance(service, dict):
        raise ValidationError(f"service {service_name} is missing from the resolved build model")
    build = service.get("build")
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict):
        raise ValidationError(f"service {service_name} has no resolved Docker build configuration")
    context = Path(build.get("context") or ROOT)
    if not context.is_absolute():
        context = ROOT / context
    dockerfile = Path(build.get("dockerfile") or "Dockerfile")
    if not dockerfile.is_absolute():
        dockerfile = context / dockerfile
    inputs = _context_input_manifest(context, dockerfile)
    args = build.get("args") or {}
    if isinstance(args, list):
        args = dict(item.split("=", 1) if "=" in item else (item, None) for item in args)
    descriptor = {
        "variant": variant,
        "service": service_name,
        "image_reference": image_ref,
        "context": str(context.resolve()),
        "dockerfile": str(dockerfile.resolve()),
        "compose_files": [str(path.resolve()) for path in compose_files],
        "platform": service.get("platform") or build.get("platform"),
        "build_args": dict(sorted(args.items())) if isinstance(args, dict) else args,
        "build_options": {key: value for key, value in sorted(build.items())
                          if key not in ("context", "dockerfile", "args")},
        **inputs,
    }
    fingerprint_payload = {key: value for key, value in descriptor.items()
                           if key not in ("variant", "image_reference", "compose_files")}
    descriptor["configuration_sha256"] = sha256_bytes(
        json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode())
    descriptor["consumers"] = IMAGE_CONSUMERS.get(variant, [])
    return descriptor


def validate_image_reuse(descriptor: dict, proof: dict) -> None:
    """Fail closed on copied-input/config/mode drift before a task-owned retag."""
    if (proof.get('status') != 'PASS' or proof.get('configuration_sha256') != descriptor['configuration_sha256'] or
            proof.get('inputs') != descriptor['inputs'] or not re.fullmatch(r'sha256:[0-9a-f]{64}', proof.get('image_id', ''))):
        raise ValidationError('verified candidate image inputs/configuration do not match')
    modes = {p: format(stat.S_IMODE((Path(descriptor['context']) / p).lstat().st_mode), '04o') for p in descriptor['inputs']}
    if proof.get('input_modes') != modes:
        raise ValidationError('verified candidate image input modes do not match')


def write_compose_override(
    directory: Path,
    ec_image: str,
    tor_image: str,
    caddy_image: str,
    fail2ban_image: str,
    auth_image: str,
    project: str,
) -> Path:
    override = directory / "ci-isolation.yml"
    override.write_text(
        "services:\n"
        "  electron-cash:\n"
        f"    image: {ec_image}\n"
        "    volumes:\n"
        "      - electron-cash-data:/home/electroncash/.electron-cash\n"
        "  tor-proxy:\n"
        f"    image: {tor_image}\n"
        "    volumes:\n"
        "      - tor-data:/var/lib/tor\n"
        "  caddy:\n"
        f"    image: {caddy_image}\n"
        "  auth-session:\n"
        f"    image: {auth_image}\n"
        "  fail2ban:\n"
        f"    image: {fail2ban_image}\n"
        "volumes:\n"
        "  electron-cash-data:\n"
        f"    name: {project}-wallet\n"
        "  tor-data:\n"
        f"    name: {project}-tor\n"
        "networks:\n"
        "  electron-network:\n"
        f"    name: {project}-network\n",
        encoding="utf-8",
    )
    return override


def write_hardware_build_override(directory: Path, image: str) -> Path:
    override = directory / "ci-ledger-image.yml"
    override.write_text(
        "services:\n  electron-cash:\n"
        f"    image: {image}\n",
        encoding="utf-8",
    )
    return override


def compose_command(project: str, override: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-p",
        project,
        "-f",
        "docker-compose.yml",
        "-f",
        str(override),
    ]


def resolved_model(command: list[str], env: dict[str, str], *, log_path: Path | None = None) -> dict:
    result = checked([*command, "config", "--format", "json"], env=env, log_path=log_path)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValidationError("resolved Compose model was not valid JSON") from error


def validate_model(
    model: dict,
    ec_image: str,
    tor_image: str,
    caddy_image: str,
    fail2ban_image: str,
    auth_image: str,
    project: str,
) -> None:
    try:
        validate_resolved_model(
            model,
            expected_ec_image=ec_image,
            expected_tor_image=tor_image,
            expected_caddy_image=caddy_image,
            expected_fail2ban_image=fail2ban_image,
            expected_auth_image=auth_image,
            expected_wallet_volume=f"{project}-wallet",
            expected_tor_volume=f"{project}-tor",
            expected_network=f"{project}-network",
            expected_project=project,
        )
    except UnsafeComposeModel as error:
        raise ValidationError(f"unsafe resolved Compose model: {error}") from error
    print(f"[ci] isolated Compose model validated for project {project}")


def fast(*, log_path: Path | None = None) -> None:
    # The full static suite includes subprocess-heavy Docker/XQuartz fixtures;
    # allow a bounded five minutes on slower physical desktop hosts.
    checked([sys.executable, str(ROOT / "tests" / "test_fast.py")], timeout=300, log_path=log_path)
    environment = os.environ.copy()
    environment["BASIC_AUTH_PASSWORD"] = "synthetic-auth-secret"
    checked(
        [
            "docker",
            "compose",
            "--env-file",
            str(ENV_FILE),
            "config",
            "--format",
            "json",
        ],
        env=environment,
        log_path=log_path,
    )
    print("PASS fast validation (source checks and Compose resolution only; no image/runtime acceptance)")


def ensure_trivy(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    configured = os.environ.get("TRIVY_BIN")
    if configured:
        path = Path(configured)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValidationError(f"TRIVY_BIN is not executable: {configured}")
        return path
    installed = shutil.which("trivy")
    if installed:
        return Path(installed)

    archive_name, expected_digest = trivy_archive_pin()
    archive_path = directory / archive_name
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{archive_name}"
    print(f"[ci] downloading pinned Trivy {TRIVY_VERSION}")
    last_error: BaseException | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=120) as response, archive_path.open("wb") as output:
                shutil.copyfileobj(response, output)
            break
        except urllib.error.HTTPError as error:
            if error.code != 429 and not 500 <= error.code <= 599:
                raise ValidationError(f"unable to download Trivy {TRIVY_VERSION}: {error}") from error
            last_error = error
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last_error = error
        archive_path.unlink(missing_ok=True)
        if attempt < 2:
            print(f"[ci] transient Trivy download failure; retry {attempt + 2}/3")
            time.sleep(2 ** attempt)
    else:
        raise ValidationError(f"unable to download Trivy {TRIVY_VERSION}: {last_error}") from last_error
    import hashlib

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if digest != expected_digest:
        raise ValidationError("Trivy archive SHA-256 verification failed")
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extract("trivy", directory)
    path = directory / "trivy"
    path.chmod(0o755)
    return path


def trivy_archive_pin(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    host = (system or platform.system(), machine or platform.machine())
    try:
        return TRIVY_ARCHIVE_PINS[host]
    except KeyError as error:
        raise ValidationError(f"pinned Trivy {TRIVY_VERSION} is unavailable for host {host[0]}/{host[1]}") from error


def trivy_version(trivy: Path, report_dir: Path, manifest: dict[str, Any]) -> str:
    result = checked([str(trivy), "version"], timeout=60)
    version_text = sanitize(result.stdout + result.stderr).strip()
    (report_dir / "trivy-version.txt").write_text(version_text + "\n", encoding="utf-8")
    manifest.setdefault("tools", {})["trivy"] = version_text
    manifest["trivy_version_report"] = str(report_dir / "trivy-version.txt")
    persist_manifest(manifest)
    return version_text


def trivy_database_metadata(cache_dir: Path) -> dict[str, Any] | None:
    metadata_path = cache_dir / "db" / "metadata.json"
    if not metadata_path.is_file():
        return None
    try:
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"path": str(metadata_path), "valid": False}
    if not isinstance(document, dict):
        return {"path": str(metadata_path), "valid": False, "reason": "metadata is not an object"}
    try:
        updated = dt.datetime.fromisoformat(str(document["UpdatedAt"]).replace("Z", "+00:00"))
        next_update = dt.datetime.fromisoformat(str(document["NextUpdate"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return {"path": str(metadata_path), "valid": False, "reason": "missing or invalid freshness timestamps"}
    now = dt.datetime.now(dt.timezone.utc)
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=dt.timezone.utc)
    if next_update.tzinfo is None:
        next_update = next_update.replace(tzinfo=dt.timezone.utc)
    if updated > now:
        return {"path": str(metadata_path), "valid": False, "reason": "database update is future-dated", "metadata": document}
    if next_update <= now:
        return {"path": str(metadata_path), "valid": False, "reason": "database is stale", "metadata": document}
    return {"path": str(metadata_path), "valid": True, "metadata": document}


def require_fresh_trivy_database(cache_dir: Path, manifest: dict[str, Any]) -> None:
    database = trivy_database_metadata(cache_dir)
    manifest["trivy_database"] = database
    persist_manifest(manifest)
    if not database or not database.get("valid"):
        reason = database.get("reason", "metadata is unavailable") if database else "metadata is unavailable"
        raise ValidationError(f"Trivy vulnerability database is not fresh: {reason}")


def run_trivy_json(
    trivy: Path,
    command: list[str],
    report: Path,
    raw_directory: Path,
    *,
    timeout: int,
    redact_secrets: bool = False,
    command_log: Path | None = None,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw_directory.mkdir(parents=True, exist_ok=True)
    raw_report = raw_directory / f"{uuid.uuid4().hex}.json"
    trivy_tmp = raw_directory / "trivy-tmp"
    trivy_tmp.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["TMPDIR"] = str(trivy_tmp)
    invocation = [
        str(trivy),
        *command,
        "--format",
        "json",
        "--output",
        str(raw_report),
        "--exit-code",
        "0",
    ]
    checked(
        invocation,
        env=environment,
        timeout=timeout,
        log_path=command_log,
        disk_floor_bytes=DISK_FLOOR_BYTES,
        manifest=manifest,
    )
    if not raw_report.is_file() or raw_report.stat().st_size == 0:
        raise ValidationError(f"Trivy produced no report for {' '.join(command)}")
    try:
        document = json.loads(raw_report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValidationError(f"Trivy report was invalid for {' '.join(command)}") from error
    if not isinstance(document, dict):
        raise ValidationError(f"Trivy report was not an object for {' '.join(command)}")
    json_write(report, sanitized_secret_document(document) if redact_secrets else document)
    return document


def scan_source(
    trivy: Path,
    report_dir: Path,
    cache_dir: Path,
    raw_directory: Path,
    exceptions: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> None:
    command_log = report_dir / "trivy-commands.log"
    manifest.setdefault("scan_commands", []).extend(
        [
            shlex.join(
                [
                    "trivy",
                    "fs",
                    "--scanners",
                    "vuln",
                    "--severity",
                    "HIGH,CRITICAL",
                    str(ROOT),
                ]
            ),
            shlex.join(["trivy", "fs", "--scanners", "secret", str(ROOT)]),
        ]
    )
    vulnerability_report = report_dir / "source-vulnerabilities.json"
    secret_report = report_dir / "source-secrets.json"
    vulnerability_document = run_trivy_json(
        trivy,
        [
            "fs",
            "--cache-dir",
            str(cache_dir),
            "--scanners",
            "vuln",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            str(ROOT),
        ],
        vulnerability_report,
        raw_directory,
        timeout=900,
        command_log=command_log,
        manifest=manifest,
    )
    secret_document = run_trivy_json(
        trivy,
        [
            "fs",
            "--cache-dir",
            str(cache_dir),
            "--scanners",
            "secret",
            str(ROOT),
        ],
        secret_report,
        raw_directory,
        timeout=900,
        redact_secrets=True,
        command_log=command_log,
        manifest=manifest,
    )
    vulnerabilities = extract_vulnerabilities(vulnerability_document)
    secrets = extract_secrets(secret_document)
    manifest["source_scans"] = {
        "vulnerability_report": str(vulnerability_report),
        "secret_report": str(secret_report),
        "vulnerability_findings": len(vulnerabilities),
        "secret_findings": len(secrets),
    }
    json_write(
        report_dir / "source-secret-summary.json",
        {
            "schema_version": 1,
            "report": str(secret_report),
            "confirmed_findings": len(secrets),
            "gate_decision": "FAIL" if secrets else "PASS",
        },
    )
    require_fresh_trivy_database(cache_dir, manifest)
    persist_manifest(manifest)
    enforce_vulnerability_policy(
        [("source", vulnerabilities)], exceptions, report_dir, manifest
    )
    if secrets:
        raise ValidationError(f"source secret scan found {len(secrets)} finding(s)")


def scan_image(
    trivy: Path,
    image: str,
    scope: str,
    report_dir: Path,
    cache_dir: Path,
    raw_directory: Path,
    command_log: Path | None = None,
    report_name: str | None = None,
    manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    default_name = "electron-cash" if scope == "image:electron-cash" else "tor"
    report = report_dir / f"{report_name or default_name}.json"
    document = run_trivy_json(
        trivy,
        [
            "image",
            "--cache-dir",
            str(cache_dir),
            "--scanners",
            "vuln",
            "--severity",
            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            image,
        ],
        report,
        raw_directory,
        timeout=900,
        command_log=command_log,
        manifest=manifest,
    )
    return extract_vulnerabilities(document)


def registry_entries(registry: Path) -> list[dict[str, Any]]:
    return docker_ownership.read_claims(registry)


def _owned_docker_inventory(claims: list[dict[str, Any]], owner_token: str) -> dict[str, Any]:
    projects = sorted({claim["name"] for claim in claims
                       if claim.get("kind") == "project" and claim.get("owner_token") == owner_token})
    container_ids: set[str] = set()
    network_ids: set[str] = set()
    failures: list[str] = []
    for project in projects:
        listed = run(["docker", "ps", "-aq", "--filter", f"label={docker_ownership.PROJECT_LABEL}={project}"], timeout=60)
        if listed.returncode:
            failures.append(f"unable to list containers for claimed Compose project {project}")
        container_ids.update(listed.stdout.split())
        listed = run(["docker", "ps", "-aq", "--filter", f"label={docker_ownership.OWNER_LABEL}={owner_token}"], timeout=60)
        if listed.returncode:
            failures.append("unable to list task-owner-labeled containers")
        container_ids.update(listed.stdout.split())
        listed = run(["docker", "network", "ls", "-q", "--filter", f"label={docker_ownership.PROJECT_LABEL}={project}"], timeout=60)
        if listed.returncode:
            failures.append(f"unable to list networks for claimed Compose project {project}")
        network_ids.update(listed.stdout.split())
    listed = run(["docker", "network", "ls", "-q", "--filter", f"label={docker_ownership.OWNER_LABEL}={owner_token}"], timeout=60)
    if listed.returncode:
        failures.append("unable to list task-owner-labeled networks")
    network_ids.update(listed.stdout.split())
    containers = []
    if container_ids:
        inspected = run(["docker", "inspect", *sorted(container_ids)], timeout=120)
        if inspected.returncode:
            failures.append("unable to inspect claimed containers")
        else:
            for item in json.loads(inspected.stdout):
                containers.append({"id": item["Id"], "labels": item.get("Config", {}).get("Labels") or {}})
    networks = []
    if network_ids:
        inspected = run(["docker", "network", "inspect", *sorted(network_ids)], timeout=120)
        if inspected.returncode:
            failures.append("unable to inspect claimed networks")
        else:
            for item in json.loads(inspected.stdout):
                networks.append({"id": item["Id"], "name": item["Name"], "labels": item.get("Labels") or {}})
    volume_names = {claim["name"] for claim in claims
                    if claim.get("kind") == "volume" and claim.get("owner_token") == owner_token}
    listed = run(["docker", "volume", "ls", "-q", "--filter", f"label={docker_ownership.OWNER_LABEL}={owner_token}"], timeout=60)
    if listed.returncode:
        failures.append("unable to list task-owner-labeled volumes")
    volume_names.update(listed.stdout.split())
    volumes = []
    for name in sorted(volume_names):
        inspected = run(["docker", "volume", "inspect", name], timeout=60)
        if inspected.returncode:
            if "no such volume" in inspected.stderr.lower():
                continue
            failures.append(f"unable to inspect claimed volume {name}")
            continue
        item = json.loads(inspected.stdout)[0]
        volumes.append({"name": item["Name"], "labels": item.get("Labels") or {}})
    images = []
    for claim in claims:
        if claim.get("kind") != "image" or claim.get("owner_token") != owner_token:
            continue
        inspected = run(["docker", "image", "inspect", claim["name"]], timeout=60)
        if inspected.returncode:
            if "no such image" in inspected.stderr.lower() or "no such object" in inspected.stderr.lower():
                continue
            failures.append(f"unable to inspect claimed image {claim['name']}")
            continue
        for item in json.loads(inspected.stdout):
            images.append({"id": item["Id"], "repo_tags": item.get("RepoTags") or []})
    return {"containers": containers, "networks": networks, "volumes": volumes,
            "images": images, "failures": failures}


def cleanup_registry(registry: Path, owner_token: str) -> dict[str, Any]:
    claims = registry_entries(registry)
    inventory = _owned_docker_inventory(claims, owner_token)
    plan = docker_ownership.select_cleanup_targets(owner_token, claims,
        containers=inventory["containers"], networks=inventory["networks"],
        volumes=inventory["volumes"], images=[])
    attempts: list[dict[str, Any]] = []
    failures = list(inventory["failures"])
    removed_resources: list[dict[str, Any]] = []
    selected_volume_names = set(plan["volumes"])
    observed_volume_names = {item["name"] for item in inventory["volumes"]}
    for claim in claims:
        if (claim.get("kind") == "volume" and claim.get("owner_token") == owner_token and
                claim["name"] in observed_volume_names and claim["name"] not in selected_volume_names):
            failures.append(f"claimed volume has no matching owner label and was retained: {claim['name']}")

    def execute(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        result = run(command, timeout=timeout)
        attempts.append({"command": shlex.join(command), "returncode": result.returncode,
                         "stderr": sanitize(result.stderr)})
        if result.returncode:
            failures.append(f"owned cleanup command returned {result.returncode}: {shlex.join(command)}")
        return result

    for container_id in plan["containers"]:
        result = execute(["docker", "rm", "-f", container_id])
        if result.returncode == 0:
            item = next((item for item in inventory["containers"] if item["id"] == container_id), {})
            removed_resources.append({"kind": "container", "id": container_id, "name": item.get("name"),
                                      "owner_labels": item.get("labels"), "proof": "exact owner/project label plus preflight claim"})
    for network_id in plan["networks"]:
        result = execute(["docker", "network", "rm", network_id])
        if result.returncode == 0:
            item = next((item for item in inventory["networks"] if item["id"] == network_id), {})
            removed_resources.append({"kind": "network", "id": network_id, "name": item.get("name"),
                                      "owner_labels": item.get("labels"), "proof": "exact owner/project label plus preflight claim"})
    for volume_name in plan["volumes"]:
        # Re-inspect exact identity/ownership immediately before deletion.
        current = run(["docker", "volume", "inspect", volume_name], timeout=60)
        if current.returncode:
            if "no such volume" not in current.stderr.lower():
                failures.append(f"unable to revalidate owned volume {volume_name}")
            continue
        item = json.loads(current.stdout)[0]
        labels = item.get("Labels") or {}
        project_names = {claim["name"] for claim in claims if claim.get("kind") == "project" and
                         claim.get("owner_token") == owner_token}
        if not (labels.get(docker_ownership.OWNER_LABEL) == owner_token or
                labels.get(docker_ownership.PROJECT_LABEL) in project_names or
                labels.get(docker_ownership.ROLLBACK_PROJECT_LABEL) in project_names):
            failures.append(f"volume ownership changed before deletion; retained {volume_name}")
            continue
        result = execute(["docker", "volume", "rm", volume_name])
        if result.returncode == 0:
            removed_resources.append({"kind": "volume", "name": volume_name, "owner_labels": labels,
                                      "proof": "exact owner/project label plus preflight volume claim"})
    return {"owner_token": owner_token, "claims": claims, "owned_resources_selected": plan,
            "attempts": attempts, "removed_resources": removed_resources, "failures": failures}


def verify_registry_postcondition(registry: Path, owner_token: str) -> list[str]:
    claims = registry_entries(registry)
    inventory = _owned_docker_inventory(claims, owner_token)
    plan = docker_ownership.select_cleanup_targets(owner_token, claims,
        containers=inventory["containers"], networks=inventory["networks"],
        volumes=inventory["volumes"], images=[])
    residual = list(inventory["failures"])
    for kind in ("containers", "networks", "volumes"):
        if plan[kind]:
            residual.append(f"owned {kind} remain after cleanup: {plan[kind]}")
    for claim in claims:
        if claim.get("kind") != "volume" or claim.get("owner_token") != owner_token:
            continue
        inspected = run(["docker", "volume", "inspect", claim["name"]], timeout=60)
        if inspected.returncode == 0:
            residual.append(f"claimed volume remains or was replaced: {claim['name']}")
        elif "no such volume" not in inspected.stderr.lower():
            residual.append(f"unable to verify claimed volume postcondition: {claim['name']}")
    for claim in claims:
        if claim.get("kind") == "image" and claim.get("owner_token") == owner_token:
            check = run(["docker", "image", "inspect", claim["name"]], timeout=60)
            if check.returncode == 0:
                item = json.loads(check.stdout)[0]
                if claim.get("retain") is True and claim.get("expected_id"):
                    if (item.get("Id") != claim["expected_id"] or
                            claim["name"] not in (item.get("RepoTags") or [])):
                        residual.append(f"retained image identity changed: {claim['name']}")
                else:
                    residual.append(f"claimed image tag remains after cleanup: {claim['name']}")
            elif "no such image" not in check.stderr.lower() and "no such object" not in check.stderr.lower():
                residual.append(f"unable to verify claimed image state: {claim['name']}")
    return residual


def capture_attempted_image_ids(registry: Path, owner_token: str) -> list[str]:
    failures = []
    for claim in registry_entries(registry):
        if (claim.get("kind") != "image" or claim.get("owner_token") != owner_token or
                claim.get("build_attempted") is not True or claim.get("expected_id")):
            continue
        inspected = run(["docker", "image", "inspect", claim["name"]], timeout=60)
        if inspected.returncode == 0:
            image_id = json.loads(inspected.stdout)[0].get("Id")
            if image_id:
                docker_ownership.record_image_attempt(registry, claim["name"], owner_token, image_id)
        elif "no such image" not in inspected.stderr.lower() and "no such object" not in inspected.stderr.lower():
            failures.append(f"unable to resolve attempted candidate image {claim['name']}")
    return failures


def cleanup_images(registry: Path, owner_token: str, preexisting_image_ids: set[str]) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    failures: list[str] = []
    removed_resources: list[dict[str, Any]] = []
    retained_resources: list[dict[str, Any]] = []
    claims = registry_entries(registry)
    failures.extend(capture_attempted_image_ids(registry, owner_token))
    claims = registry_entries(registry)
    image_claims = [claim for claim in claims if claim.get("kind") == "image" and
                    claim.get("owner_token") == owner_token]
    inventory = []
    for claim in image_claims:
        inspected = run(["docker", "image", "inspect", claim["name"]], timeout=60)
        if inspected.returncode == 0:
            item = json.loads(inspected.stdout)[0]
            inventory.append({"id": item.get("Id"), "repo_tags": item.get("RepoTags") or []})
        elif "no such image" not in inspected.stderr.lower() and "no such object" not in inspected.stderr.lower():
            failures.append(f"unable to inspect claimed candidate image {claim['name']}")
    plan = docker_ownership.select_cleanup_targets(owner_token, claims, containers=[], networks=[],
                                                   volumes=[], images=inventory)
    by_name = {claim["name"]: claim for claim in image_claims}
    task_image_ids: set[str] = set()
    for claim in image_claims:
        if claim.get("retain") is not True or not claim.get("expected_id"):
            continue
        inspected = run(["docker", "image", "inspect", claim["name"]], timeout=60)
        if inspected.returncode != 0:
            failures.append(f"unable to inspect retained image {claim['name']}")
            continue
        current = json.loads(inspected.stdout)[0]
        if (current.get("Id") != claim["expected_id"] or
                claim["name"] not in (current.get("RepoTags") or [])):
            failures.append(f"retained image identity changed: {claim['name']}")
            continue
        retained_resources.append({"reference": claim["name"], "image_id": claim["expected_id"],
                                   "proof": "preflight-absent public Compose build; retained for reuse"})
    for image in plan["images"]:
        claim = by_name[image]
        inspected = run(["docker", "image", "inspect", image], timeout=60)
        if inspected.returncode != 0:
            failures.append(f"unable to revalidate owned candidate image {image}")
            continue
        current = json.loads(inspected.stdout)[0]
        if current.get("Id") != claim.get("expected_id") or image not in (current.get("RepoTags") or []):
            failures.append(f"candidate image identity changed; retained {image}")
            continue
        image_id = claim["expected_id"]
        task_image_ids.add(image_id)
        removed = run(["docker", "image", "rm", "--no-prune", image], timeout=120)
        attempts.append({"image": image, "image_id": claim["expected_id"], "returncode": removed.returncode,
                         "stderr": sanitize(removed.stderr)})
        if removed.returncode:
            failures.append(f"unable to remove claimed candidate image {image}")
        else:
            removed_resources.append({"kind": "image-tag", "reference": image,
                                      "image_id": claim["expected_id"],
                                      "proof": "preflight-absent image claim and exact post-build ID; --no-prune"})
    for image_id in sorted(task_image_ids - preexisting_image_ids):
        inspected = run(["docker", "image", "inspect", image_id], timeout=60)
        if inspected.returncode != 0:
            if "no such image" not in inspected.stderr.lower() and "no such object" not in inspected.stderr.lower():
                failures.append(f"unable to inspect task-created image object {image_id}")
            continue
        item = json.loads(inspected.stdout)[0]
        repo_tags = [tag for tag in (item.get("RepoTags") or []) if tag and not tag.startswith("<none>:")]
        if repo_tags:
            failures.append(f"task-created image has a remaining unclaimed tag; retained {image_id}: {repo_tags}")
            continue
        removed = run(["docker", "image", "rm", "--no-prune", image_id], timeout=120)
        attempts.append({"image_id": image_id, "operation": "remove-unreferenced-task-image-no-prune",
                         "returncode": removed.returncode, "stderr": sanitize(removed.stderr)})
        if removed.returncode:
            failures.append(f"unable to remove unreferenced task-created image object {image_id}")
        else:
            removed_resources.append({"kind": "image-object", "image_id": image_id,
                                      "proof": "created by claimed image build; absent from preflight inventory; --no-prune"})
    for claim in image_claims:
        if claim.get("retain") is True and claim.get("expected_id"):
            continue
        final = run(["docker", "image", "inspect", claim["name"]], timeout=60)
        if final.returncode == 0:
            failures.append(f"claimed candidate image remains after cleanup: {claim['name']}")
        elif "no such image" not in final.stderr.lower() and "no such object" not in final.stderr.lower():
            failures.append(f"unable to verify claimed candidate image cleanup: {claim['name']}")
    return {"attempts": attempts, "removed_resources": removed_resources,
            "retained_resources": retained_resources, "failures": failures}


def cleanup_candidate_dangling_images(_claims: list[dict[str, Any]]) -> dict[str, Any]:
    """Never scan/prune untagged images without an exact creation claim and ID."""
    return {"attempts": [], "failures": [],
            "retained_unclaimed_dangling_images": True,
            "reason": "unclaimed dangling images are foreign resources and are not cleanup candidates"}


def read_cleanup_failures(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    failures = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            failures.append({"raw": "[invalid cleanup failure record]"})
        else:
            failures.append(document)
    return failures


def read_resource_events(path: Path, owner_token: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValidationError(f"Docker ownership event line {line_number} is invalid JSON") from error
        if not isinstance(event, dict) or event.get("owner_token") != owner_token:
            raise ValidationError(f"Docker ownership event line {line_number} has an unexpected owner token")
        events.append(event)
    return events


def removed_resource_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    removed = []
    for event in events:
        if (event.get("kind") == "docker-run" and event.get("auto_remove") and
                event.get("container_id") and event.get("remaining") is None):
            removed.append({"kind": "ephemeral-container", "identity": event["container_id"],
                            "owner": event.get("owner_token"),
                            "evidence": "owner-labeled docker run --rm; cidfile recorded its exact ID"})
        if (event.get("kind") == "compose-lifecycle" and event.get("operation") in ("down", "rm") and
                event.get("returncode") == 0):
            for kind in ("containers", "networks", "volumes"):
                for item in event.get(kind, []):
                    identity = item.get("id") or item.get("name")
                    if identity and identity not in (event.get("remaining") or {}).get(kind, []):
                        removed.append({"kind": kind[:-1] if kind.endswith("s") else kind,
                                        "identity": identity, "owner": event.get("project"),
                                        "evidence": "pre-down exact Compose project identity"})
        elif event.get("kind") in ("container-mutation", "volume-remove", "network-remove", "image-remove") and event.get("returncode") == 0:
            for item in event.get("resources", []):
                identity = item.get("requested") or item.get("id") or item.get("name")
                if identity and identity not in event.get("remaining", []):
                    removed.append({"kind": event["kind"].removesuffix("-remove").removesuffix("-mutation"),
                                    "identity": identity, "owner": event.get("owner_token"),
                                    "evidence": "owner-token label and exact inspected identity"})
        elif event.get("kind") == "buildx-cache-prune" and event.get("returncode") == 0:
            for item in event.get("removed_cache_items", []):
                removed.append({"kind": "buildx-cache", "identity": item.get("ID"),
                                "size": item.get("Size"), "owner": event.get("builder"),
                                "evidence": "task-owned Buildx builder record"})
    return removed


def acceptance_protection_snapshots(
    report_dir: Path, manifest: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Verify gate-start snapshots and detect foreign drift immediately before task setup."""
    preflight: dict[str, Any] | None = manifest.get("docker_protection_preflight") if manifest is not None else None
    preflight_path = report_dir / "docker-protection-preflight.json"
    drift: list[str] = []
    telemetry_drift: list[dict[str, Any]] = []
    if preflight is None:
        before = capture_docker_protection_state()
        before_sha256 = write_immutable_private_json(preflight_path, before)
        confirmation_path = report_dir / "docker-protection-preflight-confirmation.json"
        confirmation = capture_docker_protection_state()
        confirmation_sha256 = write_immutable_private_json(confirmation_path, confirmation)
        preflight = {"report": str(preflight_path), "sha256": before_sha256,
                     "confirmation_report": str(confirmation_path),
                     "confirmation_sha256": confirmation_sha256}
        drift = verify_gate_protection_state(
            before, confirmation,
            task_builder={"name": None, "container_id": None, "volume_names": []},
            baseline_path=preflight_path, baseline_sha256=before_sha256,
            immutable_snapshots=[(confirmation_path, confirmation_sha256)])
        telemetry_drift.extend(docker_ownership.compare_snapshot_telemetry(before, confirmation))
        build_start = capture_docker_protection_state()
        drift.extend(verify_gate_protection_state(
            before, build_start,
            task_builder={"name": None, "container_id": None, "volume_names": []},
            baseline_path=preflight_path, baseline_sha256=before_sha256,
            immutable_snapshots=[(confirmation_path, confirmation_sha256)]))
        telemetry_drift.extend(docker_ownership.compare_snapshot_telemetry(before, build_start))
        preflight["free_bytes"] = min(int(before["root_filesystem"]["free_bytes"]),
                                       int(confirmation["root_filesystem"]["free_bytes"]),
                                       int(build_start["root_filesystem"]["free_bytes"]))
        preflight["telemetry_differences"] = telemetry_drift
    else:
        if (not isinstance(preflight, dict) or preflight.get("status") != "PASS" or
                preflight.get("report") != str(preflight_path) or
                preflight.get("confirmation_report") != str(report_dir / "docker-protection-preflight-confirmation.json") or
                not isinstance(preflight.get("sha256"), str) or
                not isinstance(preflight.get("confirmation_sha256"), str)):
            raise ValidationError("gate-start Docker protection snapshot is missing or failed integrity validation")
        before = read_immutable_docker_snapshot(preflight_path, preflight["sha256"])
        confirmation_path = report_dir / "docker-protection-preflight-confirmation.json"
        confirmation = read_immutable_docker_snapshot(confirmation_path, preflight["confirmation_sha256"])
        build_start = capture_docker_protection_state()
        task_builder_none = {"name": None, "container_id": None, "volume_names": []}
        drift = verify_gate_protection_state(
            before,
            confirmation,
            task_builder=task_builder_none,
            baseline_path=preflight_path,
            baseline_sha256=preflight["sha256"],
            immutable_snapshots=[(confirmation_path, preflight["confirmation_sha256"])],
        )
        telemetry_drift.extend(docker_ownership.compare_snapshot_telemetry(before, confirmation))
        drift.extend(
            verify_gate_protection_state(
                before,
                build_start,
                task_builder=task_builder_none,
                baseline_path=preflight_path,
                baseline_sha256=preflight["sha256"],
                immutable_snapshots=[(confirmation_path, preflight["confirmation_sha256"])],
            )
        )
        telemetry_drift.extend(docker_ownership.compare_snapshot_telemetry(before, build_start))
    write_private_json(report_dir / "docker-protection-before.json", before)
    build_start_path = report_dir / "docker-protection-build-start.json"
    write_private_json(build_start_path, build_start)
    if preflight is not None:
        if manifest is not None:
            manifest["docker_protection_telemetry_before_acceptance"] = telemetry_drift
        if manifest is not None and drift:
            manifest["foreign_state_drift_before_acceptance"] = {
                "baseline_report": str(preflight_path),
                "confirmation_report": preflight["confirmation_report"],
                "build_start_report": str(build_start_path),
                "failures": sorted(set(drift)),
            }
        if drift:
            raise ValidationError(
                "FOREIGN_STATE_DRIFT: Docker state changed since gate preflight; "
                "acceptance task resources were not created: " + "; ".join(sorted(set(drift)))
            )
    return before, build_start, preflight


def acceptance(
    *,
    report_dir: Path | None = None,
    manifest: dict[str, Any] | None = None,
    trivy: Path | None = None,
    cache_dir: Path | None = None,
    raw_directory: Path | None = None,
) -> dict[str, Any]:
    report_dir = report_dir or report_directory(new_run_id())
    report_dir.mkdir(parents=True, exist_ok=True)
    exceptions = load_vulnerability_exceptions()
    assert_safe_docker_endpoint(log_path=report_dir / "acceptance.log")
    docker_root = checked(["docker", "info", "--format", "{{.DockerRootDir}}"],
                          log_path=report_dir / "acceptance.log").stdout.strip()
    configure_disk_storage_paths(docker_root)
    protected_before, protected_build_start, protection_info = acceptance_protection_snapshots(report_dir, manifest)
    measured_free_before = disk_checkpoint("acceptance-start", manifest)
    free_before = min(int(protected_before["root_filesystem"]["free_bytes"]),
                      int(protected_build_start["root_filesystem"]["free_bytes"]),
                      int(protection_info.get("free_bytes", protected_build_start["root_filesystem"]["free_bytes"])),
                      measured_free_before)
    require_disk_floor("before task-owned builder reservation", manifest)
    try:
        builder, builder_lock, builder_record = ensure_task_buildx_builder(
            report_dir=report_dir, manifest=manifest, log_path=report_dir / "acceptance.log")
    except Exception as builder_error:
        protection_failure = None
        try:
            after = capture_docker_protection_state()
            after_path = report_dir / "docker-protection-after.json"
            write_private_json(after_path, after)
            record_path = task_builder_record_path()
            claimed_name = None
            if record_path.is_file() and not record_path.is_symlink():
                record = json.loads(record_path.read_text(encoding="utf-8"))
                if (record.get("owner") == "electron-cash-docker-v0.4-task" and
                        record.get("repository_root") == str(ROOT) and
                        str(record.get("builder", "")).startswith("ecd-v04-task-acceptance-") and
                        any(item.get("name") == record.get("builder") for item in after.get("builders", []))):
                    claimed_name = record["builder"]
            container = next((item for item in after["containers"]
                              if item["name"] == f"buildx_buildkit_{claimed_name}0"), None) if claimed_name else None
            volume_names = sorted(mount.get("name") for mount in (container or {}).get("mounts", [])
                                  if mount.get("type") == "volume" and mount.get("name"))
            preflight = protection_info
            immutable_snapshots = []
            baseline_path = None
            baseline_sha256 = None
            if (isinstance(preflight, dict) and isinstance(preflight.get("sha256"), str) and
                    isinstance(preflight.get("confirmation_sha256"), str)):
                baseline_path = report_dir / "docker-protection-preflight.json"
                baseline_sha256 = preflight.get("sha256")
                immutable_snapshots.append((report_dir / "docker-protection-preflight-confirmation.json",
                                            preflight["confirmation_sha256"]))
            proof_failures = verify_gate_protection_state(
                protected_before, after,
                task_builder={"name": claimed_name, "container_id": (container or {}).get("id"),
                              "volume_names": volume_names},
                baseline_path=baseline_path, baseline_sha256=baseline_sha256,
                immutable_snapshots=immutable_snapshots)
            protection_failure = "; ".join(proof_failures) if proof_failures else None
            if manifest is not None:
                manifest["builder_setup_protection"] = {
                    "before_report": str(report_dir / "docker-protection-before.json"),
                    "after_report": str(after_path), "verification_failures": proof_failures,
                    "telemetry_differences": docker_ownership.compare_snapshot_telemetry(protected_before, after),
                    "builder_record": str(record_path) if record_path.exists() else None}
                persist_manifest(manifest)
        except Exception as error:
            protection_failure = f"unable to verify Docker state after builder setup failure: {sanitize(str(error))}"
        if protection_failure:
            raise ValidationError(f"Buildx setup failed: {builder_error}; protection check failed: {protection_failure}") from builder_error
        raise
    try:
        if trivy is not None and cache_dir is not None:
            owned_raw_directory = raw_directory is None
            raw_directory = raw_directory or report_dir.parent / f"raw-{uuid.uuid4().hex}"
            raw_directory.mkdir(parents=True, exist_ok=True)
            try:
                return _acceptance(report_dir, manifest, trivy, cache_dir, raw_directory, exceptions,
                                   owned_builder=builder, builder_record=builder_record,
                                   protected_before=protected_before,
                                   protected_build_start=protected_build_start,
                                   protection_info=protection_info)
            finally:
                if owned_raw_directory:
                    shutil.rmtree(raw_directory, ignore_errors=True)
        with tempfile.TemporaryDirectory(
            prefix="bchforge-v021-tooling-", dir=report_dir.parent
        ) as temporary:
            temporary_path = Path(temporary)
            local_trivy = ensure_trivy(temporary_path / "trivy")
            local_cache = trivy_cache_directory()
            raw_directory = temporary_path / "raw-reports"
            return _acceptance(report_dir, manifest, local_trivy, local_cache, raw_directory, exceptions,
                               owned_builder=builder, builder_record=builder_record,
                               protected_before=protected_before,
                               protected_build_start=protected_build_start,
                               protection_info=protection_info)
    finally:
        fcntl.flock(builder_lock, fcntl.LOCK_UN)
        os.close(builder_lock)


def _acceptance(
    report_dir: Path,
    manifest: dict[str, Any] | None,
    trivy: Path,
    cache_dir: Path,
    raw_directory: Path,
    exceptions: list[dict[str, Any]],
    *,
    owned_builder: str,
    builder_record: Path,
    protected_before: dict[str, Any],
    protected_build_start: dict[str, Any],
    protection_info: dict[str, Any],
) -> dict[str, Any]:
    acceptance_log = report_dir / "acceptance.log"
    assert_safe_docker_endpoint(log_path=acceptance_log)
    ec_image, tor_image, auth_image, project = candidate_names()
    suffix = project.rsplit("-", 1)[-1]
    caddy_image = f"electron-cash-caddy-ci:{suffix}"
    fail2ban_image = f"electron-cash-fail2ban-ci:{suffix}"
    ledger_image = f"electron-cash-ledger-ci:{suffix}"
    remote_project = f"{project}-remote"
    published_project = f"{project}-published"
    remote_port = free_port()
    published_port = free_port()
    startup_project = f"{project}-startup"
    owner_token = uuid.uuid4().hex
    environment = os.environ.copy()
    cleanup_failure_file = report_dir / f"cleanup-failures-{uuid.uuid4().hex}.jsonl"
    environment.update(
        {
            "ELECTRON_CASH_IMAGE": ec_image,
            "TOR_IMAGE": tor_image,
            "CADDY_IMAGE": caddy_image,
            "FAIL2BAN_IMAGE": fail2ban_image,
            "AUTH_SESSION_IMAGE": auth_image,
            "CI_CANDIDATE_IMAGES": "1",
            "CI_RESOURCE_OWNER": owner_token,
            "CI_DOCKER_OWNER_SHIM": "1",
            "ECD_TEST_RESOURCE_OWNER": owner_token,
            "CI_PROJECT_PREFIX": project,
            "CI_REPORT_DIR": str(report_dir),
            "CI_CLEANUP_FAILURE_FILE": str(cleanup_failure_file),
            "CI_PUBLISHED_PROJECT": published_project,
            "CI_PUBLISHED_PORT": str(published_port),
            "CADDY_SITE_ADDRESS": "http://localhost",
            "CADDY_TLS_MODE": "auto",
            "CADDY_EDGE_BIND": "127.0.0.1",
            "CADDY_HTTP_HOST_PORT": str(free_port()),
            "CADDY_HTTPS_HOST_PORT": str(free_port()),
            "BASIC_AUTH_PASSWORD": "synthetic-auth-secret",
            "USE_TOR": "false",
            "CHIPNET": "false",
            "TESTNET4": "false",
            "NETWORK": "mainnet",
            "ECD_HW_IMAGE": ledger_image,
            "BUILDX_BUILDER": owned_builder,
            "CI_PRUNE_TASK_BUILDER": owned_builder,
            "CASHFUSION_ENABLED": "true",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
        }
    )
    acceptance_tests = [*ACCEPTANCE_TESTS]
    validate_mandatory_acceptance_registration(acceptance_tests)
    run_public_acceptance = os.environ.get("PUBLIC_ACCEPTANCE") == "1"
    if manifest is not None:
        manifest["acceptance_tests"] = [
            *acceptance_tests,
            "test_integrity_pins.py",
            REMOTE_ACCEPTANCE_TEST,
            *([PUBLIC_ACCEPTANCE_TEST] if run_public_acceptance else []),
        ]
        manifest["acceptance_log"] = str(acceptance_log)
        manifest["acceptance_test_results"] = []
        manifest["candidate_images"] = {
            "electron_cash": ec_image,
            "tor": tor_image,
            "caddy": caddy_image,
            "fail2ban": fail2ban_image,
            "auth_session": auth_image,
            "ledger": ledger_image,
        }
        manifest["image_builds"] = []
        manifest["build_cache_decisions"] = []
        manifest["build_cache_reclamations"] = []
        manifest["candidate_compose_project"] = project
        persist_manifest(manifest)
    with tempfile.TemporaryDirectory(
        prefix="bchforge-v021-ci-", dir=raw_directory.parent
    ) as temporary:
        temporary_path = Path(temporary)
        registry = temporary_path / "resources.jsonl"
        registry.touch(mode=0o600)
        os.chmod(registry, 0o600)
        projects = (project, remote_project, published_project, startup_project)
        volume_suffixes = ("-wallet", "-tor", "_caddy-data", "_caddy-config", "_caddy-log",
                            "_fail2ban-state", "_caddy-ban-state", "_caddy-control", "_gui-session-state", "_auth-session-data")
        for project_name in projects:
            docker_ownership.append_claim(registry, "project", project_name, owner_token)
            for suffix in volume_suffixes:
                docker_ownership.append_claim(registry, "volume", project_name + suffix, owner_token)
        candidate_images = {"electron_cash": ec_image, "tor": tor_image, "auth_session": auth_image,
                            "caddy": caddy_image, "fail2ban": fail2ban_image, "ledger": ledger_image}
        for image_ref in candidate_images.values():
            docker_ownership.append_claim(registry, "image", image_ref, owner_token)
        shim_directory = temporary_path / "docker-shim"
        shim_directory.mkdir(mode=0o700)
        docker_shim = write_docker_owner_shim(shim_directory)
        environment["PATH"] = str(docker_shim.parent) + os.pathsep + environment.get("PATH", "")
        environment["CI_REAL_DOCKER"] = shutil.which("docker") or ""
        environment["CI_RESOURCE_REGISTRY"] = str(registry)
        environment["CI_RESOURCE_EVENT_LOG"] = str(report_dir / "docker-resource-events.jsonl")
        environment["CI_TASK_BUILDER_RECORD"] = str(builder_record)
        environment["ECD_REPOSITORY_ROOT"] = str(ROOT)
        environment["CI_DISK_FLOOR_BYTES"] = str(DISK_FLOOR_BYTES)
        environment["CI_DISK_CANCEL_BYTES"] = str(DISK_CANCEL_TRIGGER_BYTES)
        environment["CI_DISK_PATHS"] = os.environ.get("CI_DISK_PATHS", str(ROOT))
        environment["CI_DISK_START_BYTES"] = str(disk_phase_admission(DISK_DEFAULT_PHASE_PEAK_BYTES))
        environment.update(
            {
                "CI_STARTUP_PROJECT": startup_project,
                "CI_STARTUP_HTTP_PORT": str(free_port()),
                "CI_STARTUP_HTTPS_PORT": str(free_port()),
            }
        )
        override = write_compose_override(
            temporary_path, ec_image, tor_image, caddy_image, fail2ban_image, auth_image, project
        )
        command = compose_command(project, override)
        canonical_command = [
            "docker",
            "compose",
            "--env-file",
            str(ENV_FILE),
            "-p",
            project,
            "-f",
            str(ROOT / "docker-compose.yml"),
        ]
        image_build_records: list[dict[str, Any]] = []
        if manifest is not None:
            manifest["image_builds"] = image_build_records
            manifest.setdefault("build_cache_decisions", [])
            manifest.setdefault("build_cache_reclamations", [])

        def save_build_evidence() -> None:
            if manifest is not None:
                manifest["image_builds"] = image_build_records
                persist_manifest(manifest)

        def build_candidate_image(
            *, service_name: str, image_key: str, variant: str, image_ref: str,
            build_model: dict[str, Any], compose_files: list[Path], prefix: list[str],
            build_environment: dict[str, str], phase_admission_bytes: int,
        ) -> str:
            descriptor = image_build_configuration(
                build_model, service_name, image_ref, variant=variant, compose_files=compose_files)
            record = {**descriptor, "builder": owned_builder, "buildkit_image": TASK_BUILDKIT_IMAGE,
                       "build_mode": "--pull --no-cache" if os.environ.get("CI_FRESH_BUILD") == "1" else "cache-aware --pull", "status": "PLANNED",
                      "image_id": None, "image_platform": None, "required_start_bytes": phase_admission_bytes}
            image_build_records.append(record)
            save_build_evidence()
            try:
                reuse_path = os.environ.get('CI_VERIFIED_IMAGE_REUSE')
                if reuse_path:
                    if os.environ.get('CI_FRESH_BUILD') == '1':
                        raise ValidationError('fresh no-cache acceptance cannot reuse images')
                    reuse = json.loads(Path(reuse_path).read_text())
                    proofs = [p for p in reuse['proof'].values() if p['variant'] == variant]
                    if len(proofs) != 1:
                        raise ValidationError('missing/ambiguous verified candidate image proof')
                    proof = proofs[0]
                    validate_image_reuse(descriptor, proof)
                    source = proof['image_reference']
                    item = json.loads(checked(['docker', 'image', 'inspect', source], env=build_environment, log_path=acceptance_log).stdout)[0]
                    if item['Id'] != proof['image_id'] or item['Os'] + '/' + item['Architecture'] != proof['image_platform']:
                        raise ValidationError('verified candidate image identity/platform changed')
                    # Destination was reserved absent above. The owner shim forbids
                    # general retagging; this exact verified source/absent destination
                    # pair is the narrowly authorized gate operation.
                    docker_ownership.assert_absent('image', image_ref)
                    checked([environment['CI_REAL_DOCKER'], 'image', 'tag', source, image_ref], timeout=60, log_path=acceptance_log)
                    docker_ownership.record_image_attempt(registry, image_ref, owner_token, item['Id'])
                    image_ids[image_key] = item['Id']
                    record.update(status='PASS', image_id=item['Id'], image_platform=proof['image_platform'],
                                  build_mode='verified exact image reuse', input_modes=proof['input_modes'],
                                  reused_from=source, reuse_proof_sha256=sha256_file(Path(reuse_path)), finished_at=utc_now())
                    save_build_evidence()
                    return item['Id']
                free_before = require_build_capacity(
                    f"before {variant} build", manifest, minimum_free_bytes=phase_admission_bytes)
                record.update({"status": "RUNNING", "disk_free_before_bytes": free_before,
                               "started_at": utc_now()})
                save_build_evidence()
                build_environment.update({"CI_DISK_FLOOR_BYTES": str(DISK_FLOOR_BYTES),
                                          "CI_DISK_CANCEL_BYTES": str(DISK_CANCEL_TRIGGER_BYTES),
                                          "CI_DISK_START_BYTES": str(phase_admission_bytes)})
                build_command = [*prefix, "--progress", "plain", "build", "--pull"]
                if os.environ.get("CI_FRESH_BUILD") == "1":
                    build_command.append("--no-cache")
                build_command.append(service_name)
                record["command"] = shlex.join(build_command)
                checked(build_command, env=build_environment, timeout=1800,
                        log_path=acceptance_log, disk_floor_bytes=DISK_FLOOR_BYTES,
                        disk_cancel_bytes=DISK_CANCEL_TRIGGER_BYTES, manifest=manifest)
                free_after = require_disk_floor(f"after {variant} build", manifest)
                image_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
                                   env=build_environment, log_path=acceptance_log).stdout.strip()
                image_platform = checked(
                    ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image_ref],
                    env=build_environment, log_path=acceptance_log).stdout.strip()
                if not image_id or not image_platform:
                    raise ValidationError(f"candidate build produced incomplete image identity: {image_ref}")
                docker_ownership.record_image_attempt(registry, image_ref, owner_token, image_id)
                image_ids[image_key] = image_id
                record.update({"status": "PASS", "image_id": image_id, "image_platform": image_platform,
                               "disk_free_after_bytes": free_after,
                               "observed_free_space_drop_bytes": free_before - free_after,
                               "finished_at": utc_now()})
                save_build_evidence()
                return image_id
            except Exception as error:
                record.update({"status": "FAIL", "error": sanitize(str(error)), "finished_at": utc_now()})
                save_build_evidence()
                raise

        def task_builder_cache_inventory() -> list[dict[str, Any]]:
            result = run(["docker", "buildx", "du", "--builder", owned_builder, "--format", "json"], timeout=240)
            if result.returncode:
                raise ValidationError(f"unable to inspect isolated task builder cache: {result.stderr}")
            return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

        def retain_or_reclaim_completed_cache(stage: str, required_free_bytes: int, reason: str) -> None:
            free_before = disk_checkpoint(f"cache-admission:{stage}", manifest)
            before_items = task_builder_cache_inventory()
            if free_before >= required_free_bytes:
                decision = {"stage": stage, "action": "RETAINED", "reason": "next phase admitted without pruning",
                            "required_free_bytes": required_free_bytes, "disk_free_before_bytes": free_before,
                            "builder": owned_builder, "cache_entry_count": len(before_items),
                            "cache_bytes": sum(_reported_size_bytes(str(item.get("Size", "0B")))
                                               for item in before_items)}
                if manifest is not None:
                    manifest.setdefault("build_cache_decisions", []).append(decision)
                    persist_manifest(manifest)
                return
            owner_record = _task_builder_record_for_gate(builder_record, owned_builder)
            if not before_items:
                raise ValidationError(
                    f"{stage} requires {required_free_bytes} bytes; no obsolete task cache exists to reclaim"
                )
            before_by_id = {item.get("ID"): item for item in before_items}
            checked(["docker", "buildx", "prune", "--builder", owned_builder, "--all", "--force"],
                    env=environment, timeout=300, log_path=acceptance_log)
            after_items = task_builder_cache_inventory()
            after_by_id = {item.get("ID"): item for item in after_items}
            free_after = disk_checkpoint(f"after-cache-reclamation:{stage}", manifest)
            decision = {"stage": stage, "action": "RECLAIMED_TASK_CACHE",
                        "reason": reason, "builder": owned_builder,
                        "owner_record": str(builder_record), "owner_record_sha256": sha256_file(builder_record),
                        "required_free_bytes": required_free_bytes,
                        "disk_free_before_bytes": free_before, "disk_free_after_bytes": free_after,
                        "removed_cache_items": [
                            {"ID": key, "Size": item.get("Size"), "Type": item.get("Type")}
                            for key, item in before_by_id.items() if key not in after_by_id],
                        "remaining_cache_items": [{"ID": item.get("ID"), "Size": item.get("Size")}
                                                   for item in after_items]}
            if manifest is not None:
                manifest.setdefault("build_cache_reclamations", []).append(decision)
                manifest.setdefault("build_cache_decisions", []).append(decision)
                persist_manifest(manifest)
            if free_after < required_free_bytes:
                raise ValidationError(
                    f"{stage} still requires {required_free_bytes} bytes after task-cache reclamation; "
                    f"observed {free_after} bytes free"
                )

        primary_error: Exception | None = None
        cleanup: dict[str, Any] = {}
        image_ids: dict[str, str] = {}
        try:
            model = resolved_model(command, environment, log_path=acceptance_log)
            validate_model(model, ec_image, tor_image, caddy_image, fail2ban_image, auth_image, project)
            if not owned_builder:
                raise ValidationError("acceptance requires one isolated task-owned Buildx builder")
            ledger_override = write_hardware_build_override(temporary_path, ledger_image)
            ledger_environment = environment.copy()
            ledger_environment.update({"DISPLAY": ":0", "XAUTHORITY": "/tmp/ecd-ci-xauthority",
                                       "HW_USB_GID": "10001",
                                       "CI_DISK_START_BYTES": str(DISK_HW_WALLET_ADMISSION_BYTES)})
            ledger_command = [
                *canonical_command,
                "-f", str(ROOT / "docker-compose.gui.yml"),
                "-f", str(ROOT / "docker-compose.hw.yml"),
                "-f", str(ledger_override),
            ]
            ledger_model = resolved_model(ledger_command, ledger_environment, log_path=acceptance_log)
            normal_compose_files = [ROOT / "docker-compose.yml"]
            ledger_compose_files = [ROOT / "docker-compose.yml", ROOT / "docker-compose.gui.yml",
                                    ROOT / "docker-compose.hw.yml", ledger_override]

            retain_or_reclaim_completed_cache(
                "normal-wallet-build", DISK_NORMAL_WALLET_ADMISSION_BYTES,
                "the measured normal-wallet admission failed; reclaiming only this task builder's prior-run cache "
                "allows a fresh normal/HW pair to build consecutively with cache hot")
            build_candidate_image(
                service_name="electron-cash", image_key="electron_cash", variant="electron-cash-normal",
                image_ref=ec_image, build_model=model, compose_files=normal_compose_files,
                prefix=canonical_command, build_environment=environment,
                phase_admission_bytes=DISK_NORMAL_WALLET_ADMISSION_BYTES)
            # Keep the exact normal wallet layers hot for the immediately
            # following HW variant; no prune or unrelated image build intervenes.
            build_candidate_image(
                service_name="electron-cash", image_key="ledger", variant="electron-cash-hw",
                image_ref=ledger_image, build_model=ledger_model, compose_files=ledger_compose_files,
                prefix=ledger_command, build_environment=ledger_environment,
                phase_admission_bytes=DISK_HW_WALLET_ADMISSION_BYTES)
            retain_or_reclaim_completed_cache(
                "caddy-image-build", DISK_CADDY_ADMISSION_BYTES,
                "normal and HW wallet configurations have completed their final shared-cache consumer")
            build_candidate_image(
                service_name="caddy", image_key="caddy", variant="caddy", image_ref=caddy_image,
                build_model=model, compose_files=normal_compose_files, prefix=canonical_command,
                build_environment=environment, phase_admission_bytes=DISK_CADDY_ADMISSION_BYTES)
            retain_or_reclaim_completed_cache(
                "auth-session-image-build", DISK_AUTH_SESSION_ADMISSION_BYTES,
                "Caddy has no later build consumer")
            build_candidate_image(
                service_name="auth-session", image_key="auth_session", variant="auth-session",
                image_ref=auth_image, build_model=model, compose_files=normal_compose_files,
                prefix=canonical_command, build_environment=environment,
                phase_admission_bytes=DISK_AUTH_SESSION_ADMISSION_BYTES)
            retain_or_reclaim_completed_cache(
                "fail2ban-image-build", DISK_FAIL2BAN_ADMISSION_BYTES,
                "auth-session has no later build consumer")
            build_candidate_image(
                service_name="fail2ban", image_key="fail2ban", variant="fail2ban",
                image_ref=fail2ban_image, build_model=model, compose_files=normal_compose_files,
                prefix=canonical_command, build_environment=environment,
                phase_admission_bytes=DISK_FAIL2BAN_ADMISSION_BYTES)
            retain_or_reclaim_completed_cache(
                "tor-image-build", DISK_TOR_ADMISSION_BYTES,
                "all Ubuntu wallet/auth/fail2ban configurations are built; Tor uses a distinct pinned base/context")
            build_candidate_image(
                service_name="tor-proxy", image_key="tor", variant="tor-proxy", image_ref=tor_image,
                build_model=model, compose_files=normal_compose_files, prefix=canonical_command,
                build_environment=environment, phase_admission_bytes=DISK_TOR_ADMISSION_BYTES)
            retain_or_reclaim_completed_cache(
                "candidate-image-scans", DISK_IMAGE_SCAN_ADMISSION_BYTES,
                "all positive image builds are complete; no remaining candidate build consumes this cache")
            environment["CI_DISK_START_BYTES"] = str(DISK_IMAGE_SCAN_ADMISSION_BYTES)
            inspected_ids = {
                "electron_cash": checked(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", ec_image],
                    log_path=acceptance_log,
                ).stdout.strip(),
                "tor": checked(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", tor_image],
                    log_path=acceptance_log,
                ).stdout.strip(),
                "caddy": checked(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", caddy_image],
                    log_path=acceptance_log,
                ).stdout.strip(),
                "fail2ban": checked(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", fail2ban_image],
                    log_path=acceptance_log,
                ).stdout.strip(),
                "auth_session": checked(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", auth_image],
                    log_path=acceptance_log,
                ).stdout.strip(),
                "ledger": checked(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", ledger_image],
                    log_path=acceptance_log,
                ).stdout.strip(),
            }
            if not all(inspected_ids.values()):
                raise ValidationError("candidate image ID was empty")
            image_ids.update(inspected_ids)
            for key, image_ref in candidate_images.items():
                docker_ownership.record_image_attempt(registry, image_ref, owner_token, image_ids[key])
            print(f"CANDIDATE_ELECTRON_CASH_IMAGE={ec_image} ID={image_ids['electron_cash']}")
            print(f"CANDIDATE_TOR_IMAGE={tor_image} ID={image_ids['tor']}")
            print(f"CANDIDATE_CADDY_IMAGE={caddy_image} BASE={CADDY_BASE_IMAGE} ID={image_ids['caddy']}")
            print(f"CANDIDATE_FAIL2BAN_IMAGE={fail2ban_image} ID={image_ids['fail2ban']}")
            print(f"CANDIDATE_AUTH_SESSION_IMAGE={auth_image} ID={image_ids['auth_session']}")
            print(f"CANDIDATE_LEDGER_IMAGE={ledger_image} ID={image_ids['ledger']}")

            caddy_dockerfile = (ROOT / "docker/caddy/Dockerfile").read_text(encoding="utf-8")
            if f"FROM {CADDY_BASE_IMAGE}\n" not in caddy_dockerfile:
                raise ValidationError("Caddy Dockerfile does not use the recorded pinned base image")
            remote_environment = environment.copy()
            remote_environment.update(
                {
                    "CADDY_IMAGE": caddy_image,
                    "FAIL2BAN_IMAGE": fail2ban_image,
                    "CI_REMOTE_PROJECT": remote_project,
                    "CI_REMOTE_PORT": str(remote_port),
                    "CADDY_SITE_ADDRESS": "https://wallet.test",
                    "CADDY_TLS_MODE": "internal",
                    "CADDY_EDGE_BIND": "127.0.0.1",
                    "CADDY_HTTP_HOST_PORT": str(free_port()),
                    "CADDY_HTTPS_HOST_PORT": str(remote_port),
                    "ECD_WALLET_VOLUME": f"{remote_project}-wallet",
                    "ECD_TOR_VOLUME": f"{remote_project}-tor",
                }
            )
            remote_command = [
                "docker",
                "compose",
                "--env-file",
                str(ENV_FILE),
                "-p",
                remote_project,
                "-f",
                str(ROOT / "docker-compose.yml"),
            ]
            remote_model = resolved_model(remote_command, remote_environment, log_path=acceptance_log)
            try:
                validate_resolved_model(
                    remote_model,
                    expected_ec_image=ec_image,
                    expected_tor_image=tor_image,
                    expected_caddy_image=caddy_image,
                    expected_fail2ban_image=fail2ban_image,
                    expected_auth_image=auth_image,
                    expected_wallet_volume=f"{remote_project}-wallet",
                    expected_tor_volume=f"{remote_project}-tor",
                    expected_network=f"{remote_project}_electron-network",
                    expected_project=remote_project,
                )
            except UnsafeComposeModel as error:
                raise ValidationError(f"unsafe resolved Compose model: {error}") from error

            if manifest is not None:
                manifest.setdefault("scan_commands", []).extend(
                    [
                        shlex.join(["trivy", "image", "--scanners", "vuln", ec_image]),
                        shlex.join(["trivy", "image", "--scanners", "vuln", tor_image]),
                        shlex.join(["trivy", "image", "--scanners", "vuln", caddy_image]),
                        shlex.join(["trivy", "image", "--scanners", "vuln", fail2ban_image]),
                        shlex.join(["trivy", "image", "--scanners", "vuln", auth_image]),
                        shlex.join(["trivy", "image", "--scanners", "vuln", ledger_image]),
                    ]
                )
            require_build_capacity("before candidate image security scans", manifest,
                                   minimum_free_bytes=DISK_IMAGE_SCAN_ADMISSION_BYTES)
            image_findings = [
                (
                    "image:electron-cash",
                    scan_image(
                        trivy,
                        ec_image,
                        "image:electron-cash",
                        report_dir,
                        cache_dir,
                        raw_directory,
                        report_dir / "trivy-commands.log",
                        manifest=manifest,
                    ),
                ),
                (
                    "image:tor",
                    scan_image(
                        trivy,
                        tor_image,
                        "image:tor",
                        report_dir,
                        cache_dir,
                        raw_directory,
                        report_dir / "trivy-commands.log",
                        manifest=manifest,
                    ),
                ),
                (
                    "image:caddy",
                    scan_image(
                        trivy,
                        caddy_image,
                        "image:caddy",
                        report_dir,
                        cache_dir,
                        raw_directory,
                        report_dir / "trivy-commands.log",
                        report_name="caddy",
                        manifest=manifest,
                    ),
                ),
                (
                    "image:fail2ban",
                    scan_image(
                        trivy,
                        fail2ban_image,
                        "image:fail2ban",
                        report_dir,
                        cache_dir,
                        raw_directory,
                        report_dir / "trivy-commands.log",
                        report_name="fail2ban",
                        manifest=manifest,
                    ),
                ),
                (
                    "image:auth-session",
                    scan_image(
                        trivy,
                        auth_image,
                        "image:auth-session",
                        report_dir,
                        cache_dir,
                        raw_directory,
                        report_dir / "trivy-commands.log",
                        report_name="auth-session",
                        manifest=manifest,
                    ),
                ),
                (
                    "image:ledger",
                    scan_image(
                        trivy,
                        ledger_image,
                        "image:ledger",
                        report_dir,
                        cache_dir,
                        raw_directory,
                        report_dir / "trivy-commands.log",
                        report_name="ledger",
                        manifest=manifest,
                    ),
                ),
            ]
            require_build_capacity("after candidate image security scans", manifest,
                                   minimum_free_bytes=DISK_IMAGE_SCAN_ADMISSION_BYTES)
            retain_or_reclaim_completed_cache(
                "runtime-acceptance", DISK_RUNTIME_ADMISSION_BYTES,
                "all candidate builds and image scans are complete; runtime suites consume output images, not BuildKit cache")
            policy_manifest = manifest or {"report_dir": str(report_dir),
                "candidate": candidate_identity(report_dir), "candidate_image_ids": image_ids}
            package_deps = checked(["docker", "run", "--rm", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint", "cat",
                caddy_image, "/etc/caddy/package-deps"], env=environment, timeout=60,
                log_path=report_dir / "inventory-commands.log").stdout
            (report_dir / "caddy-package-deps.txt").write_text(package_deps)
            require_fresh_trivy_database(cache_dir, policy_manifest)
            enforce_vulnerability_policy(image_findings, exceptions, report_dir, policy_manifest)
            validate_exception_usage(exceptions, policy_manifest, report_dir)
            policy_manifest['candidate_image_ids'] = image_ids
            persist_manifest(policy_manifest)
            try:
                release_security.inventory(sys.modules[__name__], candidate_images, image_ids,
                                           report_dir, environment, trivy)
                release_security.await_external_review(report_dir, policy_manifest)
                record_step(policy_manifest, "official-advisory-source-evaluated-preflight",
                            lambda: release_security.official_preflight(report_dir, manifest=policy_manifest))
                record_step(policy_manifest, "component-inventory-and-official-advisory-assessment",
                            lambda: release_security.complete_security(
                                sys.modules[__name__], candidate_images, image_ids, report_dir,
                                environment, trivy, policy_manifest))
            except release_security.SecurityBlocked as error:
                policy_manifest["failure_kind"] = "INFRA_FAILURE"
                persist_manifest(policy_manifest)
                raise ValidationError(str(error)) from error
            except release_security.SecurityFailure as error:
                raise ValidationError(str(error)) from error
            if manifest is not None:
                trivy_version(trivy, report_dir, manifest)
                manifest["acceptance_test_results"].append(
                    {"test": "test_integrity_pins.py", "status": "RUNNING"}
                )
                persist_manifest(manifest)
            require_build_capacity("before integrity and supply-chain acceptance", manifest,
                                   minimum_free_bytes=DISK_RUNTIME_ADMISSION_BYTES)
            checked(
                [sys.executable, str(ROOT / "tests" / "test_integrity_pins.py")],
                env=environment,
                timeout=180,
                log_path=acceptance_log,
                disk_floor_bytes=DISK_FLOOR_BYTES,
                manifest=manifest,
            )
            require_disk_floor("after integrity and supply-chain acceptance", manifest)
            if manifest is not None:
                manifest["acceptance_test_results"][-1]["status"] = "PASS"
                persist_manifest(manifest)
            for test in acceptance_tests:
                skip_reason = acceptance_skip_reason(test)
                if skip_reason:
                    record_acceptance_skip(manifest, test, skip_reason)
                    continue
                retain_or_reclaim_completed_cache(
                    f"runtime-acceptance:{test}", DISK_RUNTIME_ADMISSION_BYTES,
                    f"runtime suite {test} does not consume BuildKit cache; reclaim only if measured admission is lost")
                if manifest is not None:
                    manifest["acceptance_test_results"].append(
                        {"test": test, "status": "RUNNING"}
                    )
                    persist_manifest(manifest)
                try:
                    if test == "test_auth_browser.py":
                        browser_environment = remote_environment.copy()
                        browser_environment.update(
                            {
                                "CI_BROWSER_URL": f"https://wallet.test:{remote_port}",
                                "CI_BROWSER_IGNORE_HTTPS": "1",
                                "BROWSER_AUTH_USERNAME": "wallet",
                                "BROWSER_AUTH_PASSWORD": "synthetic-auth-secret",
                            }
                        )
                        checked(
                            [*remote_command, "up", "-d", "--no-build"],
                            env=remote_environment,
                            timeout=180,
                            log_path=acceptance_log,
                            disk_floor_bytes=DISK_FLOOR_BYTES,
                            manifest=manifest,
                        )
                        try:
                            checked(
                                [sys.executable, str(ROOT / "tests" / test)],
                                env=browser_environment,
                                timeout=600,
                                log_path=acceptance_log,
                                disk_floor_bytes=DISK_FLOOR_BYTES,
                                manifest=manifest,
                            )
                        finally:
                            checked(
                                [*remote_command, "down", "--volumes", "--remove-orphans"],
                                env=remote_environment,
                                timeout=180,
                                log_path=acceptance_log,
                            )
                    else:
                        checked(
                            [sys.executable, str(ROOT / "tests" / test)],
                            env=environment,
                            timeout=3600 if test in {"test_first_install.py", "test_gui_session_lifecycle.py", "test_auth_recovery.py"} else 1800,
                            log_path=acceptance_log,
                            disk_floor_bytes=DISK_FLOOR_BYTES,
                            manifest=manifest,
                        )
                    require_disk_floor(f"after acceptance runtime {test}", manifest)
                except Exception as error:
                    if manifest is not None:
                        failure_text = sanitize(str(error))
                        failure_kind = acceptance_failure_kind(test, failure_text)
                        manifest["acceptance_test_results"][-1].update(
                            {"status": "FAIL", "failure_kind": failure_kind, "error": failure_text}
                        )
                        persist_manifest(manifest)
                    raise
                if manifest is not None:
                    manifest["acceptance_test_results"][-1]["status"] = "PASS"
                    persist_manifest(manifest)
            if manifest is not None:
                manifest["acceptance_test_results"].append(
                    {"test": REMOTE_ACCEPTANCE_TEST, "status": "RUNNING"}
                )
                persist_manifest(manifest)
            try:
                require_build_capacity(f"before acceptance runtime {REMOTE_ACCEPTANCE_TEST}", manifest,
                                       minimum_free_bytes=DISK_RUNTIME_ADMISSION_BYTES)
                checked(
                    [sys.executable, str(ROOT / "tests" / REMOTE_ACCEPTANCE_TEST)],
                    env=remote_environment,
                    timeout=1800,
                    log_path=acceptance_log,
                    disk_floor_bytes=DISK_FLOOR_BYTES,
                    manifest=manifest,
                )
                require_disk_floor(f"after acceptance runtime {REMOTE_ACCEPTANCE_TEST}", manifest)
            except Exception as error:
                if manifest is not None:
                    manifest["acceptance_test_results"][-1].update(
                        {"status": "FAIL", "error": sanitize(str(error))}
                    )
                    persist_manifest(manifest)
                raise
            if manifest is not None:
                manifest["acceptance_test_results"][-1]["status"] = "PASS"
                persist_manifest(manifest)
            if run_public_acceptance:
                if manifest is not None:
                    manifest["acceptance_test_results"].append(
                        {"test": PUBLIC_ACCEPTANCE_TEST, "status": "RUNNING"}
                    )
                    persist_manifest(manifest)
                try:
                    require_build_capacity(f"before acceptance runtime {PUBLIC_ACCEPTANCE_TEST}", manifest,
                                           minimum_free_bytes=DISK_RUNTIME_ADMISSION_BYTES)
                    checked(
                        [sys.executable, str(ROOT / "tests" / PUBLIC_ACCEPTANCE_TEST)],
                        env=environment,
                        timeout=180,
                        log_path=acceptance_log,
                        disk_floor_bytes=DISK_FLOOR_BYTES,
                        manifest=manifest,
                    )
                    require_disk_floor(f"after acceptance runtime {PUBLIC_ACCEPTANCE_TEST}", manifest)
                except Exception as error:
                    if manifest is not None:
                        manifest["acceptance_test_results"][-1].update(
                            {"status": "FAIL", "error": sanitize(str(error))}
                        )
                        manifest["optional_public_acceptance"] = "FAIL"
                        persist_manifest(manifest)
                    raise
                if manifest is not None:
                    manifest["acceptance_test_results"][-1]["status"] = "PASS"
                    persist_manifest(manifest)
                if manifest is not None:
                    manifest["optional_public_acceptance"] = "PASS"
                    persist_manifest(manifest)
            if manifest is not None:
                validate_mandatory_acceptance_results(manifest.get("acceptance_test_results", []))
            candidate_refs = {"electron_cash": ec_image, "tor": tor_image, "caddy": caddy_image,
                              "fail2ban": fail2ban_image, "auth_session": auth_image, "ledger": ledger_image}
            for key, reference in candidate_refs.items():
                current_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                                     env=environment, log_path=acceptance_log).stdout.strip()
                if current_id != image_ids.get(key):
                    raise ValidationError(f"candidate image identity changed during acceptance: {reference}")
            print("PASS complete acceptance against freshly built wallet, Tor, Caddy, and fail2ban images")
        except Exception as error:
            primary_error = error
        finally:
            resource_events: list[dict[str, Any]] = []
            builder_cache_cleanup = {"attempted": False, "status": "RETAINED"}
            try:
                _task_builder_record_for_gate(builder_record, owned_builder)
            except Exception as error:
                builder_cache_cleanup.update({"status": "FAIL", "error": sanitize(str(error))})
            claims = registry_entries(registry)
            capture_failures = capture_attempted_image_ids(registry, owner_token)
            cleanup = cleanup_registry(registry, owner_token)
            cleanup["task_builder_cache_cleanup"] = builder_cache_cleanup
            preexisting_image_ids = {item.get("ID") for item in protected_before.get("images", [])
                                     if item.get("ID")}
            cleanup["images"] = cleanup_images(registry, owner_token, preexisting_image_ids)
            cleanup["image_capture_failures"] = capture_failures
            cleanup["dangling_images"] = cleanup_candidate_dangling_images(claims)
            try:
                cleanup["task_builder_state_after_cleanup"] = refresh_task_builder_record(
                    builder_record, owned_builder)
                cleanup["disk_free_after_cleanup_bytes"] = disk_checkpoint(
                    "after-owned-resource-cleanup", manifest)
                cleanup["disk_storage_after_cleanup"] = disk_storage_samples()
                if cleanup["disk_free_after_cleanup_bytes"] <= DISK_FLOOR_BYTES:
                    cleanup["failures"].append(
                        f"free space reached the {DISK_FLOOR_BYTES}-byte hard reserve after owned-resource cleanup")
            except Exception as error:
                cleanup["failures"].append("post-cleanup disk/builder verification failed: " + sanitize(str(error)))
            cleanup["task_builder_cache_cleanup"] = builder_cache_cleanup
            cleanup["test_failures"] = read_cleanup_failures(cleanup_failure_file)
            cleanup["resource_postcondition"] = verify_registry_postcondition(registry, owner_token)
            resource_event_path = Path(environment["CI_RESOURCE_EVENT_LOG"])
            try:
                resource_events = read_resource_events(resource_event_path, owner_token)
                cleanup["docker_resource_events"] = {
                    "path": str(resource_event_path), "sha256": sha256_file(resource_event_path)
                    if resource_event_path.is_file() else None,
                    "count": len(resource_events), "events": resource_events}
                denied_events = [event for event in resource_events
                                 if event.get("kind") == "cleanup-denied-or-unverifiable" or
                                 (event.get("kind") == "docker-build-disk-usage" and
                                  (event.get("aborted_at_floor") or event.get("returncode") != 0))]
                if denied_events:
                    cleanup["failures"].append(f"Docker owner/disk guard events require review: {denied_events}")
                cleanup["removed_resources"] = [
                    *cleanup.get("removed_resources", []),
                    *cleanup["images"].get("removed_resources", []),
                    *removed_resource_events(resource_events),
                ]
            except Exception as error:
                cleanup["docker_resource_events"] = {"path": str(resource_event_path),
                                                       "error": sanitize(str(error))}
                cleanup["failures"].append("Docker resource-removal evidence is invalid")
            cleanup["failures"].extend(cleanup["images"]["failures"])
            cleanup["failures"].extend(cleanup["dangling_images"]["failures"])
            cleanup["failures"].extend(
                f"test cleanup: {failure}" for failure in cleanup["test_failures"]
            )
            cleanup["failures"].extend(cleanup["resource_postcondition"])
            if builder_cache_cleanup["status"] == "FAIL":
                cleanup["failures"].append("task-owned Buildx cache cleanup failed")
            protected_failures: list[str] = []
            try:
                task_builder_record = refresh_task_builder_record(builder_record, owned_builder)
                task_resources = task_builder_record.get("resources", {})
                if (task_resources.get("container_id") and
                        task_resources.get("container_status") != "running"):
                    protected_failures.append("task-owned BuildKit container is not running after acceptance")
                task_builder_identity = {"name": owned_builder,
                                         "container_id": task_resources.get("container_id"),
                                         "volume_names": task_resources.get("volumes") or [],
                                         "image_ids": sorted({claim["expected_id"] for claim in
                                             registry_entries(registry)
                                             if claim.get("kind") == "image" and
                                             claim.get("owner_token") == owner_token and
                                             claim.get("retain") is True and claim.get("expected_id")})}
                docker_after = capture_docker_protection_state()
                after_path = report_dir / "docker-protection-after.json"
                write_private_json(after_path, docker_after)
                preflight = protection_info
                immutable_snapshots = []
                baseline_path = None
                baseline_sha256 = None
                if (isinstance(preflight, dict) and isinstance(preflight.get("sha256"), str) and
                        isinstance(preflight.get("confirmation_sha256"), str)):
                    baseline_path = report_dir / "docker-protection-preflight.json"
                    baseline_sha256 = preflight["sha256"]
                    immutable_snapshots.append((report_dir / "docker-protection-preflight-confirmation.json",
                                                preflight["confirmation_sha256"]))
                protected_failures.extend(verify_gate_protection_state(
                    protected_before, docker_after, task_builder=task_builder_identity,
                    baseline_path=baseline_path, baseline_sha256=baseline_sha256,
                    immutable_snapshots=immutable_snapshots))
                protected_image_ids_before = {f"{item.get('repository')}:{item.get('tag')}": item.get("ID")
                                              for item in protected_before["images"]}
                protected_image_ids_after = {f"{item.get('repository')}:{item.get('tag')}": item.get("ID")
                                             for item in docker_after["images"]}
                build_minimums = [int(event["minimum_free_bytes"]) for event in resource_events
                                  if event.get("kind") == "docker-build-disk-usage" and
                                  isinstance(event.get("minimum_free_bytes"), int)]
                manifest_minimum = (manifest or {}).get("minimum_observed_free_bytes")
                if isinstance(manifest_minimum, int):
                    build_minimums.append(manifest_minimum)
                minimum_free = min([int(protected_before["root_filesystem"]["free_bytes"]),
                                    int(protection_info.get("free_bytes", protected_before["root_filesystem"]["free_bytes"])),
                                    int(protected_build_start["root_filesystem"]["free_bytes"]),
                                    int(docker_after["root_filesystem"]["free_bytes"]),
                                    *build_minimums])
                if manifest is not None:
                    prior_minimum = manifest.get("minimum_observed_free_bytes")
                    manifest["minimum_observed_free_bytes"] = min(
                        minimum_free, prior_minimum if isinstance(prior_minimum, int) else minimum_free)
                preflight_record = protection_info
                cleanup["protected_state"] = {
                    "before_report": str(report_dir / "docker-protection-before.json"),
                    "build_start_report": str(report_dir / "docker-protection-build-start.json"),
                    "gate_preflight_report": (preflight_record.get("report")
                                              if isinstance(preflight_record, dict) else None),
                    "after_report": str(after_path),
                    "before_sha256": sha256_file(report_dir / "docker-protection-before.json"),
                    "build_start_sha256": sha256_file(report_dir / "docker-protection-build-start.json"),
                    "after_sha256": sha256_file(after_path),
                    "protected_image_ids_before": protected_image_ids_before,
                    "protected_image_ids_after": protected_image_ids_after,
                    "protected_container_image_ids_before": {
                        item["name"]: {"configured_image": item["configured_image"], "image_id": item["image_id"],
                                       "status": item["status"], "health": item["health"]}
                        for item in protected_before["containers"]},
                    "protected_container_image_ids_after": {
                        item["name"]: {"configured_image": item["configured_image"], "image_id": item["image_id"],
                                       "status": item["status"], "health": item["health"]}
                        for item in docker_after["containers"] if item["name"] in
                        {before_item["name"] for before_item in protected_before["containers"]}},
                    "task_owned_builder": task_builder_record,
                    "telemetry_differences": {
                        "gate_start_confirmation": (preflight_record.get("telemetry_differences", [])
                                                     if isinstance(preflight_record, dict) else []),
                        "before_task_resources": (manifest or {}).get(
                            "docker_protection_telemetry_before_acceptance",
                            (preflight_record or {}).get("telemetry_differences", [])),
                        "gate_start_to_after_cleanup": docker_ownership.compare_snapshot_telemetry(
                            protected_before, docker_after),
                    },
                    "disk_free_before_bytes": protected_build_start["root_filesystem"]["free_bytes"],
                    "disk_free_gate_start_bytes": protected_before["root_filesystem"]["free_bytes"],
                    "disk_free_after_bytes": docker_after["root_filesystem"]["free_bytes"],
                    "minimum_observed_free_bytes": minimum_free,
                    "failures": protected_failures,
                }
            except Exception as error:
                protected_failures = [f"protected Docker state verification failed: {sanitize(str(error))}"]
                cleanup["protected_state"] = {"failures": protected_failures}
            cleanup["failures"].extend(protected_failures)
            cleanup["overall"] = "PASS" if not cleanup["failures"] else "FAIL"
            json_write(report_dir / "cleanup.json", cleanup)
            if manifest is not None:
                manifest["candidate_image_ids"] = image_ids
                manifest["cleanup"] = cleanup
                manifest["trivy_database"] = trivy_database_metadata(cache_dir)
                persist_manifest(manifest)
        if primary_error is not None:
            if cleanup["failures"]:
                raise ValidationError(
                    f"acceptance failed: {primary_error}; cleanup also failed: {cleanup['failures']}"
                ) from primary_error
            raise primary_error
        if cleanup["failures"]:
            raise ValidationError(f"acceptance cleanup failed: {cleanup['failures']}")
    return {"images": image_ids, "cleanup": cleanup}


def gate() -> int:
    run_id = new_run_id()
    report_dir = report_directory(run_id)
    identity = candidate_identity(report_dir)
    manifest: dict[str, Any] = {
        "schema_version": 2,
        "run_id": run_id,
        "started_at": utc_now(),
        "report_dir": str(report_dir),
        "overall_status": "RUNNING",
        "mandatory_acceptance_tests": list(MANDATORY_ACCEPTANCE_TESTS),
        "optional_public_acceptance": "NOT_RUN_OPTIONAL",
        "disk_budget": {
            "hard_floor_bytes": DISK_FLOOR_BYTES,
            "cancel_trigger_bytes": DISK_CANCEL_TRIGGER_BYTES,
            "cancellation_headroom_bytes": DISK_CANCELLATION_HEADROOM_BYTES,
            "phase_peak_estimates_bytes": {
                "builder_bootstrap": DISK_BUILDKIT_BOOTSTRAP_PEAK_BYTES,
                "normal_wallet": DISK_NORMAL_WALLET_PEAK_BYTES,
                "hardware_wallet_incremental": DISK_HW_WALLET_INCREMENTAL_PEAK_BYTES,
                "tor": DISK_TOR_IMAGE_PEAK_BYTES,
                "auth_session": DISK_AUTH_SESSION_PEAK_BYTES,
                "caddy": DISK_CADDY_IMAGE_PEAK_BYTES,
                "fail2ban": DISK_FAIL2BAN_IMAGE_PEAK_BYTES,
                "image_scans": DISK_IMAGE_SCAN_PEAK_BYTES,
                "runtime_acceptance": DISK_RUNTIME_PEAK_BYTES,
                "sast": DISK_SAST_PEAK_BYTES,
            },
            "phase_admissions_bytes": DISK_PHASE_ADMISSIONS_BYTES,
            "after_cleanup_hard_reserve_bytes": DISK_FLOOR_BYTES,
            "build_mode": ("--pull --no-cache; normal and HW wallets consecutive" if os.environ.get("CI_FRESH_BUILD") == "1"
                           else "cache-aware; normal and HW wallets consecutive; unique configurations built once"),
            "peak_estimates_are_measured": False,
            "peak_estimate_note": "Phase peaks are conservative admission estimates; actual samples are recorded per phase.",
        },
        "candidate": identity,
        "tools": tool_snapshot(),
        "commands": [
            "./scripts/ci.sh gate",
            "./scripts/ci.sh fast",
            "./scripts/ci.sh sast",
            "./scripts/dependency-review.sh v0.4",
            "./scripts/ci.sh acceptance",
        ],
        "execution_graph": [
            "fast",
            "local SAST",
            "source vulnerability scan",
            "source secret scan",
            "clean candidate build",
            "image vulnerability scans",
            "v0.2.1 regression acceptance",
            "generic backup/restore and network lifecycle acceptance",
            "fresh public Compose first install, browser login/WebSocket, and warm persistence",
            "Linux local-Xauthority Compose GUI on authenticated external Xvfb",
            "macOS XQuartz wrapper contracts and synthetic Ledger backend",
            "local dependency review against v0.4",
            "cleanup and resource postcondition",
        ],
        "fast_log": str(report_dir / "fast.log"),
    }
    if os.environ.get("PUBLIC_ACCEPTANCE") == "1":
        manifest["commands"].append("PUBLIC_ACCEPTANCE=1 ./scripts/ci.sh gate")
        manifest["execution_graph"].append("public Cloudflare HTTPS/WSS acceptance")
    json_write(report_dir / "candidate-identity.json", identity)
    persist_manifest(manifest)
    try:
        validate_mandatory_acceptance_registration()
        assert_safe_docker_endpoint(log_path=report_dir / "acceptance.log")
        docker_preflight = capture_docker_protection_state()
        docker_preflight_path = report_dir / "docker-protection-preflight.json"
        preflight_sha256 = write_immutable_private_json(docker_preflight_path, docker_preflight)
        confirmation_path = report_dir / "docker-protection-preflight-confirmation.json"
        manifest["docker_protection_preflight"] = {
            "report": str(docker_preflight_path), "sha256": preflight_sha256,
            "confirmation_report": str(confirmation_path), "status": "CONFIRMATION_PENDING"}
        persist_manifest(manifest)
        docker_confirmation = capture_docker_protection_state()
        confirmation_sha256 = write_immutable_private_json(confirmation_path, docker_confirmation)
        drift = verify_gate_protection_state(
            docker_preflight, docker_confirmation,
            task_builder={"name": None, "container_id": None, "volume_names": []},
            baseline_path=docker_preflight_path, baseline_sha256=preflight_sha256)
        telemetry_drift = docker_ownership.compare_snapshot_telemetry(docker_preflight, docker_confirmation)
        free_before = min(int(docker_preflight["root_filesystem"]["free_bytes"]),
                          int(docker_confirmation["root_filesystem"]["free_bytes"]))
        manifest["docker_protection_preflight"] = {
            "report": str(docker_preflight_path), "sha256": preflight_sha256,
            "confirmation_report": str(confirmation_path), "confirmation_sha256": confirmation_sha256,
            "free_bytes": free_before, "minimum_required_bytes": DISK_FLOOR_BYTES,
            "status": ("FOREIGN_STATE_DRIFT" if drift else
                       "BLOCKED_HARD_FLOOR" if free_before <= DISK_FLOOR_BYTES else "PASS"),
            "drift": drift, "telemetry_differences": telemetry_drift}
        if drift:
            manifest["error"] = "FOREIGN_STATE_DRIFT: consecutive gate-start Docker snapshots differ: " + "; ".join(drift)
            manifest["overall_status"] = "FAIL"
            manifest["finished_at"] = utc_now()
            finalize_manifest(manifest)
            print(f"FAIL FOREIGN_STATE_DRIFT before resource creation; evidence={report_dir}", file=sys.stderr)
            return 1
        if free_before <= DISK_FLOOR_BYTES:
            manifest["error"] = (
                f"gate halted at hard floor before any build: {free_before} bytes free; "
                f"hard floor is {DISK_FLOOR_BYTES} bytes"
            )
            manifest["overall_status"] = "FAIL"
            manifest["finished_at"] = utc_now()
            finalize_manifest(manifest)
            print(f"FAIL provider-independent gate preflight; evidence={report_dir}", file=sys.stderr)
            return 1
        persist_manifest(manifest)
    except Exception as error:
        manifest["error"] = "Docker protection/capacity preflight failed: " + sanitize(str(error))
        manifest["overall_status"] = "FAIL"
        manifest["finished_at"] = utc_now()
        finalize_manifest(manifest)
        print(f"FAIL provider-independent gate preflight; evidence={report_dir}", file=sys.stderr)
        return 1
    result = 0
    try:
        record_step(manifest, "fast", lambda: fast(log_path=report_dir / "fast.log"))
        try:
            record_step(manifest, "official-advisory-source-preflight",
                        lambda: release_security.official_preflight(report_dir, refresh_only=True, manifest=manifest))
        except release_security.SecurityBlocked as error:
            manifest["failure_kind"] = "INFRA_FAILURE"
            raise ValidationError(str(error)) from error
        except release_security.SecurityFailure as error:
            raise ValidationError(str(error)) from error
        require_build_capacity("before local SAST", manifest,
                               minimum_free_bytes=DISK_SAST_ADMISSION_BYTES)
        record_step(manifest, "local-sast", lambda: run_sast(report_dir, manifest))
        require_build_capacity("after local SAST", manifest,
                               minimum_free_bytes=DISK_SAST_ADMISSION_BYTES)
        exceptions = load_vulnerability_exceptions()
        manifest["exception_authority"] = {
            "path": str(EXCEPTION_FILE),
            "sha256": sha256_file(EXCEPTION_FILE),
            "exceptions": len(exceptions),
        }
        persist_manifest(manifest)
        with tempfile.TemporaryDirectory(
            prefix="bchforge-v021-gate-", dir=report_dir.parent
        ) as temporary:
            tooling = Path(temporary)
            require_build_capacity("before Trivy setup", manifest,
                                   minimum_free_bytes=DISK_IMAGE_SCAN_ADMISSION_BYTES)
            trivy = ensure_trivy(tooling / "trivy")
            cache_dir = trivy_cache_directory()
            trivy_version(trivy, report_dir, manifest)
            require_build_capacity("before source scans", manifest,
                                   minimum_free_bytes=DISK_IMAGE_SCAN_ADMISSION_BYTES)
            record_step(
                manifest,
                "source-scans-and-vulnerability-policy",
                lambda: scan_source(
                    trivy,
                    report_dir,
                    cache_dir,
                    tooling / "raw-reports",
                    exceptions,
                    manifest,
                ),
            )
            require_build_capacity("after source scans", manifest,
                                   minimum_free_bytes=DISK_IMAGE_SCAN_ADMISSION_BYTES)
            record_step(
                manifest,
                "acceptance",
                lambda: acceptance(
                    report_dir=report_dir,
                    manifest=manifest,
                    trivy=trivy,
                    cache_dir=cache_dir,
                    raw_directory=tooling / "raw-reports",
                ),
            )
        record_step(
            manifest,
            "dependency-review",
            lambda: run_dependency_review("v0.4", report_dir, manifest),
        )
        record_step(manifest, "final-resource-postcondition", lambda: verify_gate_postcondition(manifest))
    except (ValidationError, subprocess.TimeoutExpired, OSError) as error:
        manifest["error"] = sanitize(str(error))
        failure_kind = gate_failure_kind(error)
        if failure_kind:
            manifest["failure_kind"] = failure_kind
        result = 1
    except Exception as error:
        manifest["error"] = sanitize(f"unexpected error: {error}")
        failure_kind = gate_failure_kind(error)
        if failure_kind:
            manifest["failure_kind"] = failure_kind
        result = 1
    finally:
        if not any(
            step.get("name") == "final-resource-postcondition"
            for step in manifest.get("steps", [])
        ):
            try:
                record_step(
                    manifest,
                    "final-resource-postcondition",
                    lambda: verify_gate_postcondition(manifest),
                )
            except Exception as error:
                manifest["postcondition_error"] = sanitize(str(error))
                result = 1
        try:
            manifest["final_candidate"] = candidate_identity(report_dir)
            require_frozen_candidate(identity, manifest["final_candidate"])
        except Exception as error:
            manifest["final_identity_error"] = sanitize(str(error))
            result = 1
        manifest["overall_status"] = gate_overall_status(manifest, result)
        if manifest["overall_status"] != "PASS":
            result = 1
        manifest["finished_at"] = utc_now()
        finalize_manifest(manifest)
    if manifest["overall_status"] == "PASS":
        print(f"PASS provider-independent gate; evidence={report_dir}")
    elif manifest["overall_status"] == "BLOCKED":
        print(f"BLOCKED provider-independent gate by external infrastructure; evidence={report_dir}",
              file=sys.stderr)
    else:
        print(f"FAIL provider-independent gate; evidence={report_dir}", file=sys.stderr)
    return result


def verify_gate_postcondition(manifest: dict[str, Any]) -> None:
    cleanup = manifest.get("cleanup")
    if not isinstance(cleanup, dict):
        raise ValidationError("acceptance did not produce cleanup evidence")
    failures = cleanup.get("failures") or []
    if failures:
        raise ValidationError(f"gate-owned resource cleanup failed: {failures}")
    if cleanup.get("overall") != "PASS":
        raise ValidationError("cleanup evidence did not report PASS")
    try:
        release_security.verify_completion(manifest, Path(manifest["report_dir"]))
    except (release_security.SecurityFailure, release_security.SecurityBlocked) as error:
        raise ValidationError(str(error)) from error


def main() -> int:
    if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE", "0") not in ("", "0"):
        print("FAIL validation requires Python assertions; unset PYTHONOPTIMIZE and do not use -O", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("fast", "sast", "acceptance", "gate"))
    args = parser.parse_args()
    if args.mode == "gate":
        return gate()
    try:
        if args.mode == "fast":
            fast()
        elif args.mode == "sast":
            run_sast(sast_report_directory())
        else:
            acceptance()
    except (ValidationError, subprocess.TimeoutExpired, OSError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

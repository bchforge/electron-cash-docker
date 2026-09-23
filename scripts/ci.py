#!/usr/bin/env python3
"""Canonical provider-independent validation for Electron Cash Docker."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import shlex
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from compose_guard import UnsafeComposeModel, validate_resolved_model
from dependency_review import run_dependency_review
from sast import default_report_directory as sast_report_directory
from sast import run_sast


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
EXCEPTION_FILE = ROOT / "security" / "vulnerability-exceptions.json"
TRIVY_VERSION = "0.74.0"
TRIVY_ARCHIVE_SHA256 = "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
TRIVY_ARCHIVE = f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz"
HIGH_SEVERITIES = {"HIGH", "CRITICAL"}
BASELINE_HEAD = "f63c037ed73e881a5b4ef8238a046ad36eb03dc8"
CADDY_BASE_IMAGE = "caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
ACCEPTANCE_TESTS = (
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
    "test_tor_proxy.py",
    "test_backup_restore.py",
    "test_backup_wrapper.py",
    "test_backup_acceptance.py",
)
REMOTE_ACCEPTANCE_TEST = "test_remote_access.py"
PUBLIC_ACCEPTANCE_TEST = "test_public_access.py"


class ValidationError(RuntimeError):
    """A validation check failed."""


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
    for raw_path in source_file_paths(report_dir):
        path = ROOT / raw_path
        if not path.exists() and not path.is_symlink():
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

    untracked = [
        record
        for record in records
        if git_text(["git", "ls-files", "--others", "--exclude-standard", "--", record["path"]])
    ]
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
        baseline = git_text(["git", "rev-parse", "v0.2.1^{commit}"])
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
        )):
            raise ValidationError("security exception contains an empty or invalid text field")
        if exception["severity"].upper() not in HIGH_SEVERITIES:
            raise ValidationError("security exception severity must be HIGH or CRITICAL")
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
            if severity not in HIGH_SEVERITIES:
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


def checked(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"[ci] {shutil.which(command[0]) or command[0]} {' '.join(command[1:])}")
    result = run(command, env=env, timeout=timeout)
    if log_path is not None:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {shlex.join(command)}\n")
            handle.write(sanitize(result.stdout + result.stderr) + "\n")
    if result.returncode != 0:
        raise ValidationError(
            f"command failed ({result.returncode}):\n{sanitize(result.stdout + result.stderr)}"
        )
    return result


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
    host = endpoint.get("Host", "") if isinstance(endpoint, dict) else ""
    if host and not host.startswith("unix://"):
        raise ValidationError(f"Docker endpoint is not local Unix-socket transport: {host}")
    if any(value in host.lower() for value in ("pro0", "production")):
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
    suffix = f"{os.environ.get('CI_RUN_ID', 'local')}-{uuid.uuid4().hex[:12]}".lower()
    return (
        f"electron-cash-ci:{suffix}",
        f"bchforge/electron-cash-docker-tor-ci:{suffix}",
        f"electron-cash-auth-session-ci:{suffix}",
        f"bchforge-v021-{suffix}",
    )


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
    checked([sys.executable, str(ROOT / "tests" / "test_fast.py")], log_path=log_path)
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

    archive_path = directory / TRIVY_ARCHIVE
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{TRIVY_ARCHIVE}"
    print(f"[ci] downloading pinned Trivy {TRIVY_VERSION}")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, archive_path.open("wb") as output:
            shutil.copyfileobj(response, output)
    except Exception as error:
        raise ValidationError(f"unable to download Trivy {TRIVY_VERSION}: {error}") from error
    import hashlib

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if digest != TRIVY_ARCHIVE_SHA256:
        raise ValidationError("Trivy archive SHA-256 verification failed")
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extract("trivy", directory)
    path = directory / "trivy"
    path.chmod(0o755)
    return path


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
    if command_log is not None:
        with command_log.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {shlex.join(invocation)}\n")
    result = run(
        invocation,
        env=environment,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise ValidationError(f"Trivy failed for {' '.join(command)}:\n{sanitize(result.stdout + result.stderr)}")
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
            "HIGH,CRITICAL",
            str(ROOT),
        ],
        vulnerability_report,
        raw_directory,
        timeout=900,
        command_log=command_log,
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
            "HIGH,CRITICAL",
            image,
        ],
        report,
        raw_directory,
        timeout=900,
        command_log=command_log,
    )
    return extract_vulnerabilities(document)


def registry_entries(registry: Path) -> list[tuple[str, str]]:
    if not registry.exists():
        return []
    entries = []
    for line in registry.read_text(encoding="utf-8").splitlines():
        kind, _, name = line.partition("\t")
        if kind and name:
            entries.append((kind, name))
    return list(dict.fromkeys(entries))


def cleanup_registry(registry: Path) -> dict[str, Any]:
    entries = registry_entries(registry)
    projects = sorted({name for kind, name in entries if kind == "project"})
    volumes = sorted({name for kind, name in entries if kind == "volume"})
    containers = sorted({name for kind, name in entries if kind == "container"})
    networks = sorted({name for kind, name in entries if kind == "network"})
    attempts: list[dict[str, Any]] = []
    failures: list[str] = []

    def execute(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        result = run(command, timeout=timeout)
        attempts.append(
            {
                "command": shlex.join(command),
                "returncode": result.returncode,
                "stderr": sanitize(result.stderr),
            }
        )
        if result.returncode != 0:
            failures.append(f"{shlex.join(command)} returned {result.returncode}")
        return result

    for project in projects:
        project_containers = execute(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
            timeout=60,
        )
        container_ids = project_containers.stdout.split() if project_containers.returncode == 0 else []
        if container_ids:
            execute(["docker", "rm", "-f", *container_ids])
        project_networks = execute(
            ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
            timeout=60,
        )
        network_ids = project_networks.stdout.split() if project_networks.returncode == 0 else []
        if network_ids:
            execute(["docker", "network", "rm", *network_ids])
    existing_volumes = []
    for volume in volumes:
        inspected = run(["docker", "volume", "inspect", volume], timeout=60)
        if inspected.returncode == 0:
            existing_volumes.append(volume)
        elif inspected.returncode != 1:
            failures.append(f"unable to inspect volume {volume}")
    if existing_volumes:
        execute(["docker", "volume", "rm", *existing_volumes])
    existing_containers = []
    for container in containers:
        inspected = run(["docker", "inspect", container], timeout=60)
        if inspected.returncode == 0:
            existing_containers.append(container)
        elif inspected.returncode != 1:
            failures.append(f"unable to inspect container {container}")
    if existing_containers:
        execute(["docker", "rm", "-f", *existing_containers])
    existing_networks = []
    for network in networks:
        inspected = run(["docker", "network", "inspect", network], timeout=60)
        if inspected.returncode == 0:
            existing_networks.append(network)
        elif inspected.returncode != 1:
            failures.append(f"unable to inspect network {network}")
    if existing_networks:
        execute(["docker", "network", "rm", *existing_networks])

    return {
        "owned_resources": [
            {"kind": kind, "name": name} for kind, name in entries
        ],
        "attempts": attempts,
        "failures": failures,
    }


def verify_registry_postcondition(entries: list[tuple[str, str]]) -> list[str]:
    residual: list[str] = []
    projects = sorted({name for kind, name in entries if kind == "project"})
    for project in projects:
        containers = run(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
            timeout=60,
        )
        if containers.returncode != 0:
            residual.append(f"unable to inspect containers for project {project}")
        elif containers.stdout.split():
            residual.append(f"project {project} still has containers: {containers.stdout.split()}")
        networks = run(
            ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
            timeout=60,
        )
        if networks.returncode != 0:
            residual.append(f"unable to inspect networks for project {project}")
        elif networks.stdout.split():
            residual.append(f"project {project} still has networks: {networks.stdout.split()}")
    for kind, name in entries:
        if kind == "volume":
            command = ["docker", "volume", "inspect", name]
        elif kind == "network":
            command = ["docker", "network", "inspect", name]
        elif kind == "container":
            command = ["docker", "inspect", name]
        else:
            continue
        result = run(command, timeout=60)
        if result.returncode == 0:
            residual.append(f"{kind} {name} still exists")
        elif result.returncode != 1:
            residual.append(f"unable to inspect {kind} {name}")
    return residual


def cleanup_images(images: list[str]) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    failures: list[str] = []
    for image in images:
        inspected = run(["docker", "image", "inspect", image], timeout=60)
        if inspected.returncode == 0:
            removed = run(["docker", "image", "rm", image], timeout=120)
            attempts.append(
                {
                    "image": image,
                    "returncode": removed.returncode,
                    "stderr": sanitize(removed.stderr),
                }
            )
            if removed.returncode != 0:
                failures.append(f"unable to remove candidate image {image}")
        elif inspected.returncode != 1:
            failures.append(f"unable to inspect candidate image {image}")
        final = run(["docker", "image", "inspect", image], timeout=60)
        if final.returncode == 0:
            failures.append(f"candidate image {image} remains after cleanup")
        elif final.returncode != 1:
            failures.append(f"unable to verify candidate image {image} cleanup")
    return {"attempts": attempts, "failures": failures}


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
    if trivy is not None and cache_dir is not None:
        owned_raw_directory = raw_directory is None
        raw_directory = raw_directory or report_dir.parent / f"raw-{uuid.uuid4().hex}"
        raw_directory.mkdir(parents=True, exist_ok=True)
        try:
            return _acceptance(report_dir, manifest, trivy, cache_dir, raw_directory, exceptions)
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
        return _acceptance(report_dir, manifest, local_trivy, local_cache, raw_directory, exceptions)


def _acceptance(
    report_dir: Path,
    manifest: dict[str, Any] | None,
    trivy: Path,
    cache_dir: Path,
    raw_directory: Path,
    exceptions: list[dict[str, Any]],
) -> dict[str, Any]:
    acceptance_log = report_dir / "acceptance.log"
    assert_safe_docker_endpoint(log_path=acceptance_log)
    ec_image, tor_image, auth_image, project = candidate_names()
    suffix = project.rsplit("-", 1)[-1]
    caddy_image = f"electron-cash-caddy-ci:{suffix}"
    fail2ban_image = f"electron-cash-fail2ban-ci:{suffix}"
    remote_project = f"{project}-remote"
    published_project = f"{project}-published"
    remote_port = free_port()
    published_port = free_port()
    startup_project = f"{project}-startup"
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
            "CASHFUSION_ENABLED": "true",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
        }
    )
    acceptance_tests = [*ACCEPTANCE_TESTS]
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
        }
        manifest["candidate_compose_project"] = project
        persist_manifest(manifest)
    with tempfile.TemporaryDirectory(
        prefix="bchforge-v021-ci-", dir=raw_directory.parent
    ) as temporary:
        temporary_path = Path(temporary)
        registry = temporary_path / "resources.tsv"
        registry.write_text(
            "\n".join(
                (
                    f"project\t{remote_project}",
                    f"volume\t{remote_project}-wallet",
                    f"volume\t{remote_project}-tor",
                    f"volume\t{remote_project}_caddy-data",
                    f"volume\t{remote_project}_caddy-config",
                    f"volume\t{remote_project}_caddy-log",
                    f"volume\t{remote_project}_fail2ban-state",
                    f"volume\t{remote_project}_caddy-ban-state",
                    f"volume\t{remote_project}_caddy-control",
                    f"project\t{published_project}",
                    f"volume\t{published_project}-wallet",
                    f"volume\t{published_project}-tor",
                    f"volume\t{published_project}_caddy-data",
                    f"volume\t{published_project}_caddy-config",
                    f"volume\t{published_project}_caddy-log",
                    f"volume\t{published_project}_fail2ban-state",
                    f"volume\t{published_project}_caddy-ban-state",
                    f"volume\t{published_project}_caddy-control",
                    f"project\t{startup_project}",
                    f"volume\t{startup_project}-wallet",
                    f"volume\t{startup_project}-tor",
                    f"volume\t{startup_project}_caddy-data",
                    f"volume\t{startup_project}_caddy-config",
                    f"volume\t{startup_project}_caddy-log",
                    f"volume\t{startup_project}_fail2ban-state",
                    f"volume\t{startup_project}_caddy-ban-state",
                    f"volume\t{startup_project}_caddy-control",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        environment["CI_RESOURCE_REGISTRY"] = str(registry)
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
        primary_error: Exception | None = None
        cleanup: dict[str, Any] = {}
        image_ids: dict[str, str] = {}
        try:
            model = resolved_model(command, environment, log_path=acceptance_log)
            validate_model(model, ec_image, tor_image, caddy_image, fail2ban_image, auth_image, project)
            checked(
                [*canonical_command, "--progress", "plain", "build", "--pull", "--no-cache"],
                env=environment,
                timeout=1800,
                log_path=acceptance_log,
            )
            image_ids = {
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
            }
            if not all(image_ids.values()):
                raise ValidationError("candidate image ID was empty")
            print(f"CANDIDATE_ELECTRON_CASH_IMAGE={ec_image} ID={image_ids['electron_cash']}")
            print(f"CANDIDATE_TOR_IMAGE={tor_image} ID={image_ids['tor']}")
            print(f"CANDIDATE_CADDY_IMAGE={caddy_image} BASE={CADDY_BASE_IMAGE} ID={image_ids['caddy']}")
            print(f"CANDIDATE_FAIL2BAN_IMAGE={fail2ban_image} ID={image_ids['fail2ban']}")
            print(f"CANDIDATE_AUTH_SESSION_IMAGE={auth_image} ID={image_ids['auth_session']}")

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
                    ]
                )
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
                    ),
                ),
            ]
            policy_manifest = manifest or {"report_dir": str(report_dir)}
            require_fresh_trivy_database(cache_dir, policy_manifest)
            enforce_vulnerability_policy(image_findings, exceptions, report_dir, policy_manifest)
            validate_exception_usage(exceptions, policy_manifest, report_dir)
            if manifest is not None:
                trivy_version(trivy, report_dir, manifest)
                manifest["acceptance_test_results"].append(
                    {"test": "test_integrity_pins.py", "status": "RUNNING"}
                )
                persist_manifest(manifest)
            checked(
                [sys.executable, str(ROOT / "tests" / "test_integrity_pins.py")],
                env=environment,
                timeout=180,
                log_path=acceptance_log,
            )
            if manifest is not None:
                manifest["acceptance_test_results"][-1]["status"] = "PASS"
                persist_manifest(manifest)
            for test in acceptance_tests:
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
                        )
                        try:
                            checked(
                                [sys.executable, str(ROOT / "tests" / test)],
                                env=browser_environment,
                                timeout=600,
                                log_path=acceptance_log,
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
                            timeout=1800,
                            log_path=acceptance_log,
                        )
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
            if manifest is not None:
                manifest["acceptance_test_results"].append(
                    {"test": REMOTE_ACCEPTANCE_TEST, "status": "RUNNING"}
                )
                persist_manifest(manifest)
            try:
                checked(
                    [sys.executable, str(ROOT / "tests" / REMOTE_ACCEPTANCE_TEST)],
                    env=remote_environment,
                    timeout=1800,
                    log_path=acceptance_log,
                )
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
                    checked(
                        [sys.executable, str(ROOT / "tests" / PUBLIC_ACCEPTANCE_TEST)],
                        env=environment,
                        timeout=180,
                        log_path=acceptance_log,
                    )
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
            print("PASS complete acceptance against freshly built wallet, Tor, Caddy, and fail2ban images")
        except Exception as error:
            primary_error = error
        finally:
            entries = registry_entries(registry)
            cleanup = cleanup_registry(registry)
            cleanup["images"] = cleanup_images([ec_image, tor_image, caddy_image, fail2ban_image, auth_image])
            cleanup["test_failures"] = read_cleanup_failures(cleanup_failure_file)
            cleanup["resource_postcondition"] = verify_registry_postcondition(entries)
            cleanup["failures"].extend(cleanup["images"]["failures"])
            cleanup["failures"].extend(
                f"test cleanup: {failure}" for failure in cleanup["test_failures"]
            )
            cleanup["failures"].extend(cleanup["resource_postcondition"])
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
        "candidate": identity,
        "tools": tool_snapshot(),
        "commands": [
            "./scripts/ci.sh gate",
            "./scripts/ci.sh fast",
            "./scripts/ci.sh sast",
            "./scripts/dependency-review.sh v0.2.1",
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
            "v0.3 gateway, CashFusion, and backup acceptance",
            "local dependency review against v0.2.1",
            "cleanup and resource postcondition",
        ],
        "fast_log": str(report_dir / "fast.log"),
    }
    if os.environ.get("PUBLIC_ACCEPTANCE") == "1":
        manifest["commands"].append("PUBLIC_ACCEPTANCE=1 ./scripts/ci.sh gate")
        manifest["execution_graph"].append("public Cloudflare HTTPS/WSS acceptance")
    json_write(report_dir / "candidate-identity.json", identity)
    persist_manifest(manifest)
    result = 0
    try:
        record_step(manifest, "fast", lambda: fast(log_path=report_dir / "fast.log"))
        record_step(manifest, "local-sast", lambda: run_sast(report_dir, manifest))
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
            trivy = ensure_trivy(tooling / "trivy")
            cache_dir = trivy_cache_directory()
            trivy_version(trivy, report_dir, manifest)
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
            lambda: run_dependency_review("v0.2.1", report_dir, manifest),
        )
        record_step(manifest, "final-resource-postcondition", lambda: verify_gate_postcondition(manifest))
    except (ValidationError, subprocess.TimeoutExpired, OSError) as error:
        manifest["error"] = sanitize(str(error))
        result = 1
    except Exception as error:
        manifest["error"] = sanitize(f"unexpected error: {error}")
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
        except Exception as error:
            manifest["final_identity_error"] = sanitize(str(error))
            result = 1
        manifest["overall_status"] = "PASS" if result == 0 else "FAIL"
        manifest["finished_at"] = utc_now()
        finalize_manifest(manifest)
    if result == 0:
        print(f"PASS provider-independent gate; evidence={report_dir}")
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


def main() -> int:
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

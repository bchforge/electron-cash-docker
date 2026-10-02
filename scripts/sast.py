#!/usr/bin/env python3
"""Provider-independent Python static security analysis."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BANDIT_VERSION = "1.9.4"
TARGETS = ("docker", "scripts", "tests")


class SastError(RuntimeError):
    """Raised when the required SAST tool cannot produce a valid result."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_report_directory() -> Path:
    configured = os.environ.get("CI_REPORT_DIR")
    if configured:
        directory = Path(configured).expanduser()
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        run_id = f"sast-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
        directory = state_home / "electron-cash-docker" / "ci" / run_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def tool_directory() -> Path:
    configured = os.environ.get("SAST_TOOL_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return (state_home / "electron-cash-docker" / "tools" / f"bandit-{BANDIT_VERSION}").resolve()


def json_write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def persist_manifest(manifest: dict[str, Any]) -> None:
    json_write(Path(manifest["report_dir"]) / "gate-manifest.json", manifest)


def bootstrap_bandit() -> Path:
    target = tool_directory()
    marker = target / "bandit" / "__init__.py"
    if marker.is_file():
        return target

    if target.is_symlink():
        raise SastError("Bandit tool directory is a symbolic link; refusing to replace it")
    if target.exists():
        raise SastError(
            f"Bandit tool directory exists but is incomplete: {target}; "
            "it was retained unchanged"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f"bandit-{BANDIT_VERSION}-", dir=target.parent))
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--no-cache-dir",
        "--only-binary=:all:",
        "--index-url",
        "https://pypi.org/simple",
        "--target",
        str(temporary),
        "--requirement",
        str(ROOT / "requirements-sast.txt"),
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=900,
    )
    if result.returncode != 0:
        shutil.rmtree(temporary, ignore_errors=True)
        raise SastError(f"Bandit bootstrap failed ({result.returncode}): {result.stderr[-4000:]}")
    temporary.rename(target)
    return target


def bandit_environment(tool: Path) -> dict[str, str]:
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(tool) + (os.pathsep + existing if existing else "")
    return environment


def sarif_document(report: dict[str, Any]) -> dict[str, Any]:
    results = []
    rules = {}
    for finding in report.get("results", []):
        rule_id = finding.get("test_id", "bandit")
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.get("test_name", rule_id),
            "shortDescription": {"text": finding.get("issue_text", rule_id)},
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": finding.get("issue_text", "Bandit finding")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("filename", "")},
                            "region": {"startLine": finding.get("line_number", 1)},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "version": BANDIT_VERSION, "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def run_sast(report_dir: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "sast-bandit.json"
    sarif_path = report_dir / "sast.sarif"
    command_log = report_dir / "sast-command.log"
    command: list[str] = []
    try:
        tool = bootstrap_bandit()
        version = subprocess.run(
            [sys.executable, "-m", "bandit", "--version"],
            env=bandit_environment(tool),
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=60,
        )
        if version.returncode != 0:
            raise SastError(f"Bandit version check failed: {version.stderr[-2000:]}")
        command = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            *[str(ROOT / target) for target in TARGETS],
            "--format",
            "json",
            "--output",
            str(report_path),
            "--severity-level",
            "high",
            "--confidence-level",
            "high",
        ]
        result = subprocess.run(
            command,
            env=bandit_environment(tool),
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=900,
        )
        command_log.write_text(
            "$ " + " ".join(command) + "\n" + result.stdout + result.stderr,
            encoding="utf-8",
        )
        if not report_path.is_file():
            raise SastError("Bandit produced no JSON report")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            raise SastError("Bandit JSON report was malformed")
        if report.get("errors"):
            raise SastError(f"Bandit reported scanner errors: {report['errors']}")
        if result.returncode not in (0, 1):
            raise SastError(f"Bandit failed with exit code {result.returncode}")
        json_write(sarif_path, sarif_document(report))
        summary = {
            "tool": "Bandit",
            "version": version.stdout.strip() or version.stderr.strip(),
            "policy": {"blocking_severity": ["HIGH"], "blocking_confidence": ["HIGH"]},
            "targets": list(TARGETS),
            "command": " ".join(command),
            "exit_code": result.returncode,
            "finding_count": len(report["results"]),
            "error_count": len(report.get("errors", [])),
            "report": str(report_path),
            "sarif": str(sarif_path),
            "gate_decision": "PASS" if not report["results"] else "FAIL",
        }
        if manifest is not None:
            manifest["sast"] = summary
            persist_manifest(manifest)
        if report["results"]:
            raise SastError(f"local SAST found {len(report['results'])} blocking finding(s)")
        return summary
    except SastError as error:
        if not report_path.is_file():
            json_write(
                report_path,
                {
                    "tool": "Bandit",
                    "version": BANDIT_VERSION,
                    "command": " ".join(command),
                    "gate_decision": "FAIL",
                    "error": str(error),
                },
            )
        if manifest is not None and "sast" not in manifest:
            manifest["sast"] = {
                "tool": "Bandit",
                "version": BANDIT_VERSION,
                "command": " ".join(command),
                "gate_decision": "FAIL",
                "error": str(error),
            }
            persist_manifest(manifest)
        raise
    except (OSError, json.JSONDecodeError) as error:
        failure = {
            "tool": "Bandit",
            "version": BANDIT_VERSION,
            "command": " ".join(command),
            "gate_decision": "FAIL",
            "error": str(error),
        }
        json_write(report_path, failure)
        if manifest is not None:
            manifest["sast"] = failure
            persist_manifest(manifest)
        raise SastError(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path)
    args = parser.parse_args()
    report_dir = (args.report_dir or default_report_directory()).resolve()
    try:
        summary = run_sast(report_dir)
    except SastError as error:
        print(f"FAIL local SAST: {error}", file=sys.stderr)
        return 1
    print(f"PASS local SAST ({summary['version']}); evidence={report_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

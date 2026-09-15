#!/usr/bin/env python3
"""Read-only provider-independent dependency update discovery."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


class DependencyCheckError(RuntimeError):
    """Raised when update discovery cannot complete safely."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_report_directory() -> Path:
    configured = os.environ.get("CI_REPORT_DIR")
    if configured:
        directory = Path(configured).expanduser()
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        run_id = f"dependencies-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
        directory = state_home / "electron-cash-docker" / "dependencies" / run_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def json_write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_requirements() -> list[tuple[str, str]]:
    values = []
    for line_number, line in enumerate((ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.count("==") != 1:
            raise DependencyCheckError(f"requirements.txt:{line_number}: expected an exact == pin")
        name, version = value.split("==", 1)
        if not name or not version or any(char.isspace() for char in value):
            raise DependencyCheckError(f"requirements.txt:{line_number}: malformed pin")
        values.append((name, version))
    return values


def version_key(value: str) -> tuple[tuple[int, Any], ...]:
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in re.split(r"[._+-]", value)
        if part
    )


def pypi_latest(name: str) -> str:
    encoded = urllib.parse.quote(name, safe="")
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{encoded}/json",
        headers={"Accept": "application/json", "User-Agent": "electron-cash-docker-local-dependency-check/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise DependencyCheckError(f"PyPI lookup failed for {name}: {error}") from error
    version = document.get("info", {}).get("version")
    if not isinstance(version, str) or not version:
        raise DependencyCheckError(f"PyPI response for {name} lacked info.version")
    return version


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Local Dependency Update Discovery",
        "",
        "This report is read-only. It does not modify source, create branches, or create merge requests.",
        "",
        f"- Tool: `{report['tool']}`",
        f"- Generated: `{report['generated_at']}`",
        "",
        "## Python Dependencies",
        "",
        "| Package | Current | Latest | Status |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["python_dependencies"]:
        lines.append(f"| `{item['name']}` | `{item['current']}` | `{item['latest']}` | {item['status']} |")
    lines.extend(["", "## Manual Authorities", ""])
    lines.extend(
        [
            "- Electron Cash, noVNC, Tor, and plugin pins remain manual integrity tuples.",
            "- GitHub/GitLab release APIs are not queried by this command.",
            "- Docker base-image tags are reviewed by the local dependency-review command and image gate.",
        ]
    )
    if report["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in report["errors"])
    return "\n".join(lines) + "\n"


def run_update_check(report_dir: Path) -> dict[str, Any]:
    report_dir.mkdir(parents=True, exist_ok=True)
    items = []
    errors = []
    for name, current in read_requirements():
        try:
            latest = pypi_latest(name)
        except DependencyCheckError as error:
            errors.append(str(error))
            latest = None
        if latest is None:
            status = "LOOKUP_FAILED"
        elif version_key(latest) > version_key(current):
            status = "UPDATE_AVAILABLE"
        else:
            status = "CURRENT_OR_NEWER"
        items.append({"name": name, "current": current, "latest": latest, "type": "python", "status": status})
    report = {
        "schema_version": 1,
        "tool": "electron-cash-docker-read-only-pypi-discovery-v1",
        "generated_at": utc_now(),
        "source_mutation": "NO",
        "python_dependencies": items,
        "errors": errors,
        "gate_decision": "FAIL" if errors else "PASS",
    }
    json_path = report_dir / "dependency-updates.json"
    markdown_path = report_dir / "dependency-updates.md"
    json_write(json_path, report)
    markdown_path.write_text(markdown_report(report), encoding="utf-8")
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    if errors:
        raise DependencyCheckError("dependency update discovery failed: " + "; ".join(errors))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("check",))
    parser.add_argument("--report-dir", type=Path)
    args = parser.parse_args()
    try:
        report = run_update_check((args.report_dir or default_report_directory()).resolve())
    except (DependencyCheckError, OSError) as error:
        print(f"FAIL dependency update discovery: {error}", file=sys.stderr)
        return 1
    available = sum(item["status"] == "UPDATE_AVAILABLE" for item in report["python_dependencies"])
    print(f"PASS dependency update discovery; updates_available={available}; evidence={report['json_report']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

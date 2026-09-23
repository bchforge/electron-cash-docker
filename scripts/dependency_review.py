#!/usr/bin/env python3
"""Provider-independent base-versus-candidate dependency review."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HASH_KEY = re.compile(r"(?:sha|hash|digest|checksum|commit|archive)", re.IGNORECASE)


class DependencyReviewError(RuntimeError):
    """Raised when dependency metadata cannot be reviewed safely."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_report_directory() -> Path:
    configured = os.environ.get("CI_REPORT_DIR")
    if configured:
        directory = Path(configured).expanduser()
    else:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
        run_id = f"dependency-review-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
        directory = state_home / "electron-cash-docker" / "ci" / run_id
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def json_write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def persist_manifest(manifest: dict[str, Any]) -> None:
    json_write(Path(manifest["report_dir"]) / "gate-manifest.json", manifest)


def source_text(ref: str | None, relative_path: str) -> str | None:
    if ref is None:
        path = ROOT / relative_path
        return path.read_text(encoding="utf-8") if path.is_file() else None
    result = subprocess.run(
        ["git", "show", f"{ref}:{relative_path}"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=60,
    )
    return result.stdout if result.returncode == 0 else None


def record(records: list[dict[str, Any]], key: str, value: str, source: str, immutable: bool, kind: str) -> None:
    records.append(
        {
            "key": key,
            "value": value,
            "source": source,
            "immutable": immutable,
            "kind": kind,
        }
    )


def parse_requirements(
    text: str,
    source: str,
    records: list[dict[str, Any]],
    errors: list[str],
    key_prefix: str = "python",
) -> None:
    for line_number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if "==" not in value or value.count("==") != 1:
            errors.append(f"{source}:{line_number}: dependency is not an exact == pin")
            continue
        name, version = value.split("==", 1)
        if not name or not version or any(char.isspace() for char in value):
            errors.append(f"{source}:{line_number}: malformed dependency pin")
            continue
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        record(records, f"{key_prefix}:{normalized}", version, source, True, key_prefix)


def parse_dockerfile(text: str, source: str, records: list[dict[str, Any]]) -> None:
    stage_index = 0
    for index, line in enumerate(text.splitlines(), 1):
        argument = re.match(r"\s*ARG\s+([A-Z0-9_]+)=(\S+)", line)
        if argument:
            key, value = argument.groups()
            record(
                records,
                f"docker-arg:{source}:{key}",
                value,
                f"{source}:{index}",
                bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))
                if re.search(r"(?:SHA|HASH|DIGEST|CHECKSUM)", key, re.IGNORECASE)
                else False,
                "docker-arg",
            )
        syntax = re.match(r"\s*#\s*syntax=(\S+)", line)
        if syntax:
            value = syntax.group(1)
            record(records, f"dockerfile-frontend:{source}", value, f"{source}:{index}", "@sha256:" in value, "dockerfile")
        match = re.match(r"\s*FROM\s+(\S+)", line, re.IGNORECASE)
        if match and not match.group(1).startswith("${"):
            value = match.group(1)
            record(records, f"container-base:{source}:{stage_index}", value, f"{source}:{index}", "@sha256:" in value, "container")
            stage_index += 1


def parse_env(text: str, source: str, records: list[dict[str, Any]]) -> None:
    for index, line in enumerate(text.splitlines(), 1):
        match = re.match(r"\s*([A-Z0-9_]+)=(.*)", line)
        if not match:
            continue
        key, value = match.groups()
        if not re.search(r"(?:VERSION|COMMIT|SHA256|DIGEST|CHECKSUM)", key):
            continue
        record(
            records,
            f"pin:{key}",
            value,
            f"{source}:{index}",
            bool(re.search(r"(?:COMMIT|SHA256|DIGEST|CHECKSUM)", key)),
            "source-pin",
        )


def parse_plugins(text: str, source: str, records: list[dict[str, Any]], errors: list[str]) -> None:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        errors.append(f"{source}: invalid JSON: {error}")
        return
    plugins = document.get("plugins") if isinstance(document, dict) else None
    if not isinstance(plugins, list):
        errors.append(f"{source}: plugins must be a list")
        return
    for index, plugin in enumerate(plugins):
        if not isinstance(plugin, dict) or not plugin.get("package_name"):
            errors.append(f"{source}:{index + 1}: plugin is missing package_name")
            continue
        package = str(plugin["package_name"])
        for field in ("source", "version", "artifact", "archive_sha256", "sha256"):
            if field not in plugin or not plugin[field]:
                errors.append(f"{source}:{index + 1}: plugin is missing {field}")
                continue
            value = str(plugin[field])
            record(
                records,
                f"plugin:{package}:{field}",
                value,
                f"{source}:{index + 1}",
                field in {"archive_sha256", "sha256"} and bool(re.fullmatch(r"[0-9a-fA-F]{64}", value)),
                "plugin",
            )


def parse_tool_pin(text: str, source: str, records: list[dict[str, Any]]) -> None:
    version = re.search(r"^TRIVY_VERSION\s*=\s*[\"']([^\"']+)", text, re.MULTILINE)
    digest = re.search(r"^TRIVY_ARCHIVE_SHA256\s*=\s*[\"']([^\"']+)", text, re.MULTILINE)
    if version:
        record(records, "tool:trivy:version", version.group(1), source, False, "tool")
    if digest:
        record(records, "tool:trivy:archive_sha256", digest.group(1), source, True, "tool")


def inventory(ref: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    requirements = source_text(ref, "requirements.txt")
    if requirements is not None:
        parse_requirements(requirements, "requirements.txt", records, errors)
    else:
        dockerfile = source_text(ref, "docker/Dockerfile")
        if dockerfile is not None:
            parse_requirements(
                "\n".join(
                    f"{name}=={version}"
                    for name, version in re.findall(
                        r"^\s*([A-Za-z0-9_.-]+)==([^\s\\]+)", dockerfile, re.MULTILINE
                    )
                ),
                "docker/Dockerfile",
                records,
                errors,
            )
    sast_requirements = source_text(ref, "requirements-sast.txt")
    if sast_requirements is not None:
        parse_requirements(sast_requirements, "requirements-sast.txt", records, errors, "sast-tool")
    for path in (
        "docker/Dockerfile",
        "docker/tor/Dockerfile",
        "docker/caddy/Dockerfile",
        "docker/fail2ban/Dockerfile",
    ):
        text = source_text(ref, path)
        if text is not None:
            parse_dockerfile(text, path, records)
    env = source_text(ref, ".env.example")
    if env is not None:
        parse_env(env, ".env.example", records)
    plugins = source_text(ref, "plugins.json")
    if plugins is not None:
        parse_plugins(plugins, "plugins.json", records, errors)
    ci = source_text(ref, "scripts/ci.py")
    if ci is not None:
        parse_tool_pin(ci, "scripts/ci.py", records)
    return records, errors


def compare(base: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    base_map = {item["key"]: item for item in base}
    candidate_map = {item["key"]: item for item in candidate}
    added = [candidate_map[key] for key in sorted(candidate_map.keys() - base_map.keys())]
    removed = [base_map[key] for key in sorted(base_map.keys() - candidate_map.keys())]
    changed = []
    for key in sorted(base_map.keys() & candidate_map.keys()):
        if base_map[key]["value"] != candidate_map[key]["value"] or base_map[key]["immutable"] != candidate_map[key]["immutable"]:
            changed.append({"before": base_map[key], "after": candidate_map[key]})
    return {"added": added, "removed": removed, "changed": changed}


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Local Dependency Review",
        "",
        f"- Base: `{report['base_ref']}`",
        "- Candidate: `UNCOMMITTED_CANDIDATE`",
        f"- Decision: **{report['gate_decision']}**",
        "",
        "## Changes",
    ]
    for category in ("added", "removed", "changed"):
        lines.append(f"### {category.title()}")
        values = report["changes"][category]
        if not values:
            lines.append("- None")
        for value in values:
            if category == "changed":
                lines.append(f"- `{value['after']['key']}`: `{value['before']['value']}` -> `{value['after']['value']}`")
            else:
                lines.append(f"- `{value['key']}` = `{value['value']}`")
    if report["failures"]:
        lines.extend(["", "## Failures"])
        lines.extend(f"- {failure}" for failure in report["failures"])
    return "\n".join(lines) + "\n"


def run_dependency_review(base_ref: str, report_dir: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    report_dir.mkdir(parents=True, exist_ok=True)
    base, base_errors = inventory(base_ref)
    candidate, candidate_errors = inventory(None)
    changes = compare(base, candidate)
    failures = [*base_errors, *candidate_errors]
    for item in candidate:
        if (
            (item["kind"] == "container" and ":" in item["value"])
            or item["kind"] == "dockerfile"
            or HASH_KEY.search(item["key"])
        ) and not item["immutable"]:
            failures.append(f"integrity metadata is not immutable for {item['key']}")
    for change in changes["changed"]:
        before = change["before"]
        after = change["after"]
        if before["immutable"] and not after["immutable"]:
            failures.append(f"integrity protection lost for {after['key']}")
    for removed in changes["removed"]:
        if HASH_KEY.search(removed["key"]):
            failures.append(f"integrity metadata removed for {removed['key']}")
    vulnerability_path = report_dir / "vulnerability-dispositions.json"
    vulnerability_evidence: dict[str, Any] = {"available": vulnerability_path.is_file()}
    if vulnerability_path.is_file():
        try:
            vulnerability_evidence = json.loads(vulnerability_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            failures.append(f"malformed vulnerability evidence: {error}")
        else:
            if vulnerability_evidence.get("overall") == "FAIL":
                failures.append("existing vulnerability disposition is FAIL")
    report = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "base_ref": base_ref,
        "candidate_identity": "UNCOMMITTED_CANDIDATE",
        "base_record_count": len(base),
        "candidate_record_count": len(candidate),
        "changes": changes,
        "vulnerability_evidence": vulnerability_evidence,
        "failures": failures,
        "gate_decision": "FAIL" if failures else "PASS",
    }
    json_path = report_dir / "dependency-review.json"
    markdown_path = report_dir / "dependency-review.md"
    json_write(json_path, report)
    markdown_path.write_text(markdown_report(report), encoding="utf-8")
    report["json_report"] = str(json_path)
    report["markdown_report"] = str(markdown_path)
    if manifest is not None:
        manifest["dependency_review"] = report
        persist_manifest(manifest)
    if failures:
        raise DependencyReviewError("local dependency review failed: " + "; ".join(failures))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_ref", nargs="?", default="v0.2.1")
    parser.add_argument("--report-dir", type=Path)
    args = parser.parse_args()
    try:
        report = run_dependency_review(args.base_ref, (args.report_dir or default_report_directory()).resolve())
    except (DependencyReviewError, OSError) as error:
        print(f"FAIL local dependency review: {error}", file=sys.stderr)
        return 1
    print(f"PASS local dependency review against {report['base_ref']}; evidence={report['json_report']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

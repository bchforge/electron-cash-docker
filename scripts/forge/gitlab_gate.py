#!/usr/bin/env python3
"""Optional GitLab external commit-status adapter for the local release gate."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
STATUS_NAME = "ecd-local-gate"


class AdapterError(RuntimeError):
    """Raised when an external status cannot be safely published."""


class ApiError(AdapterError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def run_git(command: list[str]) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise AdapterError(f"command failed: {' '.join(command)}")
    return result.stdout.strip()


def repository_identity() -> tuple[str, str]:
    status = run_git(["git", "status", "--porcelain", "--untracked-files=all"])
    if status:
        raise AdapterError("refusing to publish a commit status for a dirty working tree")
    sha = run_git(["git", "rev-parse", "--verify", "HEAD"])
    ref = run_git(["git", "symbolic-ref", "--quiet", "--short", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not ref:
        raise AdapterError("could not determine an exact committed SHA/ref")
    return sha, ref


def response_status_code(text: str) -> int | None:
    match = re.search(r"HTTP/\S+\s+(\d{3})", text)
    return int(match.group(1)) if match else None


def verify_status_response(document: dict[str, Any], sha: str, state: str) -> dict[str, Any]:
    if document.get("sha") != sha or document.get("name") != STATUS_NAME or document.get("status") != state:
        raise ApiError("GitLab status response did not match the requested SHA/name/state")
    return document


def glab_post_status(
    sha: str,
    ref: str,
    state: str,
    *,
    project: str,
    hostname: str,
) -> dict[str, Any]:
    encoded_project = urllib.parse.quote(project, safe="")
    endpoint = f"projects/{encoded_project}/statuses/{sha}"
    command = [
        "glab",
        "api",
        "--hostname",
        hostname,
        "--include",
        "--output",
        "json",
        "--method",
        "POST",
        endpoint,
        "--raw-field",
        f"state={state}",
        "--raw-field",
        f"name={STATUS_NAME}",
        "--raw-field",
        f"ref={ref}",
        "--raw-field",
        "description=Provider-independent local release gate",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=60,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise ApiError(
            f"GitLab status API failed without exposing credentials: {output[-2000:]}",
            response_status_code(output),
        )
    status_code = response_status_code(result.stdout)
    body = result.stdout.split("\r\n\r\n", 1)[-1].split("\n\n", 1)[-1]
    try:
        document = json.loads(body)
    except json.JSONDecodeError as error:
        raise ApiError("GitLab status API returned malformed JSON", status_code) from error
    if not isinstance(document, dict):
        raise ApiError("GitLab status API returned a non-object response", status_code)
    try:
        return verify_status_response(document, sha, state)
    except ApiError as error:
        raise ApiError(str(error), status_code) from error


def post_with_retry(
    post: Callable[[str], dict[str, Any]], state: str, *, attempts: int = 3, delay: float = 2.0
) -> dict[str, Any]:
    last_error: ApiError | None = None
    for attempt in range(attempts):
        try:
            return post(state)
        except ApiError as error:
            last_error = error
            retryable = error.status_code == 409 or (error.status_code is not None and error.status_code >= 500)
            if not retryable or attempt == attempts - 1:
                raise
            time.sleep(delay)
    raise last_error or ApiError("GitLab status publication failed")


def run_adapter(
    *,
    gate_runner: Callable[[], int],
    status_poster: Callable[[str], dict[str, Any]],
    sha: str,
    ref: str,
) -> int:
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not ref:
        raise AdapterError("status adapter requires an exact commit SHA and ref")
    post_with_retry(status_poster, "pending")
    gate_result = gate_runner()
    final_state = "success" if gate_result == 0 else "failed"
    post_with_retry(status_poster, final_state)
    return gate_result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default=os.environ.get("GITLAB_PROJECT", "bchforge/electron-cash-docker"))
    parser.add_argument("--hostname", default=os.environ.get("GITLAB_HOST", "gitlab.com"))
    args = parser.parse_args()
    try:
        sha, ref = repository_identity()
        status_poster = lambda state: glab_post_status(
            sha, ref, state, project=args.project, hostname=args.hostname
        )

        def gate_runner() -> int:
            result = subprocess.run(
                ["./scripts/ci.sh", "gate"],
                cwd=ROOT,
                check=False,
            )
            return result.returncode

        result = run_adapter(gate_runner=gate_runner, status_poster=status_poster, sha=sha, ref=ref)
    except (AdapterError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAIL GitLab local-gate adapter: {error}", file=sys.stderr)
        return 1
    print(f"PASS GitLab status {STATUS_NAME}={result} for {sha} ({ref})")
    return result


if __name__ == "__main__":
    raise SystemExit(main())

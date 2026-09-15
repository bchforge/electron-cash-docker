#!/usr/bin/env python3
"""Deterministic tests for the optional GitLab status adapter."""

from __future__ import annotations

import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.forge.gitlab_gate import (  # noqa: E402
    AdapterError,
    ApiError,
    post_with_retry,
    run_adapter,
    verify_status_response,
)
import scripts.forge.gitlab_gate as adapter  # noqa: E402


SHA = "a" * 40


def test_success_and_failure_mapping() -> None:
    posted: list[str] = []
    result = run_adapter(
        gate_runner=lambda: 0,
        status_poster=lambda state: posted.append(state) or {"sha": SHA, "name": "ecd-local-gate", "status": state},
        sha=SHA,
        ref="feature/test",
    )
    assert result == 0
    assert posted == ["pending", "success"]

    posted.clear()
    result = run_adapter(
        gate_runner=lambda: 1,
        status_poster=lambda state: posted.append(state) or {"sha": SHA, "name": "ecd-local-gate", "status": state},
        sha=SHA,
        ref="feature/test",
    )
    assert result == 1
    assert posted == ["pending", "failed"]


def test_api_failure_and_bounded_retry() -> None:
    calls = 0

    def flaky(state: str) -> dict:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ApiError("temporary", 503)
        return {"sha": SHA, "name": "ecd-local-gate", "status": state}

    assert post_with_retry(flaky, "pending", attempts=3, delay=0) == {
        "sha": SHA,
        "name": "ecd-local-gate",
        "status": "pending",
    }
    assert calls == 3

    try:
        post_with_retry(lambda state: (_ for _ in ()).throw(ApiError("bad", 400)), "pending", attempts=3, delay=0)
    except ApiError:
        pass
    else:
        raise AssertionError("non-retryable API failure was accepted")

    try:
        verify_status_response({"sha": "b" * 40, "name": "ecd-local-gate", "status": "success"}, SHA, "success")
    except ApiError:
        pass
    else:
        raise AssertionError("wrong SHA response was accepted")


def test_dirty_tree_precondition_is_fail_closed() -> None:
    original = adapter.run_git
    try:
        adapter.run_git = lambda command: " M README.md" if "status" in command else SHA
        try:
            adapter.repository_identity()
        except AdapterError as error:
            assert "dirty working tree" in str(error)
        else:
            raise AssertionError("dirty tree was accepted")
    finally:
        adapter.run_git = original


def test_status_command_does_not_receive_token() -> None:
    original = adapter.subprocess.run
    captured: list[list[str]] = []

    def fake_run(command, **kwargs):
        captured.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout='HTTP/2 201\n\n{"sha":"' + SHA + '","name":"ecd-local-gate","status":"success"}',
            stderr="",
        )

    try:
        adapter.subprocess.run = fake_run
        adapter.glab_post_status(
            SHA,
            "feature/test",
            "success",
            project="bchforge/electron-cash-docker",
            hostname="gitlab.com",
        )
    finally:
        adapter.subprocess.run = original
    assert captured
    command_text = " ".join(captured[0])
    assert "GITLAB_TOKEN" not in command_text
    assert "name=ecd-local-gate" in command_text
    assert "ref=feature/test" in command_text
    assert "state=success" in command_text


def test_malformed_api_response_is_rejected() -> None:
    original = adapter.subprocess.run

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="HTTP/2 200\n\nnot-json", stderr="")

    try:
        adapter.subprocess.run = fake_run
        try:
            adapter.glab_post_status(
                SHA,
                "feature/test",
                "success",
                project="bchforge/electron-cash-docker",
                hostname="gitlab.com",
            )
        except ApiError as error:
            assert "malformed JSON" in str(error)
        else:
            raise AssertionError("malformed API response was accepted")
    finally:
        adapter.subprocess.run = original


def main() -> None:
    test_success_and_failure_mapping()
    test_api_failure_and_bounded_retry()
    test_dirty_tree_precondition_is_fail_closed()
    test_status_command_does_not_receive_token()
    test_malformed_api_response_is_rejected()
    print("PASS GitLab status adapter tests")


if __name__ == "__main__":
    main()

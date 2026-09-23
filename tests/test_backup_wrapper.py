#!/usr/bin/env python3
"""Static contract tests for the two cross-platform backup launchers."""

from __future__ import annotations

import subprocess
import re
import importlib.util
import os
import time
from pathlib import Path
from unittest import SkipTest


ROOT = Path(__file__).resolve().parents[1]
POSIX = ROOT / "scripts" / "backup.sh"
POWERSHELL = ROOT / "scripts" / "backup.ps1"
DOCKER_HELPER = ROOT / "docker" / "backup.sh"
TOOL = ROOT / "docker" / "backup_tool.py"
ELECTRON_CASH_WRAPPER = ROOT / "docker" / "electroncash-wrapper.py"
ELECTRON_CASH_TEST_IMAGE = os.environ.get("ELECTRON_CASH_TEST_IMAGE", "electron-cash:4.4.6")
SHUTDOWN_MARKER = "/tmp/electron-cash-shutdown"


def load_electron_cash_wrapper():
    spec = importlib.util.spec_from_file_location(
        "electroncash_wrapper_test", ELECTRON_CASH_WRAPPER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def docker_command(
    *args: str, timeout: float = 30, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def docker_output(*args: str) -> str:
    result = docker_command(*args)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def compose_command(
    project: str,
    *args: str,
    env: dict[str, str],
    timeout: float = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ROOT / ".env.example"),
            "-p",
            project,
            *args,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def compose_output(project: str, *args: str, env: dict[str, str]) -> str:
    result = compose_command(project, *args, env=env)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def wait_for_compose_healthy(container: str, timeout: float = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = docker_output(
            "inspect",
            "--format",
            "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
            container,
        )
        if state == "running|healthy":
            return
        if state.endswith("|unhealthy") or state.startswith(("exited|", "dead|")):
            logs = docker_output("logs", container)
            raise AssertionError(f"Electron Cash is not healthy ({state}):\n{logs}")
        time.sleep(1)
    raise AssertionError(f"Electron Cash did not become healthy within {timeout}s")


def assert_gui_services_and_port(container: str) -> None:
    processes = docker_command("top", container, "-eo", "user,pid,args")
    process_list = processes.stdout
    assert processes.returncode == 0, processes.stderr or processes.stdout
    assert "x11vnc" in process_list
    assert "websockify" in process_list

    port = docker_command(
        "exec",
        "--user",
        "10001:10001",
        container,
        "/opt/electroncash-venv/bin/python",
        "-c",
        "import socket; s=socket.create_connection(('127.0.0.1', 6080), 1); "
        "s.sendall(b'GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n'); "
        "response=s.recv(128); s.close(); raise SystemExit(0 if b'HTTP/' in response else 1)",
        timeout=10,
    )
    assert port.returncode == 0, port.stderr or port.stdout


def test_public_help_is_exact() -> None:
    result = subprocess.run([str(POSIX)], cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 2
    assert result.stderr == "Usage:\n  ./scripts/backup.sh backup <name>\n  ./scripts/backup.sh restore <name>\n"


def test_public_name_validation_happens_before_docker() -> None:
    for value in ("../wallet", "wallet/name", r"wallet\name", "wallet..copy", "", "."):
        result = subprocess.run(
            [str(POSIX), "backup", value], cwd=ROOT, text=True, capture_output=True, check=False
        )
        assert result.returncode == 1
        assert "Invalid backup name" in result.stderr
        assert "Docker" not in result.stderr


def test_wrappers_use_docker_for_archive_and_archive_copying() -> None:
    posix = POSIX.read_text(encoding="utf-8")
    powershell = POWERSHELL.read_text(encoding="utf-8")
    for source in (posix, powershell):
        cleaned = source.replace(".ecd.gpg", "")
        assert "docker" in source
        assert "python3" not in source
        assert not re.search(r"\bgpg\b|\btar\b|\bgzip\b|\bpython3\b", cleaned, re.IGNORECASE)
        assert "docker.sock" not in source
        assert "--privileged" not in source
    assert "create" in posix and "verify" in posix and "snapshot" in posix
    assert "replace" in posix and "restore-snapshot" in posix
    assert "create" in powershell and "verify" in powershell and "snapshot" in powershell
    assert "replace" in powershell and "restore-snapshot" in powershell


def test_no_durable_protocol_in_backup_production() -> None:
    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (POSIX, POWERSHELL, DOCKER_HELPER, TOOL, ROOT / "docker" / "Dockerfile")
    ).lower()
    for obsolete in ("session_id", "action_receipt", "pending_action", "reconciliation"):
        assert obsolete not in production
    assert not (ROOT / "scripts" / "backup_orchestrator.py").exists()


def test_helper_has_no_docker_daemon_access_and_tool_keeps_archive_checks() -> None:
    helper = DOCKER_HELPER.read_text(encoding="utf-8")
    tool = TOOL.read_text(encoding="utf-8")
    assert "--network none" not in helper  # the host wrapper owns isolation
    assert "backup decryption or integrity verification failed" in helper
    assert "unsafe archive path" in tool
    assert "duplicate archive path" in tool
    assert "restored config contains unsanitized secrets" in tool
    assert "snapshot_volume" in tool
    assert "restore_snapshot" in tool


def test_shutdown_marker_is_consumed_as_a_one_shot_event() -> None:
    module = load_electron_cash_wrapper()
    marker = ROOT / ".test-shutdown-marker"
    marker.write_text("", encoding="utf-8")
    try:
        setattr(module, "SHUTDOWN_MARKER", marker)
        assert module.consume_shutdown_marker() is True
        assert not marker.exists()
        assert module.consume_shutdown_marker() is True
    finally:
        marker.unlink(missing_ok=True)


def test_shutdown_marker_unlink_failure_is_explicit_and_fail_safe(capsys) -> None:
    module = load_electron_cash_wrapper()
    marker = ROOT / ".test-shutdown-marker-directory"
    marker.mkdir(exist_ok=True)
    try:
        setattr(module, "SHUTDOWN_MARKER", marker)
        assert module.consume_shutdown_marker() is False
        assert marker.is_dir()
        assert "unable to consume shutdown marker" in capsys.readouterr().err
    finally:
        marker.rmdir()


def test_real_electron_cash_container_restarts_after_shutdown_marker() -> None:
    try:
        daemon = docker_command("info", timeout=10)
    except FileNotFoundError as error:
        raise SkipTest("docker is not installed") from error
    if daemon.returncode != 0:
        raise SkipTest(f"docker daemon is unavailable: {daemon.stderr.strip()}")

    image = docker_command("image", "inspect", ELECTRON_CASH_TEST_IMAGE)
    if image.returncode != 0:
        raise SkipTest(f"test image is unavailable: {ELECTRON_CASH_TEST_IMAGE}")

    project = f"ecd-marker-regression-{os.getpid()}"
    volume = f"{project}-wallet"
    environment = os.environ.copy()
    environment.update(
        {
            "BASIC_AUTH_PASSWORD": "marker-regression-test",
            "CASHFUSION_ENABLED": "false",
            "ECD_WALLET_VOLUME": volume,
            "ELECTRON_CASH_IMAGE": ELECTRON_CASH_TEST_IMAGE,
            "JSONRPC_ENABLED": "false",
            "TEST_WALLET_PASSWORD": "",
            "USE_TOR": "false",
            "WALLET_AUTO_CREATE": "false",
        }
    )
    container = ""
    try:
        started = compose_command(
            project,
            "up",
            "-d",
            "--no-deps",
            "electron-cash",
            env=environment,
            timeout=120,
        )
        assert started.returncode == 0, started.stderr or started.stdout
        container = compose_output(project, "ps", "-q", "electron-cash", env=environment)
        assert container

        wait_for_compose_healthy(container)
        marker_created = docker_command(
            "exec",
            "--user",
            "10001:10001",
            container,
            "/bin/bash",
            "-c",
            f": > {SHUTDOWN_MARKER}",
        )
        assert marker_created.returncode == 0, marker_created.stderr

        stopped = docker_command("wait", container, timeout=120)
        assert stopped.returncode == 0, stopped.stderr or stopped.stdout
        assert stopped.stdout.strip() == "0", stopped.stdout

        restarted = docker_command("start", container, timeout=60)
        assert restarted.returncode == 0, restarted.stderr or restarted.stdout

        wait_for_compose_healthy(container)
        marker_consumed = docker_command("exec", container, "test", "!", "-e", SHUTDOWN_MARKER)
        assert marker_consumed.returncode == 0, marker_consumed.stderr
        assert_gui_services_and_port(container)

        time.sleep(45)
        state = docker_output(
            "inspect",
            "--format",
            "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.RestartCount}}",
            container,
        )
        assert state == "running|healthy|0", state
    finally:
        compose_command(
            project,
            "down",
            "--volumes",
            "--remove-orphans",
            env=environment,
            timeout=60,
        )
        docker_command("volume", "rm", "--force", volume, timeout=30)


if __name__ == "__main__":
    for test in (
        test_public_help_is_exact,
        test_public_name_validation_happens_before_docker,
        test_wrappers_use_docker_for_archive_and_archive_copying,
        test_no_durable_protocol_in_backup_production,
        test_helper_has_no_docker_daemon_access_and_tool_keeps_archive_checks,
        test_shutdown_marker_is_consumed_as_a_one_shot_event,
    ):
        test()
    print("PASS backup launcher contracts")

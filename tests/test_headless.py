#!/usr/bin/env python3
"""Acceptance checks for the explicit headless daemon mode."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from test_support import (
    electron_cash_image,
    record_cleanup_result,
    tor_image,
    unique_project,
    unique_resource,
)


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
IMAGE = electron_cash_image()
TOR_IMAGE = tor_image()
CLI = "/opt/electroncash-venv/bin/electron-cash"
PYTHON = "/opt/electroncash-venv/bin/python"


def run(command: list[str], *, env=None, timeout=120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def compose_base(project: str, override: Path) -> list[str]:
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
        "docker-compose.headless.yml",
        "-f",
        str(override),
    ]


def write_volume_override(
    directory: str, volume: str, tor_volume: str
) -> Path:
    override = Path(directory) / "volumes.yml"
    override.write_text(
        "services:\n"
        "  electron-cash:\n"
        "    volumes:\n"
        "      - electron-cash-data:/home/electroncash/.electron-cash\n"
        "volumes:\n"
        "  electron-cash-data:\n"
        f"    name: {volume}\n"
        "  tor-data:\n"
        f"    name: {tor_volume}\n",
        encoding="utf-8",
    )
    return override


def read_wallet_autofuse(command: list[str], environment: dict[str, str]) -> dict:
    code = r'''
import json
import os

from electroncash.storage import WalletStorage
from electroncash_plugins.fusion.conf import Conf

storage = WalletStorage(
    "/home/electroncash/.electron-cash/chipnet/wallets/default_wallet",
    manual_upgrades=True,
)
storage.decrypt(os.environ["TEST_WALLET_PASSWORD"])
wallet = type("Wallet", (), {"storage": storage})()
print(json.dumps({"encrypted": storage.is_encrypted(), "autofuse": Conf(wallet).autofuse}))
'''
    result = run(
        [
            *command,
            "exec",
            "-T",
            "--user",
            "10001:10001",
            "electron-cash",
            PYTHON,
            "-c",
            code,
        ],
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def wait_for_wallet_autofuse(
    command: list[str], environment: dict[str, str], expected: dict[str, bool]
) -> dict[str, bool]:
    deadline = time.monotonic() + 30
    observed = {}
    while time.monotonic() < deadline:
        observed = read_wallet_autofuse(command, environment)
        if observed == expected:
            return observed
        time.sleep(1)
    raise AssertionError(f"wallet state did not become {expected}: {observed}")


def compose_environment(*, use_tor: bool = False) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "USE_TOR": str(use_tor).lower(),
            "CHIPNET": "false",
            "TESTNET4": "false",
            "NETWORK": "mainnet",
            "CASHFUSION_ENABLED": "true",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
            "JSONRPC_ENABLED": "false",
            "JSONRPC_USER": "electroncash",
            "JSONRPC_PASSWORD": "",
        }
    )
    return environment


def wait_for_healthy(
    command: list[str], service: str, environment: dict[str, str]
) -> str:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = run([*command, "ps", "-q", service], env=environment)
        container = result.stdout.strip()
        if container:
            health = run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container]
            )
            if health.stdout.strip() == "healthy":
                return container
            if health.stdout.strip() == "unhealthy":
                logs = run(["docker", "logs", container])
                raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(1)
    raise AssertionError(f"{service} did not become healthy")


def wait_for_running(command: list[str], environment: dict[str, str]) -> str:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = run([*command, "ps", "-q", "electron-cash"], env=environment)
        container = result.stdout.strip()
        if container:
            state = run(["docker", "inspect", "--format", "{{.State.Status}}", container])
            if state.stdout.strip() == "running":
                return container
            if state.stdout.strip() in {"dead", "exited"}:
                logs = run(["docker", "logs", container])
                raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(1)
    raise AssertionError("headless Electron Cash did not become running")


def wait_for_daemon(
    command: list[str], environment: dict[str, str], *, chipnet: bool = False
) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = run(
            [
                *command,
                "exec",
                "-T",
                "--user",
                "10001:10001",
                "electron-cash",
                CLI,
                *(("--chipnet",) if chipnet else ()),
                "daemon",
                "status",
            ],
            env=environment,
        )
        if result.returncode == 0:
            return
        time.sleep(1)
    logs = run([*command, "logs", "electron-cash"], env=environment)
    raise AssertionError(logs.stdout + logs.stderr)


def test_headless_runtime_and_port_isolation() -> None:
    project = unique_project("headless")
    volume = unique_resource("headless-wallet")
    tor_volume = unique_resource("headless-tor")
    environment = compose_environment()

    with tempfile.TemporaryDirectory(prefix="bchforge-headless-") as temporary:
        override = write_volume_override(temporary, volume, tor_volume)
        compose = compose_base(project, override)
        try:
            config = run([*compose, "config", "--format", "json"], env=environment)
            assert config.returncode == 0, config.stdout + config.stderr
            resolved = json.loads(config.stdout)["services"]["electron-cash"]
            assert resolved["environment"]["MODE"] == "headless"
            assert "ports" not in resolved

            started = run([*compose, "up", "-d", "--no-build"], env=environment, timeout=120)
            assert started.returncode == 0, started.stdout + started.stderr
            container = wait_for_running(compose, environment)
            wait_for_daemon(compose, environment)

            top = run(["docker", "top", container, "-eo", "user,pid,args"])
            assert top.returncode == 0, top.stdout + top.stderr
            for process in ("Xvfb", "openbox-session", "x11vnc", "websockify"):
                assert process not in top.stdout
        finally:
            record_cleanup_result(
                run([*compose, "down", "-v", "--remove-orphans"], env=environment, timeout=120),
                [*compose, "down", "-v", "--remove-orphans"],
            )


def test_headless_runtime_with_tor() -> None:
    project = unique_project("headless-tor")
    volume = unique_resource("headless-tor-wallet")
    tor_volume = unique_resource("headless-tor-state")
    environment = compose_environment(use_tor=True)

    with tempfile.TemporaryDirectory(prefix="bchforge-headless-tor-") as temporary:
        override = write_volume_override(temporary, volume, tor_volume)
        compose = compose_base(project, override)
        try:
            config = run([*compose, "config", "--format", "json"], env=environment)
            assert config.returncode == 0, config.stdout + config.stderr
            document = json.loads(config.stdout)
            electron_service = document["services"]["electron-cash"]
            tor_service = document["services"]["tor-proxy"]
            assert electron_service["environment"]["MODE"] == "headless"
            assert electron_service["environment"]["USE_TOR"] == "true"
            assert "ports" not in electron_service
            assert tor_service["image"] == TOR_IMAGE
            assert "ports" not in tor_service
            assert "9050" in tor_service["expose"]

            started = run([*compose, "up", "-d", "--no-build"], env=environment, timeout=120)
            assert started.returncode == 0, started.stdout + started.stderr
            tor_container = wait_for_healthy(compose, "tor-proxy", environment)
            container = wait_for_running(compose, environment)
            wait_for_daemon(compose, environment)

            inspected_tor = json.loads(run(["docker", "inspect", tor_container]).stdout)[0]
            assert inspected_tor["Config"]["Image"] == TOR_IMAGE
            assert inspected_tor["NetworkSettings"]["Ports"].get("9050/tcp") is None

            config_result = run(
                [
                    "docker",
                    "exec",
                    "--user",
                    "10001:10001",
                    container,
                    PYTHON,
                    "-c",
                    "import json; print(json.load(open('/home/electroncash/.electron-cash/config'))['proxy'])",
                ]
            )
            assert config_result.returncode == 0, config_result.stdout + config_result.stderr
            assert config_result.stdout.strip() == "socks5:tor-proxy:9050"

            tor_top = run(["docker", "top", tor_container, "-eo", "user,pid,args"])
            assert tor_top.returncode == 0, tor_top.stdout + tor_top.stderr
            assert len(
                [line for line in tor_top.stdout.splitlines() if "/usr/local/bin/tor" in line]
            ) == 1

            electron_top = run(["docker", "top", container, "-eo", "user,pid,args"])
            assert electron_top.returncode == 0, electron_top.stdout + electron_top.stderr
            assert not any(
                re.search(r"(?:^|\s)(?:\S*/)?tor(?:\s|$)", line)
                for line in electron_top.stdout.splitlines()[1:]
            )
            for process in ("Xvfb", "openbox-session", "x11vnc", "websockify"):
                assert process not in electron_top.stdout
        finally:
            record_cleanup_result(
                run([*compose, "down", "-v", "--remove-orphans"], env=environment, timeout=120),
                [*compose, "down", "-v", "--remove-orphans"],
            )


def test_headless_encrypted_cashfusion_toggle_preserves_wallet_authority() -> None:
    project = unique_project("headless-fusion")
    volume = unique_resource("headless-fusion-wallet")
    tor_volume = unique_resource("headless-fusion-tor")
    environment = compose_environment()
    environment.update(
        {
            "WALLET_AUTO_CREATE": "true",
            "TEST_WALLET_PASSWORD": "cashfusion-test-password",
            "CASHFUSION_AUTO_FUSE": "true",
        }
    )

    with tempfile.TemporaryDirectory(prefix="bchforge-headless-chipnet-fusion-") as temporary:
        override = write_volume_override(temporary, volume, tor_volume)
        compose = [
            "docker",
            "compose",
            "--env-file",
            str(ENV_FILE),
            "-p",
            project,
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.headless.yml",
            "-f",
            str(override),
        ]
        environment["NETWORK"] = "chipnet"
        try:
            started = run([*compose, "up", "-d", "--no-build"], env=environment, timeout=120)
            assert started.returncode == 0, started.stdout + started.stderr
            wait_for_running(compose, environment)
            wait_for_daemon(compose, environment, chipnet=True)
            observed = wait_for_wallet_autofuse(
                compose, environment, {"encrypted": True, "autofuse": True}
            )

            environment["CASHFUSION_ENABLED"] = "false"
            restarted = run(
                [*compose, "up", "-d", "--force-recreate", "--no-build"],
                env=environment,
                timeout=120,
            )
            assert restarted.returncode == 0, restarted.stdout + restarted.stderr
            wait_for_running(compose, environment)
            wait_for_daemon(compose, environment, chipnet=True)
            observed = wait_for_wallet_autofuse(
                compose, environment, {"encrypted": True, "autofuse": True}
            )

            environment["CASHFUSION_ENABLED"] = "true"
            restarted = run(
                [*compose, "up", "-d", "--force-recreate", "--no-build"],
                env=environment,
                timeout=120,
            )
            assert restarted.returncode == 0, restarted.stdout + restarted.stderr
            wait_for_running(compose, environment)
            wait_for_daemon(compose, environment, chipnet=True)
            observed = wait_for_wallet_autofuse(
                compose, environment, {"encrypted": True, "autofuse": True}
            )
        finally:
            record_cleanup_result(
                run([*compose, "down", "-v", "--remove-orphans"], env=environment, timeout=120),
                [*compose, "down", "-v", "--remove-orphans"],
            )


def main() -> None:
    test_headless_runtime_and_port_isolation()
    test_headless_runtime_with_tor()
    test_headless_encrypted_cashfusion_toggle_preserves_wallet_authority()
    print("PASS headless mainnet/Chipnet mode, daemon readiness, port isolation, and CashFusion persistence")


if __name__ == "__main__":
    main()

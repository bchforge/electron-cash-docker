#!/usr/bin/env python3
"""Acceptance checks for optional authenticated localhost-only RPC."""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
IMAGE = "electron-cash:4.4.6"
PYTHON = "/opt/electroncash-venv/bin/python"
CLI = "/opt/electroncash-venv/bin/electron-cash"
RPC_USER = "electroncash"
RPC_PASSWORD = secrets.token_urlsafe(24)


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


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def compose_base(project: str, override: Path, *, rpc: bool = False) -> list[str]:
    command = [
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
    ]
    if rpc:
        command.extend(["-f", "docker-compose.rpc.yml"])
    command.extend(["-f", str(override)])
    return command


def write_volume_override(directory: str, volume: str, tor_volume: str) -> Path:
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


def compose_environment(*, enabled: bool, host_port: int | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "USE_TOR": "false",
            "CASHFUSION_ENABLED": "true",
            "CASHFUSION_AUTO_FUSE": "false",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
            "JSONRPC_ENABLED": str(enabled).lower(),
            "JSONRPC_USER": RPC_USER,
            "JSONRPC_PASSWORD": RPC_PASSWORD if enabled else "",
        }
    )
    if host_port is not None:
        environment["JSONRPC_HOST_PORT"] = str(host_port)
    return environment


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
    raise AssertionError("Electron Cash did not become running")


def wait_for_daemon(command: list[str], environment: dict[str, str]) -> None:
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


def test_default_rpc_is_disabled() -> None:
    for files in (("docker-compose.yml",), ("docker-compose.yml", "docker-compose.headless.yml")):
        command = ["docker", "compose", "--env-file", str(ENV_FILE)]
        for compose_file in files:
            command.extend(["-f", compose_file])
        command.extend(["config", "--format", "json"])
        result = run(command)
        assert result.returncode == 0, result.stdout + result.stderr
        document = json.loads(result.stdout)
        service = document["services"]["electron-cash"]
        assert service["environment"]["JSONRPC_ENABLED"] == "false"
        assert service["environment"]["JSONRPC_USER"] == RPC_USER
        assert service["environment"]["JSONRPC_PASSWORD"] == ""
        assert "secrets" not in document
        if "ports" in service:
            assert all("50001" not in str(port) for port in service["ports"])


def test_rpc_disabled_removes_stale_persisted_credentials() -> None:
    project = f"bchforge-rpc-disabled-{uuid.uuid4().hex}"
    environment = compose_environment(enabled=False)
    with tempfile.TemporaryDirectory(prefix="bchforge-rpc-disabled-") as temporary:
        compose = compose_base(
            project,
            write_volume_override(temporary, f"{project}-wallet", f"{project}-tor"),
        )
        try:
            started = run([*compose, "up", "-d", "--no-build"], env=environment, timeout=120)
            assert started.returncode == 0, started.stdout + started.stderr
            container = wait_for_running(compose, environment)
            wait_for_daemon(compose, environment)
            code = (
                "import json; p='/home/electroncash/.electron-cash/config'; "
                "c=json.load(open(p)); print(json.dumps(c, sort_keys=True))"
            )
            inspected = run(["docker", "exec", container, PYTHON, "-c", code])
            assert inspected.returncode == 0, inspected.stdout + inspected.stderr
            config = json.loads(inspected.stdout)
            assert config["rpcuser"] == ""
            assert config["rpcpassword"] == ""
            assert config["rpcport"] == 0
            assert config["rpchost"] == "127.0.0.1"
        finally:
            run([*compose, "down", "-v", "--remove-orphans"], env=environment, timeout=120)


def test_rpc_missing_or_empty_credentials_fail_closed() -> None:
    for user, password, message in (
        ("", "rpc-test-password", "non-empty JSONRPC_USER"),
        (RPC_USER, "", "non-empty JSONRPC_PASSWORD"),
    ):
        environment = os.environ.copy()
        environment.update(
            {
                "JSONRPC_USER": user,
                "JSONRPC_PASSWORD": password,
            }
        )
        result = run(
            [
                "docker",
                "run",
                "--pull=never",
                "--rm",
                "-e",
                "MODE=headless",
                "-e",
                "USE_TOR=false",
                "-e",
                "CASHFUSION_ENABLED=true",
                "-e",
                "CASHFUSION_AUTO_FUSE=false",
                "-e",
                "JSONRPC_ENABLED=true",
                "-e",
                "JSONRPC_USER",
                "-e",
                "JSONRPC_PASSWORD",
                IMAGE,
            ],
            env=environment,
        )
        assert result.returncode != 0
        assert message in result.stdout + result.stderr
        if password:
            assert password not in result.stdout + result.stderr


def test_rpc_authentication_and_credential_exposure() -> None:
    project = f"bchforge-rpc-{uuid.uuid4().hex}"
    rpc_port = free_port()
    environment = compose_environment(enabled=True, host_port=rpc_port)
    with tempfile.TemporaryDirectory(prefix="bchforge-rpc-") as temporary:
        compose = compose_base(
            project,
            write_volume_override(temporary, f"{project}-wallet", f"{project}-tor"),
            rpc=True,
        )
        try:
            config_result = run([*compose, "config", "--format", "json"], env=environment)
            assert config_result.returncode == 0, config_result.stdout + config_result.stderr
            document = json.loads(config_result.stdout)
            service = document["services"]["electron-cash"]
            assert service["environment"]["JSONRPC_ENABLED"] == "true"
            assert service["environment"]["JSONRPC_USER"] == RPC_USER
            assert service["environment"]["JSONRPC_PASSWORD"] == RPC_PASSWORD
            assert "secrets" not in document
            assert service["ports"][0]["published"] == str(rpc_port)
            assert service["ports"][0]["host_ip"] == "127.0.0.1"

            started = run([*compose, "up", "-d", "--no-build"], env=environment, timeout=120)
            assert started.returncode == 0, started.stdout + started.stderr
            container = wait_for_running(compose, environment)
            wait_for_daemon(compose, environment)

            ping_body = json.dumps({"method": "ping", "params": [], "id": 1}).encode()
            ping_authorization = base64.b64encode(
                f"{RPC_USER}:{RPC_PASSWORD}".encode()
            ).decode()
            ping_request = Request(
                f"http://127.0.0.1:{rpc_port}/",
                data=ping_body,
                headers={
                    "Authorization": f"Basic {ping_authorization}",
                    "Content-Type": "application/json",
                },
            )
            with urlopen(ping_request, timeout=5) as response:
                ping_payload = json.loads(response.read())
            assert ping_payload.get("error") is None
            assert "result" in ping_payload

            body = json.dumps({"method": "getinfo", "params": [], "id": 1}).encode()
            authorization = base64.b64encode(f"{RPC_USER}:{RPC_PASSWORD}".encode()).decode()
            request = Request(
                f"http://127.0.0.1:{rpc_port}/",
                data=body,
                headers={
                    "Authorization": f"Basic {authorization}",
                    "Content-Type": "application/json",
                },
            )
            with urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
            assert payload["result"]["version"] == "4.4.6"

            for headers, description in (
                ({"Content-Type": "application/json"}, "unauthenticated"),
                (
                    {
                        "Authorization": "Basic "
                        + base64.b64encode(f"{RPC_USER}:wrong-password".encode()).decode(),
                        "Content-Type": "application/json",
                    },
                    "invalid-credentials",
                ),
            ):
                request = Request(
                    f"http://127.0.0.1:{rpc_port}/",
                    data=body,
                    headers=headers,
                )
                try:
                    urlopen(request, timeout=5)
                except HTTPError as error:
                    assert error.code == 401
                else:
                    raise AssertionError(f"{description} RPC request was accepted")

            inspected = run(["docker", "inspect", container])
            assert inspected.returncode == 0, inspected.stdout + inspected.stderr
            container_data = json.loads(inspected.stdout)[0]
            configured_environment = container_data["Config"]["Env"]
            assert f"JSONRPC_PASSWORD={RPC_PASSWORD}" in configured_environment
            assert not any(
                str(mount.get("Destination", "")).startswith("/run/secrets")
                for mount in container_data["Mounts"]
            )

            top = run(["docker", "top", container, "-eo", "user,pid,args"])
            assert top.returncode == 0, top.stdout + top.stderr
            assert RPC_PASSWORD not in top.stdout
            logs = run(["docker", "logs", container])
            assert RPC_PASSWORD not in logs.stdout + logs.stderr
            assert RPC_PASSWORD not in f"http://127.0.0.1:{rpc_port}/"
            tracked = run(["git", "grep", "-n", RPC_PASSWORD, "--", "."])
            assert tracked.returncode == 1, tracked.stdout + tracked.stderr
        finally:
            run([*compose, "down", "-v", "--remove-orphans"], env=environment, timeout=120)


def main() -> None:
    test_default_rpc_is_disabled()
    test_rpc_disabled_removes_stale_persisted_credentials()
    test_rpc_missing_or_empty_credentials_fail_closed()
    test_rpc_authentication_and_credential_exposure()
    print("PASS RPC configuration, authentication, and exposure checks")


if __name__ == "__main__":
    main()

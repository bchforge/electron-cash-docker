#!/usr/bin/env python3
"""Tor supply-chain and isolated runtime acceptance tests.

The runtime portion creates uniquely named Compose resources and a disposable
wallet volume. It never starts the default project and never removes the
canonical bchforge-electron-cash-data volume.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

from test_support import electron_cash_image, tor_image, unique_project, unique_resource


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
TOR_DIR = ROOT / "docker" / "tor"


def parse_env() -> dict[str, str]:
    values = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


ENV_DEFAULTS = parse_env()
TOR_VERSION = ENV_DEFAULTS["TOR_VERSION"]
TOR_SOURCE_SHA256 = ENV_DEFAULTS["TOR_SOURCE_SHA256"]
TOR_IMAGE = tor_image()
EC_IMAGE = electron_cash_image()


def run(command: list[str], *, env=None, timeout=120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def require_command(command: str) -> None:
    if not shutil.which(command):
        raise AssertionError(f"required command is unavailable: {command}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def compose_base(project: str, override: Path | None = None) -> list[str]:
    command = [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-p",
        project,
        "-f",
        "docker-compose.yml",
    ]
    if override is not None:
        command.extend(["-f", str(override)])
    return command


def compose_environment(port: int) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "NOVNC_BIND": "127.0.0.1",
            "NOVNC_HOST_PORT": str(port),
            "USE_TOR": "true",
            "CASHFUSION_ENABLED": "true",
            "CASHFUSION_AUTO_FUSE": "false",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
        }
    )
    return environment


def wait_running(
    command: list[str], service: str, environment: dict[str, str], timeout=90
) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run([*command, "ps", "-q", service], env=environment)
        if result.returncode == 0 and result.stdout.strip():
            container = result.stdout.strip()
            state = run(["docker", "inspect", "--format", "{{.State.Status}}", container])
            if state.stdout.strip() == "running":
                return container
            if state.stdout.strip() in {"dead", "exited"}:
                logs = run(["docker", "logs", container])
                raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(1)
    raise AssertionError(f"{service} did not become running")


def wait_healthy(container: str, timeout=90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container]
        )
        if result.stdout.strip() == "healthy":
            return
        if result.stdout.strip() == "unhealthy":
            logs = run(["docker", "logs", container])
            raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(1)
    logs = run(["docker", "logs", container])
    raise AssertionError(f"Tor healthcheck timed out\n{logs.stdout}{logs.stderr}")


def wait_bootstrap(container: str, *, previous_output="", timeout=180) -> str:
    deadline = time.monotonic() + timeout
    output = ""
    while time.monotonic() < deadline:
        logs = run(["docker", "logs", container])
        output = logs.stdout + logs.stderr
        new_output = output
        if previous_output and output.startswith(previous_output):
            new_output = output[len(previous_output) :]
        if "Bootstrapped 100%" in new_output:
            return output
        state = run(["docker", "inspect", "--format", "{{.State.Status}}", container])
        if state.stdout.strip() in {"dead", "exited"}:
            raise AssertionError(output)
        time.sleep(2)
    raise AssertionError(f"Tor did not bootstrap to 100%\n{output}")


def compose_exec(
    command: list[str],
    environment: dict[str, str],
    service: str,
    args: list[str],
    *,
    user: str | None = None,
    timeout=120,
) -> subprocess.CompletedProcess[str]:
    exec_command = [*command, "exec", "-T"]
    if user is not None:
        exec_command.extend(["--user", user])
    exec_command.extend([service, *args])
    return run(
        exec_command,
        env=environment,
        timeout=timeout,
    )


def wait_novnc(port: int, timeout=60) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as response:
                if response.status == 200:
                    return
                last_error = f"unexpected HTTP status: {response.status}"
        except Exception as error:
            last_error = error
        time.sleep(1)
    raise AssertionError(f"noVNC did not become reachable: {last_error}")


def test_static_provenance() -> None:
    compose = run(
        ["docker", "compose", "--env-file", str(ENV_FILE), "config", "--format", "json"]
    )
    assert compose.returncode == 0, compose.stdout + compose.stderr
    resolved = json.loads(compose.stdout)
    tor_service = resolved["services"]["tor-proxy"]
    build = tor_service["build"]

    assert Path(build["context"]).resolve() == TOR_DIR.resolve()
    assert build["dockerfile"] == "Dockerfile"
    assert tor_service["image"] == TOR_IMAGE
    assert "ports" not in tor_service
    assert "9050" in tor_service["expose"]
    assert tor_service["read_only"] is True
    assert tor_service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in tor_service["security_opt"]
    assert tor_service["volumes"][0]["target"] == "/var/lib/tor"
    assert tor_service["volumes"][0]["source"] == "tor-data"

    dockerfile = (TOR_DIR / "Dockerfile").read_text(encoding="utf-8")
    torrc = (TOR_DIR / "torrc").read_text(encoding="utf-8")
    keys = (TOR_DIR / "tor-release-keys.asc").read_text(encoding="utf-8")
    assert "https://dist.torproject.org/" in dockerfile
    assert "gpgv" in dockerfile
    assert "sha256sum" in dockerfile
    assert "([.][0-9]+){3}" in dockerfile
    assert "--disable-module-relay" in dockerfile
    assert "--disable-module-dirauth" in dockerfile
    assert TOR_SOURCE_SHA256 in ENV_FILE.read_text(encoding="utf-8")
    supply_chain = (ROOT / "docs" / "tor-supply-chain.md").read_text(encoding="utf-8")
    assert "1C1BC007A9F607AA8152C040BEA7B180B1491921" in supply_chain
    assert "keys.openpgp.org/vks/v1/by-fingerprint" in supply_chain
    assert "B74417EDDF22AC9F9E90F49142E86A2A11F48D36" in dockerfile
    assert "514102454D0A87DB0767A1EBBE6A0531C18A9179" in dockerfile
    assert keys.count("BEGIN PGP PUBLIC KEY BLOCK") >= 1
    assert keys.count("BEGIN PGP PUBLIC KEY BLOCK") == keys.count(
        "END PGP PUBLIC KEY BLOCK"
    )

    active = {}
    for raw_line in torrc.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        active[fields[0]] = fields[1:]

    assert active["ClientOnly"] == ["1"]
    assert active["Sandbox"] == ["1"]
    assert active["SocksPort"] == ["0.0.0.0:9050"]
    assert active["DataDirectory"] == ["/var/lib/tor"]
    assert active["RunAsDaemon"] == ["0"]
    for option in ("ControlPort", "DNSPort", "HTTPTunnelPort", "TransPort", "NATDPort"):
        assert active[option] == ["0"]
    for option in ("ORPort", "DirPort", "Bridge", "BridgeRelay", "HiddenServiceDir"):
        assert option not in active

    forbidden = "dockurr" + "/tor"
    active_extensions = {".yml", ".yaml", ".sh", ".py", ".c", ".Dockerfile"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.name == "CHANGELOG.md":
            continue
        if path.suffix in active_extensions or path.name == "Dockerfile":
            assert forbidden not in path.read_text(encoding="utf-8"), path


def test_missing_and_bad_pins_fail_closed() -> None:
    environment = os.environ.copy()
    environment.pop("TOR_VERSION", None)
    environment.pop("TOR_SOURCE_SHA256", None)
    with tempfile.TemporaryDirectory(prefix="bchforge-tor-env-") as temporary:
        missing_pin_env = Path(temporary) / "missing.env"
        missing_pin_env.write_text(
            "\n".join(
                line
                for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
                if not line.startswith("TOR_SOURCE_SHA256=")
            )
            + "\n",
            encoding="utf-8",
        )
        result = run(
            ["docker", "compose", "--env-file", str(missing_pin_env), "config"],
            env=environment,
        )
        assert result.returncode != 0
        assert "TOR_SOURCE_SHA256" in result.stdout + result.stderr

    result = run(
        [
            "docker",
            "build",
            "--target",
            "tor-verifier",
            "--build-arg",
            "TOR_VERSION=0x4x9x11",
            "--build-arg",
            f"TOR_SOURCE_SHA256={TOR_SOURCE_SHA256}",
            "./docker/tor",
        ],
        timeout=180,
    )
    assert result.returncode != 0
    assert "TOR_VERSION must be a stable numeric Tor release" in result.stdout + result.stderr

    result = run(
        [
            "docker",
            "build",
            "--no-cache",
            "--progress=plain",
            "--target",
            "tor-verifier",
            "--build-arg",
            f"TOR_VERSION={TOR_VERSION}",
            "--build-arg",
            "TOR_SOURCE_SHA256=" + "0" * 64,
            "./docker/tor",
        ],
        timeout=180,
    )
    assert result.returncode != 0
    assert "does not match the Tor Project checksum file" in result.stdout + result.stderr


def test_runtime() -> None:
    require_command("docker")
    image = run(["docker", "image", "inspect", TOR_IMAGE])
    assert image.returncode == 0, "build the Tor image before running this suite"
    ec_image = run(["docker", "image", "inspect", EC_IMAGE])
    assert ec_image.returncode == 0, "build the Electron Cash image before running this suite"

    project = unique_project("tor")
    wallet_volume = unique_resource("tor-wallet")
    tor_volume = unique_resource("tor-state")
    port = free_port()
    environment = compose_environment(port)
    canonical_before = run(["docker", "volume", "inspect", "bchforge-electron-cash-data"])

    with tempfile.TemporaryDirectory(prefix="bchforge-tor-compose-") as temporary:
        override = Path(temporary) / "isolated-volumes.yml"
        override.write_text(
            "services:\n"
            "  electron-cash:\n"
            "    volumes:\n"
            "      - electron-cash-data:/home/electroncash/.electron-cash\n"
            "  tor-proxy:\n"
            "    volumes:\n"
            "      - tor-data:/var/lib/tor\n"
            "volumes:\n"
            "  electron-cash-data:\n"
            f"    name: {wallet_volume}\n"
            "  tor-data:\n"
            f"    name: {tor_volume}\n",
            encoding="utf-8",
        )
        command = compose_base(project, override)
        try:
            started = run([*command, "up", "-d", "--no-build"], env=environment, timeout=180)
            assert started.returncode == 0, started.stdout + started.stderr

            tor_container = wait_running(command, "tor-proxy", environment)
            electron_container = wait_running(command, "electron-cash", environment)
            wait_healthy(tor_container)
            bootstrap_logs = wait_bootstrap(tor_container)
            assert "Bootstrapped 100%" in bootstrap_logs

            inspect = json.loads(run(["docker", "inspect", tor_container]).stdout)[0]
            assert inspect["Config"]["User"] == "10001:10001"
            assert inspect["HostConfig"]["ReadonlyRootfs"] is True
            assert inspect["HostConfig"]["CapDrop"] == ["ALL"]
            assert "no-new-privileges:true" in inspect["HostConfig"]["SecurityOpt"]
            assert inspect["HostConfig"]["Privileged"] is False
            assert inspect["HostConfig"]["NetworkMode"] != "host"
            assert inspect["NetworkSettings"]["Ports"].get("9050/tcp") is None
            targets = {mount["Destination"] for mount in inspect["Mounts"]}
            assert targets == {"/var/lib/tor"}
            assert "/home/electroncash/.electron-cash" not in targets
            assert "/var/run/docker.sock" not in targets

            top = run(["docker", "top", tor_container, "-eo", "user,pid,ppid,args"])
            assert top.returncode == 0, top.stdout + top.stderr
            assert "10001" in top.stdout
            assert "root" not in top.stdout.lower()

            version = run(
                ["docker", "exec", tor_container, "/usr/local/bin/tor", "--version"]
            )
            assert version.returncode == 0
            assert f"Tor version {TOR_VERSION}." in version.stdout

            verified = run(
                [
                    "docker",
                    "exec",
                    tor_container,
                    "/usr/local/bin/tor",
                    "--verify-config",
                    "-f",
                    "/etc/tor/torrc",
                ]
            )
            assert verified.returncode == 0, verified.stdout + verified.stderr

            local_health = run(["docker", "exec", tor_container, "/usr/local/bin/tor-healthcheck"])
            assert local_health.returncode == 0, local_health.stdout + local_health.stderr

            routed = compose_exec(
                command,
                environment,
                "electron-cash",
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--socks5-hostname",
                    "tor-proxy:9050",
                    "--connect-timeout",
                    "30",
                    "--max-time",
                    "90",
                    "https://check.torproject.org/api/ip",
                ],
                timeout=120,
            )
            assert routed.returncode == 0, routed.stdout + routed.stderr
            assert json.loads(routed.stdout)["IsTor"] is True

            config_result = compose_exec(
                command,
                environment,
                "electron-cash",
                ["cat", "/home/electroncash/.electron-cash/config"],
            )
            assert config_result.returncode == 0, config_result.stdout + config_result.stderr
            config = json.loads(config_result.stdout)
            assert config["proxy"] == "socks5:tor-proxy:9050"
            assert config["use_fusion"] is True
            assert config["cashfusion_tor_host"] == "tor-proxy"
            assert config["cashfusion_tor_port_manual"] == 9050
            assert config["cashfusion_tor_port_auto"] is False

            wait_novnc(port)

            electron_top = run(["docker", "top", electron_container, "-eo", "user,pid,ppid,args"])
            assert electron_top.returncode == 0
            assert "root" not in electron_top.stdout.lower()
            assert not any(
                re.search(r"(?:^|\s)(?:\S*/)?tor(?:\s|$)", line)
                for line in electron_top.stdout.splitlines()[1:]
            ), electron_top.stdout

            sentinel = "/home/electroncash/.electron-cash/.v012-tor-persistence"
            write = compose_exec(
                command,
                environment,
                    "electron-cash",
                    [
                        "bash",
                        "-c",
                        f"printf '%s' tor-supply-chain > {sentinel}",
                    ],
                    user="10001:10001",
                )
            assert write.returncode == 0, write.stdout + write.stderr

            def assert_sentinel() -> None:
                deadline = time.monotonic() + 60
                last = ""
                while time.monotonic() < deadline:
                    check = compose_exec(
                        command,
                        environment,
                        "electron-cash",
                        ["cat", sentinel],
                    )
                    if check.returncode == 0 and check.stdout.strip() == "tor-supply-chain":
                        return
                    last = check.stdout + check.stderr
                    time.sleep(1)
                logs = run(
                    [*command, "logs", "--no-color", "electron-cash"],
                    env=environment,
                )
                raise AssertionError(
                    "persistence sentinel was not ready:\n"
                    + last
                    + "\nElectron Cash logs:\n"
                    + logs.stdout
                    + logs.stderr
                )

            assert_sentinel()
            before_restart = run(["docker", "logs", tor_container])
            before_restart_logs = before_restart.stdout + before_restart.stderr
            restarted = run([*command, "restart", "tor-proxy"], env=environment, timeout=120)
            assert restarted.returncode == 0, restarted.stdout + restarted.stderr
            tor_container = wait_running(command, "tor-proxy", environment)
            wait_healthy(tor_container)
            wait_bootstrap(tor_container, previous_output=before_restart_logs)
            assert_sentinel()

            recreated = run(
                [*command, "up", "-d", "--force-recreate", "--no-build", "tor-proxy"],
                env=environment,
                timeout=120,
            )
            assert recreated.returncode == 0, recreated.stdout + recreated.stderr
            tor_container = wait_running(command, "tor-proxy", environment)
            wait_healthy(tor_container)
            wait_bootstrap(tor_container)
            assert_sentinel()

            recreated_ec = run(
                [*command, "up", "-d", "--force-recreate", "--no-build", "electron-cash"],
                env=environment,
                timeout=120,
            )
            assert recreated_ec.returncode == 0, recreated_ec.stdout + recreated_ec.stderr
            electron_container = wait_running(command, "electron-cash", environment)
            assert_sentinel()
            wait_novnc(port)
        finally:
            run([*command, "down", "--remove-orphans"], env=environment, timeout=120)
            for volume in (wallet_volume, tor_volume):
                run(["docker", "volume", "rm", volume], timeout=30)

    canonical_after = run(["docker", "volume", "inspect", "bchforge-electron-cash-data"])
    assert (canonical_before.returncode, canonical_before.stdout, canonical_before.stderr) == (
        canonical_after.returncode,
        canonical_after.stdout,
        canonical_after.stderr,
    )
    assert run(["docker", "volume", "inspect", wallet_volume]).returncode != 0
    assert run(["docker", "volume", "inspect", tor_volume]).returncode != 0
    leftovers = run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ]
    )
    assert not leftovers.stdout.strip()


def main() -> None:
    test_static_provenance()
    print("PASS static Tor provenance, client-only configuration, and dependency removal")
    test_missing_and_bad_pins_fail_closed()
    print("PASS missing-pin and bad-checksum fail-closed tests")
    test_runtime()
    print("PASS isolated Tor hardening, bootstrap, SOCKS, Electron Cash, noVNC, and lifecycle tests")


if __name__ == "__main__":
    main()

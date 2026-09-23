#!/usr/bin/env python3
"""Prove distinct clients retain distinct identity through published Caddy ports."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"


def run(command: list[str], *, env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False, timeout=timeout)


def checked(command: list[str], *, env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = run(command, env=env, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def compose(project: str) -> list[str]:
    return ["docker", "compose", "--env-file", str(ENV_FILE), "-p", project, "-f", "docker-compose.yml"]


def wait_running(command: list[str], service: str, *, env: dict[str, str]) -> str:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = checked([*command, "ps", "-q", service], env=env)
        identifier = result.stdout.strip()
        if identifier:
            state = checked(["docker", "inspect", "--format", "{{.State.Status}}", identifier], env=env).stdout.strip()
            if state == "running":
                return identifier
            if state in {"exited", "dead"}:
                logs = run(["docker", "logs", identifier], env=env)
                raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(1)
    raise AssertionError(f"{service} did not become running")


def client_container(image: str, name: str, *, env: dict[str, str]) -> str:
    checked(
        [
            "docker",
            "run",
            "--pull=never",
            "-d",
            "--name",
            name,
            "--network",
            "bridge",
            "--entrypoint",
            "/bin/bash",
            image,
            "-c",
            "sleep infinity",
        ],
        env=env,
    )
    return checked(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
        env=env,
    ).stdout.strip()


def client_probe(client: str, gateway: str, port: int, path: str, *, env: dict[str, str]) -> None:
    result = checked(
        [
            "docker",
            "exec",
            client,
            "/bin/bash",
            "-lc",
            "curl --noproxy '*' --max-time 10 -sk --resolve "
            f"wallet.test:{port}:{gateway} -o /dev/null -w '%{{http_code}}' "
            f"https://wallet.test:{port}{path}",
        ],
        env=env,
    )
    assert result.stdout == "401", result.stdout + result.stderr


def access_records(caddy: str, *, env: dict[str, str]) -> list[dict]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = checked(["docker", "exec", caddy, "cat", "/var/log/caddy/access.log"], env=env)
        records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        if records:
            return records
        time.sleep(0.25)
    raise AssertionError("Caddy did not write an access record")


def main() -> None:
    required = ("ELECTRON_CASH_IMAGE", "TOR_IMAGE", "CADDY_IMAGE", "FAIL2BAN_IMAGE", "AUTH_SESSION_IMAGE")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise AssertionError(f"missing published-port acceptance environment: {', '.join(missing)}")

    project = os.environ.get("CI_PUBLISHED_PROJECT", f"ecd-published-{uuid.uuid4().hex[:10]}")
    port = int(os.environ.get("CI_PUBLISHED_PORT", str(free_port())))
    environment = os.environ.copy()
    environment.update(
        {
            "CADDY_SITE_ADDRESS": "https://wallet.test",
            "CADDY_TLS_MODE": "internal",
            "BASIC_AUTH_PASSWORD": "synthetic-auth-secret",
            # The published-port test intentionally exercises the gateway as
            # another Docker network peer, not the host loopback shortcut.
            "CADDY_EDGE_BIND": "0.0.0.0",
            "CADDY_HTTP_HOST_PORT": str(free_port()),
            "CADDY_HTTPS_HOST_PORT": str(port),
            "FAIL2BAN_MAXRETRY": "100",
            "FAIL2BAN_FINDTIME": "60",
            "ECD_WALLET_VOLUME": f"{project}-wallet",
            "ECD_TOR_VOLUME": f"{project}-tor",
        }
    )
    command = compose(project)
    clients: list[str] = []
    expected_client_ips: set[str] = set()
    try:
        checked([*command, "up", "-d", "--no-build"], env=environment, timeout=180)
        caddy = wait_running(command, "caddy", env=environment)
        wait_running(command, "auth-session", env=environment)
        fail2ban = wait_running(command, "fail2ban", env=environment)
        gateway = checked(
            ["docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"],
            env=environment,
        ).stdout.strip()
        assert gateway
        for suffix in ("a", "b"):
            client = f"{project}-client-{suffix}"
            clients.append(client)
            client_ip = client_container(environment["ELECTRON_CASH_IMAGE"], client, env=environment)
            expected_client_ips.add(client_ip)
            path = f"/vnc.html?published_client_probe={suffix}-{time.time_ns()}"
            client_probe(client, gateway, port, path, env=environment)
            for _ in range(30):
                records = access_records(caddy, env=environment)
                if any((record.get("request") or {}).get("uri") == path for record in records):
                    break
                time.sleep(0.25)
            else:
                raise AssertionError(f"missing published-port access record for {path}")

        records = access_records(caddy, env=environment)
        probes = [
            record
            for record in records
            if (record.get("request") or {}).get("uri", "").startswith("/vnc.html?published_client_probe=")
        ]
        assert len(probes) >= 2, probes
        remote_ips = {(record.get("request") or {}).get("remote_ip") for record in probes[-2:]}
        client_ips = {(record.get("request") or {}).get("client_ip") for record in probes[-2:]}
        if len(remote_ips) == 2:
            assert remote_ips == client_ips, probes[-2:]
            assert remote_ips == expected_client_ips, (probes[-2:], expected_client_ips)
            identity_result = "distinct client identities"
        else:
            assert len(remote_ips) == 1 and remote_ips == client_ips, probes[-2:]
            identity = json.loads(
                checked(
                    ["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/client-identity.json"],
                    env=environment,
                ).stdout
            )
            collapsed = [identity.get(address) for address in remote_ips]
            assert all(
                isinstance(entry, dict)
                and entry.get("mode") == "collapsed"
                and entry.get("packet_drop") is False
                for entry in collapsed
            ), (probes[-2:], identity)
            adapter_logs = run(["docker", "logs", fail2ban], env=environment)
            assert "fail-closed topology event" in adapter_logs.stdout + adapter_logs.stderr
            identity_result = "collapsed ingress identity failed closed without packet DROP"
        ban_state = json.loads(
            checked(["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/banlist.json"], env=environment).stdout
        )
        assert ban_state.get("version") == 1 and ban_state.get("bans") == [], ban_state
        print(f"PASS published-port {identity_result} and fail2ban stays below threshold")
    finally:
        for client in clients:
            run(["docker", "rm", "-f", client], env=environment, timeout=60)
        run([*command, "down", "--volumes", "--remove-orphans"], env=environment, timeout=180)


if __name__ == "__main__":
    main()

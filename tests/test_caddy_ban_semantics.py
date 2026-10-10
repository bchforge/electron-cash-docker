#!/usr/bin/env python3
"""Prove the production Caddy ban helper installs a real namespace DROP."""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import time
import uuid
from test_support import unique_resource


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CADDY_IMAGE = os.environ.get("CADDY_IMAGE", "electron-cash-docker-caddy:1.0")
FAIL2BAN_IMAGE = os.environ.get("FAIL2BAN_IMAGE", "electron-cash-docker-fail2ban:1.0")
CLIENT_IMAGE = os.environ.get("ELECTRON_CASH_IMAGE", "electron-cash:4.4.6")


def run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, timeout=timeout)


def checked(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = run(command, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(client: str, caddy_ip: str, *, timeout: int = 3) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "docker",
            "exec",
            client,
            "bash",
            "-lc",
            f"curl --noproxy '*' --max-time {timeout} -sS -o /dev/null -w '%{{http_code}}' http://{caddy_ip}/",
        ],
        timeout=timeout + 10,
    )


def helper(caddy: str, state: str, control: str, config: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            f"container:{caddy}",
            "--read-only",
            "--cap-add",
            "NET_ADMIN",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            "--mount",
            f"type=volume,src={state},dst=/var/lib/caddy-bans",
            "--mount",
            f"type=volume,src={control},dst=/run/caddy",
            "--mount",
            f"type=bind,src={config},dst=/var/lib/caddy-bans/Caddyfile,readonly",
            "--entrypoint",
            "/usr/local/bin/caddy-ban",
            FAIL2BAN_IMAGE,
            *arguments,
        ],
        timeout=60,
    )


def seed_identity(state: str, client_ip: str) -> None:
    checked(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "none",
            "--mount",
            f"type=volume,src={state},dst=/var/lib/caddy-bans",
            "--entrypoint",
            "python3",
            FAIL2BAN_IMAGE,
            "-c",
            "import json; from pathlib import Path; p=Path('/var/lib/caddy-bans/client-identity.json'); p.write_text(json.dumps({%r: {'client_ip': %r, 'peer_ip': %r, 'mode': 'direct', 'packet_drop': True}}) + '\\n')"
            % (client_ip, client_ip, client_ip),
        ]
    )


def main() -> None:
    suffix = uuid.uuid4().hex[:10]
    network = unique_resource("caddy-ban-network", kind="network")
    state = unique_resource("caddy-ban-state")
    control = unique_resource("caddy-ban-control")
    caddy = f"ecd-caddy-ban-caddy-{suffix}"
    clients = [f"ecd-caddy-ban-client-{suffix}-{letter}" for letter in ("a", "b")]
    port = free_port()
    config_path = os.path.join(tempfile.gettempdir(), f"ecd-caddy-ban-{suffix}.Caddyfile")
    config = f'''{{
    admin unix//run/caddy/admin.sock
}}

http://127.0.0.1:80 {{
    route {{
        import /var/lib/caddy-bans/banlist.caddy
        respond "ok"
    }}
}}
'''
    resources = [network, state, control]
    try:
        for resource in resources:
            if resource == network:
                checked(["docker", "network", "create", resource])
            else:
                checked(["docker", "volume", "create", resource])
        with open(config_path, "w", encoding="utf-8") as output:
            output.write(config)
        checked(
            [
                "docker",
                "run",
                "--pull=never",
                "--rm",
                "--network",
                "none",
                "--mount",
                f"type=volume,src={state},dst=/var/lib/caddy-bans",
                "--entrypoint",
                "python3",
                FAIL2BAN_IMAGE,
                "-c",
                 "from pathlib import Path; p=Path('/var/lib/caddy-bans'); (p / 'banlist.caddy').write_text('# No active Caddy client-IP bans.\\n'); (p / 'banlist.json').write_text('{\\\"version\\\":1,\\\"bans\\\":[]}\\n')",
            ]
        )
        checked(
            [
                "docker",
                "run",
                "--pull=never",
                "-d",
                "--name",
                caddy,
                "--network",
                network,
                "-p",
                f"127.0.0.1:{port}:80",
                "--mount",
                f"type=volume,src={state},dst=/var/lib/caddy-bans",
                "--mount",
                f"type=volume,src={control},dst=/run/caddy",
                "--mount",
                f"type=bind,src={config_path},dst=/tmp/Caddyfile,readonly",
                "--entrypoint",
                "caddy",
                CADDY_IMAGE,
                "run",
                "--config",
                "/tmp/Caddyfile",
            ]
        )
        state_result = subprocess.CompletedProcess([], 1, "", "")
        for _ in range(40):
            state_result = run(["docker", "inspect", "--format", "{{.State.Status}}", caddy])
            if state_result.stdout.strip() == "running":
                break
            time.sleep(0.25)
        else:
            raise AssertionError(run(["docker", "logs", caddy]).stdout)

        client_ips = []
        caddy_ip = checked(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", caddy]
        ).stdout.strip()
        for client in clients:
            checked(
                [
                    "docker",
                    "run",
                    "--pull=never",
                    "-d",
                    "--name",
                    client,
                    "--network",
                    network,
                    "--entrypoint",
                    "/bin/bash",
                    CLIENT_IMAGE,
                    "-c",
                    "sleep infinity",
                ]
            )
            client_ips.append(
                checked(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", client]).stdout.strip()
            )
        for client in clients:
            deadline = time.monotonic() + 20
            result = subprocess.CompletedProcess([], 1, "", "")
            while time.monotonic() < deadline:
                result = request(client, caddy_ip)
                if result.returncode == 0 and result.stdout == "200":
                    break
                time.sleep(0.25)
            else:
                raise AssertionError(result.stdout + result.stderr + run(["docker", "logs", caddy]).stdout)

        banned_ip = client_ips[0]
        seed_identity(state, banned_ip)
        result = helper(caddy, state, control, config_path, "ban", banned_ip)
        assert result.returncode == 0, result.stdout + result.stderr
        result = helper(caddy, state, control, config_path, "check")
        assert result.returncode == 0, result.stdout + result.stderr
        rules = run(
            [
                "docker",
                "run",
                "--pull=never",
                "--rm",
                "--network",
                f"container:{caddy}",
                "--cap-add",
                "NET_ADMIN",
                "--cap-drop",
                "ALL",
                "--entrypoint",
                "/usr/sbin/iptables",
                FAIL2BAN_IMAGE,
                "-S",
                "ECD_FAIL2BAN",
            ]
        )
        assert rules.returncode == 0 and banned_ip in rules.stdout
        assert "--dports 80,443 -j DROP" in rules.stdout, rules.stdout

        blocked = request(clients[0], caddy_ip, timeout=2)
        assert blocked.returncode != 0 and blocked.stdout not in {"200", "403"}, blocked.stdout + blocked.stderr
        available = request(clients[1], caddy_ip)
        assert available.returncode == 0 and available.stdout == "200", available.stdout + available.stderr

        result = helper(caddy, state, control, config_path, "unban", banned_ip)
        assert result.returncode == 0, result.stdout + result.stderr
        released = request(clients[0], caddy_ip)
        assert released.returncode == 0 and released.stdout == "200", released.stdout + released.stderr
        print("PASS real namespace TCP DROP, unaffected client, idempotent unban, and no HTTP-403 false positive")
    finally:
        for client in clients:
            run(["docker", "rm", "-f", client])
        run(["docker", "rm", "-f", caddy])
        if os.path.exists(config_path):
            os.unlink(config_path)
        run(["docker", "network", "rm", network])
        for volume in (state, control):
            run(["docker", "volume", "rm", "-f", volume])


if __name__ == "__main__":
    main()

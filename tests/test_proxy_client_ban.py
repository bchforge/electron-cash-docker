#!/usr/bin/env python3
"""Prove proxy visitor bans are client-aware application bans, not peer DROPs."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CADDY_IMAGE = os.environ.get("CADDY_IMAGE", "electron-cash-docker-caddy:0.3")
FAIL2BAN_IMAGE = os.environ.get("FAIL2BAN_IMAGE", "electron-cash-docker-fail2ban:0.3")
CLIENT_IMAGE = os.environ.get("ELECTRON_CASH_IMAGE", "electron-cash:4.4.6")


def run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, timeout=timeout)


def checked(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = run(command, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_running(name: str, timeout: int = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = run(["docker", "inspect", "--format", "{{.State.Status}}", name])
        if state.stdout.strip() == "running":
            return
        if state.stdout.strip() in {"exited", "dead"}:
            logs = run(["docker", "logs", name])
            raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(0.25)
    raise AssertionError(f"{name} did not become running")


def wait_jail(name: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = run(["docker", "exec", name, "fail2ban-client", "status", "caddy-basicauth"])
        if result.returncode == 0:
            return
        time.sleep(0.25)
    logs = run(["docker", "logs", name])
    raise AssertionError(logs.stdout + logs.stderr)


def write_state(state: str, config: str, proxy_ip: str) -> None:
    code = (
        "from pathlib import Path; p=Path('/var/lib/caddy-bans'); "
        "(p/'Caddyfile').write_text(" + repr(config) + "); "
        "(p/'banlist.caddy').write_text('# No active Caddy client-IP bans.\\n'); "
        "(p/'banlist.json').write_text('{\"version\":1,\"bans\":[]}\\n'); "
        "(p/'trusted-proxies.txt').write_text(" + repr(proxy_ip + "/32\n") + "); "
        "(p/'client-identity.json').write_text('{}\\n'); "
        "(p/'Caddyfile').chmod(0o644)"
    )
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
            code,
        ]
    )


def main() -> None:
    suffix = uuid.uuid4().hex[:12]
    network = f"ecd-proxy-ban-network-{suffix}"
    state = f"ecd-proxy-ban-state-{suffix}"
    logs = f"ecd-proxy-ban-logs-{suffix}"
    control = f"ecd-proxy-ban-control-{suffix}"
    f2b_state = f"ecd-proxy-ban-f2b-{suffix}"
    caddy = f"ecd-proxy-ban-caddy-{suffix}"
    proxy = f"ecd-proxy-ban-proxy-{suffix}"
    direct = f"ecd-proxy-ban-direct-{suffix}"
    port = free_port()
    resources = [network, state, logs, control, f2b_state]
    proxy_code = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        visitor = "198.51.100.10" if self.path.startswith("/a") else "198.51.100.11"
        request = Request("http://caddy:80/", headers={"X-Forwarded-For": visitor})
        try:
            with urlopen(request, timeout=3) as response:
                status, body = response.status, response.read()
        except HTTPError as error:
            status, body = error.code, error.read()
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_args):
        return

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''
    try:
        checked(["docker", "network", "create", "--label", "com.bchforge.ecd-test=true", network])
        for volume in (state, logs, control, f2b_state):
            checked(["docker", "volume", "create", "--label", "com.bchforge.ecd-test=true", volume])
        checked(
            [
                "docker",
                "run",
                "--pull=never",
                "-d",
                "--name",
                proxy,
                "--label",
                "com.bchforge.ecd-test=true",
                "--network",
                network,
                "-p",
                f"127.0.0.1:{port}:8080",
                "--entrypoint",
                "/opt/electroncash-venv/bin/python",
                CLIENT_IMAGE,
                "-c",
                proxy_code,
            ]
        )
        wait_running(proxy)
        proxy_ip = checked(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", proxy]).stdout.strip()
        assert proxy_ip
        config = f'''{{
    admin unix//run/caddy/admin.sock
    servers {{
        trusted_proxies static {proxy_ip}/32
        trusted_proxies_strict
        client_ip_headers X-Forwarded-For
    }}
}}

:80 {{
    route {{
        import /var/lib/caddy-bans/banlist.caddy
        respond "unauthorized" 401
    }}
    log {{
         output file /var/log/caddy/access.log
        format json
    }}
}}
'''
        write_state(state, config, proxy_ip)
        checked(
            [
                "docker",
                "run",
                "--pull=never",
                "-d",
                "--name",
                caddy,
                "--label",
                "com.bchforge.ecd-test=true",
                "--network",
                network,
                "--network-alias",
                "caddy",
                "--mount",
                f"type=volume,src={state},dst=/var/lib/caddy-bans",
                "--mount",
                f"type=volume,src={logs},dst=/var/log/caddy",
                "--mount",
                f"type=volume,src={control},dst=/run/caddy",
                "--entrypoint",
                "/usr/bin/caddy",
                CADDY_IMAGE,
                "run",
                "--config",
                "/var/lib/caddy-bans/Caddyfile",
            ]
        )
        wait_running(caddy)
        checked(
            [
                "docker",
                "run",
                "--pull=never",
                "-d",
                "--name",
                f2b_state,
                "--label",
                "com.bchforge.ecd-test=true",
                "--network",
                f"container:{caddy}",
                "--cap-add",
                "NET_ADMIN",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--mount",
                f"type=volume,src={logs},dst=/var/log/caddy,ro",
                "--mount",
                f"type=volume,src={state},dst=/var/lib/caddy-bans",
                "--mount",
                f"type=volume,src={control},dst=/run/caddy",
                "--mount",
                f"type=volume,src={f2b_state},dst=/var/lib/fail2ban",
                "-e",
                "CADDY_EDGE_BIND=0.0.0.0",
                "-e",
                "FAIL2BAN_MAXRETRY=3",
                "-e",
                "FAIL2BAN_FINDTIME=30",
                "-e",
                "FAIL2BAN_BANTIME=60",
                "--label",
                "com.bchforge.ecd-test=true",
                FAIL2BAN_IMAGE,
            ]
        )
        wait_running(f2b_state)
        wait_jail(f2b_state)

        for _ in range(3):
            result = run(["curl", "--noproxy", "*", "--max-time", "5", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"http://127.0.0.1:{port}/a"])
            assert result.returncode == 0 and result.stdout == "401", result.stdout + result.stderr
        deadline = time.monotonic() + 30
        state_text = ""
        while time.monotonic() < deadline:
            state_text = run(["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/banlist.json"]).stdout
            try:
                document = json.loads(state_text)
            except json.JSONDecodeError:
                document = {}
            if document.get("bans"):
                break
            time.sleep(0.25)
        else:
            diagnostics = "\n".join(
                [
                    state_text,
                    run(["docker", "logs", f2b_state]).stdout,
                    run(["docker", "exec", caddy, "cat", "/var/log/caddy/access.log"]).stdout,
                    run(["docker", "exec", f2b_state, "cat", "/var/lib/fail2ban/access.log"]).stdout,
                    run(["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/client-identity.json"]).stdout,
                    run(["docker", "exec", f2b_state, "ls", "-l", "/var/log/caddy"]).stdout,
                    run(["docker", "exec", f2b_state, "cat", "/var/log/caddy/access.log"]).stdout,
                    run(["docker", "inspect", f2b_state, "--format", "{{json .Mounts}}"]).stdout,
                    run(["docker", "inspect", caddy, "--format", "{{json .Mounts}}"]).stdout,
                ]
            )
            raise AssertionError(diagnostics)
        entry = document["bans"][0]
        assert entry["client_ip"] == "198.51.100.10", document
        assert entry["mode"] == "trusted_proxy" and entry["packet_drop"] is False, document
        assert entry["peer_ip"] == proxy_ip, document
        rules = run(["docker", "exec", f2b_state, "/usr/sbin/iptables", "-S", "ECD_FAIL2BAN"])
        assert rules.returncode == 0, rules.stdout + rules.stderr
        assert proxy_ip not in rules.stdout and "198.51.100.10" not in rules.stdout, rules.stdout

        banned = run(["curl", "--noproxy", "*", "--max-time", "5", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"http://127.0.0.1:{port}/a"])
        available = run(["curl", "--noproxy", "*", "--max-time", "5", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"http://127.0.0.1:{port}/b"])
        assert banned.returncode == 0 and banned.stdout == "403", banned.stdout + banned.stderr
        assert available.returncode == 0 and available.stdout == "401", available.stdout + available.stderr

        checked(
            [
                "docker",
                "run",
                "--pull=never",
                "-d",
                "--name",
                direct,
                "--label",
                "com.bchforge.ecd-test=true",
                "--network",
                network,
                "--entrypoint",
                "/bin/sleep",
                CLIENT_IMAGE,
                "infinity",
            ]
        )
        direct_request = checked(
            [
                "docker",
                "exec",
                direct,
                "/bin/bash",
                "-lc",
                "curl --noproxy '*' --max-time 5 -sS -H 'X-Forwarded-For: 203.0.113.99' http://caddy/",
            ]
        )
        assert "203.0.113.99" not in run(["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/client-identity.json"]).stdout
        assert direct_request.stdout
        print("PASS trusted-proxy per-visitor application ban, shared-peer non-DROP, unaffected visitor, and spoof resistance")
    finally:
        for name in (direct, f2b_state, caddy, proxy):
            run(["docker", "rm", "-f", name])
        for volume in (state, logs, control, f2b_state):
            run(["docker", "volume", "rm", "-f", volume])
        run(["docker", "network", "rm", network])


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise Caddy's native direct and trusted-proxy client-IP branches."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("CADDY_IMAGE", "electron-cash-docker-caddy:0.3")


def run(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, timeout=timeout)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_log(container: str, *, count: int = 1) -> list[dict]:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        records = []
        result = run(["docker", "logs", container])
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(record.get("logger", "")).startswith("http.log"):
                records.append(record)
        if len(records) >= count:
            return records
        time.sleep(0.25)
    raise AssertionError(f"Caddy did not write {count} structured access log records: {container}")


def caddyfile(listen_port: int) -> str:
    return f'''{{
    admin off
    servers {{
        trusted_proxies static 127.0.0.1/32 ::1/128
        trusted_proxies_strict
        client_ip_headers CF-Connecting-IP X-Forwarded-For
    }}
}}

:{listen_port} {{
    respond "ok"
    log {{
        output stdout
        format json
    }}
}}
'''


def start(name: str, config: Path, port: int, *, host_network: bool) -> None:
    command = [
        "docker",
        "run",
        "--pull=never",
        "-d",
        "--name",
        name,
        "--mount",
        f"type=bind,src={config},dst=/tmp/Caddyfile,readonly",
    ]
    if host_network:
        command.extend(["--network", "host"])
    else:
        command.extend(["-p", f"127.0.0.1:{port}:80"])
    command.extend(["--entrypoint", "caddy", IMAGE, "run", "--config", "/tmp/Caddyfile"])
    result = run(command)
    assert result.returncode == 0, result.stdout + result.stderr
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        state = run(["docker", "inspect", "--format", "{{.State.Status}}", name]).stdout.strip()
        if state == "running":
            probe = run(["curl", "--noproxy", "*", "--max-time", "1", "-sS", "-o", "/dev/null", f"http://127.0.0.1:{port}/"])
            if probe.returncode == 0:
                return
        if state in {"exited", "dead"}:
            logs = run(["docker", "logs", name])
            raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(0.25)
    raise AssertionError(f"Caddy test container {name} did not become ready")


def request(port: int, *, headers: dict[str, str], container: str) -> None:
    command = ["curl", "--noproxy", "*", "--max-time", "5", "-sS", "-o", "/dev/null"]
    for key, value in headers.items():
        command.extend(["-H", f"{key}: {value}"])
    command.append(f"http://127.0.0.1:{port}/")
    result = run(command)
    if result.returncode != 0:
        logs = run(["docker", "logs", container])
        raise AssertionError(result.stdout + result.stderr + logs.stdout + logs.stderr)


def assert_record(record: dict, expected: str, forbidden: tuple[str, ...]) -> None:
    request_data = record.get("request") or {}
    actual = request_data.get("client_ip")
    assert actual == expected, record
    assert all(value != actual for value in forbidden), record


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ecd-client-ip-") as directory:
        root = Path(directory)
        config = root / "Caddyfile"
        config.write_text(caddyfile(80), encoding="utf-8")
        trusted_config = root / "trusted-Caddyfile"
        direct_name = f"ecd-client-ip-direct-{os.getpid()}"
        trusted_name = f"ecd-client-ip-trusted-{os.getpid()}"
        direct_port = free_port()
        trusted_port = free_port()
        trusted_config.write_text(caddyfile(trusted_port), encoding="utf-8")
        try:
            start(direct_name, config, direct_port, host_network=False)
            request(
                direct_port,
                container=direct_name,
                headers={
                    "CF-Connecting-IP": "203.0.113.123",
                    "X-Forwarded-For": "203.0.113.124",
                },
            )
            direct_record = wait_log(direct_name)[-1]
            direct_peer = (direct_record.get("request") or {}).get("remote_ip")
            assert direct_peer and direct_peer != "203.0.113.123", direct_record
            assert_record(direct_record, direct_peer, ("203.0.113.123", "203.0.113.124"))

            start(trusted_name, trusted_config, trusted_port, host_network=True)
            request(trusted_port, container=trusted_name, headers={"CF-Connecting-IP": "198.51.100.20"})
            trusted_record = wait_log(trusted_name)[-1]
            assert_record(trusted_record, "198.51.100.20", ("127.0.0.1",))
            request(trusted_port, container=trusted_name, headers={"CF-Connecting-IP": "2001:db8::20"})
            ipv6_record = wait_log(trusted_name, count=2)[-1]
            assert_record(ipv6_record, "2001:db8::20", ("127.0.0.1",))
            print("PASS direct spoof resistance and trusted-proxy IPv4/IPv6 client-IP normalization")
        finally:
            run(["docker", "rm", "-f", direct_name])
            run(["docker", "rm", "-f", trusted_name])


if __name__ == "__main__":
    main()

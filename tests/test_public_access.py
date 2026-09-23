#!/usr/bin/env python3
"""Verify public HTTPS, WSS, and Cloudflare-origin identity normalization."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]


def http_status(
    host: str,
    path: str,
    cookie: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> int:
    headers = {"Host": host}
    if cookie:
        headers["Cookie"] = cookie
    headers.update(extra_headers or {})
    command = ["curl", "--noproxy", "*", "--max-time", "20", "-sS", "-o", "/dev/null", "-w", "%{http_code}"]
    for key, value in headers.items():
        command.extend(["-H", f"{key}: {value}"])
    command.append(f"https://{host}{path}")
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return int(result.stdout)


def login(host: str, password: str) -> tuple[int, str]:
    connection = http.client.HTTPSConnection(host, timeout=20)
    body = urlencode({"password": password})
    connection.request(
        "POST",
        "/auth/login",
        body=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"https://{host}",
        },
    )
    response = connection.getresponse()
    status = response.status
    headers = response.headers
    response.read()
    connection.close()
    if status != 303:
        return status, ""
    cookie = SimpleCookie(headers["Set-Cookie"])
    return status, f"ecd_session={cookie['ecd_session'].value}"


def websocket_status(host: str, cookie: str) -> tuple[int, bytes]:
    sock = socket.create_connection((host, 443), timeout=20)
    sock.settimeout(20)
    context = ssl.create_default_context()
    tls = context.wrap_socket(sock, server_hostname=host)
    request = (
        f"GET /websockify HTTP/1.1\r\nHost: {host}\r\n"
        "Connection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: SGVsbG9XZWJTb2NrZXQ=\r\n"
        f"Cookie: {cookie}\r\n\r\n"
    ).encode()
    try:
        tls.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = tls.recv(4096)
            if not chunk:
                raise AssertionError("public WebSocket handshake closed early")
            response.extend(chunk)
        status = int(bytes(response).split(None, 2)[1])
        payload = bytes(response).split(b"\r\n\r\n", 1)[1]
        if status != 101:
            return status, b""
        while len(payload) < 2:
            payload += tls.recv(4096)
        length = payload[1] & 0x7F
        offset = 2
        if length == 126:
            while len(payload) < 4:
                payload += tls.recv(4096)
            length = int.from_bytes(payload[2:4], "big")
            offset = 4
        elif length == 127:
            while len(payload) < 10:
                payload += tls.recv(4096)
            length = int.from_bytes(payload[2:10], "big")
            offset = 10
        while len(payload) < offset + length:
            payload += tls.recv(4096)
        return status, payload[offset : offset + length]
    finally:
        tls.close()


def assert_origin_identity(host: str) -> None:
    container = os.environ.get("PUBLIC_CADDY_CONTAINER")
    if not container:
        raise AssertionError("PUBLIC_CADDY_CONTAINER is required for origin identity evidence")
    probe_path = f"/vnc.html?public_acceptance_probe={os.getpid()}-{time.time_ns()}"
    assert http_status(
        host,
        probe_path,
    ) == 401
    result = subprocess.run(
        ["docker", "exec", container, "cat", "/var/log/caddy/access.log"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    record = next(
        record
        for record in reversed(records)
        if record.get("status") == 401 and record.get("request", {}).get("uri") == probe_path
    )
    request = record["request"]
    ranges = [
        ipaddress.ip_network(line.strip())
        for path in (ROOT / "docker/caddy/cloudflare-ipv4.txt", ROOT / "docker/caddy/cloudflare-ipv6.txt")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    remote_ip = ipaddress.ip_address(request["remote_ip"])
    client_ip = ipaddress.ip_address(request["client_ip"])
    assert any(remote_ip in network for network in ranges), remote_ip
    assert client_ip.is_global


def main() -> None:
    host = os.environ.get("PUBLIC_HOST", "ecd-test.bchforge.org")
    password = os.environ.get("PUBLIC_AUTH_PASSWORD")
    if not password:
        raise AssertionError("PUBLIC_AUTH_PASSWORD is required and must not be committed")
    assert_origin_identity(host)
    assert http_status(host, "/") == 200
    assert http_status(host, "/vnc.html") == 401
    wrong_status, _ = login(host, "wrong-secret")
    assert wrong_status == 401
    login_status, cookie = login(host, password)
    assert login_status == 303 and cookie
    assert http_status(host, "/", cookie) == 303
    assert http_status(host, "/vnc.html", cookie) == 200
    status, banner = websocket_status(host, cookie)
    for _ in range(2):
        if status == 101 and banner.startswith(b"RFB "):
            break
        time.sleep(1)
        status, banner = websocket_status(host, cookie)
    assert status == 101 and banner.startswith(b"RFB "), (status, banner)
    print("PASS public HTTPS auth, noVNC, WSS/RFB, and Cloudflare identity checks")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Disposable Caddy gateway, noVNC WebSocket, and fail2ban acceptance test."""

from __future__ import annotations

import http.client
import json
import os
import shlex
import socket
import subprocess
import time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
AUTH_PASSWORD = "synthetic-auth-secret"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def checked(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = run(command, env=env, timeout=timeout)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result


def compose(project: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-p",
        project,
        "-f",
        "docker-compose.yml",
    ]


class LocalTLSConnection(http.client.HTTPSConnection):
    """Connect to loopback while retaining the requested TLS hostname."""

    def connect(self) -> None:
        raw = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        self.sock = getattr(self, "_context").wrap_socket(raw, server_hostname=self.host)


def https_request(
    port: int,
    path: str,
    *,
    cookie: str = "",
    method: str = "GET",
    body: str | None = None,
) -> tuple[int, http.client.HTTPMessage, bytes]:
    connection = LocalTLSConnection("wallet.test", port, context=__import__("ssl")._create_unverified_context())
    headers = {"Cookie": cookie} if cookie else {}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    status = response.status
    response_headers = response.headers
    connection.close()
    return status, response_headers, payload


def login(port: int, password: str = AUTH_PASSWORD, *, remember: bool = False) -> str:
    fields = {"password": password}
    if remember:
        fields["remember"] = "on"
    status, headers, body = https_request(
        port,
        "/auth/login",
        method="POST",
        body=urlencode(fields),
    )
    if status != 303:
        raise AssertionError(f"login failed: {status} {body!r}")
    cookie = SimpleCookie(headers["Set-Cookie"])
    return f"ecd_session={cookie['ecd_session'].value}"


def websocket_status(port: int, cookie: str = "") -> int:
    cookie_header = f"Cookie: {cookie}\r\n" if cookie else ""
    context = __import__("ssl")._create_unverified_context()
    raw = socket.create_connection(("127.0.0.1", port), 5)
    connection = context.wrap_socket(raw, server_hostname="wallet.test")
    connection.sendall(
        (
            "GET /websockify HTTP/1.1\r\n"
            "Host: wallet.test\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: SGVsbG9XZWJTb2NrZXQ=\r\n"
            f"{cookie_header}\r\n"
        ).encode()
    )
    data = connection.recv(4096)
    connection.close()
    return int(data.split(None, 2)[1])


def container_name(project: str, service: str) -> str:
    result = checked([*compose(project), "ps", "-q", service])
    container_id = result.stdout.strip()
    if not container_id:
        raise AssertionError(f"no container for {service}")
    return container_id


def exec_in(container: str, command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return run(["docker", "exec", container, *command], timeout=timeout)


def client_container(project: str, network: str, name: str) -> str:
    checked(
        [
            "docker",
            "run",
            "--pull=never",
            "-d",
            "--name",
            name,
            "--network",
            network,
            "--entrypoint",
            "/bin/sleep",
            os.environ["ELECTRON_CASH_IMAGE"],
            "infinity",
        ]
    )
    return checked(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name]).stdout.strip()


def client_request(
    container: str,
    caddy_ip: str,
    *,
    cookie: str = "",
    count: int = 1,
    forwarded: str = "",
    path: str = "/vnc.html",
) -> subprocess.CompletedProcess[str]:
    cookie_header = shlex.join(["-H", f"Cookie: {cookie}"]) if cookie else ""
    forwarding = shlex.join(["-H", f"X-Forwarded-For: {forwarded}"]) if forwarded else ""
    command = (
        f"for i in $(seq 1 {count}); do "
        f"curl --noproxy '*' --max-time 3 -sk --resolve wallet.test:443:{caddy_ip} "
        f"{cookie_header} {forwarding} -o /dev/null -w '%{{http_code}} ' https://wallet.test{path}; "
        "done"
    )
    return exec_in(container, ["/bin/bash", "-lc", command], timeout=30)


def client_websocket_request(container: str, caddy_ip: str, *, cookie: str = "") -> subprocess.CompletedProcess[str]:
    cookie_header = shlex.join(["-H", f"Cookie: {cookie}"]) if cookie else ""
    command = (
        "curl --noproxy '*' --max-time 5 -sk --http1.1 --resolve wallet.test:443:"
        f"{caddy_ip} {cookie_header} -H 'Connection: Upgrade' -H 'Upgrade: websocket' "
        "-H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: SGVsbG9XZWJTb2NrZXQ=' "
        "-o /dev/null -w '%{http_code}' https://wallet.test/websockify"
    )
    return exec_in(container, ["/bin/bash", "-lc", command], timeout=30)


def wait_for_ban_state(fail2ban: str, caddy: str, client_ip: str, *, present: bool) -> None:
    """Wait for fail2ban and Caddy's shared authoritative state to agree."""
    deadline = time.monotonic() + 30
    jail_output = ""
    state_output = ""
    while time.monotonic() < deadline:
        jail = run(["docker", "exec", fail2ban, "fail2ban-client", "status", "caddy-basicauth"])
        state = run(["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/banlist.json"])
        jail_output = jail.stdout + jail.stderr
        state_output = state.stdout + state.stderr
        try:
            document = json.loads(state.stdout)
            bans = document.get("bans", []) if isinstance(document, dict) else []
        except json.JSONDecodeError:
            bans = []
        jail_has_ip = client_ip in jail.stdout
        caddy_has_ip = any(
            isinstance(entry, dict) and entry.get("client_ip") == client_ip
            for entry in bans
        ) if isinstance(bans, list) else False
        packet = run(["docker", "exec", fail2ban, "/usr/sbin/iptables", "-S", "ECD_FAIL2BAN"])
        packet_has_ip = packet.returncode == 0 and client_ip in packet.stdout and "--dports 80,443 -j DROP" in packet.stdout
        packet_ok = packet_has_ip if present else not packet_has_ip
        if jail.returncode == 0 and state.returncode == 0 and jail_has_ip == present and caddy_has_ip == present and packet_ok:
            return
        time.sleep(0.25)
    raise AssertionError(
        f"ban state did not reach present={present}: jail={jail_output} caddy={state_output}"
    )


def wait_for_client_http_status(
    container: str, caddy_ip: str, *, cookie: str = "", expected: str
) -> subprocess.CompletedProcess[str]:
    """Wait for the gateway to become ready after a Caddy restart."""
    deadline = time.monotonic() + 30
    result = subprocess.CompletedProcess([], 1, "", "")
    while time.monotonic() < deadline:
        result = client_request(container, caddy_ip, cookie=cookie)
        if result.returncode == 0 and expected in result.stdout:
            return result
        time.sleep(0.25)
    raise AssertionError(f"client HTTP status did not become {expected}: {result.stdout}{result.stderr}")


def wait_for_client_websocket_status(
    container: str, caddy_ip: str, *, cookie: str = "", expected: str
) -> subprocess.CompletedProcess[str]:
    """Wait for the gateway WebSocket endpoint after a Caddy restart."""
    deadline = time.monotonic() + 30
    result = subprocess.CompletedProcess([], 1, "", "")
    while time.monotonic() < deadline:
        result = client_websocket_request(container, caddy_ip, cookie=cookie)
        if result.returncode == 0 and result.stdout == expected:
            return result
        time.sleep(0.25)
    raise AssertionError(f"client WebSocket status did not become {expected}: {result.stdout}{result.stderr}")


def packet_drop_counters(fail2ban: str, client_ip: str) -> tuple[int, int]:
    result = run(["docker", "exec", fail2ban, "/usr/sbin/iptables", "-L", "ECD_FAIL2BAN", "-v", "-n"])
    assert result.returncode == 0, result.stdout + result.stderr
    for line in result.stdout.splitlines():
        if client_ip not in line or "DROP" not in line or not any(
            token in line.split() for token in ("tcp", "6")
        ):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0].isdigit() and fields[1].isdigit():
            return int(fields[0]), int(fields[1])
    raise AssertionError(f"no packet DROP counter for {client_ip}: {result.stdout}")


def main() -> None:
    required = ("ELECTRON_CASH_IMAGE", "TOR_IMAGE", "FAIL2BAN_IMAGE", "AUTH_SESSION_IMAGE", "CI_REMOTE_PROJECT")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise AssertionError(f"missing remote acceptance environment: {', '.join(missing)}")
    project = os.environ["CI_REMOTE_PROJECT"]
    port = int(os.environ.get("CI_REMOTE_PORT", "18443"))
    environment = os.environ.copy()
    environment.update(
        {
            "ELECTRON_CASH_IMAGE": os.environ["ELECTRON_CASH_IMAGE"],
            "TOR_IMAGE": os.environ["TOR_IMAGE"],
            "FAIL2BAN_IMAGE": os.environ["FAIL2BAN_IMAGE"],
            "AUTH_SESSION_IMAGE": os.environ["AUTH_SESSION_IMAGE"],
            "USE_TOR": "false",
            "CADDY_SITE_ADDRESS": "https://wallet.test",
            "CADDY_TLS_MODE": "internal",
            "CADDY_EDGE_BIND": "127.0.0.1",
            "CADDY_HTTP_HOST_PORT": str(free_port()),
            "CADDY_HTTPS_HOST_PORT": str(port),
            "BASIC_AUTH_PASSWORD": AUTH_PASSWORD,
            "FAIL2BAN_MAXRETRY": "5",
            "FAIL2BAN_FINDTIME": "30",
            # Keep the ban active through the restart and explicit unban
            # assertions; expiry is covered by the dedicated jail test.
            "FAIL2BAN_BANTIME": "60",
            "ECD_WALLET_VOLUME": f"{project}-wallet",
            "ECD_TOR_VOLUME": f"{project}-tor",
        }
    )
    clients: list[str] = []
    try:
            checked([*compose(project), "up", "-d", "--no-build"], env=environment, timeout=180)
            model = json.loads(checked([*compose(project), "config", "--format", "json"], env=environment).stdout)
            assert not model["services"]["electron-cash"].get("ports"), "direct noVNC port is still published"
            for _ in range(30):
                try:
                    if https_request(port, "/vnc.html")[0] == 401:
                        break
                except (OSError, http.client.HTTPException):
                    time.sleep(1)
            else:
                raise AssertionError("authenticated HTTPS edge did not become ready")
            status, headers, _ = https_request(port, "/vnc.html")
            assert status == 401 and not headers.get("WWW-Authenticate")
            assert https_request(port, "/auth/login", method="POST", body=urlencode({"password": "wrong-secret"}))[0] == 401
            cookie = login(port, remember=True)
            authenticated_status = 0
            for _ in range(60):
                authenticated_status, _, _ = https_request(port, "/vnc.html", cookie=cookie)
                if authenticated_status == 200:
                    break
                time.sleep(1)
            assert authenticated_status == 200, f"authenticated noVNC status was {authenticated_status}"
            assert https_request(port, "/", cookie=cookie)[0] == 303
            assert websocket_status(port) == 401
            assert websocket_status(port, cookie=cookie) == 101

            caddy = container_name(project, "caddy")
            fail2ban = container_name(project, "fail2ban")
            caddy_ip = checked(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", caddy]).stdout.strip()
            network = next(iter(json.loads(checked(["docker", "inspect", caddy]).stdout)[0]["NetworkSettings"]["Networks"]))
            client_a = f"{project}-client-a"
            client_b = f"{project}-client-b"
            clients.extend((client_a, client_b))
            client_container(project, network, client_a)
            client_a_ip = checked(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", client_a]).stdout.strip()
            result = client_request(client_a, caddy_ip, count=5, forwarded="203.0.113.9")
            assert result.returncode == 0 and "401" in result.stdout, result.stdout + result.stderr
            wait_for_ban_state(fail2ban, caddy, client_a_ip, present=True)
            status = checked(["docker", "exec", fail2ban, "fail2ban-client", "status", "caddy-basicauth"]).stdout
            assert "203.0.113.9" not in status
            regex = checked(
                [
                    "docker",
                    "exec",
                    fail2ban,
                    "fail2ban-regex",
                    "--print-all-matched",
                    "/var/log/caddy/access.log",
                    "/etc/fail2ban/filter.d/caddy-basicauth.conf",
                ],
                env=environment,
            ).stdout
            matched = regex.split("|- Matched line(s):", 1)[-1].split("|- Missed line(s):", 1)[0]
            matched_records = [
                json.loads(line[3:])
                for line in matched.splitlines()
                if line.startswith("|  {")
            ]
            assert matched_records, regex
            matched_ips = {(record.get("request") or {}).get("client_ip") for record in matched_records}
            assert client_a_ip in matched_ips, regex
            assert "203.0.113.9" not in matched_ips, regex
            client_container(project, network, client_b)
            result = client_request(client_b, caddy_ip, cookie=cookie)
            assert result.returncode == 0 and "200" in result.stdout, result.stdout + result.stderr
            before_drop = packet_drop_counters(fail2ban, client_a_ip)
            blocked = client_request(client_a, caddy_ip, cookie=cookie)
            assert blocked.returncode != 0 and "200" not in blocked.stdout, blocked.stdout + blocked.stderr
            after_drop = packet_drop_counters(fail2ban, client_a_ip)
            assert after_drop[0] > before_drop[0] and after_drop[1] > before_drop[1], (before_drop, after_drop)
            print(f"direct DROP evidence: client={client_a_ip} packets={before_drop[0]}->{after_drop[0]} bytes={before_drop[1]}->{after_drop[1]}")
            blocked_websocket = client_websocket_request(client_a, caddy_ip, cookie=cookie)
            assert blocked_websocket.returncode != 0, blocked_websocket.stdout + blocked_websocket.stderr

            checked([*compose(project), "restart", "caddy"], env=environment, timeout=120)
            caddy = container_name(project, "caddy")
            fail2ban = container_name(project, "fail2ban")
            wait_for_ban_state(fail2ban, caddy, client_a_ip, present=True)
            blocked = client_request(client_a, caddy_ip, cookie=cookie)
            assert blocked.returncode != 0 and "200" not in blocked.stdout, blocked.stdout + blocked.stderr

            checked(["docker", "exec", fail2ban, "fail2ban-client", "set", "caddy-basicauth", "unbanip", client_a_ip])
            wait_for_ban_state(fail2ban, caddy, client_a_ip, present=False)
            released = client_request(client_a, caddy_ip)
            assert released.returncode == 0 and "401" in released.stdout, released.stdout + released.stderr
            released_websocket = client_websocket_request(client_a, caddy_ip)
            assert released_websocket.returncode == 0 and released_websocket.stdout == "401", released_websocket.stdout + released_websocket.stderr
            print("PASS Caddy auth, authenticated WebSocket, fail2ban enforcement, client isolation, and release")
    finally:
        for client in clients:
            run(["docker", "rm", "-f", client])
        if os.environ.get("CI_KEEP_REMOTE") != "1":
            run([*compose(project), "down", "--volumes", "--remove-orphans"], env=environment, timeout=120)


if __name__ == "__main__":
    main()

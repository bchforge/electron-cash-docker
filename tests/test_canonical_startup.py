#!/usr/bin/env python3
"""Mandatory raw-Compose fresh-start, restart, and noVNC/RFB acceptance gate."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from test_auth_browser import run_browser_acceptance
from test_support import unique_project


ROOT = Path(__file__).resolve().parents[1]
AUTH_PASSWORD = "canonical-meta-password"
BCRYPT_PATTERN = re.compile(r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}")
OBSERVATION_SECONDS = max(120, int(os.environ.get("CI_STARTUP_STABILITY_SECONDS", "120")))
RESTART_OBSERVATION_SECONDS = 30


class NoRedirectHandler(HTTPRedirectHandler):
    def http_error_303(self, req, fp, code, msg, headers):
        return fp


NO_REDIRECT_OPENER = build_opener(NoRedirectHandler)


def run(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path = ROOT,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        errors="replace",  # BuildKit progress can contain non-UTF-8 terminal bytes.
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def redacted_output(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout + result.stderr).replace(AUTH_PASSWORD, "[REDACTED]")


def checked(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path = ROOT,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    result = run(command, env=env, cwd=cwd, timeout=timeout)
    if result.returncode != 0:
        raise AssertionError(redacted_output(result))
    return result


def compose() -> list[str]:
    return ["docker", "compose"]


def http_get(port: int, path: str, *, cookie: str = "", host: str = "localhost") -> tuple[int, bytes]:
    headers = {"Host": host}
    if cookie:
        headers["Cookie"] = cookie
    request = Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=5) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


def login(port: int, password: str = AUTH_PASSWORD, *, host: str = "localhost") -> tuple[int, str]:
    request = Request(
        f"http://127.0.0.1:{port}/auth/login",
        data=urlencode({"password": password}).encode(),
        headers={
            "Host": host,
            "Origin": f"http://{host}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=5) as response:
            status = response.status
            headers = response.headers
            response.read()
    except HTTPError as error:
        return error.code, ""
    if status != 303:
        return status, ""
    cookie = SimpleCookie(headers["Set-Cookie"])
    return status, f"ecd_session={cookie['ecd_session'].value}"


def recv_exact(sock: socket.socket, length: int, initial: bytearray | None = None) -> bytes:
    data = initial if initial is not None else bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise AssertionError("socket closed before the expected data arrived")
        data.extend(chunk)
    result = bytes(data[:length])
    del data[:length]
    return result


def read_headers(sock: socket.socket) -> tuple[bytes, bytearray]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("WebSocket handshake closed before headers")
        data.extend(chunk)
    headers, remainder = bytes(data).split(b"\r\n\r\n", 1)
    return headers, bytearray(remainder)


def websocket_frame(payload: bytes, *, opcode: int = 2) -> bytes:
    key = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length < 65536:
        header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack(">H", length)
    else:
        header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack(">Q", length)
    masked = bytes(value ^ key[index % 4] for index, value in enumerate(payload))
    return header + key + masked


class RFBWebSocket:
    def __init__(self, sock: socket.socket, initial: bytearray):
        self.sock = sock
        self.raw = initial
        self.rfb = bytearray()

    def raw_exact(self, length: int) -> bytes:
        return recv_exact(self.sock, length, self.raw)

    def receive_frame(self) -> tuple[int, bytes]:
        first, second = self.raw_exact(2)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", self.raw_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self.raw_exact(8))[0]
        masked = bool(second & 0x80)
        mask = self.raw_exact(4) if masked else b""
        payload = bytearray(self.raw_exact(length))
        if masked:
            payload = bytearray(value ^ mask[index % 4] for index, value in enumerate(payload))
        return first & 0x0F, bytes(payload)

    def receive_rfb(self, length: int) -> bytes:
        while len(self.rfb) < length:
            opcode, payload = self.receive_frame()
            if opcode == 9:
                self.sock.sendall(websocket_frame(payload, opcode=10))
                continue
            if opcode == 8:
                raise AssertionError("RFB WebSocket closed unexpectedly")
            self.rfb.extend(payload)
        return recv_exact(self.sock, length, self.rfb)


def websocket_rfb(port: int, *, cookie: str = "", host: str = "localhost") -> tuple[int, int, int]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    cookie_header = f"Cookie: {cookie}\r\n" if cookie else ""
    request = (
        "GET /websockify HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: SGVsbG9XZWJTb2NrZXQ=\r\n"
        f"{cookie_header}\r\n"
    ).encode()
    try:
        sock.sendall(request)
        response, initial = read_headers(sock)
        status = int(response.split(None, 2)[1])
        if status != 101:
            return status, 0, 0

        stream = RFBWebSocket(sock, initial)
        banner = stream.receive_rfb(12)
        assert banner == b"RFB 003.008\n", banner
        sock.sendall(websocket_frame(b"RFB 003.008\n"))

        security_count = stream.receive_rfb(1)[0]
        security_types = stream.receive_rfb(security_count)
        assert 1 in security_types, security_types
        sock.sendall(websocket_frame(b"\x01"))
        assert stream.receive_rfb(4) == b"\x00\x00\x00\x00"
        sock.sendall(websocket_frame(b"\x01"))

        server_init = stream.receive_rfb(24)
        width, height = struct.unpack(">HH", server_init[:4])
        bits_per_pixel = server_init[4]
        name_length = struct.unpack(">I", server_init[20:24])[0]
        name = stream.receive_rfb(name_length)
        assert width > 0 and height > 0 and name, (width, height, name)
        assert bits_per_pixel in {8, 16, 32}, bits_per_pixel

        # Request only raw rectangles so the returned payload is deterministic.
        sock.sendall(websocket_frame(struct.pack(">BBH", 2, 0, 1) + struct.pack(">i", 0)))
        sock.sendall(websocket_frame(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height)))
        message_type = stream.receive_rfb(1)[0]
        assert message_type == 0, message_type
        stream.receive_rfb(1)
        rectangle_count = struct.unpack(">H", stream.receive_rfb(2))[0]
        assert rectangle_count > 0
        framebuffer_bytes = 0
        for _ in range(rectangle_count):
            rectangle = stream.receive_rfb(12)
            rectangle_width, rectangle_height, encoding = struct.unpack(">HHI", rectangle[4:12])
            assert encoding == 0, encoding
            bytes_per_pixel = bits_per_pixel // 8
            framebuffer_bytes += rectangle_width * rectangle_height * bytes_per_pixel
            stream.receive_rfb(rectangle_width * rectangle_height * bytes_per_pixel)
        assert framebuffer_bytes > 0
        return status, width, framebuffer_bytes
    finally:
        sock.close()


def container_id(command: list[str], service: str, *, env: dict[str, str], cwd: Path) -> str:
    result = checked([*command, "ps", "-aq", service], env=env, cwd=cwd)
    identifier = result.stdout.strip()
    if not identifier:
        raise AssertionError(f"Compose did not create {service}")
    return identifier


def inspect(identifier: str) -> dict:
    result = subprocess.run(
        ["docker", "inspect", identifier],
        cwd=ROOT,
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)[0]


def wait_running(command: list[str], service: str, *, env: dict[str, str], cwd: Path) -> str:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        identifier = container_id(command, service, env=env, cwd=cwd)
        state = inspect(identifier)["State"]
        if state["Status"] == "running":
            return identifier
        if state["Status"] in {"dead", "exited"}:
            logs = subprocess.run(
                ["docker", "logs", identifier],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
            raise AssertionError(f"{service} exited\n{redacted_output(logs)}")
        time.sleep(1)
    raise AssertionError(f"{service} did not become running")


def wait_http(port: int) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            status, _ = http_get(port, "/")
            if status == 200:
                return
        except (OSError, URLError):
            pass
        time.sleep(1)
    raise AssertionError("Caddy did not serve authenticated HTTP")


def wait_healthy(identifier: str, service: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        health = inspect(identifier)["State"].get("Health", {})
        if health.get("Status") == "healthy":
            return
        if health.get("Status") == "unhealthy":
            raise AssertionError(f"{service} became unhealthy")
        time.sleep(1)
    raise AssertionError(f"{service} did not become healthy")


def assert_candidate_image(identifier: str, expected_image: str, *, env: dict[str, str]) -> None:
    expected_id = checked(
        ["docker", "image", "inspect", "--format", "{{.Id}}", expected_image],
        env=env,
    ).stdout.strip()
    assert expected_id == inspect(identifier)["Image"]


def assert_direct_ports_blocked() -> None:
    for port in (5900, 6080):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                raise AssertionError(f"direct port {port} is reachable")
        except (ConnectionRefusedError, TimeoutError, OSError):
            pass


def client_container(image: str, network: str, name: str, *, env: dict[str, str]) -> str:
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
            "/bin/bash",
            image,
            "-c",
            "sleep infinity",
        ],
        env=env,
        cwd=ROOT,
    )
    return checked(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
        env=env,
        cwd=ROOT,
    ).stdout.strip()


def client_http(
    client: str,
    caddy_ip: str,
    *,
    cookie: str = "",
    count: int = 1,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    cookie_header = shlex.join(["-H", f"Cookie: {cookie}"]) if cookie else ""
    command = (
        f"for i in $(seq 1 {count}); do "
        "curl --noproxy '*' --max-time 3 -sS -o /dev/null "
        "-w '%{http_code} ' -H 'Host: localhost' "
        f"{cookie_header} http://{caddy_ip}/vnc.html; "
        "done"
    )
    return run(
        ["docker", "exec", client, "/bin/bash", "-lc", command],
        env=env,
        cwd=ROOT,
        timeout=30,
    )


def wait_for_ban(caddy: str, client_ip: str, *, present: bool, env: dict[str, str]) -> None:
    deadline = time.monotonic() + 30
    last_state = ""
    while time.monotonic() < deadline:
        state = run(
            ["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/banlist.json"],
            env=env,
            cwd=ROOT,
        )
        last_state = state.stdout + state.stderr
        try:
            document = json.loads(state.stdout)
            bans = document.get("bans", []) if isinstance(document, dict) else []
        except json.JSONDecodeError:
            bans = []
        banned = any(
            isinstance(entry, dict) and entry.get("client_ip") == client_ip
            for entry in bans
        )
        if state.returncode == 0 and banned == present:
            return
        time.sleep(0.25)
    raise AssertionError(f"clean-path fail2ban state did not reach present={present}: {last_state}")


def assert_clean_path_fail2ban(
    identifiers: dict[str, str], *, image: str, env: dict[str, str], project: str, cookie: str
) -> None:
    caddy = identifiers["caddy"]
    networks = inspect(caddy)["NetworkSettings"]["Networks"]
    assert len(networks) == 1, networks
    network, details = next(iter(networks.items()))
    caddy_ip = details["IPAddress"]
    client_names = [f"{project}-ban-a", f"{project}-ban-b"]
    try:
        client_ips = [
            client_container(image, network, name, env=env)
            for name in client_names
        ]
        failed = client_http(
            client_names[0], caddy_ip, count=5, env=env
        )
        assert failed.returncode == 0 and "401" in failed.stdout, failed.stdout + failed.stderr
        wait_for_ban(caddy, client_ips[0], present=True, env=env)

        blocked = client_http(
            client_names[0], caddy_ip, cookie=cookie, env=env
        )
        assert blocked.returncode != 0 and "200" not in blocked.stdout, blocked.stdout + blocked.stderr
        available = client_http(
            client_names[1], caddy_ip, cookie=cookie, env=env
        )
        assert available.returncode == 0 and "200" in available.stdout, available.stdout + available.stderr
        checked(
            [
                "docker",
                "exec",
                identifiers["fail2ban"],
                "fail2ban-client",
                "set",
                "caddy-basicauth",
                "unbanip",
                client_ips[0],
            ],
            env=env,
            cwd=ROOT,
        )
        wait_for_ban(caddy, client_ips[0], present=False, env=env)
        released = client_http(
            client_names[0], caddy_ip, cookie=cookie, env=env
        )
        assert released.returncode == 0 and "200" in released.stdout, released.stdout + released.stderr
    finally:
        for name in client_names:
            run(["docker", "rm", "-f", name], env=env, cwd=ROOT, timeout=60)


def assert_runtime_auth(port: int, *, host: str = "localhost") -> str:
    status, body = http_get(port, "/", host=host)
    assert status == 200 and b"Electron Cash Docker" in body
    assert http_get(port, "/vnc.html", host=host)[0] == 401
    assert login(port, password="wrong-password", host=host)[0] == 401
    status, cookie = login(port, host=host)
    assert status == 303 and cookie
    root_status, root_cookie = login(port, host=host)
    assert root_status == 303 and root_cookie
    status, body = http_get(port, "/", cookie=root_cookie, host=host)
    assert status == 200 and b'name="password"' in body
    for path in ("/vnc.html", "/novnc-keepalive.js"):
        status, body = http_get(port, path, cookie=cookie, host=host)
        assert status == 200 and body
    assert websocket_rfb(port, host=host)[0] == 401
    status, width, framebuffer_bytes = websocket_rfb(port, cookie=cookie, host=host)
    assert status == 101 and width > 0 and framebuffer_bytes > 0
    return cookie


def assert_no_secret_leak(caddy: str, command: list[str], *, env: dict[str, str], cwd: Path) -> None:
    config = checked(["docker", "exec", caddy, "cat", "/var/lib/caddy-bans/Caddyfile"], env=env).stdout
    assert AUTH_PASSWORD not in config
    assert "forward_auth auth-session:8080" in config
    assert "basic_auth" not in config
    assert "/run/secrets" not in config
    assert checked(["docker", "exec", caddy, "test", "-S", "/run/caddy/admin.sock"], env=env).returncode == 0
    logs = checked([*command, "logs", "--no-color"], env=env, cwd=cwd).stdout
    assert AUTH_PASSWORD not in logs
    assert not BCRYPT_PATTERN.search(logs)
    container = inspect(caddy)
    runtime_args = json.dumps({"entrypoint": container["Config"].get("Entrypoint"), "cmd": container["Config"].get("Cmd")})
    assert AUTH_PASSWORD not in runtime_args
    assert not BCRYPT_PATTERN.search(runtime_args)


def assert_stable(identifiers: dict[str, str], *, port: int, cookie: str, env: dict[str, str], seconds: int) -> None:
    deadline = time.monotonic() + seconds
    websocket_due = time.monotonic()
    next_progress = time.monotonic() + 15
    while time.monotonic() < deadline:
        for service, identifier in identifiers.items():
            container = inspect(identifier)
            assert container["State"]["Status"] == "running", service
            assert container["RestartCount"] == 0, (service, container["RestartCount"])
        assert inspect(identifiers["tor-proxy"])["State"]["Health"]["Status"] == "healthy"
        assert http_get(port, "/vnc.html", cookie=cookie)[0] == 200
        if time.monotonic() >= websocket_due:
            status, width, framebuffer_bytes = websocket_rfb(port, cookie=cookie)
            assert status == 101 and width > 0 and framebuffer_bytes > 0
            websocket_due = time.monotonic() + 15
        if time.monotonic() >= next_progress:
            print(f"stable deployment observation: {seconds - max(0, int(deadline - time.monotonic()))}s/{seconds}s", flush=True)
            next_progress = time.monotonic() + 15
        time.sleep(5)


def fresh_checkout(directory: Path) -> Path:
    checkout = directory / "checkout"

    def ignore(_source: str, names: list[str]) -> set[str]:
        ignored = {
            ".env",
            ".git",
            ".codebase-memory",
            "secrets",
            "backups",
            "__pycache__",
        }
        return {
            name
            for name in names
            if name in ignored or name.endswith(".pyc") or name.endswith(".hash")
        }

    shutil.copytree(ROOT, checkout, ignore=ignore)
    assert not (checkout / ".env").exists()
    assert not (checkout / "secrets").exists()
    assert not list(checkout.rglob("*.hash"))
    return checkout


def fresh_env(directory: Path, *, environment: dict[str, str]) -> Path:
    env_file = directory / ".env"
    # Exercise the same first command documented for a new checkout.
    checked(["cp", ".env.example", ".env"], env=environment, cwd=directory)
    content = env_file.read_text(encoding="utf-8")
    content, replacements = re.subn(
        r"^BASIC_AUTH_PASSWORD=.*$",
        f"BASIC_AUTH_PASSWORD={AUTH_PASSWORD}",
        content,
        flags=re.MULTILINE,
    )
    assert replacements == 1
    assert "CHANGE_ME_AUTH_PASSWORD" not in content
    env_file.write_text(content, encoding="utf-8")
    return env_file


def acceptance_run(*, project: str, temporary: Path, base_environment: dict[str, str], first: bool) -> None:
    checkout = fresh_checkout(temporary)
    fresh_env(checkout, environment=base_environment)
    environment = {
        key: value
        for key, value in base_environment.items()
        if key
        not in {
            "BASIC_AUTH_PASSWORD",
            "COMPOSE_FILE",
            "COMPOSE_PROFILES",
        }
    }
    environment.update(
        {
            "ELECTRON_CASH_IMAGE": base_environment["ELECTRON_CASH_IMAGE"],
            "TOR_IMAGE": base_environment["TOR_IMAGE"],
            "CADDY_IMAGE": base_environment["CADDY_IMAGE"],
            "FAIL2BAN_IMAGE": base_environment["FAIL2BAN_IMAGE"],
            "AUTH_SESSION_IMAGE": base_environment["AUTH_SESSION_IMAGE"],
            "CADDY_SITE_ADDRESS": "http://localhost",
            "CADDY_TLS_MODE": "auto",
            "CADDY_EDGE_BIND": "127.0.0.1",
            "CADDY_HTTP_HOST_PORT": str(base_environment[f"CI_STARTUP_HTTP_PORT_{'FIRST' if first else 'SECOND'}"]),
            "CADDY_HTTPS_HOST_PORT": str(base_environment[f"CI_STARTUP_HTTPS_PORT_{'FIRST' if first else 'SECOND'}"]),
            "ECD_WALLET_VOLUME": f"{project}-wallet",
            "ECD_TOR_VOLUME": f"{project}-tor",
            # Published-port probes appear as the Docker bridge gateway to
            # Caddy. Keep those host probes below the jail threshold; the
            # separate clients exercise the real ban path.
            "FAIL2BAN_MAXRETRY": "5",
            "COMPOSE_PROJECT_NAME": project,
        }
    )
    command = compose()
    port = int(environment["CADDY_HTTP_HOST_PORT"])
    identifiers: dict[str, str] = {}
    primary_error: Exception | None = None
    try:
        model = json.loads(checked([*command, "config", "--format", "json"], env=environment, cwd=checkout).stdout)
        services = model["services"]
        assert set(services) == {"electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban"}
        assert not services["electron-cash"].get("ports")
        assert "6080" in [str(value) for value in services["electron-cash"].get("expose", [])]
        assert not services["tor-proxy"].get("ports")
        assert services["caddy"]["image"] == environment["CADDY_IMAGE"]
        assert services["auth-session"]["image"] == environment["AUTH_SESSION_IMAGE"]
        assert services["fail2ban"]["image"] == environment["FAIL2BAN_IMAGE"]
        assert services["fail2ban"].get("network_mode") == "service:caddy"
        assert services["fail2ban"].get("cap_add") == ["NET_ADMIN"]
        assert "BASIC_AUTH_USERNAME" not in services["caddy"]["environment"]
        assert "/run/secrets" not in json.dumps(services["caddy"])

        # The canonical gate has already built these exact unique candidate
        # references with --no-cache. Reuse them in this clean-checkout startup
        # test rather than compiling a second duplicate image set here.
        images = {
            "electron-cash": environment["ELECTRON_CASH_IMAGE"],
            "tor-proxy": environment["TOR_IMAGE"],
            "caddy": environment["CADDY_IMAGE"],
            "fail2ban": environment["FAIL2BAN_IMAGE"],
            "auth-session": environment["AUTH_SESSION_IMAGE"],
        }
        if environment.get("CI_CANDIDATE_IMAGES") != "1":
            raise AssertionError("canonical startup requires the prebuilt task-owned candidate image set")
        for image in images.values():
            checked(["docker", "image", "inspect", image], env=environment, cwd=checkout)
        checked([*command, "up", "--pull", "never", "-d", "--no-build"],
                env=environment, cwd=checkout, timeout=180)
        for service in ("tor-proxy", "electron-cash", "auth-session", "caddy", "fail2ban"):
            identifiers[service] = wait_running(command, service, env=environment, cwd=checkout)
        for service in identifiers:
            wait_healthy(identifiers[service], service)
        for service, image in images.items():
            assert_candidate_image(identifiers[service], image, env=environment)

        cookie = assert_runtime_auth(port)
        assert_runtime_auth(port, host="127.0.0.1")
        run_browser_acceptance(f"http://127.0.0.1:{port}")
        assert_direct_ports_blocked()
        assert_no_secret_leak(identifiers["caddy"], command, env=environment, cwd=checkout)
        persistence_marker = ".canonical-clean-user-persistence"
        checked(
            [
                "docker",
                "exec",
                "--user",
                "10001:10001",
                identifiers["electron-cash"],
                "bash",
                "-c",
                f"printf '%s' canonical > /home/electroncash/.electron-cash/{persistence_marker}",
            ],
            env=environment,
        )
        fail2ban_status = checked(
            ["docker", "exec", identifiers["fail2ban"], "fail2ban-client", "status", "caddy-basicauth"],
            env=environment,
        ).stdout
        assert "Status for the jail" in fail2ban_status
        assert_clean_path_fail2ban(
            identifiers,
            image=environment["ELECTRON_CASH_IMAGE"],
            env=environment,
            project=project,
            cookie=cookie,
        )
        electron_env = inspect(identifiers["electron-cash"])["Config"]["Env"]
        assert {
            item
            for item in electron_env
            if item.startswith("CASHFUSION_")
        } == {
            "CASHFUSION_AUTOFUSE_CONFIRMED_ONLY=true",
            "CASHFUSION_AUTO_FUSE=false",
            "CASHFUSION_ENABLED=true",
            "CASHFUSION_FUSE_DEPTH=3",
            "CASHFUSION_FUSION_MODE=custom",
            "CASHFUSION_QUEUED_AUTOFUSE=4",
            "CASHFUSION_SELECTOR_COUNT=10",
            "CASHFUSION_SELECTOR_FRACTION=1.0",
            "CASHFUSION_SELECTOR_MODE=count",
            "CASHFUSION_SELECTOR_SIZE_BCH=0.0001",
            "CASHFUSION_SELF_FUSE_PLAYERS=1",
        }
        assert_stable(identifiers, port=port, cookie=cookie, env=environment, seconds=OBSERVATION_SECONDS)

        wallet_volume = model["volumes"]["electron-cash-data"]["name"]
        tor_volume = model["volumes"]["tor-data"]["name"]
        checked([*command, "down", "--remove-orphans"], env=environment, cwd=checkout, timeout=180)
        assert subprocess.run(["docker", "volume", "inspect", wallet_volume], capture_output=True, check=False).returncode == 0
        assert subprocess.run(["docker", "volume", "inspect", tor_volume], capture_output=True, check=False).returncode == 0
        checked([*command, "up", "-d"], env=environment, cwd=checkout, timeout=180)
        identifiers = {
            service: wait_running(command, service, env=environment, cwd=checkout)
            for service in ("tor-proxy", "electron-cash", "auth-session", "caddy", "fail2ban")
        }
        for service in identifiers:
            wait_healthy(identifiers[service], service)
        checked(
            [
                "docker",
                "exec",
                identifiers["electron-cash"],
                "test",
                "-f",
                f"/home/electroncash/.electron-cash/{persistence_marker}",
            ],
            env=environment,
        )
        cookie = assert_runtime_auth(port)
        run_browser_acceptance(f"http://127.0.0.1:{port}")
        assert_direct_ports_blocked()
        assert_stable(identifiers, port=port, cookie=cookie, env=environment, seconds=RESTART_OBSERVATION_SECONDS)
        print(f"PASS fresh clean-start {'#1' if first else '#2'} and non-destructive restart/recreate")
    except Exception as error:
        primary_error = error
    finally:
        cleanup = run(
            [*command, "down", "--volumes", "--remove-orphans"],
            env=environment,
            cwd=checkout,
            timeout=180,
        )
        if primary_error is None and cleanup.returncode != 0:
            primary_error = AssertionError(redacted_output(cleanup))
    if primary_error is not None:
        raise primary_error


def main() -> None:
    required = (
        "CI_STARTUP_PROJECT",
        "ELECTRON_CASH_IMAGE",
        "TOR_IMAGE",
        "CADDY_IMAGE",
        "FAIL2BAN_IMAGE",
        "AUTH_SESSION_IMAGE",
        "CI_STARTUP_HTTP_PORT",
        "CI_STARTUP_HTTPS_PORT",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise AssertionError(f"missing canonical startup environment: {', '.join(missing)}")

    base_environment = os.environ.copy()
    base_environment["CI_STARTUP_HTTP_PORT_FIRST"] = base_environment.get("CI_STARTUP_HTTP_PORT", "0")
    base_environment["CI_STARTUP_HTTPS_PORT_FIRST"] = base_environment.get("CI_STARTUP_HTTPS_PORT", "0")
    base_environment["CI_STARTUP_HTTP_PORT_SECOND"] = str(free_port())
    base_environment["CI_STARTUP_HTTPS_PORT_SECOND"] = str(free_port())
    first_project = unique_project("canonical-startup-first")
    second_project = unique_project("canonical-startup-second")
    with tempfile.TemporaryDirectory(prefix="ecd-canonical-1-") as first_dir, tempfile.TemporaryDirectory(
        prefix="ecd-canonical-2-"
    ) as second_dir:
        acceptance_run(
            project=first_project,
            temporary=Path(first_dir),
            base_environment=base_environment,
            first=True,
        )
        acceptance_run(
            project=second_project,
            temporary=Path(second_dir),
            base_environment=base_environment,
            first=False,
        )
    print("PASS mandatory raw Compose startup, full authenticated RFB/framebuffer exchange, restart, and second clean run")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Regression checks for protocol and application WebSocket keepalives."""

from __future__ import annotations

import base64
import hashlib
import os
import select
import shlex
import socket
import subprocess
import time
from pathlib import Path
from threading import Event, Thread

from test_support import electron_cash_image


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
DOCKERFILE = ROOT / "docker" / "Dockerfile"
KEEPALIVE = ROOT / "docker" / "novnc-keepalive.js"
ENV_FILE = ROOT / ".env.example"
IMAGE = electron_cash_image()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_websockify_uses_30_second_heartbeat() -> None:
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    command = next(
        line.strip()
        for line in entrypoint.splitlines()
        if line.strip().startswith("websockify ")
    )

    arguments = shlex.split(command)
    heartbeat_index = arguments.index("--heartbeat")

    assert arguments[heartbeat_index + 1] == "30"


def test_novnc_uses_application_keepalive() -> None:
    script = KEEPALIVE.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "const interval = 10000;" in script
    assert "socket.send(new Uint8Array(0));" in script
    assert "new URL(socket.url, window.location.href).pathname === \"/websockify\"" in script
    assert "COPY docker/novnc-keepalive.js /opt/noVNC/novnc-keepalive.js" in dockerfile
    assert 'marker="<script src=\\"/novnc-keepalive.js\\"></script>"' in dockerfile


def test_generated_novnc_html_has_clean_keepalive_injection() -> None:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "/usr/bin/python3",
            IMAGE,
            "-c",
            'import sys; sys.stdout.buffer.write(open("/opt/noVNC/vnc.html", "rb").read())',
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")

    html = result.stdout
    marker = b'<script src="/novnc-keepalive.js"></script>'
    assert html.count(marker) == 1
    assert html.count(b"</head>") == 1
    assert marker + b"\n</head>" in html
    assert marker + b"\\n</head>" not in html


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    while sum(len(chunk) for chunk in chunks) < size:
        chunk = sock.recv(size - sum(len(part) for part in chunks))
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
    return b"".join(chunks)


def read_http_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("HTTP handshake closed")
        data.extend(chunk)
    return bytes(data)


def frame(payload: bytes, opcode: int) -> bytes:
    key = os.urandom(4)
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length < 65536:
        header = bytes((0x80 | opcode, 0x80 | 126)) + length.to_bytes(2, "big")
    else:
        header = bytes((0x80 | opcode, 0x80 | 127)) + length.to_bytes(8, "big")
    masked = bytes(value ^ key[index % 4] for index, value in enumerate(payload))
    return header + key + masked


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(sock, 2)
    length = second & 0x7F
    if length == 126:
        length = int.from_bytes(recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(recv_exact(sock, 8), "big")
    mask = recv_exact(sock, 4) if second & 0x80 else None
    payload = recv_exact(sock, length)
    if mask is not None:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 0x0F, payload


def websocket_connect(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /websockify HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    sock.sendall(request)
    response = read_http_headers(sock)
    assert response.startswith(b"HTTP/1.1 101")
    return sock


class TargetServer:
    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.stop_event = Event()
        self.thread = Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        self.listener.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                client, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                raise
            client.settimeout(0.2)
            while not self.stop_event.is_set():
                try:
                    if not client.recv(4096):
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
            client.close()

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=2)


class IdleEdge:
    """A local edge proxy that ignores WebSocket control frames for idleness."""

    def __init__(self, upstream_port: int, timeout: float = 2.0) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.stop_event = Event()
        self.thread = Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        self.listener.settimeout(0.2)
        while not self.stop_event.is_set():
            try:
                client, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                raise
            try:
                self.proxy(client)
            finally:
                client.close()

    def proxy(self, client: socket.socket) -> None:
        client.settimeout(5)
        upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5)
        try:
            request = read_http_headers(client)
            upstream.sendall(request)
            response = read_http_headers(upstream)
            client.sendall(response)
            client.settimeout(None)
            upstream.settimeout(None)
            sockets = [client, upstream]
            last_data = time.monotonic()
            while not self.stop_event.is_set():
                if time.monotonic() - last_data >= self.timeout:
                    return
                readable, _writable, _exceptional = select.select(sockets, [], [], 0.1)
                for source in readable:
                    try:
                        raw, opcode = self.read_wire_frame(source)
                    except (EOFError, ConnectionResetError, OSError):
                        return
                    destination = upstream if source is client else client
                    destination.sendall(raw)
                    if opcode not in {0x8, 0x9, 0xA}:
                        last_data = time.monotonic()
        finally:
            upstream.close()

    @staticmethod
    def read_wire_frame(sock: socket.socket) -> tuple[bytes, int]:
        first_two = recv_exact(sock, 2)
        first, second = first_two
        length = second & 0x7F
        if length == 126:
            extension = recv_exact(sock, 2)
        elif length == 127:
            extension = recv_exact(sock, 8)
        else:
            extension = b""
        mask = recv_exact(sock, 4) if second & 0x80 else b""
        payload = recv_exact(sock, length if length < 126 else int.from_bytes(extension, "big"))
        return first_two + extension + mask + payload, first & 0x0F

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=2)


def run_websockify(
    port: int, target_port: int
) -> tuple[subprocess.Popen[bytes], int]:
    process = subprocess.Popen(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "host",
            "--entrypoint",
            "/usr/bin/websockify",
            IMAGE,
            "--heartbeat",
            "1",
            str(port),
            f"127.0.0.1:{target_port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, port
        except OSError:
            if process.poll() is not None:
                raise AssertionError("websockify exited before becoming ready")
            time.sleep(0.1)
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    raise AssertionError("websockify did not become ready")


def wait_for_edge_close(sock: socket.socket, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    sock.settimeout(0.2)
    while time.monotonic() < deadline:
        try:
            opcode, payload = read_frame(sock)
        except socket.timeout:
            continue
        except (EOFError, ConnectionResetError):
            return True
        if opcode == 0x9:
            sock.sendall(frame(payload, 0xA))
        elif opcode == 0x8:
            return True
    return False


def test_application_keepalive_survives_control_frame_blind_edge() -> None:
    target = TargetServer()
    target.start()
    process, upstream_port = run_websockify(free_port(), target.port)
    edge = IdleEdge(upstream_port)
    edge.start()
    try:
        control_only = websocket_connect(edge.port)
        try:
            assert wait_for_edge_close(control_only, 4), "control-only connection stayed open"
        finally:
            control_only.close()

        application_data = websocket_connect(edge.port)
        application_data.settimeout(0.2)
        deadline = time.monotonic() + 4
        next_keepalive = time.monotonic()
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_keepalive:
                application_data.sendall(frame(b"", 0x2))
                next_keepalive = now + 0.5
            try:
                opcode, payload = read_frame(application_data)
            except socket.timeout:
                continue
            except (EOFError, ConnectionResetError) as error:
                raise AssertionError("application keepalive connection closed") from error
            if opcode == 0x9:
                application_data.sendall(frame(payload, 0xA))
            elif opcode == 0x8:
                raise AssertionError("application keepalive connection closed")
        application_data.close()
    finally:
        edge.close()
        target.close()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def main() -> None:
    test_websockify_uses_30_second_heartbeat()
    test_novnc_uses_application_keepalive()
    test_generated_novnc_html_has_clean_keepalive_injection()
    test_application_keepalive_survives_control_frame_blind_edge()
    print("PASS protocol heartbeat, application keepalive, and edge-idle regression")


if __name__ == "__main__":
    main()

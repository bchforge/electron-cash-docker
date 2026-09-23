#!/usr/bin/env python3
"""Focused tests for the private same-origin noVNC session gate."""

from __future__ import annotations

import http.client
import importlib.util
import os
import threading
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH_SERVER = ROOT / "docker/auth-session/server.py"
spec = importlib.util.spec_from_file_location("auth_session_server", AUTH_SERVER)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load auth session helper")
server_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_module)
AuthServer = server_module.AuthServer
Handler = server_module.Handler


PASSWORD = "synthetic-auth-secret"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def request(port: int, method: str, path: str, *, body: str = "", cookie: str = "", host: str = "localhost", scheme: str = "http", origin: str | None = "http://localhost") -> tuple[int, http.client.HTTPMessage, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": host, "X-Forwarded-Proto": scheme}
    if cookie:
        headers["Cookie"] = cookie
    if origin is not None:
        headers["Origin"] = origin
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body.encode()))
    connection.request(method, path, body=body or None, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    headers = response.headers
    status = response.status
    connection.close()
    return status, headers, payload


def start(site: str) -> tuple[AuthServer, threading.Thread, int]:
    os.environ["BASIC_AUTH_USERNAME"] = "legacy-value-is-ignored"
    os.environ["BASIC_AUTH_PASSWORD"] = PASSWORD
    os.environ["CADDY_SITE_ADDRESS"] = site
    server = AuthServer(("127.0.0.1", 0), Handler, site)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


def test_http_session() -> None:
    server, thread, port = start("http://localhost")
    try:
        status, headers, body = request(port, "GET", "/")
        text = body.decode()
        assert status == 200
        assert '<title>Electron Cash Docker</title>' in text
        assert f'<h1>Electron Cash Docker <span class="version">&middot; v{VERSION}</span></h1>' in text
        assert text.count(f"v{VERSION}") == 1
        assert '<div class="version">v' not in text
        assert 'name="password"' in text
        assert 'name="username"' not in text
        assert "Electron Cash Docker" in text
        assert "Sign out" not in text and "Continue to wallet" not in text
        assert "#4ade80" in text
        assert "localStorage" not in text and "sessionStorage" not in text
        assert PASSWORD not in text

        status, headers, body = request(port, "GET", "/favicon.svg")
        assert status == 200 and headers["Content-Type"].startswith("image/svg+xml") and b"#4ade80" in body

        status, headers, _ = request(port, "GET", "/auth/check")
        assert status == 401 and not headers.get("WWW-Authenticate")

        status, _, body = request(
            port,
            "POST",
            "/auth/login",
            body=urlencode({"password": "wrong-secret"}),
        )
        assert status == 401
        assert b"Invalid password." in body

        status, headers, body = request(
            port,
            "POST",
            "/auth/login",
            body=urlencode({"username": "legacy-value-is-ignored", "password": PASSWORD}),
        )
        assert status == 303 and body == b""
        assert PASSWORD not in str(headers) and PASSWORD not in headers.get("Location", "")
        assert "/vnc.html?autoconnect=true" in headers["Location"]
        cookie_header = headers["Set-Cookie"]
        cookie = SimpleCookie(cookie_header)
        assert cookie["ecd_session"]["httponly"]
        assert cookie["ecd_session"]["samesite"] == "Strict"
        assert not cookie["ecd_session"]["secure"]
        assert not cookie["ecd_session"]["max-age"]
        assert not cookie["ecd_session"]["expires"]
        assert PASSWORD not in cookie_header
        cookie_value = cookie["ecd_session"].value

        status, _, _ = request(port, "GET", "/auth/check", cookie=f"ecd_session={cookie_value}")
        assert status == 204
        status, headers, body = request(port, "GET", "/", cookie=f"ecd_session={cookie_value}")
        assert status == 200 and b'name="password"' in body
        assert "Location" not in headers
        assert "Max-Age=0" in headers["Set-Cookie"]
        status, _, _ = request(port, "GET", "/auth/check", cookie=f"ecd_session={cookie_value}")
        assert status == 401

        status, headers, body = request(
            port,
            "POST",
            "/auth/login",
            body=urlencode({"password": PASSWORD, "remember": "on"}),
        )
        assert status == 303 and body == b""
        assert PASSWORD not in str(headers) and PASSWORD not in headers.get("Location", "")
        cookie_header = headers["Set-Cookie"]
        cookie = SimpleCookie(cookie_header)
        assert cookie["ecd_session"]["httponly"]
        assert cookie["ecd_session"]["samesite"] == "Strict"
        assert not cookie["ecd_session"]["secure"]
        assert int(cookie["ecd_session"]["max-age"]) == server_module.REMEMBER_TTL
        assert int(cookie["ecd_session"]["max-age"]) > 8 * 60 * 60
        assert not cookie["ecd_session"]["expires"]
        assert PASSWORD not in cookie_header
        cookie_value = cookie["ecd_session"].value

        status, _, _ = request(port, "GET", "/auth/check", cookie=f"ecd_session={cookie_value}")
        assert status == 204
        status, headers, body = request(port, "GET", "/", cookie=f"ecd_session={cookie_value}")
        assert status == 303 and body == b""
        assert headers["Location"].startswith("/vnc.html?autoconnect=true")
        status, _, _ = request(port, "GET", "/vnc.html", cookie=f"ecd_session={cookie_value}")
        assert status == 404

        status, headers, _ = request(port, "POST", "/auth/logout", cookie=f"ecd_session={cookie_value}")
        assert status == 303 and headers["Location"] == "/"
        status, _, _ = request(port, "GET", "/auth/check", cookie=f"ecd_session={cookie_value}")
        assert status == 401

        status, _, _ = request(
            port,
            "POST",
            "/auth/login",
            body=urlencode({"password": PASSWORD}),
            origin="https://evil.example",
        )
        assert status == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_https_cookie() -> None:
    server, thread, port = start("https://wallet.test")
    try:
        status, headers, _ = request(
            port,
            "POST",
            "/auth/login",
            host="wallet.test",
            scheme="https",
            origin="https://wallet.test",
            body=urlencode({"password": PASSWORD}),
        )
        assert status == 303
        cookie = SimpleCookie(headers["Set-Cookie"])["ecd_session"]
        assert cookie["secure"]
        assert cookie["httponly"] and cookie["samesite"] == "Strict"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_invalid_configuration() -> None:
    for password in ("", "CHANGE_ME_AUTH_PASSWORD"):
        os.environ["BASIC_AUTH_PASSWORD"] = password
        try:
            AuthServer(("127.0.0.1", 0), Handler, "http://localhost")
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid auth configuration was accepted")
    os.environ["BASIC_AUTH_USERNAME"] = "legacy-value-is-ignored"
    os.environ["BASIC_AUTH_PASSWORD"] = PASSWORD


def main() -> None:
    test_http_session()
    test_https_cookie()
    test_invalid_configuration()
    print("PASS same-origin session login, logout, CSRF, cookie, invalid-config, and no-leak checks")


if __name__ == "__main__":
    main()

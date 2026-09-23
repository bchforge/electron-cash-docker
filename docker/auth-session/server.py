#!/usr/bin/env python3
"""Small same-origin session gate for the Caddy noVNC edge."""

from __future__ import annotations

import hashlib
import hmac
import http.server
import os
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit


COOKIE_NAME = "ecd_session"
SESSION_TTL = 30 * 60
REMEMBER_TTL = 30 * 24 * 60 * 60
PBKDF2_ROUNDS = 200_000
MAX_BODY = 8 * 1024
MAX_CREDENTIAL_LENGTH = 256
VERSION_PATHS = (Path("/etc/electroncash-docker/VERSION"), Path(__file__).resolve().parents[2] / "VERSION")


def _product_version() -> str:
    for path in VERSION_PATHS:
        try:
            version = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if version:
            return version
    raise RuntimeError("Electron Cash Docker VERSION file is missing")


PRODUCT_VERSION = _product_version()


LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="same-origin">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'">
  <title>Electron Cash Docker</title>
  <style>
    :root { color-scheme: dark; --bg: #0f1419; --card: #1a1f2e; --text: #e8e8e8; --muted: #8b95a7; --accent: #4ade80; --success: #22c55e; --danger: #f87171; --border: #2a3142; }
    * { box-sizing: border-box; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 1.5rem; background: radial-gradient(circle at top, #223444, var(--bg) 58%); color: var(--text); font: 16px/1.5 system-ui, sans-serif; }
    .card { width: min(100%, 28rem); padding: 2.25rem; border: 1px solid var(--border); border-radius: 1.25rem; background: color-mix(in srgb, var(--card) 94%, transparent); box-shadow: 0 1.5rem 4rem #0008; }
    .logo { width: 3rem; height: 3rem; display: grid; place-items: center; margin-bottom: 1.25rem; border-radius: .9rem; background: var(--accent); }
    .logo svg { width: 1.75rem; }
     h1 { margin: 0; font-size: 1.8rem; letter-spacing: -.03em; }
     .version { color: var(--muted); font-size: .8em; font-weight: 500; white-space: nowrap; }
     .subtitle { margin: .35rem 0 1.75rem; color: var(--muted); }
    label { display: block; margin: 1rem 0 .35rem; color: var(--muted); font-size: .9rem; }
    input[type=text], input[type=password] { width: 100%; padding: .75rem .8rem; border: 1px solid var(--border); border-radius: .55rem; background: #0c1116; color: var(--text); font: inherit; }
    input:focus { outline: 2px solid var(--accent); outline-offset: 2px; }
    .remember { display: flex; align-items: center; gap: .55rem; margin: 1rem 0; color: var(--muted); font-size: .9rem; }
    .remember label { margin: 0; }
    button, .continue { display: block; width: 100%; padding: .8rem 1rem; border: 0; border-radius: .55rem; background: var(--accent); color: #17120a; font: 700 1rem inherit; text-align: center; text-decoration: none; cursor: pointer; }
    button:hover, .continue:hover { background: var(--success); }
    .error { min-height: 1.5rem; margin: .5rem 0; color: var(--danger); }
    .footer { margin-top: 1.5rem; padding-top: 1.25rem; border-top: 1px solid var(--border); color: var(--muted); font-size: .78rem; text-align: center; }
  </style>
</head>
<body>
  <main class="card">
    <div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#0f1419" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12V8H6a2 2 0 0 1-2-2c0-1.1.9-2 2-2h12v4"/><path d="M4 6v12c0 1.1.9 2 2 2h14v-4"/><path d="M18 12a2 2 0 0 0 0 4h4v-4Z"/></svg></div>
      <h1>Electron Cash Docker <span class="version">&middot; v{{VERSION}}</span></h1>
      <p class="subtitle">Bitcoin Cash wallet &middot; Tor-routed SPV</p>
     {{CONTENT}}
    <div class="footer">Your session is temporary and the password is never stored in this browser.</div>
  </main>
</body>
</html>
"""


def _digest(value: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, PBKDF2_ROUNDS)


def _host(value: str) -> str:
    parsed = urlsplit("//" + value)
    return (parsed.hostname or "").lower().rstrip(".")


class SessionStore:
    def __init__(self, password: str) -> None:
        self._salt = secrets.token_bytes(16)
        self._password = _digest(password, self._salt)
        self._sessions: dict[str, tuple[float, bool]] = {}
        self._lock = threading.Lock()

    def authenticate(self, password: str) -> bool:
        return hmac.compare_digest(_digest(password, self._salt), self._password)

    def create(self, remember: bool) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        ttl = REMEMBER_TTL if remember else SESSION_TTL
        with self._lock:
            self._sessions[token] = (time.time() + ttl, remember)
        return token, ttl

    def state(self, token: str | None) -> bool | None:
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session[0] <= time.time():
                self._sessions.pop(token, None)
                return None
            return session[1]

    def valid(self, token: str | None) -> bool:
        return self.state(token) is not None

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)


class AuthServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[http.server.BaseHTTPRequestHandler], site: str) -> None:
        password = os.environ.get("BASIC_AUTH_PASSWORD", "")
        if (
            not password
            or password.startswith("CHANGE_ME")
            or len(password) > MAX_CREDENTIAL_LENGTH
            or any(char in password for char in "\r\n\x00")
        ):
            raise SystemExit("auth-session requires a valid non-placeholder password")
        self.sessions = SessionStore(password)
        del password
        site_host = _host(urlsplit(site).netloc or urlsplit(site).path)
        self.allowed_hosts = {site_host} if site_host else set()
        if site_host in {"localhost", "127.0.0.1", "::1"}:
            self.allowed_hosts.update({"localhost", "127.0.0.1", "::1"})
        self.site_scheme = urlsplit(site).scheme or "http"
        super().__init__(address, handler)


class Handler(http.server.BaseHTTPRequestHandler):
    def _auth_server(self) -> AuthServer:
        return cast(AuthServer, self.server)

    def log_message(self, format: str, *args: object) -> None:
        # Requests contain credentials in the form body or session cookie.
        return

    def _request_host(self) -> str:
        return _host(self.headers.get("Host", ""))

    def _scheme(self) -> str:
        return self.headers.get("X-Forwarded-Proto", self._auth_server().site_scheme).split(",", 1)[0].strip().lower()

    def _same_origin(self) -> bool:
        if self._request_host() not in self._auth_server().allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.scheme.lower() != self._scheme() or _host(parsed.netloc) != self._request_host():
                return False
        return self.headers.get("Sec-Fetch-Site", "").lower() not in {"cross-site", "cross-origin"}

    def _token(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except ValueError:
            return None
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def _expired_cookie(self) -> str:
        cookie = f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        if self._scheme() == "https":
            cookie += "; Secure"
        return cookie

    def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _page(self, error: str = "") -> bytes:
        content = """<form method="post" action="/auth/login">
  <label for="pass">Password</label><input id="pass" name="password" type="password" autocomplete="current-password" required>
  <div class="remember"><input id="remember" name="remember" type="checkbox"><label for="remember">Remember this session</label></div>
  <div class="error" role="alert">{{ERROR}}</div>
  <button type="submit">Connect</button>
 </form>"""
        return LOGIN_PAGE.replace("{{CONTENT}}", content.replace("{{ERROR}}", error)).replace("{{VERSION}}", PRODUCT_VERSION).encode("utf-8")

    def do_GET(self) -> None:
        request_path = urlsplit(self.path).path
        if request_path == "/":
            token = self._token()
            session_state = self._auth_server().sessions.state(token)
            if session_state is True:
                self._send(HTTPStatus.SEE_OTHER, headers={"Location": "/vnc.html?autoconnect=true&reconnect=true&reconnect_delay=3000"})
                return
            headers = {"Content-Type": "text/html; charset=utf-8"}
            if session_state is False:
                self._auth_server().sessions.revoke(token)
                headers["Set-Cookie"] = self._expired_cookie()
            self._send(HTTPStatus.OK, self._page(), headers)
            return
        if request_path == "/favicon.svg":
            try:
                body = (Path(__file__).with_name("favicon.svg")).read_bytes()
            except OSError:
                self._send(HTTPStatus.NOT_FOUND, b"not found\n", {"Content-Type": "text/plain; charset=utf-8"})
            else:
                self._send(HTTPStatus.OK, body, {"Content-Type": "image/svg+xml"})
            return
        if request_path == "/auth/check":
            self._check()
            return
        self._send(HTTPStatus.NOT_FOUND, b"not found\n", {"Content-Type": "text/plain; charset=utf-8"})

    def do_POST(self) -> None:
        request_path = urlsplit(self.path).path
        if request_path == "/auth/login":
            self._login()
            return
        if request_path == "/auth/logout":
            self._logout()
            return
        self._send(HTTPStatus.NOT_FOUND, b"not found\n", {"Content-Type": "text/plain; charset=utf-8"})

    def _check(self) -> None:
        if self._auth_server().sessions.valid(self._token()) and self._request_host() in self._auth_server().allowed_hosts:
            self._send(HTTPStatus.NO_CONTENT)
        else:
            self._send(HTTPStatus.UNAUTHORIZED, b"authentication required\n", {"Content-Type": "text/plain; charset=utf-8"})

    def _login(self) -> None:
        if not self._same_origin():
            self._send(HTTPStatus.FORBIDDEN, b"forbidden\n")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._send(HTTPStatus.BAD_REQUEST, b"invalid request\n")
            return
        try:
            fields = parse_qs(self.rfile.read(length).decode("utf-8", "strict"), keep_blank_values=True)
        except UnicodeDecodeError:
            self._send(HTTPStatus.BAD_REQUEST, b"invalid request\n")
            return
        password = fields.get("password", [""])[0]
        if len(password) > MAX_CREDENTIAL_LENGTH:
            self._send(
                HTTPStatus.UNAUTHORIZED,
                self._page("Invalid password."),
                {"Content-Type": "text/html; charset=utf-8"},
            )
            return
        if not self._auth_server().sessions.authenticate(password):
            self._send(
                HTTPStatus.UNAUTHORIZED,
                self._page("Invalid password."),
                {"Content-Type": "text/html; charset=utf-8"},
            )
            return
        remember = bool(fields.get("remember"))
        token, ttl = self._auth_server().sessions.create(remember)
        cookie = f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict"
        if remember:
            cookie += f"; Max-Age={ttl}"
        if self._scheme() == "https":
            cookie += "; Secure"
        self._send(HTTPStatus.SEE_OTHER, headers={"Location": "/vnc.html?autoconnect=true&reconnect=true&reconnect_delay=3000", "Set-Cookie": cookie})

    def _logout(self) -> None:
        if not self._same_origin():
            self._send(HTTPStatus.FORBIDDEN, b"forbidden\n")
            return
        self._auth_server().sessions.revoke(self._token())
        self._send(HTTPStatus.SEE_OTHER, headers={"Location": "/", "Set-Cookie": self._expired_cookie()})


def main() -> None:
    site = os.environ.get("CADDY_SITE_ADDRESS", "http://localhost")
    server = AuthServer(("0.0.0.0", 8080), Handler, site)
    server.serve_forever()


if __name__ == "__main__":
    main()

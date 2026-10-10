#!/usr/bin/env python3
"""Small same-origin session gate for the Caddy noVNC edge."""

from __future__ import annotations

import hashlib
import html
import base64
import hmac
import http.server
import os
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit

from login_locale import login_language
from login_catalog import CATALOGS, metadata


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
<html lang="{{LANG}}" dir="{{DIR}}">
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
     h1 { margin: 0; font-size: 1.8rem; letter-spacing: -.03em; direction: ltr; unicode-bidi: isolate; }
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
      <p class="subtitle">{{SUBTITLE}}</p>
     {{CONTENT}}
    <div class="footer">{{NOTICE}}</div>
  </main>
</body>
</html>
"""

LOGIN_COPY = CATALOGS


def _digest(value: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, PBKDF2_ROUNDS)


def _host(value: str) -> str:
    parsed = urlsplit("//" + value)
    return (parsed.hostname or "").lower().rstrip(".")


class SessionStore:
    """Durable opaque-token verifiers; no GUI-generation or wallet dependency."""
    def __init__(self, password: str, path: str | Path | None = None, *, clock=time.time) -> None:
        self.path = Path(path or os.environ.get('AUTH_SESSION_DB', '/auth-data/sessions.sqlite'))
        self.clock = clock
        directory = self.path.parent
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('auth-session requires an owner-only persistence directory')
        new = not self.path.exists() and not self.path.is_symlink()
        if new:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('auth-session requires an owner-only regular database')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if new:
                db.execute('CREATE TABLE credential (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, salt BLOB NOT NULL, verifier BLOB NOT NULL)')
                db.execute('CREATE TABLE sessions (verifier BLOB PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL, remember INTEGER NOT NULL CHECK(remember IN (0,1)), generation INTEGER NOT NULL)')
                salt = secrets.token_bytes(16)
                db.execute('INSERT INTO credential VALUES (1,1,?,?)', (salt, _digest(password, salt)))
                db.execute('PRAGMA user_version=1')
            if db.execute('PRAGMA user_version').fetchone()[0] != 1 or db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise RuntimeError('unsupported or corrupt auth-session database')
            row = db.execute('SELECT generation,salt,verifier FROM credential WHERE id=1').fetchone()
            if row is None or type(row[0]) is not int or row[0] < 1 or type(row[1]) is not bytes or type(row[2]) is not bytes or len(row[1]) != 16 or len(row[2]) != 32:
                raise RuntimeError('invalid auth-session credential metadata')
            generation, salt, verifier = row
            if not hmac.compare_digest(_digest(password, salt), verifier):
                generation += 1
                salt = secrets.token_bytes(16)
                verifier = _digest(password, salt)
                db.execute('DELETE FROM sessions')
                db.execute('UPDATE credential SET generation=?,salt=?,verifier=? WHERE id=1', (generation, salt, verifier))
            db.execute('DELETE FROM sessions WHERE expires<=?', (self.clock(),))
            db.execute('SELECT verifier,created,expires,remember,generation FROM sessions LIMIT 0')
            self._generation, self._salt, self._password = generation, salt, verifier

    @contextmanager
    def _connect(self):
        # A fresh connection per operation supports ThreadingHTTPServer safely.
        # DELETE journal + FULL synchronization are durable SQLite defaults.
        file = self.path.lstat(); directory = self.path.parent.lstat()
        if (not stat.S_ISREG(file.st_mode) or file.st_nlink != 1 or file.st_uid != os.geteuid() or stat.S_IMODE(file.st_mode) != 0o600 or
                not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700 or
                not os.access(self.path, os.W_OK) or not os.access(self.path.parent, os.W_OK)):
            raise RuntimeError('auth-session persistence is not writable')
        db = sqlite3.connect(self.path.resolve().as_uri() + '?mode=rw', uri=True, timeout=2)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def healthy(self) -> bool:
        with self._connect() as db:
            return (db.execute('SELECT generation FROM credential WHERE id=1').fetchone() == (self._generation,) and
                    db.execute('PRAGMA user_version').fetchone()[0] == 1 and db.execute('PRAGMA quick_check').fetchone()[0] == 'ok')

    @staticmethod
    def _token_verifier(token: str) -> bytes:
        return hashlib.sha256(token.encode('utf-8')).digest()

    def authenticate(self, password: str) -> bool:
        return hmac.compare_digest(_digest(password, self._salt), self._password) and self.healthy()

    def create(self, remember: bool) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        ttl = REMEMBER_TTL if remember else SESSION_TTL
        now = self.clock()
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT generation FROM credential WHERE id=1').fetchone() != (self._generation,):
                raise RuntimeError('auth-session credential generation changed; restart required')
            db.execute('DELETE FROM sessions WHERE expires<=?', (now,))
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,?)', (self._token_verifier(token), now, now + ttl, int(remember), self._generation))
        return token, ttl

    def state(self, token: str | None) -> bool | None:
        if not token:
            return None
        if len(token) > 256:
            return None
        with self._connect() as db:
            row = db.execute('SELECT s.remember FROM sessions s JOIN credential c ON c.id=1 AND c.generation=s.generation WHERE s.verifier=? AND s.expires>? AND c.generation=?',
                             (self._token_verifier(token), self.clock(), self._generation)).fetchone()
        return bool(row[0]) if row else None

    def valid(self, token: str | None) -> bool:
        return self.state(token) is not None

    def revoke(self, token: str | None) -> None:
        if token:
            with self._connect() as db:
                db.execute('DELETE FROM sessions WHERE verifier=?', (self._token_verifier(token),))


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
        try:
            self.sessions = SessionStore(password)
        except (sqlite3.Error, OSError, RuntimeError) as error:
            raise SystemExit('auth-session durable storage initialization failed: ' + str(error)) from error
        del password
        site_host = _host(urlsplit(site).netloc or urlsplit(site).path)
        self.allowed_hosts = {site_host} if site_host else set()
        if site_host in {"localhost", "127.0.0.1", "::1"}:
            self.allowed_hosts.update({"localhost", "127.0.0.1", "::1"})
        self.site_scheme = urlsplit(site).scheme or "http"
        super().__init__(address, handler)


class Handler(http.server.BaseHTTPRequestHandler):
    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (sqlite3.Error, OSError, RuntimeError):
            # Never issue successful login/cookies or fall back to RAM on failure.
            print('auth-session durable storage unavailable', flush=True)
            self._text(HTTPStatus.SERVICE_UNAVAILABLE, 'UNAVAILABLE')

    def _text(self, status, key):
        self._send(status, (LOGIN_COPY[login_language()][key] + '\n').encode('utf-8'),
                   {'Content-Type': 'text/plain; charset=utf-8'})

    def send_error(self, code, message=None, explain=None):
        # Keep HTTP status/reason phrases and request parsing unchanged; never
        # reflect untrusted protocol text in browser-visible error documents.
        key = {401: 'REQUIRED', 403: 'FORBIDDEN', 404: 'NOT_FOUND',
               503: 'UNAVAILABLE'}.get(code, 'BAD_REQUEST')
        language = login_language()
        lang, direction = metadata(language)
        text = html.escape(LOGIN_COPY[language][key])
        body = (f'<!doctype html><html lang="{lang}" dir="{direction}"><meta charset="utf-8">'
                f'<title>{text}</title><body><p>{text}</p></body></html>').encode('utf-8')
        self.close_connection = True
        self._send(code, b'' if getattr(self, 'command', None) == 'HEAD' else body,
                   {'Content-Type': 'text/html; charset=utf-8', 'Connection': 'close'})

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
        language = login_language()
        copy = LOGIN_COPY[language]
        content = """<form method="post" action="/auth/login">
  <label for="pass">{{PASSWORD}}</label><input id="pass" name="password" type="password" autocomplete="current-password" required>
  <div class="remember"><input id="remember" name="remember" type="checkbox"><label for="remember">{{REMEMBER}}</label></div>
  <div class="error" role="alert">{{ERROR}}</div>
  <button type="submit">{{CONNECT}}</button>
 </form>"""
        lang, direction = metadata(language)
        page = LOGIN_PAGE.replace('{{CONTENT}}', content).replace('{{LANG}}', lang).replace('{{DIR}}', direction)
        page = page.replace('{{ERROR}}', html.escape(copy['INVALID']) if error else '')
        page = page.replace('{{VERSION}}', html.escape(PRODUCT_VERSION))
        for key, value in copy.items():
            page = page.replace('{{' + key + '}}', html.escape(value))
        return page.encode('utf-8')

    def do_GET(self) -> None:
        request_path = urlsplit(self.path).path
        if request_path == '/health':
            self._send(HTTPStatus.NO_CONTENT if self._auth_server().sessions.healthy() else HTTPStatus.SERVICE_UNAVAILABLE)
            return
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
                self._text(HTTPStatus.NOT_FOUND, 'NOT_FOUND')
            else:
                self._send(HTTPStatus.OK, body, {"Content-Type": "image/svg+xml"})
            return
        if request_path == "/auth/check":
            self._check()
            return
        if request_path == '/auth/gui-session':
            import json
            if not (self._auth_server().sessions.valid(self._token()) and self._request_host() in self._auth_server().allowed_hosts):
                self._text(HTTPStatus.UNAUTHORIZED, 'REQUIRED')
                return
            import re
            try:
                state = Path('/run/ecd-gui-session/state').read_text(encoding='ascii')
            except FileNotFoundError:
                state = ''
            match = re.fullmatch(r'([0-9a-f]{32}) (active|ended)\n', state)
            import socket
            ready = False
            if match and match.group(2) == 'active':
                try:
                    with socket.create_connection(('electron-cash', 6080), timeout=0.5):
                        ready = Path('/run/ecd-gui-session/state').read_text(encoding='ascii') == state
                except OSError:
                    pass
            language = login_language()
            lang, direction = metadata(language)
            body = json.dumps({'state': match.group(2) if match else 'unavailable',
                               'generation': match.group(1) if match else None, 'ready': ready,
                               'lang': lang, 'dir': direction,
                               'copy': LOGIN_COPY[language]}).encode()
            self._send(HTTPStatus.OK, body, {'Content-Type': 'application/json'})
            return
        self._text(HTTPStatus.NOT_FOUND, 'NOT_FOUND')

    def do_POST(self) -> None:
        request_path = urlsplit(self.path).path
        if request_path == "/auth/login":
            self._login()
            return
        if request_path == "/auth/logout":
            self._logout()
            return
        self._text(HTTPStatus.NOT_FOUND, 'NOT_FOUND')

    def _check(self) -> None:
        if self._auth_server().sessions.valid(self._token()) and self._request_host() in self._auth_server().allowed_hosts:
            self._send(HTTPStatus.NO_CONTENT)
        else:
            # Expiry/revocation can race a successful availability probe and
            # the following document navigation. Keep HTTP 401 protection, but
            # let that top-level noVNC error document reach the existing login.
            if (self.headers.get('Sec-Fetch-Dest') == 'document' and
                    urlsplit(self.headers.get('X-Forwarded-Uri', '')).path == '/vnc.html'):
                script = b"setTimeout(()=>location.replace('/'),0);"
                integrity = base64.b64encode(hashlib.sha256(script).digest()).decode('ascii')
                lang, direction = metadata(login_language())
                title = html.escape(LOGIN_COPY[login_language()]['REQUIRED'])
                body = (f'<!doctype html><html lang="{lang}" dir="{direction}"><meta charset=utf-8><title>{title}</title><script>'.encode() + script + b'</script></html>')
                self._send(HTTPStatus.UNAUTHORIZED, body, {'Content-Type':'text/html; charset=utf-8',
                    'Content-Security-Policy':"default-src 'none'; script-src 'sha256-" + integrity + "'; base-uri 'none'; frame-ancestors 'none'"})
                return
            self._text(HTTPStatus.UNAUTHORIZED, 'REQUIRED')

    def _login(self) -> None:
        if not self._same_origin():
            self._text(HTTPStatus.FORBIDDEN, 'FORBIDDEN')
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._text(HTTPStatus.BAD_REQUEST, 'BAD_REQUEST')
            return
        try:
            fields = parse_qs(self.rfile.read(length).decode("utf-8", "strict"), keep_blank_values=True)
        except UnicodeDecodeError:
            self._text(HTTPStatus.BAD_REQUEST, 'BAD_REQUEST')
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
            self._text(HTTPStatus.FORBIDDEN, 'FORBIDDEN')
            return
        self._auth_server().sessions.revoke(self._token())
        self._send(HTTPStatus.SEE_OTHER, headers={"Location": "/", "Set-Cookie": self._expired_cookie()})


def main() -> None:
    site = os.environ.get("CADDY_SITE_ADDRESS", "http://localhost")
    server = AuthServer(("0.0.0.0", 8080), Handler, site)
    server.serve_forever()


if __name__ == "__main__":
    main()

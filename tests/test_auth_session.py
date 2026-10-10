#!/usr/bin/env python3
"""Focused tests for the private same-origin noVNC session gate."""

from __future__ import annotations

import http.client
import importlib.util
import os
import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'docker'))
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


def request(port: int, method: str, path: str, *, body: str = "", cookie: str = "", host: str = "localhost", scheme: str = "http", origin: str | None = "http://localhost", document: bool = False, language: str = 'en-US') -> tuple[int, http.client.HTTPMessage, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": host, "X-Forwarded-Proto": scheme}
    headers['Accept-Language'] = language
    if document:headers.update({'Sec-Fetch-Dest':'document','X-Forwarded-Uri':'/vnc.html?autoconnect=true'})
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
    directory = tempfile.TemporaryDirectory(prefix='ecd-auth-unit-')
    os.environ['AUTH_SESSION_DB'] = str(Path(directory.name) / 'sessions.sqlite')
    server = AuthServer(("127.0.0.1", 0), Handler, site)
    server.persistence_fixture = directory
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
        assert f'Electron Cash Docker <span class="version">&middot; v{VERSION}</span>' in text
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
        status,headers,body=request(port,'GET','/auth/check',document=True)
        assert status==401 and headers['Content-Type'].startswith('text/html')
        assert b"location.replace('/')" in body and 'sha256-' in headers['Content-Security-Policy']
        assert not headers.get('Set-Cookie') and not headers.get('WWW-Authenticate')

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
        server.persistence_fixture.cleanup()


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
        server.persistence_fixture.cleanup()


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
    test_durable_store()
    test_http_session()
    test_https_cookie()
    test_invalid_configuration()
    test_login_localization()
    print("PASS same-origin session login, logout, CSRF, cookie, invalid-config, and no-leak checks")


def test_durable_store() -> None:
    from concurrent.futures import ThreadPoolExecutor
    Store = server_module.SessionStore
    with tempfile.TemporaryDirectory(prefix='ecd-auth-durable-') as directory:
        path = Path(directory) / 'sessions.sqlite'; now = [1000.0]
        clock = lambda: now[0]
        store = Store(PASSWORD, path, clock=clock)
        temporary, ttl = store.create(False); remembered, long_ttl = store.create(True)
        assert ttl == 1800 and long_ttl == 2592000
        with sqlite3.connect(path) as db:
            original = db.execute('SELECT * FROM sessions ORDER BY expires').fetchall()
            assert db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
            assert db.execute('PRAGMA synchronous').fetchone()[0] == 2
        reopened = Store(PASSWORD, path, clock=clock)
        assert reopened.state(temporary) is False and reopened.state(remembered) is True
        assert reopened.state(hashlib.sha256(temporary.encode()).hexdigest()) is None
        for _ in range(20):assert reopened.valid(temporary)
        with sqlite3.connect(path) as db:assert db.execute('SELECT * FROM sessions ORDER BY expires').fetchall() == original
        for file in Path(directory).iterdir():
            assert temporary.encode() not in file.read_bytes() and remembered.encode() not in file.read_bytes()
            assert file.stat().st_mode & 0o777 == 0o600
        now[0] += ttl
        assert not reopened.valid(temporary) and reopened.valid(remembered)
        assert not Store(PASSWORD, path, clock=clock).valid(temporary)
        reopened.revoke(remembered)
        assert not Store(PASSWORD, path, clock=clock).valid(remembered)
        survivor, _ = reopened.create(True)
        changed = Store('different-test-password', path, clock=clock)
        assert not changed.valid(survivor) and not reopened.authenticate(PASSWORD)
        try:reopened.create(True)
        except RuntimeError:pass
        else:raise AssertionError('stale credential authority issued a session')
        assert not Store(PASSWORD, path, clock=clock).valid(survivor)
        current = Store(PASSWORD, path, clock=clock)
        def concurrent(_):
            token, _ = current.create(True);assert current.valid(token)
            current.revoke(token);assert not current.valid(token)
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(concurrent, range(32)))
        # Actual process exit without graceful store serialization.
        code = "import runpy,os,sys; from pathlib import Path; sys.path.insert(0,str(Path(sys.argv[1]).resolve().parents[1])); m=runpy.run_path(sys.argv[1]); s=m['SessionStore']('synthetic-auth-secret',sys.argv[2]); t,_=s.create(True); print(t,flush=True); os._exit(9)"
        child = subprocess.run([sys.executable,'-c',code,str(AUTH_SERVER),str(path)],text=True,capture_output=True,timeout=10)
        assert child.returncode == 9
        assert Store(PASSWORD,path).valid(child.stdout.strip())
    for corruption in ('corrupt','unsupported'):
        with tempfile.TemporaryDirectory(prefix='ecd-auth-invalid-') as directory:
            path=Path(directory)/'sessions.sqlite'
            if corruption=='corrupt':path.write_bytes(b'not a database');path.chmod(0o600)
            else:
                Store(PASSWORD,path)
                with sqlite3.connect(path) as db:db.execute('PRAGMA user_version=99')
            before=path.read_bytes()
            try:Store(PASSWORD,path)
            except (sqlite3.Error,RuntimeError):pass
            else:raise AssertionError('invalid existing persistence accepted')
            assert path.read_bytes()==before
    server,thread,port=start('http://localhost')
    try:
        locked=sqlite3.connect(server.sessions.path);locked.execute('BEGIN EXCLUSIVE')
        status,headers,_=request(port,'POST','/auth/login',body=urlencode({'password':PASSWORD}))
        assert status==503 and not headers.get('Set-Cookie')
        locked.rollback();locked.close()
        assert request(port,'GET','/health')[0]==204
        def concurrent_http(_):
            status,headers,_=request(port,'POST','/auth/login',body=urlencode({'password':PASSWORD}))
            assert status==303
            value=SimpleCookie(headers['Set-Cookie'])['ecd_session'].value
            assert request(port,'GET','/auth/check',cookie='ecd_session='+value)[0]==204
            assert request(port,'POST','/auth/logout',cookie='ecd_session='+value)[0]==303
            assert request(port,'GET','/auth/check',cookie='ecd_session='+value)[0]==401
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(concurrent_http,range(12)))
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5);server.persistence_fixture.cleanup()
    print('PASS durable hashed-token store, both absolute expiries, restart/abrupt process loss, revocation/password generations, concurrency and fail-closed persistence')


def test_login_localization() -> None:
    import json
    import login_locale
    from unittest.mock import patch
    from html.parser import HTMLParser

    class Document(HTMLParser):
        def __init__(self, text):
            super().__init__(); self.tags = []; self.text = []
            self.feed(text)
        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, dict(attrs)))
        def handle_data(self, data):
            self.text.append(data)

    # Model upstream's two-level source precedence, with real persistence and
    # its exact get/set_key contract; never feed the auth service the config.
    class Config:
        def __init__(self, path, options=None):
            self.path = path
            self.options = options or {}
            self.values = json.loads(path.read_text()) if path.exists() else {}
        def get(self, key):
            assert key == 'language', 'bridge read private config fields'
            return self.options.get(key, self.values.get(key))
        def set_key(self, key, value, save=True):
            if key not in self.options:
                self.values[key] = value
                if save:
                    self.path.write_text(json.dumps(self.values))

    with tempfile.TemporaryDirectory(prefix='ecd-locale-test-') as directory:
        root = Path(directory); locale = root / 'login-language'; config_path = root / 'private-config'
        marker = 'synthetic-private-config-marker'
        config_path.write_text(json.dumps({'language': 'es_ES', 'rpcpassword': marker, 'gui_last_wallet': marker}))
        with patch.object(login_locale, 'LOCALE_FILE', locale), patch.dict(os.environ, {'ECD_GUI_SESSION': 'true', 'EC_LANGUAGE': 'en_US'}):
            login_locale.install_language_bridge(Config, lambda config: login_locale.publish_language(config, system_language=lambda: 'en_US'))
            config = Config(config_path)
            assert locale.read_text() == 'es_es\n'
            assert locale.stat().st_mode & 0o777 == 0o644
            assert marker not in locale.read_text()
            server, thread, port = start('http://localhost')
            try:
                def page(expected, browser='en-US'):
                    from login_catalog import metadata
                    expected = {'es': 'es_es', 'en': 'en_us'}.get(expected, expected)
                    lang, direction = metadata(expected)
                    status, headers, body = request(port, 'GET', '/', language=browser)
                    text = body.decode(); parsed = Document(text)
                    assert status == 200 and headers['Cache-Control'] == 'no-store'
                    assert ('html', {'lang': lang, 'dir': direction}) in parsed.tags
                    assert marker not in text and PASSWORD not in text and '{{' not in text
                    assert not any(tag == 'script' for tag, attrs in parsed.tags)
                    assert ('form', {'method': 'post', 'action': '/auth/login'}) in parsed.tags
                    assert any(tag == 'input' and attrs.get('name') == 'password' and attrs.get('autocomplete') == 'current-password' for tag, attrs in parsed.tags)
                    for key in ('PASSWORD', 'REMEMBER', 'CONNECT', 'SUBTITLE', 'NOTICE'):
                        assert server_module.LOGIN_COPY[expected][key] in ''.join(parsed.text)
                    assert '<title>Electron Cash Docker</title>' in text and '#4ade80' in text
                    return text

                spanish = page('es')
                assert 'Contraseña' in spanish and 'Conectar' in spanish and 'Recordar esta sesión' in spanish
                assert 'Remember this session' not in spanish and '>Password<' not in spanish
                for value in ('es_MX', 'es-AR', 'ES-es.UTF-8', 'es', 'es_ES@euro'):
                    config.set_key('language', value)
                    page('es_ar' if value in ('es_MX', 'es-AR', 'es') else 'es_es', 'fr-FR')
                for value, code in [('fr_FR', 'fr_fr'), ('ar_SA', 'ar_sa'), ('fa_IR', 'fa_ir')]:
                    config.set_key('language', value)
                    page(code, 'es-ES')
                for value in ('en_US', 'en-GB', 'zz_ZZ', 'es_ES"><script>alert(1)</script>', {'private': marker}):
                    config.set_key('language', value)
                    with patch.dict(os.environ, {'EC_LANGUAGE': 'es_ES'}):
                        page('en', 'es-ES')
                # Even an unmodifiable CLI value uses config.get, not the
                # rejected Settings argument. The persisted fixture is private.
                locked = Config(config_path, {'language': 'en_US'})
                locked.set_key('language', 'es_ES')
                page('en', 'es-ES')
                config.set_key('language', None)
                page('en', 'es-ES')
                login_locale.publish_language(config, system_language=lambda: 'es_ES')
                page('es')  # EC's System choice, resolved inside its container
                for malformed in (b'', b'<script>private</script>', b'x' * 66, b'\xff'):
                    locale.write_bytes(malformed)
                    with patch.dict(os.environ, {'EC_LANGUAGE': 'es_ES'}):
                        page('es')
                locale.unlink()
                page('en', 'es-ES')
                with patch.dict(os.environ, {'EC_LANGUAGE': 'es_ES'}):
                    page('es')  # missing publication/older wallet image
                locale.symlink_to(config_path)
                page('en')
                assert config_path.read_text().find(marker) >= 0
                locale.unlink(); locale.mkdir()
                page('en')  # unreadable/non-regular input
                locale.rmdir()
                config.set_key('language', 'es_ES')
                for password in ('wrong-synthetic-password', 'x' * 257):
                    status, headers, body = request(port, 'POST', '/auth/login', body=urlencode({'password': password}))
                    assert status == 401 and 'Contraseña incorrecta' in body.decode()
                    assert not headers.get('Set-Cookie') and marker.encode() not in body
                for path in ('/login-language', '/config', '/private-config', '/auth/language', '/auth/gui-session'):
                    status, headers, body = request(port, 'GET', path)
                    assert status in (401, 404) and marker.encode() not in body
                status, headers, body = request(port, 'POST', '/auth/login', body=urlencode({'password': PASSWORD, 'remember': 'on'}))
                assert status == 303 and body == b'' and headers['Location'].startswith('/vnc.html?autoconnect=true')
                cookie = SimpleCookie(headers['Set-Cookie'])['ecd_session']
                assert cookie['httponly'] and cookie['samesite'] == 'Strict' and int(cookie['max-age']) == server_module.REMEMBER_TTL
                assert request(port, 'GET', '/auth/check', cookie='ecd_session=' + cookie.value)[0] == 204
                assert request(port, 'POST', '/auth/logout', cookie='ecd_session=' + cookie.value)[0] == 303
                assert request(port, 'GET', '/auth/check', cookie='ecd_session=' + cookie.value)[0] == 401
                assert request(port, 'POST', '/auth/login', body=urlencode({'password': PASSWORD}), origin='https://evil.example')[0] == 403
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5); server.persistence_fixture.cleanup()
            # Bridge failure must leave EC's config save successful, with no
            # config values/exception details disclosed in diagnostics.
            with patch('login_locale.tempfile.mkstemp', side_effect=PermissionError), patch('builtins.print') as diagnostic:
                config.set_key('language', 'es_ES')
                assert json.loads(config_path.read_text())['language'] == 'es_ES'
                assert not locale.exists()
                diagnostic.assert_called_once_with('[!] Login locale publication unavailable', flush=True)
    from login_catalog import load_catalogs, ENGLISH
    assert load_catalogs('/nonexistent-ecd-catalog') == {'en_us': ENGLISH}
    with tempfile.TemporaryDirectory() as directory:
        malformed = Path(directory) / 'catalog'; malformed.write_text('fr_FR|incomplete')
        assert load_catalogs(malformed) == {'en_us': ENGLISH}
    # Even compromised catalog text is rendered as inert text, never markup.
    from unittest.mock import patch
    payload = '<img src=x onerror="alert(1)"> & {{CONTENT}}'
    hostile = dict(ENGLISH, PASSWORD=payload, INVALID=payload, NOTICE=payload)
    handler = object.__new__(Handler)
    with patch.dict(server_module.LOGIN_COPY, {'en_us': hostile}), patch.object(server_module, 'login_language', return_value='en_us'):
        document = Document(handler._page('wrong').decode())
        assert not any(tag in ('img', 'script') for tag, attrs in document.tags)
        assert payload in ''.join(document.text)
    print('PASS persisted EC selection -> locale-only bridge -> HTTP translated UI, Settings reload, variants/defaults, no-JS failures, auth and no-disclosure')


if __name__ == "__main__":
    main()

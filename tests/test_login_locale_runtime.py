#!/usr/bin/env python3
"""Real EC SimpleConfig/catalog -> locale-only bridge -> HTTP acceptance.

Uses one disposable, network-isolated container, tmpfs config/auth fixtures,
and source-only read-only mounts. Never starts Compose or mounts user data.
Run: python3 tests/test_login_locale_runtime.py
"""
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def inside():
    import json
    import gettext
    from unittest.mock import patch
    sys.path.insert(0, str(ROOT / 'docker'))
    sys.path.insert(0, str(ROOT / 'tests'))
    from electroncash.simple_config import SimpleConfig
    from electroncash import i18n, version
    import login_locale
    from login_catalog import CATALOGS, KEYS, ENGLISH, metadata
    import gui_session
    from test_auth_session import start, request, PASSWORD
    from urllib.parse import urlencode

    assert version.PACKAGE_VERSION == '4.4.6'
    assert len(i18n.languages) == 39 and '' in i18n.languages
    assert set(CATALOGS) == {code.lower() for code in i18n.languages if code}
    # Independent raw-data coverage: do not let resolver fallback fake a pass.
    rows = [line.split('|') for line in (ROOT / 'docker/login-translations.tsv').read_text().splitlines() if line and not line.startswith('#')]
    assert len(rows) == 38 and {row[0] for row in rows} == set(i18n.languages) - {''}
    for row in rows:
        assert len(row) == 14 and all(value.strip() for value in row)
        if row[0] != 'en_US':
            assert row[2] != ENGLISH['REMEMBER'] and row[6] != ENGLISH['NOTICE']
            assert row[12] != ENGLISH['ENDED']
    # Execute the actual startup validation and config writer from source;
    # no copied validator and no wallet data mounts.
    entrypoint = (ROOT / 'docker/entrypoint.sh').read_text()
    validator = entrypoint.split('ECD_VERSION_FILE=', 1)[0]
    writer = entrypoint.split('ensure_config() {', 1)[1].split('\n}\n', 1)[0]
    with tempfile.TemporaryDirectory(prefix='ecd-startup-language-') as directory:
        path = Path(directory) / 'config'
        def seed(value, validate=True):
            environment = dict(os.environ, CONFIG_DIR=directory, CONFIG_FILE=str(path), USE_TOR='false',
                               PYTHONPATH=str(ROOT / 'docker'))
            if value is None:
                environment.pop('EC_LANGUAGE', None)
            else:
                environment['EC_LANGUAGE'] = value
            command = validator + '\nCONFIG_DIR="$TEST_CONFIG_DIR"\nCONFIG_FILE="$TEST_CONFIG_FILE"\nUSE_TOR=false\n' + writer
            environment.update(TEST_CONFIG_DIR=directory, TEST_CONFIG_FILE=str(path))
            return subprocess.run(['bash', '-c', command], env=environment, capture_output=True)
        for code in i18n.languages:
            path.unlink(missing_ok=True)
            result = seed(code)
            assert result.returncode == 0, result.stderr
            assert json.loads(path.read_text())['language'] == code
        path.unlink(); assert seed(None).returncode == 0
        assert json.loads(path.read_text())['language'] == 'en_US'
        for persisted in ('ru_RU', '', None):
            original = {'config_version': 2, 'private-marker': 'synthetic'}
            if persisted is not None:
                original['language'] = persisted
            path.write_text(json.dumps(original))
            assert seed('en_US').returncode == 0
            actual = json.loads(path.read_text())
            assert actual.get('language') == persisted and ('language' in actual) == ('language' in original)
        before = path.read_bytes()
        for bad in ('fr', 'zz_ZZ', 'es_MX', 'si_LK', '../config', 'es_ES;id', '"<script>', 'es_ES\n'):
            result = seed(bad)
            assert result.returncode != 0 and b'EC_LANGUAGE must be an official' in result.stderr
            assert path.read_bytes() == before
    with tempfile.TemporaryDirectory(prefix='ecd-network-language-') as directory:
        # The real upstream path selector, not a mock mapping.
        options = [None, 'testnet', 'testnet4', 'scalenet', 'chipnet', 'regtest']
        for network in options:
            config = SimpleConfig(dict(electron_cash_path=directory, **({network: True} if network else {})))
            config.set_key('language', 'pt_BR' if network == 'chipnet' else 'ru_RU')
        for network in options:
            config = SimpleConfig(dict(electron_cash_path=directory, **({network: True} if network else {})))
            assert config.get('language') == ('pt_BR' if network == 'chipnet' else 'ru_RU')
    # Verify catalog labels against the shipped, pinned release, not our map.
    spanish = gettext.translation('electron-cash', i18n.LOCALE_DIR, languages=['es_ES'])
    assert spanish.gettext('Password') == 'Contraseña'
    assert spanish.gettext('Wallet') == 'Cartera'
    assert spanish.gettext('Save') == 'Guardar'
    assert spanish.gettext('Incorrect password') == 'Contraseña incorrecta'
    with tempfile.TemporaryDirectory(prefix='ecd-real-locale-') as directory:
        root = Path(directory); state = root / 'state'; state.mkdir()
        locale = state / 'login-language'; config_dir = root / 'config'; config_dir.mkdir()
        private = config_dir / 'config'
        private.write_text(json.dumps({'config_version': 2, 'language': 'es_ES', 'rpcpassword': 'synthetic-private-marker'}))
        with patch.object(login_locale, 'LOCALE_FILE', locale), patch.object(gui_session, 'DIRECTORY', state), patch.object(gui_session, 'STATE', state / 'state'), patch.dict(os.environ, {'ECD_GUI_SESSION': 'true', 'EC_LANGUAGE': 'en_US'}):
            gui_session.initialize()
            login_locale.install_language_bridge()
            config = SimpleConfig({'electron_cash_path': str(config_dir)})
            assert locale.read_text() == 'es_es\n'
            assert set(p.name for p in state.iterdir()) == {'state', 'login-language'}
            server, thread, port = start('http://localhost')
            try:
                def verify(language, label):
                    status, headers, payload = request(port, 'GET', '/', language='en-US' if language == 'es' else 'es-ES')
                    text = payload.decode()
                    code = language.lower().replace('-', '_')
                    lang, direction = metadata(code)
                    assert status == 200 and f'<html lang="{lang}" dir="{direction}">' in text and label in text
                    assert 'synthetic-private-marker' not in text and PASSWORD not in text
                    assert headers['Cache-Control'] == 'no-store'
                verify('es_ES', 'Conectar')
                # This is the real API called by EC Settings; the original
                # method must still persist every change normally.
                for code in i18n.languages:
                    config.set_key('language', code)
                    assert json.loads(private.read_text())['language'] == code
                    effective = code or i18n.get_system_language_match() or 'en_US'
                    copy = CATALOGS[effective.lower()]
                    verify(effective, copy['CONNECT'])
                    # Real HTTP errors and form text for every official locale.
                    from html import unescape
                    rendered = unescape(request(port, 'GET', '/')[2].decode())
                    for key in ('PASSWORD', 'REMEMBER', 'CONNECT', 'SUBTITLE', 'NOTICE'):
                        assert copy[key] in rendered, (code, key)
                    for path, key, status in [('/missing', 'NOT_FOUND', 404), ('/auth/check', 'REQUIRED', 401)]:
                        response = request(port, 'GET', path)
                        assert response[0] == status and copy[key] in response[2].decode()
                    response = request(port, 'POST', '/auth/login', body=urlencode({'password': 'wrong'}))
                    assert response[0] == 401 and copy['INVALID'] in unescape(response[2].decode())
                    assert not response[1].get('Set-Cookie')
                    response = request(port, 'POST', '/auth/login', body='x', origin='https://evil.example')
                    assert response[0] == 403 and copy['FORBIDDEN'] in response[2].decode()
                    import http.client
                    connection = http.client.HTTPConnection('127.0.0.1', port)
                    connection.request('POST', '/auth/login', body=b'\xff', headers={'Host':'localhost', 'Origin':'http://localhost'})
                    bad = connection.getresponse()
                    assert bad.status == 400 and copy['BAD_REQUEST'] in bad.read().decode()
                    connection.close()
                    response = request(port, 'PUT', '/unsupported')
                    assert response[0] == 501 and copy['BAD_REQUEST'] in response[2].decode()
                    with patch.object(server.sessions, 'authenticate', side_effect=RuntimeError('synthetic')):
                        response = request(port, 'POST', '/auth/login', body=urlencode({'password': 'wrong'}))
                        assert response[0] == 503 and copy['UNAVAILABLE'] in response[2].decode()
                    response = request(port, 'POST', '/auth/login', body=urlencode({'password': PASSWORD, 'remember': 'on'}))
                    from http.cookies import SimpleCookie
                    token = SimpleCookie(response[1]['Set-Cookie'])['ecd_session'].value
                    response = request(port, 'GET', '/auth/gui-session', cookie='ecd_session=' + token)
                    notice = json.loads(response[2])
                    assert notice['copy'] == copy and notice['lang'] == metadata(effective)[0]
                    assert notice['dir'] == metadata(effective)[1]
                    assert 'synthetic-private-marker' not in response[2].decode()
                    # New SimpleConfig process-equivalent reload with en_US env
                    # must preserve the real persisted choice, including ''.
                    reloaded = SimpleConfig({'electron_cash_path': str(config_dir)})
                    assert reloaded.get('language') == code
                    verify(effective, copy['CONNECT'])
                assert json.loads(private.read_text())['rpcpassword'] == 'synthetic-private-marker'
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(lambda code: config.set_key('language', code), ['ru_RU','ar_SA','fa_IR','th_TH'] * 8))
                assert locale.read_text().strip() == json.loads(private.read_text())['language'].lower()
                assert not list(state.glob('.login-language-*'))
                # CLI source precedence is upstream's real behavior.
                cli = SimpleConfig({'electron_cash_path': str(config_dir), 'language': 'en_US'})
                cli.set_key('language', 'es_ES')
                verify('en_US', 'Connect')
                config.set_key('language', 'es_ES')
                status, headers, payload = request(port, 'POST', '/auth/login', body=urlencode({'password': 'synthetic-wrong'}))
                assert status == 401 and 'Contraseña incorrecta' in payload.decode() and not headers.get('Set-Cookie')
                status, headers, payload = request(port, 'POST', '/auth/login', body=urlencode({'password': PASSWORD}))
                assert status == 303 and headers['Location'].startswith('/vnc.html?autoconnect=true') and not payload
                gui_session.initialize()
                assert not locale.exists()  # stale previous session discarded
                verify('en_US', 'Connect')
                # First boot and absent/unreadable EC config use EC's defaults.
                private.unlink()
                SimpleConfig({'electron_cash_path': str(config_dir)})
                assert login_locale.login_language() == 'en_us'
                private.write_text('not JSON')
                SimpleConfig({'electron_cash_path': str(config_dir)})
                assert login_locale.login_language() == 'en_us'
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5); server.persistence_fixture.cleanup()
    print('PASS 38/38 real EC locales + System; 494/494 catalog fields; real SimpleConfig saves/reloads, precedence, HTTP labels/errors, RTL metadata, auth and locale-only isolation')
    print('CATALOG_COVERAGE ' + json.dumps({'upstream_version': version.PACKAGE_VERSION,
        'explicit_locales': 38, 'system_accepted': True, 'fields_per_locale': len(KEYS),
        'total_fields': 38 * len(KEYS), 'locales': {code: {'fields': len(CATALOGS[code.lower()]),
            'direction': metadata(code)[1], 'non_english_copy': code != 'en_US'}
            for code in i18n.languages if code}}, sort_keys=True))


def main():
    if '--inside' in sys.argv:
        inside()
        return
    import test_support
    image = test_support.electron_cash_image()
    name = test_support.register_resource('container', 'ecd-login-locale-test-' + uuid.uuid4().hex[:12])
    command = ['docker', 'run', '--rm', '--name', name, '--network', 'none',
               '--label', test_support.docker_ownership.OWNER_LABEL + '=' + test_support.resource_owner(),
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
               '--user', '10001:10001', '--tmpfs', '/tmp:rw,mode=1777,size=32m',
               '--env', 'PYTHONDONTWRITEBYTECODE=1']
    for directory in ('docker', 'tests'):
        command += ['--mount', f'type=bind,source={ROOT / directory},target=/source/{directory},readonly']
    command += ['--mount', f'type=bind,source={ROOT / "VERSION"},target=/source/VERSION,readonly']
    command += ['--entrypoint', '/opt/electroncash-venv/bin/python', image,
                '/source/tests/test_login_locale_runtime.py', '--inside']
    try:
        result = subprocess.run(command, check=False, timeout=120, text=True, capture_output=True)
        print(result.stdout, end='')
        if result.returncode:
            print(result.stderr, file=sys.stderr, end='')
            result.check_returncode()
        if os.environ.get('CI_REPORT_DIR'):
            import json
            report = next(line.removeprefix('CATALOG_COVERAGE ') for line in result.stdout.splitlines() if line.startswith('CATALOG_COVERAGE '))
            directory = Path(os.environ['CI_REPORT_DIR']); directory.mkdir(parents=True, exist_ok=True)
            (directory / 'language-catalog-coverage.json').write_text(json.dumps(json.loads(report), indent=2, sort_keys=True) + '\n')
    finally:
        # Only our uniquely named test container, including on timeout.
        test_support.remove_owned_container(name)


if __name__ == '__main__':
    main()

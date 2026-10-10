#!/usr/bin/env python3
"""Offline, disposable real Qt Settings -> shared code -> Caddy/browser proof.

Requires candidate ELECTRON_CASH_IMAGE and AUTH_SESSION_IMAGE. No real wallet,
external network, production service or host wallet/config mount is used.
"""
import json
import os
import tempfile
import time
from pathlib import Path
from playwright.sync_api import sync_playwright
from test_support import unique_project
from test_canonical_startup import free_port
from test_gui_session_lifecycle import checked, connect, main_window, windows

ROOT = Path(__file__).resolve().parents[1]


def main():
    project = unique_project('language-browser')
    assert os.environ.get('ELECTRON_CASH_IMAGE') and os.environ.get('AUTH_SESSION_IMAGE')
    environment = dict(os.environ, BASIC_AUTH_PASSWORD='disposable-language-auth',
        USE_TOR='false', NETWORK='chipnet', WALLET_AUTO_CREATE='true',
        TEST_WALLET_PASSWORD='disposable-language-wallet', EC_LANGUAGE='en_US',
        ECD_WALLET_VOLUME=project+'-wallet', ECD_TOR_VOLUME=project+'-tor',
        CADDY_SITE_ADDRESS='http://localhost', CADDY_EDGE_BIND='127.0.0.1',
        CADDY_HTTP_HOST_PORT=str(free_port()), CADDY_HTTPS_HOST_PORT=str(free_port()))
    with tempfile.TemporaryDirectory(prefix='ecd-language-browser-') as directory:
        directory = Path(directory)
        override = directory / 'offline.yml'
        override.write_text('services:\n  caddy:\n    networks:\n      - acceptance-edge\n'
            'networks:\n  electron-network:\n    internal: true\n'
            '  acceptance-edge:\n    driver: bridge\n    driver_opts:\n'
            '      com.docker.network.bridge.enable_ip_masquerade: "false"\n')
        command = ['docker', 'compose', '--env-file', str(ROOT / '.env.example'), '-p', project,
                   '-f', str(ROOT / 'docker-compose.yml'), '-f', str(override)]
        try:
            checked(command + ['up', '-d', '--wait', '--no-build', '--pull', 'never', 'caddy'], environment, 240)
            wallet = checked(command + ['ps', '-q', 'electron-cash'], environment).strip()
            gateway = checked(command + ['ps', '-q', 'auth-session'], environment).strip()
            inspected = json.loads(checked(['docker', 'inspect', gateway], environment))[0]
            assert not any(m['Destination'].startswith('/home/electroncash') for m in inspected['Mounts'])
            assert any(m['Destination'] == '/run/ecd-gui-session' and not m['RW'] for m in inspected['Mounts'])
            for name in inspected['NetworkSettings']['Networks']:
                net = json.loads(checked(['docker', 'network', 'inspect', name], environment))[0]
                assert net['Internal'], 'test network must deny external routing'
            def config():
                return json.loads(checked(['docker', 'exec', '--user', '10001:10001', wallet,
                    '/opt/electroncash-venv/bin/python', '-c',
                    'import json; from pathlib import Path; print(Path("/home/electroncash/.electron-cash/chipnet/config").read_text())'], environment))
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, args=['--disable-dev-shm-usage'])
                try:
                    context = browser.new_context(viewport={'width': 1280, 'height': 900}, locale='es-ES')
                    page = context.new_page()
                    url = 'http://localhost:' + environment['CADDY_HTTP_HOST_PORT']
                    connect(page, url, environment)
                    main_window(page, wallet, environment, directory, 'language')
                    page.locator('#noVNC_container canvas').click(position={'x':640, 'y':400})
                    page.keyboard.press('Control+,')
                    deadline = time.monotonic() + 15
                    prefs = None
                    while time.monotonic() < deadline:
                        prefs = next((w for w in windows(wallet, environment) if w['name'] == 'Preferences'), None)
                        if prefs:
                            break
                        page.wait_for_timeout(200)
                    assert prefs, 'real Qt Preferences dialog did not open'
                    # X11 mapping precedes the remote frame/focus update.
                    page.wait_for_timeout(500)
                    # General tab's first field is upstream's language combo.
                    canvas = page.locator('#noVNC_container canvas')
                    size = canvas.evaluate('(c) => ({x:c.getBoundingClientRect().width/c.width, y:c.getBoundingClientRect().height/c.height})')
                    codes = json.loads(checked(['docker', 'exec', wallet,
                        '/opt/electroncash-venv/bin/python', '-c',
                        'import json; from electroncash.i18n import languages; print(json.dumps(list(languages)))'], environment))
                    # Login probes must not share the active ordinary session:
                    # visiting '/' with that cookie deliberately revokes it.
                    probe = browser.new_context(locale='es-ES')
                    login = probe.new_page()
                    for code, label in [('ar_SA','كلمة المرور'), ('fa_IR','گذرواژه'),
                                        ('ru_RU','Пароль'), ('th_TH','รหัสผ่าน'), ('','Password'), ('zh_TW','密碼')]:
                        page.bring_to_front()
                        size = canvas.evaluate('(c) => ({x:c.getBoundingClientRect().width/c.width, y:c.getBoundingClientRect().height/c.height})')
                        canvas.click(position={'x':(prefs['x'] + prefs['width'] - 70)*size['x'], 'y':(prefs['y'] + 65)*size['y']})
                        page.wait_for_timeout(250)
                        page.keyboard.press('Home', delay=80)
                        page.wait_for_timeout(100)
                        for _ in range(codes.index(code)):
                            page.keyboard.press('ArrowDown', delay=60)
                        page.keyboard.press('Enter')
                        deadline = time.monotonic() + 10
                        while config()['language'] != code and time.monotonic() < deadline:
                            page.wait_for_timeout(200)
                        assert config()['language'] == code, ('language combo not selected', code, prefs, config().get('language'))
                        # A second tab observes real Settings saves without a
                        # container restart or browser-header override.
                        login.goto(url)
                        effective = code or 'en_US'
                        assert login.locator('html').get_attribute('lang') == effective.replace('_','-')
                        assert login.locator('label[for=pass]').inner_text() == label
                        direction = 'rtl' if code in ('ar_SA','fa_IR') else 'ltr'
                        assert login.locator('html').get_attribute('dir') == direction
                        assert login.locator('h1').evaluate('(e) => getComputedStyle(e).direction') == 'ltr'
                        assert login.locator('script').count() == 0
                        page.wait_for_function('(locale) => document.documentElement.lang === locale', arg=effective.replace('_','-'))
                    probe.close(); context.close()
                finally:
                    browser.close()
            checked(command + ['restart', 'electron-cash'], environment, 120)
            checked(command + ['up', '-d', '--wait', '--no-build', '--pull', 'never', 'caddy'], environment, 240)
            assert config()['language'] == 'zh_TW', 'en_US environment overwrote GUI Settings at restart'
            print('PASS offline real Qt Preferences save -> Caddy login reload + live noVNC locale, browser-header precedence, restart persistence and gateway mount isolation')
            checked(command + ['stop'], environment, 120)
            headless = command + ['-f', str(ROOT / 'docker-compose.headless.yml')]
            environment.update(NETWORK='mainnet', EC_LANGUAGE='', WALLET_AUTO_CREATE='false', TEST_WALLET_PASSWORD='')
            checked(headless + ['up', '-d', '--wait', '--no-build', '--pull', 'never', 'electron-cash'], environment, 180)
            wallet = checked(headless + ['ps', '-q', 'electron-cash'], environment).strip()
            code = ('import json; from pathlib import Path; '
                    'root=Path("/home/electroncash/.electron-cash"); '
                    'print(json.dumps([json.loads((root/"config").read_text())["language"], '
                    'json.loads((root/"chipnet/config").read_text())["language"]]))')
            result = checked(['docker', 'exec', wallet, '/opt/electroncash-venv/bin/python', '-c', code], environment)
            assert json.loads(result) == ['', 'zh_TW']
            processes = checked(['docker', 'top', wallet, '-eo', 'pid,comm'], environment)
            assert all(name not in processes for name in ('Xvfb', 'x11vnc', 'websockify', 'openbox'))
            print('PASS real offline headless System first boot; chipnet GUI preference remains isolated; no GUI processes required')
        finally:
            checked(command + ['down', '--volumes', '--remove-orphans'], environment, 120)


if __name__ == '__main__':
    main()

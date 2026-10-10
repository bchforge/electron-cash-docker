#!/usr/bin/env python3
"""Real Compose hardening, RFB boundary and EN/ES Qt-session acceptance."""
import json
import os
import subprocess
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from test_support import unique_project
from test_canonical_startup import free_port, wait_running, wait_healthy, inspect

ROOT = Path(__file__).resolve().parents[1]


def checked(command, env):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=180, check=False)
    if result.returncode:
        raise AssertionError((result.stdout + result.stderr).replace(env['BASIC_AUTH_PASSWORD'], '[REDACTED]'))
    return result.stdout


def assert_hardening(identifiers):
    for service, identifier in identifiers.items():
        host = inspect(identifier)['HostConfig']
        assert host['ReadonlyRootfs'] and not host['Privileged'], service
        assert 'ALL' in host['CapDrop'], service
        assert 'no-new-privileges:true' in host['SecurityOpt'], service
        assert 0 < host['PidsLimit'] <= 256 and host['Memory'] > 0 and host['NanoCpus'] > 0, service
        assert host['LogConfig'] == {'Type':'json-file', 'Config':{'max-file':'3','max-size':'10m'}}, host['LogConfig']
        if service != 'caddy':
            assert not host.get('PortBindings'), service
        assert not host.get('Devices') and not host.get('DeviceCgroupRules'), service
        allowed = {'electron-cash':{'CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'},
                   'fail2ban':{'NET_ADMIN'}}.get(service, set())
        assert {cap.removeprefix('CAP_') for cap in host.get('CapAdd') or []} == allowed, (service,host.get('CapAdd'))
        cgroups=subprocess.run(['docker','exec',identifier,'cat','/sys/fs/cgroup/pids.max',
                               '/sys/fs/cgroup/memory.max','/sys/fs/cgroup/cpu.max'],text=True,capture_output=True)
        if cgroups.returncode == 0:
            pids,memory,cpu=cgroups.stdout.splitlines()
            quota,period=cpu.split()
        else:
            cgroups=subprocess.run(['docker','exec',identifier,'cat','/sys/fs/cgroup/pids/pids.max',
                '/sys/fs/cgroup/memory/memory.limit_in_bytes','/sys/fs/cgroup/cpu/cpu.cfs_quota_us',
                '/sys/fs/cgroup/cpu/cpu.cfs_period_us'],text=True,capture_output=True)
            assert cgroups.returncode==0,cgroups.stderr
            pids,memory,quota,period=cgroups.stdout.splitlines()
        assert int(pids)==host['PidsLimit'] and int(memory)==host['Memory'],service
        assert int(quota)/int(period)==host['NanoCpus']/1_000_000_000,service
    wallet = identifiers['electron-cash']
    proof = subprocess.run(['docker','exec',wallet,'/opt/electroncash-venv/bin/python','-c',
        "from pathlib import Path; s=Path('/proc/1/status').read_text(); "
        "assert 'Uid:\\t10001\\t10001\\t10001\\t10001' in s; "
        "assert 'CapEff:\\t0000000000000000' in s; assert 'NoNewPrivs:\\t1' in s; "
        "print('runtime UID=10001 CapEff=0 NoNewPrivs=1')"], text=True, capture_output=True)
    assert proof.returncode == 0, proof.stderr
    # Even bootstrap root cannot write an arbitrary path in the immutable image.
    write = subprocess.run(['docker','exec',wallet,'touch','/etc/runtime-must-not-write'], capture_output=True)
    assert write.returncode != 0 and b'Read-only file system' in write.stderr
    probe = subprocess.run(['docker','exec','--user','10001:10001',wallet,'sh','-c',
        'touch /tmp/runtime-write /home/electroncash/.cache/runtime-write /home/electroncash/.electron-cash/.runtime-write'], capture_output=True)
    assert probe.returncode == 0, probe.stderr
    # Raw RFB must reject an independent peer, while internal noVNC is reachable
    # only on the private bridge (never host-published).
    gateway = identifiers['auth-session']
    network_probe = subprocess.run(['docker','exec',gateway,'python3','-c',
        "import socket; s=socket.create_connection(('electron-cash',6080),2); s.close(); "
        "s=socket.socket(); s.settimeout(2); assert s.connect_ex(('electron-cash',5900)) != 0"], capture_output=True)
    assert network_probe.returncode == 0, network_probe.stderr
    print('PASS effective service controls, zero-capability wallet, immutable root, writable state and peer RFB rejection')


def keyboard_acceptance(wallet, port, env):
    # A harmless Qt field on the real desktop, reached through the real browser,
    # gateway, noVNC, WebSocket and x11vnc. Never type test text into a wallet seed.
    probe = """
import json
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QDialog, QLineEdit, QVBoxLayout
from PyQt5.QtCore import QTimer, Qt
app=QApplication([]); dialog=QDialog(); dialog.setWindowTitle('runtime keyboard acceptance')
dialog.setWindowFlags(Qt.Window | Qt.WindowStaysOnTopHint)
layout=QVBoxLayout(dialog); field=QLineEdit(); layout.addWidget(field)
dialog.setGeometry(100,100,700,180); dialog.show(); dialog.raise_(); dialog.activateWindow(); field.setFocus()
def save():
    pos=field.mapToGlobal(field.rect().center())
    Path('/tmp/runtime-keyboard.json').write_text(json.dumps({'text':field.text(),'x':pos.x(),'y':pos.y()}))
def focus():
    dialog.raise_(); dialog.activateWindow(); field.setFocus()
focus_timer=QTimer(); focus_timer.timeout.connect(focus); focus_timer.start(500)
field.textChanged.connect(save); QTimer.singleShot(1000,save); QTimer.singleShot(90000,app.quit)
app.exec_()
"""
    checked(['docker','exec','-d','--user','10001:10001','-e','DISPLAY=:99',wallet,
             '/opt/electroncash-venv/bin/python','-c',probe],env)
    def observed():
        return json.loads(checked(['docker','exec',wallet,'cat','/tmp/runtime-keyboard.json'],env))
    deadline=time.monotonic()+30
    while subprocess.run(['docker','exec',wallet,'test','-f','/tmp/runtime-keyboard.json'],capture_output=True).returncode:
        assert time.monotonic()<deadline
        time.sleep(0.2)
    position=observed()
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
        page=browser.new_page()
        page.goto(f'http://127.0.0.1:{port}/')
        page.locator('input[name=password]').fill(env['BASIC_AUTH_PASSWORD'])
        page.locator('button[type=submit]').click()
        page.wait_for_url('**/vnc.html**')
        cookies=page.context.cookies()
        page.close()
        directory=Path(os.environ['CI_REPORT_DIR'])
        context=browser.new_context(record_video_dir=str(directory/'runtime-demo-video'))
        context.add_cookies([dict(cookie) for cookie in cookies])
        page=context.new_page()
        page.goto(f'http://127.0.0.1:{port}/vnc.html?autoconnect=true&resize=scale')
        page.wait_for_function("async () => { const UI=(await import('/app/ui.js')).default; return UI.rfb && UI.rfb._rfb_connection_state === 'connected'; }")
        canvas=page.locator('#noVNC_container canvas')
        page.wait_for_timeout(1000)
        box=canvas.bounding_box(); assert box
        canvas.click(position={'x':position['x']*box['width']/1600,'y':position['y']*box['height']/900})
        page.keyboard.type('abc'); page.keyboard.press('Backspace'); page.keyboard.type('Z')
        deadline=time.monotonic()+10
        while observed()['text'] != 'abZ':
            if time.monotonic()>=deadline:
                page.screenshot(path=str(Path(os.environ['CI_REPORT_DIR'])/'runtime-keyboard-failure.png'))
                raise AssertionError({'qt':observed(),'canvas':box})
            page.wait_for_timeout(200)
        # noVNC's standard hidden input is the mobile/virtual text path.
        page.evaluate("""() => { const input=document.getElementById('noVNC_keyboardinput');
            input.focus(); input.value += ' ñ'; input.dispatchEvent(new Event('input',{bubbles:true})); }""")
        deadline=time.monotonic()+10
        while observed()['text'] != 'abZ ñ':
            assert time.monotonic()<deadline,observed()
            page.wait_for_timeout(200)
        language=env['EC_LANGUAGE']
        page.screenshot(path=str(directory/f'runtime-keyboard-{language}.png'))
        (directory/f'runtime-keyboard-{language}.json').write_text(json.dumps({'browser':'Chromium','language':language,'physical_edit':'abZ',
            'virtual_input':'abZ ñ','transport':'Caddy/session/noVNC/WebSocket/RFB/Qt','no_wallet_input':True})+'\n')
        context.close()
        browser.close()
    print('PASS real browser physical/editing and standard noVNC virtual text input reaching Qt (including ñ)')


def main():
    required = ('ELECTRON_CASH_IMAGE','TOR_IMAGE','CADDY_IMAGE','AUTH_SESSION_IMAGE','FAIL2BAN_IMAGE')
    assert os.environ.get('CI_CANDIDATE_IMAGES') == '1', 'requires freshly built candidate images'
    assert all(os.environ.get(name) for name in required)
    project = unique_project('runtime')
    env = dict(os.environ, BASIC_AUTH_PASSWORD='runtime-disposable-auth', USE_TOR='false',
               NETWORK='chipnet', WALLET_AUTO_CREATE='false', TEST_WALLET_PASSWORD='',
               ECD_WALLET_VOLUME=project+'-wallet', ECD_TOR_VOLUME=project+'-tor',
               CADDY_HTTP_HOST_PORT=str(free_port()), CADDY_HTTPS_HOST_PORT=str(free_port()),
               CADDY_SITE_ADDRESS='http://localhost', CADDY_EDGE_BIND='127.0.0.1')
    command = ['docker','compose','--env-file','.env.example','-p',project,'-f','docker-compose.yml']
    try:
        for index, (language, word) in enumerate([('en_US','Wallet'), ('es_ES','Cartera'), ('en_US','Wallet')]):
            if index:
                # Existing configs change through EC's persisted Settings API,
                # never by forcing the first-boot environment on restart.
                checked(['docker','exec','--user','10001:10001',wallet,
                    '/opt/electroncash-venv/bin/python','-c',
                    'from electroncash.simple_config import SimpleConfig; '
                    f'SimpleConfig({{"chipnet":True}}).set_key("language", {language!r})'],env)
            env['EC_LANGUAGE'] = language
            checked(command+['up','-d','--no-build','--pull','never'],env)
            identifiers = {service:wait_running(command,service,env=env,cwd=ROOT)
                           for service in ('electron-cash','auth-session','caddy','fail2ban','tor-proxy')}
            for service, identifier in identifiers.items(): wait_healthy(identifier,service)
            wallet = identifiers['electron-cash']
            deadline = time.monotonic()+60
            expected = f'Electron Cash GUI language: {language} ({word})'
            while expected not in checked(['docker','logs',wallet],env):
                assert time.monotonic() < deadline, f'real Qt session did not report {expected}'
                time.sleep(1)
            assert_hardening(identifiers)
            if index < 2:
                keyboard_acceptance(wallet,int(env['CADDY_HTTP_HOST_PORT']),env)
            checked(['docker','exec','--user','10001:10001',wallet,'pkill','-x','x11vnc'],env)
            failed_health=subprocess.run(['docker','exec',wallet,'/opt/electroncash-venv/bin/python',
                '/home/electroncash/healthcheck.py'],capture_output=True)
            assert failed_health.returncode != 0,'wallet health falsely passed without the real RFB transport'
            checked(command+['restart','electron-cash'],env)
            wait_healthy(wallet,'electron-cash')
            deadline=time.monotonic()+60
            while checked(['docker','logs',wallet],env).count(expected) < 2:
                assert time.monotonic()<deadline, 'restart did not launch the selected Qt session'
                time.sleep(1)
            print(f'PASS real Qt {language}/{word}, restart and existing-volume language switch')
        checked(command+['stop','electron-cash'],env)
        digest_command=command+['run','--rm','--no-deps','--entrypoint','/opt/electroncash-venv/bin/python',
            'electron-cash','-c',"import hashlib; from pathlib import Path; h=hashlib.sha256(); "
            "[(h.update(str(p.relative_to('/home/electroncash/.electron-cash')).encode()),h.update(p.read_bytes())) "
            "for p in sorted(Path('/home/electroncash/.electron-cash').rglob('*')) if p.is_file()]; print(h.hexdigest())"]
        before=checked(digest_command,env)
        for invalid in ('zz_ZZ', 'es', 'es_ES;id', '../../config', '<script>'):
            # Run the actual image entrypoint against a fresh disposable container;
            # invalid language must fail before the existing wallet volume is touched.
            env['EC_LANGUAGE'] = invalid
            result = subprocess.run(command+['run','--rm','--no-deps','electron-cash'],
                                    cwd=ROOT,env=env,text=True,capture_output=True,timeout=60)
            assert result.returncode != 0 and 'EC_LANGUAGE must be an official Electron Cash locale or empty (System)' in result.stdout+result.stderr, result.stderr
            assert checked(digest_command,env)==before,'invalid language changed persisted state'
        env['EC_LANGUAGE']='en_US'; env['ELECTRONCASH_ARGS']='--lang=fr_FR'
        result=subprocess.run(command+['run','--rm','--no-deps','electron-cash'],cwd=ROOT,
                              env=env,text=True,capture_output=True,timeout=60)
        assert result.returncode != 0 and 'use EC_LANGUAGE' in result.stdout+result.stderr
        assert checked(digest_command,env)==before,'reserved CLI language changed persisted state'
        print('PASS unsupported/injection language fails before state mutation; System is valid')
    finally:
        checked(command+['down','--volumes','--remove-orphans'],env)


if __name__ == '__main__':
    main()

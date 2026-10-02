#!/usr/bin/env python3
r"""Regenerate docs/assets/electron-cash-docker-demo.gif from continuous video.

Prerequisites: a dedicated, already-running mainnet demo Compose stack with a
new, empty disposable wallet (never a funded wallet), Docker
access, Python Playwright with Chromium, Pillow, rapidocr-onnxruntime (read-only
UI verification), and Playwright's bundled ffmpeg. These are developer/release
dependencies only; normal installations do not use this tool.
If the bundled ffmpeg lacks GIF/palette support, install imageio-ffmpeg in the
developer Python environment for its standalone binary (no system install).

Example (from the repository root, with the developer Python environment active):
    python3 scripts/record_demo.py \
      --mode record \
      --url https://ecd-demo.bchforge.org/ \
      --env-file /home/ubuntu/.local/state/electron-cash-docker/demo-ecd-demo-20260923T054928Z/demo.env \
      --project-name ecd-demo-20260923t054928z \
      --fps 12 --final-hold 7 \
      --output docs/assets/electron-cash-docker-demo.gif

After inspecting the candidate and validation PNGs under /tmp/ecd-demo-fluid:
    python3 scripts/record_demo.py --mode install
Use the same URL/project/output/work-dir arguments if overriding the defaults.

Safety: password is read from env (BASIC_AUTH_PASSWORD or the local env file);
it is never stored or printed. Never start a CashFusion round. After showing the
manual-first defaults, briefly LEFT-click the icon to show green Auto-Fuse on
the verified empty wallet. Disable it again outside the recording, even on error.
Only verified status/settings controls
are clicked. This tool never sends/signs/broadcasts transactions or opens keys,
seeds, or transaction controls. It never starts or changes Docker deployments.
Intermediate video, palette, validation frames, and backup stay under /tmp.
Record mode produces a candidate only; inspect its PNGs, then --mode install
validates the media and installs it. Existing output is backed up before recording.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from functools import lru_cache
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.parse import urlsplit

DEFAULT_ENV = Path('/home/ubuntu/.local/state/electron-cash-docker/'
                   'demo-ecd-demo-20260923T054928Z/demo.env')
WIDTH, HEIGHT = 1280, 800

OVERLAY = r"""
(() => {
  function install() {
    if (!document.body || document.getElementById('demo-chrome')) return;
    const style = document.createElement('style');
    style.textContent = `
      #demo-chrome {position:fixed;top:0;left:0;right:0;height:40px;
        z-index:2147483645;background:#e9edf2;border-bottom:1px solid #bec7d1;
        display:flex;align-items:center;gap:14px;padding:0 18px;
        font:14px Arial;color:#253443;pointer-events:none;box-sizing:border-box}
      #demo-address {background:white;border:1px solid #ccd3db;border-radius:14px;
        padding:5px 18px;min-width:460px}
      #demo-pointer {position:fixed;left:70px;top:80px;width:24px;height:30px;
        z-index:2147483647;pointer-events:none;filter:drop-shadow(1px 2px 2px #0008)}
      .demo-ripple {position:fixed;width:22px;height:22px;border:3px solid #e7a400;
        border-radius:50%;z-index:2147483646;pointer-events:none;
        transform:translate(-50%,-50%);animation:demo-click .6s ease-out forwards}
      @keyframes demo-click {to {transform:translate(-50%,-50%) scale(3);opacity:0}}
      body {box-sizing:border-box;padding-top:40px !important}
      #noVNC_container {top:40px !important;height:calc(100% - 40px) !important}
    `;
    document.head.appendChild(style);
    const bar = document.createElement('div');bar.id='demo-chrome';
    bar.innerHTML='<span style="color:#16784b">🔒 HTTPS</span><span id="demo-address"></span>';
    document.body.appendChild(bar);
    document.getElementById('demo-address').textContent=location.origin;
    const pointer=document.createElement('div');pointer.id='demo-pointer';
    pointer.innerHTML='<svg width="24" height="30" viewBox="0 0 24 30">'+
      '<path d="M2 2 L2 23 L8 18 L13 28 L18 25 L13 16 L22 16 Z" '+
      'fill="white" stroke="#182333" stroke-width="1.6"/></svg>';
    document.body.appendChild(pointer);
    window.demoPosition={x:70,y:80};
    window.demoMove=(x,y)=>{window.demoPosition={x,y};pointer.style.left=x+'px';pointer.style.top=y+'px'};
    window.demoClick=(x,y)=>{const r=document.createElement('div');r.className='demo-ripple';
      r.style.left=x+'px';r.style.top=y+'px';document.body.appendChild(r);setTimeout(()=>r.remove(),650)};
  }
  document.addEventListener('DOMContentLoaded',install);install();
})();
"""


def password_from_env(path):
    password = os.environ.get('BASIC_AUTH_PASSWORD')
    if password is None:
        for line in path.read_text().splitlines():
            key, sep, value = line.strip().removeprefix('export ').partition('=')
            if sep and key.strip() == 'BASIC_AUTH_PASSWORD':
                password = value.strip()
                if len(password) > 1 and password[0] == password[-1] and password[0] in "\"'":
                    password = password[1:-1]
                break
    if not password:
        raise RuntimeError('BASIC_AUTH_PASSWORD is missing or empty')
    return password


@lru_cache(maxsize=1)
def ffmpeg_path():
    system = shutil.which('ffmpeg')
    if system:
        return system
    for path in sorted((Path.home() / '.cache/ms-playwright').glob('**/ffmpeg*')):
        if path.is_file() and os.access(path, os.X_OK):
            filters = subprocess.check_output([str(path), '-hide_banner', '-filters'],
                                              text=True, stderr=subprocess.DEVNULL)
            if 'palettegen' in filters and 'paletteuse' in filters:
                return str(path)
            # Playwright's minimal build can record VP8 but often cannot encode GIF.
    try:
        from imageio_ffmpeg import get_ffmpeg_exe
        return get_ffmpeg_exe()
    except ImportError:
        pass
    raise RuntimeError('Install Playwright bundled ffmpeg before recording')


def ffmpeg(*args):
    subprocess.run([ffmpeg_path(), '-hide_banner', '-loglevel', 'error', '-y', *map(str, args)], check=True)


def runtime(args):
    """Read only allowlisted runtime fields, never the container's secret env."""
    ids = subprocess.check_output(['docker', 'ps', '--filter',
        f'label=com.docker.compose.project={args.project_name}', '--filter',
        'label=com.docker.compose.service=electron-cash', '--format', '{{.ID}}'], text=True).split()
    if len(ids) != 1:
        raise RuntimeError('Expected exactly one running dedicated Electron Cash container')
    fields = ['NETWORK', 'CASHFUSION_ENABLED', 'CASHFUSION_AUTO_FUSE', 'CASHFUSION_SELECTOR_COUNT']
    values = subprocess.check_output(['docker', 'exec', ids[0], 'printenv', *fields], text=True).splitlines()
    result = dict(zip(fields, values))
    if result != dict(zip(fields, ['mainnet', 'true', 'false', '10'])):
        raise RuntimeError(f'Demo runtime does not match safe mainnet defaults: {result}')
    return result


def verify_empty_wallet(args):
    """Read only balances/history, never serialize seed or keystore information."""
    code = '''
import json
from electroncash.storage import WalletStorage
from electroncash.wallet import Wallet
path = '/home/electroncash/.electron-cash/wallets/default_wallet'
wallet = Wallet(WalletStorage(path))
balance = list(wallet.get_balance())
coins = len(wallet.get_utxos())
history = sum(bool(v) for v in wallet.storage.get('addr_history', {}).values())
transactions = len(wallet.storage.get('transactions', {}))
assert not any(balance) and not coins and not history and not transactions
print(json.dumps({'balance_satoshis': balance, 'utxos': coins, 'transactions': transactions}))
'''
    result = subprocess.check_output(['docker','exec',
        args.project_name+'-electron-cash-1','/opt/electroncash-venv/bin/python',
        '-c',code],text=True,stderr=subprocess.DEVNULL)
    return json.loads(result.strip().splitlines()[-1])


def move_mouse(page, x, y, seconds=.8):
    start = page.evaluate('window.demoPosition')
    for i in range(1, 33):
        t = i / 32
        t = t*t*(3-2*t)
        px, py = start['x']+(x-start['x'])*t, start['y']+(y-start['y'])*t
        page.mouse.move(px, py)
        page.evaluate('p=>window.demoMove(p.x,p.y)', {'x':px, 'y':py})
        page.wait_for_timeout(seconds*1000/32)


def click_mouse(page, x, y, button='left'):
    move_mouse(page, x, y)
    page.wait_for_timeout(180)
    page.evaluate('p=>window.demoClick(p.x,p.y)', {'x':x, 'y':y})
    page.mouse.down(button=button)
    page.wait_for_timeout(100)
    page.mouse.up(button=button)
    page.wait_for_timeout(650)


class VerifiedUI:
    """OCR guards canvas controls; unknown UI fails closed before clicking."""
    def __init__(self, page, args):
        from rapidocr_onnxruntime import RapidOCR
        self.ocr = RapidOCR(intra_op_num_threads=2, inter_op_num_threads=2)
        self.page, self.args = page, args
        self.events = []
        self.started = time.monotonic()

    def read(self):
        import numpy as np
        from PIL import Image
        from io import BytesIO
        raw = self.page.screenshot(style='#demo-pointer,.demo-ripple {visibility:hidden!important}')
        image = Image.open(BytesIO(raw)).convert('RGB').resize((WIDTH*2, HEIGHT*2))
        result, _ = self.ocr(np.asarray(image))
        return [(text, [(float(x)/2, float(y)/2) for x,y in box]) for box,text,_ in (result or [])]

    def require(self, text, rows=None):
        rows = rows if rows is not None else self.read()
        normalize = lambda s: re.sub(r'[^a-z0-9]', '', s.casefold())
        found = [(label, box) for label,box in rows if normalize(text) in normalize(label)]
        exact = [(label, box) for label,box in found if normalize(text) == normalize(label)]
        if exact:
            found = exact
        if len(found) != 1:
            raise AssertionError(f'Expected one visible {text!r}, found {len(found)}: {[t for t,_ in rows]}')
        return found[0][1]

    def click_label(self, text, rows=None):
        box = self.require(text, rows)
        click_mouse(self.page, sum(x for x,_ in box)/4, sum(y for _,y in box)/4)

    def stage(self, name, required=()):
        self.page.screenshot(path=str(self.args.work_dir / (name+'.png')))
        rows = self.read()
        for text in required:
            if not any(re.sub(r'[^a-z0-9]', '', text.casefold()) in
                       re.sub(r'[^a-z0-9]', '', label.casefold()) for label,_ in rows):
                raise AssertionError(f'Missing visible {text!r}: {[t for t,_ in rows]}')
        self.events.append({'stage':name, 'seconds':round(time.monotonic()-self.started,3),
                            'visible_text':[t for t,_ in rows]})
        return rows

    def icon(self, native_x, native_y):
        canvas = self.page.locator('canvas').first
        dimensions = canvas.evaluate('(c)=>({w:c.width,h:c.height})')
        if dimensions != {'w':1600, 'h':900}:
            raise AssertionError('Unknown remote desktop dimensions; refusing icon click')
        box = canvas.bounding_box()
        return box['x']+native_x*box['width']/1600, box['y']+native_y*box['height']/900


def metadata(path):
    from PIL import Image
    with Image.open(path) as image:
        size, count = image.size, image.n_frames
        durations = []
        for i in range(count):
            image.seek(i)
            durations.append(image.info.get('duration',0))
    seconds = sum(durations)/1000
    return {'resolution':list(size), 'frames':count, 'duration':seconds,
            'effective_fps':round(count/seconds,3), 'bytes':path.stat().st_size}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def close_known_dialogs(ui):
    """Restore only verified status/settings windows before recording starts."""
    for _ in range(4):
        rows = ui.read()
        if any('automatichighdpi' in re.sub(r'[^a-z0-9]','',t.casefold()) for t,_ in rows):
            ui.click_label('OK',rows)
        elif any('Auto-Fuse' in t for t,_ in rows):
            ui.page.keyboard.press('Escape')
            ui.page.wait_for_timeout(600)
        elif any('Fusion mode' in t or t == 'Network' for t,_ in rows):
            ui.click_label('Close',rows)
        else:
            return
    raise AssertionError('Could not restore main wallet from known dialogs')


def record(args):
    from playwright.sync_api import sync_playwright
    verified_runtime = runtime(args)
    empty_wallet = verify_empty_wallet(args)
    password = password_from_env(args.env_file)
    if args.output.exists():
        backup = args.work_dir/('before-'+sha256(args.output)[:12]+'.gif')
        if not backup.exists():
            shutil.copy2(args.output, backup)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        # Establish a clean main-wallet starting state outside the final recording.
        setup = browser.new_context(viewport={'width':WIDTH,'height':HEIGHT})
        setup.add_init_script(OVERLAY)
        setup_page = setup.new_page()
        setup_page.goto(args.url,wait_until='networkidle')
        setup_page.locator('input[type=password]').fill(password)
        setup_page.get_by_role('button',name='Connect',exact=True).click()
        setup_page.wait_for_url('**/vnc.html**')
        setup_page.goto(args.url.rstrip('/')+'/vnc.html?autoconnect=true&resize=scale')
        setup_page.locator('canvas').first.wait_for(state='visible')
        setup_page.wait_for_timeout(3000)
        close_known_dialogs(VerifiedUI(setup_page,args))
        setup.close()
        context = browser.new_context(viewport={'width':WIDTH,'height':HEIGHT},
            record_video_dir=str(args.work_dir/'video'),
            record_video_size={'width':WIDTH,'height':HEIGHT})
        context.add_init_script(OVERLAY)
        recorded_started = time.monotonic()
        page = context.new_page()
        video = page.video
        active_attempted = False
        try:
            page.goto(args.url, wait_until='networkidle')
            if 'Electron Cash Docker · v0.4' not in page.locator('body').inner_text():
                raise AssertionError('Expected real v0.4 login')
            ui = VerifiedUI(page,args)
            ui.started = recorded_started
            ui.stage('01-login', ['Electron Cash Docker', 'v0.4'])
            page.wait_for_timeout(2000)
            field = page.locator('input[type=password]')
            box = field.bounding_box()
            assert box is not None
            click_mouse(page, box['x']+box['width']/2,box['y']+box['height']/2)
            for index, char in enumerate(password):
                page.keyboard.type(char, delay=125)
                if index in (1,7):
                    ui.events.append({'stage':f'02-typing-{index}',
                                      'seconds':time.monotonic()-recorded_started})
            del password
            page.wait_for_timeout(500)
            page.screenshot(path=str(args.work_dir/'02-password.png'))
            control = page.get_by_role('button',name='Connect',exact=True)
            box = control.bounding_box()
            assert box is not None
            ui.events.append({'stage':'02-connect','seconds':time.monotonic()-recorded_started+1})
            click_mouse(page,box['x']+box['width']/2,box['y']+box['height']/2)
            page.wait_for_url('**/vnc.html**')
            page.goto(args.url.rstrip('/')+'/vnc.html?autoconnect=true&reconnect=true&resize=scale',
                      wait_until='domcontentloaded')
            page.locator('canvas').first.wait_for(state='visible')
            page.wait_for_timeout(5000)
            ui.stage('03-wallet',['CashTokens','History','Balance'])
            page.wait_for_timeout(1500)
            # Hover verifies the actual network status icon before opening it.
            x,y = ui.icon(1585,881)
            move_mouse(page,x,y)
            page.wait_for_timeout(1600)
            ui.stage('04-connected',['Network Status','via proxy'])
            click_mouse(page,x,y)
            rows = ui.stage('05-network',['Network','Proxy'])
            ui.click_label('Proxy',rows)
            ui.stage('06-tor',['Use proxy','SOCKS5','tor-proxy','9050'])
            page.wait_for_timeout(2500)
            ui.click_label('Close')
            ui.stage('07-main',['CashTokens','History','Balance'])
            # Right-click first to show the unchanged manual-first defaults.
            x,y = ui.icon(1462,881)
            move_mouse(page,x,y)
            page.wait_for_timeout(1700)
            ui.stage('08-fusion-hover',['CashFusion'])
            click_mouse(page,x,y,button='right')
            rows = ui.stage('09-fusion-click-menu',['Auto-Fuse in Background','Wallet Fusion Settings'])
            # Verify the REAL menu checkbox is empty, in addition to runtime env.
            # Checkbox position is relative to its OCR-verified label, never clicked.
            from PIL import Image
            box = ui.require('Auto-Fuse in Background', rows)
            label_x = min(x for x,_ in box)
            label_y = sum(y for _,y in box)/4
            with Image.open(args.work_dir/'09-fusion-click-menu.png') as menu:
                check = menu.convert('L').crop((round(label_x-14),round(label_y-3),
                                               round(label_x-8),round(label_y+3)))
                if check.getextrema()[0] < 180:
                    raise AssertionError('Auto-Fuse checkbox is not visibly unchecked')
            page.wait_for_timeout(2000)
            ui.click_label('Wallet Fusion Settings',rows)
            rows = ui.stage('10-fusion-settings',['CashFusion',
                'Custom','Target number of coins in wallet','10','Number of queued fusions'])
            target_box = ui.require('Target number of coins in wallet',rows)
            count_box = ui.require('10',rows)
            if abs(sum(y for _,y in target_box)/4-sum(y for _,y in count_box)/4) > 8:
                raise AssertionError('Visible 10 is not aligned with the target-count control')
            # No settings are edited. Move away so the configuration remains unobscured.
            move_mouse(page,980,620)
            page.screenshot(path=str(args.work_dir/'11-final.png'))
            ui.events.append({'stage':'11-final','seconds':time.monotonic()-recorded_started,
                              'visible_text':[t for t,_ in rows]})
            page.wait_for_timeout(3000)
            ui.click_label('Close')
            verify_empty_wallet(args)
            x,y = ui.icon(1462,881)
            move_mouse(page,x,y)
            page.wait_for_timeout(1300)
            ui.stage('12-before-activation',['Auto-fusion','Disabled'])
            # Only the verified empty disposable wallet may enable Auto-Fuse.
            active_attempted = True
            click_mouse(page,x,y)
            # Qt status tips refresh on re-entry, not merely on a changed icon.
            move_mouse(page,x-45,y-55)
            move_mouse(page,x,y)
            page.wait_for_timeout(1500)
            ui.stage('13-autofuse-active',['CashFusion','Enabled'])
            move_mouse(page,x-45,y-55)
            page.wait_for_timeout(600)
            page.screenshot(path=str(args.work_dir/'14-green-icon.png'))
            with Image.open(args.work_dir/'14-green-icon.png') as active_image:
                icon = active_image.convert('RGB').crop((round(x-11),round(y-11),round(x+11),round(y+11)))
                pixels = icon.load()
                green_pixels = sum(g > r+18 and g > b+8 and g > 100
                    for r,g,b in (pixels[i,j] for i in range(icon.width) for j in range(icon.height)))
                if green_pixels < 12:
                    raise AssertionError('CashFusion icon is not visibly green')
            # Leave the real green icon unobscured by both pointer and tooltip.
            ui.stage('15-final-active',['CashTokens','History','Balance'])
            verify_empty_wallet(args)
            final_started = time.monotonic()
            page.wait_for_timeout(args.final_hold*1000)
            final_elapsed = time.monotonic()-final_started
        finally:
            context.close()
            if video is not None:
                video.save_as(str(args.work_dir/'recording.webm'))
            # Cleanup is outside the video; always restore Auto-Fuse disabled.
            if active_attempted:
                cleanup = browser.new_context(viewport={'width':WIDTH,'height':HEIGHT})
                cleanup.add_init_script(OVERLAY)
                p = cleanup.new_page()
                p.goto(args.url,wait_until='networkidle')
                p.locator('input[type=password]').fill(password_from_env(args.env_file))
                p.get_by_role('button',name='Connect',exact=True).click()
                p.wait_for_url('**/vnc.html**')
                p.goto(args.url.rstrip('/')+'/vnc.html?autoconnect=true&resize=scale')
                p.locator('canvas').first.wait_for(state='visible')
                p.wait_for_timeout(3000)
                cleanup_ui = VerifiedUI(p,args)
                x,y = cleanup_ui.icon(1462,881)
                move_mouse(p,x,y)
                p.wait_for_timeout(1400)
                rows = cleanup_ui.read()
                if any('autofusion' in re.sub(r'[^a-z0-9]','',t.casefold())
                       and 'enabled' in t.casefold() for t,_ in rows):
                    click_mouse(p,x,y)
                    move_mouse(p,x-45,y-55)
                    move_mouse(p,x,y)
                    p.wait_for_timeout(1300)
                cleanup_ui.stage('cleanup-autofuse-off',['Auto-fusion','Disabled'])
                verify_empty_wallet(args)
                cleanup.close()
            browser.close()
        assert video is not None
    runtime(args)
    webm, candidate = args.work_dir/'recording.webm',args.work_dir/'candidate.gif'
    palette = args.work_dir/'palette.png'
    # Two-pass palette conversion retains every 12 fps sample, including pointer travel.
    filters = f'fps={args.fps},scale={WIDTH}:-2:flags=lanczos'
    ffmpeg('-i',webm,'-vf',filters+',palettegen=stats_mode=full','-frames:v','1',palette)
    ffmpeg('-i',webm,'-i',palette,'-lavfi',filters+'[v];[v][1:v]paletteuse=dither=bayer:bayer_scale=3',
           '-loop','0',candidate)
    media = metadata(candidate)
    if media['effective_fps'] < args.fps*.95 or media['frames'] < 200:
        raise AssertionError('Candidate is not a dense continuous recording')
    # Extract representative frames from encoded GIF, not just browser screenshots.
    for event in ui.events:
        ffmpeg('-i',candidate,'-ss',event['seconds'],'-frames:v','1',
               args.work_dir/('encoded-'+event['stage']+'.png'))
    report = {'url':args.url,'project':args.project_name,'runtime':verified_runtime,
        'events':ui.events,'final_hold':final_elapsed,'media':media,
        'empty_wallet':empty_wallet,'autofuse_green_verified':True,'autofuse_restored_off':True,
        'sha256':sha256(candidate),'no_fusion_or_transaction_actions':True,
        'output_before':sha256(args.output) if args.output.exists() else None}
    (args.work_dir/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(media))
    print(f'Candidate ready: {candidate}. Inspect encoded-*.png and 09-fusion-click-menu.png; '
          'then run the same arguments with --mode install.')


def install(args):
    report = json.loads((args.work_dir/'validation.json').read_text())
    candidate = args.work_dir/'candidate.gif'
    if sha256(candidate) != report['sha256']:
        raise AssertionError('Candidate differs from validated recording')
    if report['project'] != args.project_name or report['url'] != args.url:
        raise AssertionError('Candidate was recorded against another demo')
    if args.output.exists() and sha256(args.output) != report['output_before']:
        raise AssertionError('Output changed after recording; refusing to overwrite')
    runtime(args)
    shutil.copy2(candidate,args.output)
    print(json.dumps({'installed':str(args.output),**metadata(args.output)}))


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or '').split('\n')[0],
        epilog=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--mode',choices=['record','install'],required=True,
                        help='record candidate; install only after visual validation')
    parser.add_argument('--url',default='https://ecd-demo.bchforge.org/',help='HTTPS demo URL')
    parser.add_argument('--env-file',type=Path,default=DEFAULT_ENV,
                        help='local password env file; BASIC_AUTH_PASSWORD environment takes precedence')
    parser.add_argument('--project-name',default='ecd-demo-20260923t054928z',help='dedicated running Compose project')
    parser.add_argument('--output',type=Path,default=Path('docs/assets/electron-cash-docker-demo.gif'),help='final GIF destination')
    parser.add_argument('--fps',type=int,default=12,help='continuous GIF cadence (10–15 fps)')
    parser.add_argument('--final-hold',type=float,default=7,help='final green Auto-Fuse status hold, in seconds (5–10)')
    parser.add_argument('--work-dir',type=Path,default=Path('/tmp/ecd-demo-fluid'),help='intermediate media directory under /tmp')
    args = parser.parse_args()
    if not 10 <= args.fps <= 15 or not 5 <= args.final_hold <= 10:
        parser.error('Use 10–15 fps and a 5–10 second final hold')
    if urlsplit(args.url).scheme != 'https' or urlsplit(args.url).username:
        parser.error('Use an HTTPS URL without embedded credentials')
    if not args.work_dir.resolve().is_relative_to(Path('/tmp')):
        parser.error('--work-dir must stay under /tmp')
    args.work_dir.mkdir(parents=True,exist_ok=True)
    record(args) if args.mode == 'record' else install(args)


if __name__ == '__main__':
    main()

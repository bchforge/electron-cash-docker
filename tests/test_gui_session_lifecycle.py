#!/usr/bin/env python3
"""Real Qt Quit/WM close, browser terminal semantics and owned stack lifecycle."""
import ctypes
import base64
from contextlib import contextmanager
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from playwright.sync_api import sync_playwright

from test_support import unique_project, electron_cash_image, tor_image
from test_canonical_startup import free_port, wait_running, wait_healthy, inspect

ROOT = Path(__file__).resolve().parents[1]
X11 = r'''
import ctypes as c,json,sys
X=c.CDLL('libX11.so.6');X.XOpenDisplay.argtypes=[c.c_char_p];X.XOpenDisplay.restype=c.c_void_p
d=X.XOpenDisplay(b':99');assert d
class Error(c.Structure):_fields_=[('type',c.c_int),('display',c.c_void_p),('resource',c.c_ulong),('serial',c.c_ulong),('code',c.c_ubyte),('request',c.c_ubyte),('minor',c.c_ubyte)]
bad_windows=set();errors=[];command_phase=False
@c.CFUNCTYPE(c.c_int,c.c_void_p,c.POINTER(Error))
def error_handler(display,event):
 e=event.contents
 if e.code==3 and not command_phase:bad_windows.add(e.resource)
 else:errors.append((e.code,e.request,e.resource))
 return 0
X.XSetErrorHandler.argtypes=[type(error_handler)];X.XSetErrorHandler(error_handler)
X.XSync.argtypes=[c.c_void_p,c.c_int]
X.XDefaultRootWindow.argtypes=[c.c_void_p];X.XDefaultRootWindow.restype=c.c_ulong
X.XQueryTree.argtypes=[c.c_void_p,c.c_ulong,c.POINTER(c.c_ulong),c.POINTER(c.c_ulong),c.POINTER(c.POINTER(c.c_ulong)),c.POINTER(c.c_uint)]
X.XFetchName.argtypes=[c.c_void_p,c.c_ulong,c.POINTER(c.c_char_p)];X.XFree.argtypes=[c.c_void_p]
X.XInternAtom.argtypes=[c.c_void_p,c.c_char_p,c.c_int];X.XInternAtom.restype=c.c_ulong
X.XFlush.argtypes=[c.c_void_p];X.XCloseDisplay.argtypes=[c.c_void_p]
class A(c.Structure):
 _fields_=[('x',c.c_int),('y',c.c_int),('width',c.c_int),('height',c.c_int),('border',c.c_int),('depth',c.c_int),('visual',c.c_void_p),('root',c.c_ulong),('klass',c.c_int),('bit_gravity',c.c_int),('win_gravity',c.c_int),('backing_store',c.c_int),('backing_planes',c.c_ulong),('backing_pixel',c.c_ulong),('save_under',c.c_int),('colormap',c.c_ulong),('map_installed',c.c_int),('map_state',c.c_int),('all_event_masks',c.c_long),('your_event_mask',c.c_long),('do_not_propagate_mask',c.c_long),('override_redirect',c.c_int),('screen',c.c_void_p)]
X.XGetWindowAttributes.argtypes=[c.c_void_p,c.c_ulong,c.POINTER(A)]
X.XTranslateCoordinates.argtypes=[c.c_void_p,c.c_ulong,c.c_ulong,c.c_int,c.c_int,c.POINTER(c.c_int),c.POINTER(c.c_int),c.POINTER(c.c_ulong)]
X.XGetWindowProperty.argtypes=[c.c_void_p,c.c_ulong,c.c_ulong,c.c_long,c.c_long,c.c_int,c.c_ulong,c.POINTER(c.c_ulong),c.POINTER(c.c_int),c.POINTER(c.c_ulong),c.POINTER(c.c_ulong),c.POINTER(c.POINTER(c.c_ubyte))]
def wm_state(w):
 atom=c.c_ulong();fmt=c.c_int();num=c.c_ulong();after=c.c_ulong();data=c.POINTER(c.c_ubyte)()
 X.XGetWindowProperty(d,w,X.XInternAtom(d,b'WM_STATE',0),0,2,0,0,c.byref(atom),c.byref(fmt),c.byref(num),c.byref(after),c.byref(data))
 state=int(c.cast(data,c.POINTER(c.c_long))[0]) if num.value else None
 if data:X.XFree(data)
 return state
ws=[]
def visit(w,n=0):
 p=c.c_char_p()
 if X.XFetchName(d,w,c.byref(p)):
  a=A();xx=c.c_int();yy=c.c_int();child=c.c_ulong()
  X.XGetWindowAttributes(d,w,c.byref(a));X.XTranslateCoordinates(d,w,X.XDefaultRootWindow(d),0,0,c.byref(xx),c.byref(yy),c.byref(child))
  state=wm_state(w);X.XSync(d,0)
  if w not in bad_windows:ws.append({'id':w,'name':(p.value or b'').decode(errors='replace'),'x':xx.value,'y':yy.value,'width':a.width,'height':a.height,'mapped':a.map_state==2,'wm_state':state,'override_redirect':bool(a.override_redirect)})
  X.XFree(p)
 if n>5:return
 r=c.c_ulong();a=c.c_ulong();cs=c.POINTER(c.c_ulong)();num=c.c_uint()
 if X.XQueryTree(d,w,c.byref(r),c.byref(a),c.byref(cs),c.byref(num)):
  ids=[cs[i] for i in range(num.value)]
  if cs:X.XFree(cs)
  for i in ids:visit(i,n+1)
visit(X.XDefaultRootWindow(d))
if len(sys.argv)>1:
 command_phase=True
 class D(c.Union):_fields_=[('b',c.c_char*20),('s',c.c_short*10),('l',c.c_long*5)]
 class M(c.Structure):_fields_=[('type',c.c_int),('serial',c.c_ulong),('send_event',c.c_int),('display',c.c_void_p),('window',c.c_ulong),('message_type',c.c_ulong),('format',c.c_int),('data',D)]
 class E(c.Union):_fields_=[('m',M),('pad',c.c_long*24)]
 e=E();e.m.type=33;e.m.display=d;e.m.window=int(sys.argv[1]);e.m.message_type=X.XInternAtom(d,b'WM_PROTOCOLS',0);e.m.format=32;e.m.data.l[0]=X.XInternAtom(d,b'WM_DELETE_WINDOW',0)
 X.XSendEvent.argtypes=[c.c_void_p,c.c_ulong,c.c_int,c.c_long,c.POINTER(E)]
 action=sys.argv[2] if len(sys.argv)>2 else 'close'
 if action=='activate':
  X.XMapRaised.argtypes=[c.c_void_p,c.c_ulong];X.XMapRaised(d,e.m.window)
  e.m.message_type=X.XInternAtom(d,b'_NET_ACTIVE_WINDOW',0);e.m.data.l[0]=2;e.m.data.l[1]=0
  assert X.XSendEvent(d,X.XDefaultRootWindow(d),0,(1<<19)|(1<<20),c.byref(e))
 elif action=='minimize':
  X.XIconifyWindow.argtypes=[c.c_void_p,c.c_ulong,c.c_int];assert X.XIconifyWindow(d,e.m.window,0)
 else:assert X.XSendEvent(d,e.m.window,0,0,c.byref(e))
 X.XFlush(d);X.XSync(d,0)
assert not errors,errors
print(json.dumps(ws));X.XCloseDisplay(d)
'''


def checked(command, env, timeout=120):
    p = subprocess.run(command, cwd=ROOT, env=env, text=True, errors='replace', capture_output=True, timeout=timeout)
    if p.returncode:
        text = (p.stdout + p.stderr).replace(env.get('BASIC_AUTH_PASSWORD', 'not-a-secret'), '[REDACTED]')
        raise AssertionError((command, text[-5000:]))
    return p.stdout


def windows(wallet, env, target=None, action='close'):
    return json.loads(checked(['docker', 'exec', '--user', '10001:10001', wallet,
        '/opt/electroncash-venv/bin/python', '-c', X11, *([] if target is None else [str(target),action])], env, 15))


def connect(page, url, env, remember=False):
    page.set_default_timeout(15000)
    page.goto(url, timeout=20000)
    page.locator('input[name=password]').fill(env['BASIC_AUTH_PASSWORD'])
    if remember:page.locator('input[name=remember]').check()
    page.locator('button[type=submit]').click()
    page.wait_for_url('**/vnc.html**', timeout=20000)
    page.evaluate("async () => {window.ecdTestUI=(await import('/app/ui.js')).default}")
    page.wait_for_function("window.ecdTestUI.rfb && window.ecdTestUI.rfb._rfbConnectionState==='connected'", timeout=30000)


def main_window(page, wallet, env, output, label):
    names = []
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        names = windows(wallet, env)
        modal = next((w for w in names if 'High DPI' in w['name']), None)
        if modal:
            page.screenshot(path=str(output/(label+'-modal.png')), timeout=10000)
            page.locator('#noVNC_container canvas').click(position={'x':640, 'y':450})
            page.keyboard.press('Enter')
            page.wait_for_timeout(500)
            continue
        window = next((w for w in names if 'Electron Cash' in w['name'] and 'default_wallet' in w['name']), None)
        if window:
            return window
        page.wait_for_timeout(250)
    page.screenshot(path=str(output/(label+'-blocked.png')), timeout=10000)
    raise AssertionError(('no interactive wallet main window', names))


def process_snapshot(identifiers, env):
    result = {}
    for service, identifier in identifiers.items():
        lines = checked(['docker','top',identifier,'-eo','pid,ppid,comm'],env,15).splitlines()[1:]
        for line in lines:
            pid, parent, command = line.split(None,2)
            try:
                start = Path('/proc/'+pid+'/stat').read_text().split()[21]
            except FileNotFoundError:
                continue
            result[pid] = {'service':service,'parent':parent,'command':command,'start':start}
    return result


def assert_no_processes(before):
    for pid, item in before.items():
        path = Path('/proc/'+pid+'/stat')
        try:
            fields = path.read_text().split()
        except FileNotFoundError:
            continue
        assert fields[21] != item['start'], ('GUI process or zombie survived', pid, item['command'])


def states(ids):
    return {s: {'state':inspect(i)['State']['Status'], 'exit_code':inspect(i)['State']['ExitCode'],
                'restart_count':inspect(i)['RestartCount']} for s,i in ids.items()}


def persistent_identity(wallet, env):
    code = """import hashlib,json
from pathlib import Path
root=Path('/home/electroncash/.electron-cash/chipnet')
wallet=json.loads((root/'wallets/default_wallet').read_text())
config=json.loads((root/'config').read_text())
identity={k:wallet[k] for k in ('keystore','wallet_type')}
print(json.dumps({'wallet_identity_sha256':hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest(),
 'configuration_probe':config['gui_lifecycle_persistence_probe']}))
"""
    return json.loads(checked(['docker','exec','--user','10001:10001',wallet,
        '/opt/electroncash-venv/bin/python','-c',code],env))


@contextmanager
def independent_workloads(output):
    stacks = []
    try:
        for rpc in (False, True):
            project = unique_project('gui-independent-' + ('rpc' if rpc else 'headless'))
            env = dict(os.environ, ELECTRON_CASH_IMAGE=electron_cash_image(), TOR_IMAGE=tor_image(),
                BASIC_AUTH_PASSWORD='independent-disposable', NETWORK='chipnet', USE_TOR='false',
                ECD_WALLET_VOLUME=project+'-wallet', ECD_TOR_VOLUME=project+'-tor',
                JSONRPC_ENABLED=str(rpc).lower(), JSONRPC_USER='lifecycle',
                JSONRPC_PASSWORD='independent-rpc-disposable', JSONRPC_HOST_PORT=str(free_port()))
            command = ['docker','compose','--env-file','.env.example','-p',project,
                '-f','docker-compose.yml','-f','docker-compose.headless.yml']
            if rpc: command += ['-f','docker-compose.rpc.yml']
            stacks.append((command,env,{},rpc))
            checked(command+['up','-d','--wait','--no-build','--pull','never'],env,180)
            ids = {s:wait_running(command,s,env=env,cwd=ROOT) for s in ('electron-cash','tor-proxy')}
            stacks[-1] = (command,env,ids,rpc)
        initial = [{s: (inspect(i)['State']['StartedAt'],inspect(i)['RestartCount']) for s,i in ids.items()}
                   for _,_,ids,_ in stacks]
        def verify():
            for index, (_,env,ids,rpc) in enumerate(stacks):
                for s,i in ids.items():
                    info = inspect(i)
                    assert info['State']['Running'] and info['State']['Health']['Status']=='healthy'
                    assert (info['State']['StartedAt'],info['RestartCount']) == initial[index][s]
                if rpc:
                    auth = base64.b64encode(b'lifecycle:independent-rpc-disposable').decode()
                    request = Request('http://127.0.0.1:'+env['JSONRPC_HOST_PORT']+'/',
                        data=b'{"method":"ping","params":[],"id":1}',
                        headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
                    with urlopen(request,timeout=5) as response:
                        assert json.loads(response.read())['result'] is True
        verify()
        yield verify
        verify()
        (output/'independent-workloads.json').write_text(json.dumps({
            'concurrent_headless_and_rpc':'PASS','unchanged_start_times_and_restart_counts':initial,
            'rpc_authenticated_ping_after_both_gui_exits':'PASS',
            'rpc_authenticated_ping_after_all_registered_gui_cases':'PASS'},indent=2)+'\n')
    finally:
        for command,env,_,_ in reversed(stacks):
            checked(command+['down','--volumes','--remove-orphans'],env,180)


def run_case(action, browser, output, verify_independent):
    project = unique_project('gui-lifecycle-'+action)
    env = dict(os.environ, ELECTRON_CASH_IMAGE=electron_cash_image(), TOR_IMAGE=tor_image(),
        BASIC_AUTH_PASSWORD='gui-lifecycle-disposable', NETWORK='chipnet', USE_TOR='false', EC_LANGUAGE='en_US',
        WALLET_AUTO_CREATE='true', TEST_WALLET_PASSWORD='', ECD_WALLET_VOLUME=project+'-wallet',
        ECD_TOR_VOLUME=project+'-tor', CADDY_HTTP_HOST_PORT=str(free_port()), CADDY_HTTPS_HOST_PORT=str(free_port()),
        CADDY_SITE_ADDRESS='http://localhost', CADDY_EDGE_BIND='127.0.0.1')
    command = ['docker','compose','--env-file','.env.example','-p',project,'-f','docker-compose.yml']
    page = browser.new_page();events=[]
    ids = {}
    page.on('websocket', lambda socket: events.append({'url':socket.url,'at':time.monotonic()}))
    url = 'http://127.0.0.1:'+env['CADDY_HTTP_HOST_PORT']
    try:
        model = json.loads(checked(command+['config','--format','json'], env))
        checked(command+['up','-d','--no-build','--pull','never'], env, 180)
        ids = {s:wait_running(command,s,env=env,cwd=ROOT) for s in model['services']}
        for s,i in ids.items():wait_healthy(i,s)
        for s,i in ids.items():
            expected = model['services'][s]['image']
            assert inspect(i)['Image'] == checked(['docker','image','inspect','--format','{{.Id}}',expected],env).strip()
        wallet = ids['electron-cash']
        # Load a harmless persisted preference into the real Qt process, so
        # deployment-written defaults cannot mask loss of saved configuration.
        checked(command+['stop','electron-cash'],env,120)
        assert all(inspect(i)['State']['Running'] for s,i in ids.items() if s!='electron-cash')
        probe = "import json; from pathlib import Path; p=Path('/home/electroncash/.electron-cash/chipnet/config'); c=json.loads(p.read_text()); c['gui_lifecycle_persistence_probe']='"+project+"'; p.write_text(json.dumps(c))"
        checked(command+['run','--rm','--no-deps','--user','10001:10001','--entrypoint',
            '/opt/electroncash-venv/bin/python','electron-cash','-c',probe],env,60)
        checked(command+['start','electron-cash'],env,120)
        wait_healthy(wallet,'electron-cash')
        persisted_before = persistent_identity(wallet,env)
        connect(page,url,env)
        window = main_window(page,wallet,env,output,action)
        unauthenticated = browser.new_context()
        try:
            assert unauthenticated.request.get(url+'/auth/gui-session').status == 401
        finally: unauthenticated.close()
        status=page.request.get(url+'/auth/gui-session').json()
        assert status['state']=='active' and len(status['generation'])==32 and status['ready'] is True
        assert page.request.post(url+'/auth/gui-session',data='ended').status == 404
        generation = checked(['docker','exec',wallet,'cat','/run/ecd-gui-session/state'],env).split()[0]
        for s,i in ids.items():
            info=inspect(i)
            mount=next(m for m in info['Mounts'] if m['Destination']=='/run/ecd-gui-session')
            assert mount['RW'] == (s=='electron-cash')
            assert not info['HostConfig']['Privileged']
            assert all('docker.sock' not in m['Source'] for m in info['Mounts'])
        # Close the real transport without closing Qt: default noVNC reconnect survives.
        attempts=len(events)
        page.evaluate("async () => {const U=(await import('/app/ui.js')).default; window.ecdTestOldRfb=U.rfb; U.rfb._sock._websocket.close()}")
        page.wait_for_function("window.ecdTestUI.rfb && window.ecdTestUI.rfb!==window.ecdTestOldRfb && window.ecdTestUI.rfb._rfbConnectionState==='connected'",timeout=30000)
        deadline=time.monotonic()+5
        while len(events)==attempts and time.monotonic()<deadline: page.wait_for_timeout(100)
        assert len(events)>attempts,('no observed reconnect WebSocket',events)
        assert not page.evaluate('window.ecdGuiSessionEnded === true')
        assert all(inspect(i)['State']['Running'] for i in ids.values())
        before = process_snapshot(ids,env)
        tor_signals = {}
        for pid,item in before.items():
            if item['service']=='tor-proxy' and item['command']=='tor':
                tor_signals[pid]=Path('/proc/'+pid+'/status').read_text()
                mask=next(line.split()[1] for line in tor_signals[pid].splitlines() if line.startswith('SigBlk:'))
                assert not int(mask,16)&(1<<(15-1)),('Tor main thread blocks SIGTERM',pid,mask)
        (output/(action+'-tor-signals-before.txt')).write_text(json.dumps(tor_signals,indent=2)+'\n')
        page.screenshot(path=str(output/(action+'-before.png')),timeout=10000)
        if action == 'quit':
            page.locator('#noVNC_container canvas').click(position={'x':800,'y':500})
            page.keyboard.press('Control+q')
        else:
            windows(wallet,env,window['id'])
        closed_at = time.monotonic()
        deadline = closed_at+45
        captured_signals = False
        while any(inspect(i)['State']['Running'] for i in ids.values()):
            assert time.monotonic()<deadline, ('GUI siblings survived', states(ids))
            if not captured_signals and time.monotonic()-closed_at>3 and inspect(ids['tor-proxy'])['State']['Running']:
                captured_signals=True
                signals={}
                for pid in tor_signals:
                    try:
                        for status in Path('/proc/'+pid+'/task').glob('*/status'):
                            signals[str(status)]=status.read_text()
                    except FileNotFoundError: pass
                (output/(action+'-tor-signals-after.txt')).write_text(json.dumps(signals,indent=2)+'\n')
            page.wait_for_timeout(250)
        terminal = states(ids)
        assert all(v['state']=='exited' and v['exit_code']==0 for v in terminal.values()),terminal
        for s,i in ids.items():
            logs=subprocess.run(['docker','logs',i],cwd=ROOT,env=env,text=True,errors='replace',
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True,timeout=20).stdout
            assert 'exceeded graceful shutdown deadline' not in logs,(s,'forced shutdown')
            (output/(action+'-'+s+'-shutdown.log')).write_text(logs.replace(env['BASIC_AUTH_PASSWORD'],'[REDACTED]'))
        page.wait_for_function('window.ecdGuiSessionEnded === true',timeout=10000)
        attempts = len(events);page.wait_for_timeout(15000)
        assert len(events)==attempts, ('WebSocket retries continued', events)
        assert not page.evaluate("document.documentElement.classList.contains('noVNC_reconnecting')")
        assert all(inspect(i)['State']['Status']=='exited' and inspect(i)['RestartCount']==terminal[s]['restart_count'] for s,i in ids.items())
        assert_no_processes(before)
        verify_independent()
        page.screenshot(path=str(output/(action+'-ended.png')),timeout=10000)
        record = {'action':action,'actual_main_window':window,'services':terminal,'processes_before':before,
          'transient_transport_reconnect':'PASS','authenticated_read_only_endpoint':'PASS',
          'independent_headless_rpc':'PASS',
          'persisted_identity_before':persisted_before,
          'websocket_attempts_at_terminal':attempts,'post_terminal_attempts':len(events)-attempts,
          'post_terminal_observation_seconds':15,'no_orphans':True,'image_ids':{s:inspect(i)['Image'] for s,i in ids.items()}}
        # Same ordinary command restarts all exited siblings and resets stale end state.
        checked(command+['up','-d','--wait','--no-build','--pull','never'],env,180)
        restarted={s:wait_running(command,s,env=env,cwd=ROOT) for s in model['services']}
        for s,i in restarted.items():wait_healthy(i,s)
        page.close();page=browser.new_page();connect(page,url,env)
        main_window(page,restarted['electron-cash'],env,output,action+'-restart')
        assert not page.evaluate('window.ecdGuiSessionEnded === true')
        new_state=checked(['docker','exec',restarted['electron-cash'],'cat','/run/ecd-gui-session/state'],env).split()
        assert new_state[0]!=generation and new_state[1]=='active'
        assert persistent_identity(restarted['electron-cash'],env)==persisted_before
        record['wallet_and_configuration_persistence']='PASS'
        record['normal_restart']='PASS'
        if action == 'quit':
            # An actual wrapper crash must retain recovery, never publish intentional end.
            restart_count=inspect(restarted['electron-cash'])['RestartCount']
            code="import os,signal; from pathlib import Path; ids=[int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit() and b'/home/electroncash/electroncash-wrapper.py' in (p/'cmdline').read_bytes().split(b'\\0')]; assert len(ids)==1; os.kill(ids[0],signal.SIGKILL)"
            checked(['docker','exec','--user','10001:10001',restarted['electron-cash'],'/opt/electroncash-venv/bin/python','-c',code],env)
            deadline=time.monotonic()+90
            while inspect(restarted['electron-cash'])['RestartCount']==restart_count:
                assert time.monotonic()<deadline,'wallet crash did not retain restart policy'
                page.wait_for_timeout(250)
            wait_healthy(restarted['electron-cash'],'electron-cash')
            page.wait_for_function("window.ecdTestUI.rfb && window.ecdTestUI.rfb._rfbConnectionState==='connected'",timeout=60000)
            assert not page.evaluate('window.ecdGuiSessionEnded === true')
            status=page.request.get(url+'/auth/gui-session').json()
            assert status['state']=='active' and len(status['generation'])==32 and status['ready'] is True
            assert all(inspect(i)['State']['Running'] for i in restarted.values())
            record['real_wrapper_crash_recovery']='PASS'
        # Normal external stop is not an intentional GUI event; start is repeatable.
        checked(command+['stop'],env,180)
        assert all(not inspect(i)['State']['Running'] for i in restarted.values())
        checked(command+['start'],env,180)
        for s,i in restarted.items():wait_healthy(i,s)
        assert checked(['docker','exec',restarted['electron-cash'],'cat','/run/ecd-gui-session/state'],env).split()[1]=='active'
        verify_independent()
        record['external_stop_start']='PASS'
        checked(command+['down'],env,180)
        assert not checked(['docker','ps','-q','--filter','label=com.docker.compose.project='+project],env).strip()
        record['external_down']='PASS'
        (output/(action+'-result.json')).write_text(json.dumps(record,indent=2)+'\n')
        print('PASS actual '+action+' -> zero GUI containers, no orphans/respawn/WS retries, clean restart/stop/down',flush=True)
    except Exception:
        for service, identifier in ids.items():
            p = subprocess.run(['docker','logs',identifier],cwd=ROOT,env=env,text=True,
                errors='replace',capture_output=True,timeout=20)
            (output/(action+'-'+service+'-diagnostic.log')).write_text(
                (p.stdout+p.stderr).replace(env['BASIC_AUTH_PASSWORD'],'[REDACTED]'))
            if inspect(identifier)['State']['Running']:
                top = checked(['docker','top',identifier,'-eo','pid,ppid,pgid,sid,comm'],env,15)
                state = checked(['docker','exec',identifier,'/bin/sh','-c','cat /run/ecd-gui-session/state; cat /proc/1/task/1/children'],env,15)
                (output/(action+'-'+service+'-process-diagnostic.txt')).write_text(top+'\n'+state)
        if not page.is_closed():
            try:page.screenshot(path=str(output/(action+'-failure.png')),timeout=5000)
            except Exception:pass
        raise
    finally:
        page.close()
        checked(command+['down','--volumes','--remove-orphans'],env,180)


def wait_native(stack, predicate, description, timeout=30):
    deadline=time.monotonic()+timeout
    latest=[]
    while time.monotonic()<deadline:
        latest=windows(stack.wallet,stack.env)
        value=predicate(latest)
        if value:return value
        stack.page.wait_for_timeout(100)
    stack.shot('timeout-'+description)
    raise AssertionError((description,latest))


class NativeStack:
    """One supported Qt process, controlled only through real noVNC/X11 UI."""
    def __init__(self,browser,output,label,wizard=False,remember=False,multiple_tabs=False):
        self.browser=browser;self.output=output;self.label=label
        self.remember=remember
        self.project=unique_project('last-gui-'+label)
        self.env=dict(os.environ,ELECTRON_CASH_IMAGE=electron_cash_image(),TOR_IMAGE=tor_image(),
            BASIC_AUTH_PASSWORD='last-gui-disposable',NETWORK='chipnet',USE_TOR='false',EC_LANGUAGE='en_US',
            WALLET_AUTO_CREATE='false' if wizard else 'true',TEST_WALLET_PASSWORD='last-gui-test-only-password',
            ECD_WALLET_VOLUME=self.project+'-wallet',ECD_TOR_VOLUME=self.project+'-tor',
            CADDY_HTTP_HOST_PORT=str(free_port()),CADDY_HTTPS_HOST_PORT=str(free_port()),
            CADDY_SITE_ADDRESS='http://localhost',CADDY_EDGE_BIND='127.0.0.1')
        self.command=['docker','compose','--env-file','.env.example','-p',self.project,'-f','docker-compose.yml']
        self.context=browser.new_context(viewport={'width':1600,'height':1000}) if multiple_tabs else None
        self.page=self.context.new_page() if self.context else browser.new_page(viewport={'width':1600,'height':1000})
        self.events=[];self.ids={}
        self.page.on('websocket',lambda socket:self.events.append({'url':socket.url,'at':time.monotonic()}))
        self.url='http://127.0.0.1:'+self.env['CADDY_HTTP_HOST_PORT']
        self.is_wizard=wizard

    def __enter__(self):
        try:return self.start()
        except Exception:
            self.__exit__(*sys.exc_info())
            raise

    def start(self):
        self.model=json.loads(checked(self.command+['config','--format','json'],self.env))
        checked(self.command+['up','-d','--wait','--no-build','--pull','never'],self.env,180)
        self.ids={s:wait_running(self.command,s,env=self.env,cwd=ROOT) for s in self.model['services']}
        self.wallet=self.ids['electron-cash']
        if not self.is_wizard:
            checked(self.command+['stop','electron-cash'],self.env,120)
            code="import json; from pathlib import Path; p=Path('/home/electroncash/.electron-cash/chipnet/config'); d=json.loads(p.read_text()); d['gui_lifecycle_persistence_probe']='"+self.project+"'; p.write_text(json.dumps(d))"
            checked(self.command+['run','--rm','--no-deps','--user','10001:10001','--entrypoint',
                '/opt/electroncash-venv/bin/python','electron-cash','-c',code],self.env,60)
            self.env['WALLET_AUTO_CREATE']='false'
            checked(self.command+['up','-d','--wait','--no-build','--pull','never'],self.env,180)
            self.ids={s:wait_running(self.command,s,env=self.env,cwd=ROOT) for s in self.model['services']}
            self.wallet=self.ids['electron-cash']
        connect(self.page,self.url,self.env,self.remember)
        if not self.is_wizard:main_window(self.page,self.wallet,self.env,self.output,self.label)
        self.initial=self.service_identity();self.generation=self.state()[0]
        self.images={s:inspect(i)['Image'] for s,i in self.ids.items()}
        for s,i in self.ids.items():
            expected=self.model['services'][s]['image']
            assert inspect(i)['Image']==checked(['docker','image','inspect','--format','{{.Id}}',expected],self.env).strip()
        self.before=process_snapshot(self.ids,self.env)
        self.record={'case':self.label,'services_before':self.initial,'images':self.images,'transitions':[]}
        return self

    def __exit__(self,kind,error,traceback):
        if error:
            diagnostic={'case':self.label,'error':str(error),'images':getattr(self,'images',{}),
                'services':states(self.ids),'observed_before_teardown':True,
                'validator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
            (self.output/(self.label+'-failure.json')).write_text(json.dumps(diagnostic,indent=2)+'\n')
            for s,i in self.ids.items():
                p=subprocess.run(['docker','logs',i],cwd=ROOT,env=self.env,text=True,errors='replace',capture_output=True,timeout=20)
                text=p.stdout+p.stderr
                for key in ('BASIC_AUTH_PASSWORD','TEST_WALLET_PASSWORD','JSONRPC_PASSWORD'):
                    if self.env.get(key):text=text.replace(self.env[key],'[REDACTED]')
                (self.output/(self.label+'-'+s+'-failure.log')).write_text(text)
            try:self.shot('failure')
            except Exception:pass
        self.page.close()
        if self.context:self.context.close()
        checked(self.command+['down','--volumes','--remove-orphans'],self.env,180)

    def python(self,code):
        return checked(['docker','exec','--user','10001:10001',self.wallet,
            '/opt/electroncash-venv/bin/python','-c',code],self.env,30)

    def state(self):return self.python("from gui_session import read_state; print(' '.join(read_state()))").split()

    def service_identity(self):
        return {s:{'id':i,'started':inspect(i)['State']['StartedAt'],'restarts':inspect(i)['RestartCount']} for s,i in self.ids.items()}

    def active(self,seconds=0):
        deadline=time.monotonic()+seconds
        while True:
            assert self.state()==[self.generation,'active']
            assert self.service_identity()==self.initial
            assert all(inspect(i)['State']['Running'] for i in self.ids.values())
            assert not self.page.evaluate('window.ecdGuiSessionEnded === true')
            transport=self.page.evaluate("({state:window.ecdTestUI.rfb && window.ecdTestUI.rfb._rfbConnectionState,connected:window.ecdTestUI.connected,terminal:window.ecdGuiSessionEnded===true})")
            assert transport['state']=='connected',('active transport',transport,self.events)
            if time.monotonic()>=deadline:break
            self.page.wait_for_timeout(100)

    def shot(self,suffix):self.page.screenshot(path=str(self.output/(self.label+'-'+suffix+'.png')),timeout=10000)

    def wallet_window(self,name):
        display=Path(name).name
        return wait_native(self,lambda ws:next((w for w in ws if 'Electron Cash' in w['name'] and display in w['name'] and w['wm_state'] in (1,3)),None),'wallet-'+display)

    def dialog(self,title):
        return wait_native(self,lambda ws:next((w for w in ws if w['mapped'] and title in w['name']),None),'dialog-'+title)

    def click(self,x,y):
        box=self.page.locator('#noVNC_container canvas').bounding_box()
        assert box
        self.page.locator('#noVNC_container canvas').click(position={'x':x*box['width']/1600,'y':y*box['height']/900})
        self.page.wait_for_timeout(150)  # allow the remote Qt focus event to be consumed before typing

    def focus(self,window):
        windows(self.wallet,self.env,window['id'],'activate')
        window=wait_native(self,lambda ws:next((w for w in ws if w['id']==window['id'] and w['mapped']),None),'target-window-restored')
        self.click(window['x']+min(220,window['width']//2),window['y']+min(100,window['height']//2))

    def key(self,key):self.page.keyboard.press(key)

    def next(self,wizard):self.click(wizard['x']+wizard['width']-25,wizard['y']+wizard['height']-25)

    def create_watch_wallet(self,name,acknowledge=True):
        first=self.wallet_window('default_wallet')
        self.focus(first);self.key('Control+n')
        return self.finish_watch_wizard(name,acknowledge=acknowledge)

    def finish_watch_wizard(self,name,acknowledge=True):
        wizard=self.dialog('Install Wizard');self.active(1);self.shot('wizard-name')
        self.click(wizard['x']+270,wizard['y']+62);self.key('Control+a');self.page.keyboard.type(name,delay=5)
        self.next(wizard);self.page.wait_for_timeout(250);self.shot('wizard-kind')
        wizard=self.dialog('Install Wizard')
        # Native radio group: select Import addresses, never display a seed.
        self.click(wizard['x']+150,wizard['y']+142)
        self.next(wizard);self.page.wait_for_timeout(250);self.shot('wizard-import')
        wizard=self.dialog('Install Wizard')
        address=self.python("import os; from electroncash.address import Address; from electroncash import networks; networks.set_chipnet(); print(Address(os.urandom(20),Address.ADDR_P2PKH).to_full_string(Address.FMT_CASHADDR))").strip()
        self.click(wizard['x']+250,wizard['y']+170);self.page.keyboard.type(address,delay=30)
        self.next(wizard)
        pending=wait_native(self,lambda ws:next((w for w in ws if w['mapped'] and w['name']=='Information'),None) or next((w for w in ws if 'Electron Cash' in w['name'] and Path(name).name in w['name']),None),'watch-wallet-completion')
        if pending['name']=='Information':
            self.active(1);self.shot('watch-wallet-information')
            if not acknowledge:return pending
            self.key('Enter')
        result=self.wallet_window(Path(name).name)
        self.active();return result

    def identity(self,name):
        code="""import hashlib,json,os
from pathlib import Path
from electroncash.storage import WalletStorage
p=Path('/home/electroncash/.electron-cash/chipnet/wallets')/NAME
if not p.exists():print(json.dumps({'exists':False}))
else:
 s=WalletStorage(str(p),manual_upgrades=True)
 if s.is_encrypted():s.decrypt(os.environ['TEST_WALLET_PASSWORD'])
 d=s.data;identity={'wallet_type':d.get('wallet_type'),'keystore':d.get('keystore')}
 if d.get('wallet_type')=='imported_addr':identity['addresses']=d.get('addresses')
 print(json.dumps({'exists':True,'identity_sha256':hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()}))
""".replace('NAME',repr(name))
        return json.loads(self.python(code))

    def interact(self,name):
        window=self.wallet_window(name);self.focus(window);self.key('Control+o')
        dialog=self.dialog('Select your wallet file');self.shot('interactive-'+name.replace('/','-'))
        self.key('Escape')
        wait_native(self,lambda ws:not any(w['mapped'] and w['name']=='Select your wallet file' for w in ws),'open-dialog-dismissed')
        self.wallet_window(name);self.active()
        return {'wallet':name,'window':window['id'],'native_open_dialog':dialog['id'],'harmless_interaction':'PASS'}

    def open_wallet(self,name,from_wallet='default_wallet'):
        self.focus(self.wallet_window(from_wallet));self.key('Control+o')
        dialog=self.dialog('Select your wallet file')
        self.click(dialog['x']+230,dialog['y']+dialog['height']-55);self.key('Control+a')
        self.page.keyboard.type('/home/electroncash/.electron-cash/chipnet/wallets/'+name,delay=15);self.key('Enter')
        value=wait_native(self,lambda ws:next((w for w in ws if w['mapped'] and w['name']=='Information'),None) or next((w for w in ws if 'Electron Cash' in w['name'] and Path(name).name in w['name']),None),'open-wallet-'+Path(name).name)
        if value['name']=='Information':self.key('Enter')
        return self.wallet_window(name)

    def close(self,name,action):
        window=self.wallet_window(name);self.focus(window)
        if action=='quit':self.key('Control+q')
        else:windows(self.wallet,self.env,window['id'])

    def delete_prompt(self,name):
        self.focus(self.wallet_window(name));before={w['id'] for w in windows(self.wallet,self.env)}
        self.key('Alt+f');self.key('d')
        dialog=wait_native(self,lambda ws:next((w for w in ws if w['mapped'] and w['id'] not in before and not w['override_redirect']),None),'delete-confirmation')
        self.shot('delete-confirmation');return dialog

    def delete(self,name,cancel=False,wrong_password=False):
        identity=self.identity(name);assert identity['exists']
        self.delete_prompt(name);self.active(1)
        if cancel:
            self.key('Escape');self.active();assert self.identity(name)==identity
            return {'target':name,'outcome':'cancelled','identity_unchanged':True,'interaction':self.interact(name)}
        self.key('y')
        if name=='default_wallet':
            self.dialog('Enter Password')
            self.page.keyboard.type('incorrect-test-only' if wrong_password else self.env['TEST_WALLET_PASSWORD'],delay=5);self.key('Enter')
            if wrong_password:
                self.dialog('Error');self.shot('wrong-password-error');self.key('Enter')
                self.dialog('Enter Password');self.key('Escape');self.active()
                assert self.identity(name)==identity
                return {'target':name,'outcome':'invalid-password-cancelled','identity_unchanged':True,'interaction':self.interact(name)}
        completion=self.dialog('Error')  # native 4.4.6 uses show_error for successful removal
        assert self.identity(name)=={'exists':False},('native deletion did not remove selected wallet',name)
        self.active(1);self.shot('delete-completion')
        self.key('Enter')
        return {'target':name,'outcome':'deleted','removed_identity':identity['identity_sha256'],'completion_dialog':completion['id']}

    def terminal(self):
        deadline=time.monotonic()+45
        capture_at=time.monotonic()+2;captured=False
        while any(inspect(i)['State']['Running'] for i in self.ids.values()):
            assert time.monotonic()<deadline,('GUI session survived final close',states(self.ids))
            if not captured and time.monotonic()>=capture_at and inspect(self.wallet)['State']['Running']:
                captured=True
                p=subprocess.run(['docker','top',self.wallet,'-eo','pid,ppid,stat,wchan,comm'],cwd=ROOT,env=self.env,text=True,errors='replace',capture_output=True,timeout=15)
                (self.output/(self.label+'-shutdown-process-diagnostic.txt')).write_text(p.stdout+p.stderr)
            self.page.wait_for_timeout(100)
        outcome=states(self.ids)
        assert all(v['state']=='exited' and v['exit_code']==0 and v['restart_count']==self.initial[s]['restarts'] for s,v in outcome.items()),outcome
        self.page.wait_for_function('window.ecdGuiSessionEnded === true',timeout=10000)
        attempts=len(self.events);self.page.wait_for_timeout(15000)
        assert len(self.events)==attempts,('browser retried terminal session',self.events)
        assert all(not inspect(i)['State']['Running'] for i in self.ids.values())
        assert not checked(['docker','ps','-q','--filter','label=com.docker.compose.project='+self.project],self.env).strip()
        assert_no_processes(self.before)
        for s,i in self.ids.items():
            p=subprocess.run(['docker','logs',i],cwd=ROOT,env=self.env,text=True,errors='replace',capture_output=True,timeout=20)
            assert 'exceeded graceful shutdown deadline' not in p.stdout+p.stderr,(self.label,s,'forced deadline')
        self.shot('terminal')
        self.record['terminal']={'services':outcome,'post_terminal_websocket_attempts':len(self.events)-attempts,'observation_seconds':15,'no_orphans':True,'observed_before_teardown':True}

    def restart(self,expect_wizard=False,expect_wallet='default_wallet'):
        checked(self.command+['up','-d','--wait','--no-build','--pull','never'],self.env,180)
        self.ids={s:wait_running(self.command,s,env=self.env,cwd=ROOT) for s in self.model['services']};self.wallet=self.ids['electron-cash']
        self.page.close();self.page=self.browser.new_page(viewport={'width':1600,'height':1000});connect(self.page,self.url,self.env)
        state=self.state();assert state[0]!=self.generation and state[1]=='active'
        self.initial=self.service_identity();self.generation=state[0]
        if expect_wizard:self.dialog('Install Wizard')
        else:
            found=wait_native(self,lambda ws:next((w for w in ws if w['mapped'] and w['name']=='Information'),None) or next((w for w in ws if 'Electron Cash' in w['name'] and Path(expect_wallet).name in w['name']),None),'restart-wallet')
            if found['name']=='Information':self.key('Enter')
            self.wallet_window(expect_wallet)
            probe=self.python("import json; from pathlib import Path; print(json.loads(Path('/home/electroncash/.electron-cash/chipnet/config').read_text())['gui_lifecycle_persistence_probe'])").strip()
            assert probe==self.project
        self.record['normal_restart']='PASS'

    def save(self):
        (self.output/(self.label+'-result.json')).write_text(json.dumps(self.record,indent=2)+'\n')
        print('PASS last-GUI '+self.label,flush=True)


def run_last_gui_case(case,browser,output,verify_independent):
    with NativeStack(browser,output,case,wizard=case=='wizard') as s:
        if case=='wizard':
            wizard=s.dialog('Install Wizard')
            assert not any('default_wallet' in w['name'] for w in windows(s.wallet,s.env))
            s.active(3);s.shot('initial-workflow')
            s.record['initial_zero_wallet_workflow']='PASS'
            s.key('Escape');s.terminal();verify_independent();s.save();return
        a=s.identity('default_wallet');assert a['exists']
        b={};b_identity={}
        if case=='transition-cancel':
            s.focus(s.wallet_window('default_wallet'));s.key('Control+n')
            s.dialog('Install Wizard');s.active(2)
            s.close('default_wallet','wm')
            wait_native(s,lambda ws:not any('default_wallet' in w['name'] and w['wm_state'] in (1,3) for w in ws),'A-closed-with-wizard')
            wizard=s.dialog('Install Wizard');s.active(2);s.shot('zero-wallet-native-wizard')
            s.focus(wizard);s.key('Escape');s.terminal();verify_independent()
            s.record['cancel_final_continuation']='PASS';s.save();return
        if case=='transition':
            pending=s.create_watch_wallet('wallet_b',acknowledge=False)
            assert pending['name']=='Information'
            s.record['pending_creation_information']=pending
            s.active(2);s.close('default_wallet','wm')
            wait_native(s,lambda ws:not any('default_wallet' in w['name'] and w['wm_state'] in (1,3) for w in ws),'A-closed-during-continuation')
            s.active(2);s.shot('continuation-with-no-prior-wallet')
            s.focus(pending);s.key('Enter');s.wallet_window('wallet_b');s.interact('wallet_b')
            s.record['creation_continuation_after_previous_wallet_close']='PASS'
            s.close('wallet_b','wm');s.terminal();verify_independent();s.save();return
        b_name='failure/wallet_b' if case=='failure' else 'wallet_b'
        if case!='delete-single':
            if case=='failure':s.python("from pathlib import Path; Path('/home/electroncash/.electron-cash/chipnet/wallets/failure').mkdir(mode=0o700)")
            b=s.create_watch_wallet(b_name);b_identity=s.identity(b_name)
            assert b_identity['exists'] and a['identity_sha256']!=b_identity['identity_sha256']
            aw=s.wallet_window('default_wallet');assert aw['id']!=b['id']
            s.record['two_distinct_wallets']={'A':a,'B':b_identity,'window_A':aw,'window_B':b,
                'interactions':[s.interact('default_wallet'),s.interact(b_name)]}
            s.shot('two-interactive-wallets')
        if case in ('wm','quit'):
            if case=='wm':
                windows(s.wallet,s.env,b['id'],'minimize')
                wait_native(s,lambda ws:next((w for w in ws if w['id']==b['id'] and not w['mapped']),None),'B-minimized')
                s.record['minimized_survivor']='PASS'
            s.close('default_wallet',case)
            wait_native(s,lambda ws:not any('default_wallet' in w['name'] and w['wm_state'] in (1,3) for w in ws),'A-window-closed')
            s.active(3);assert s.identity('default_wallet')==a and s.identity(b_name)==b_identity
            s.record['transitions'].append({'from':2,'to':1,'action':case,'A_file_preserved':True,'B_interaction':s.interact(b_name),'service_identity_unchanged':True})
            s.close(b_name,case);s.terminal();verify_independent()
            s.restart(expect_wallet=b_name);assert s.identity('default_wallet')==a and s.identity(b_name)==b_identity
            s.interact(b_name);s.open_wallet('default_wallet',from_wallet=b_name);s.interact('default_wallet')
            s.record['non_deleted_restart_identity']='PASS'
        elif case in ('delete-two','delete-single'):
            s.record['deletion_cancellation']=s.delete('default_wallet',cancel=True)
            s.record['invalid_password_cancellation']=s.delete('default_wallet',wrong_password=True)
            if case=='delete-two':assert s.identity(b_name)==b_identity
            s.record['transitions'].append(s.delete('default_wallet'))
            if case=='delete-two':
                wait_native(s,lambda ws:not any('default_wallet' in w['name'] and w['wm_state'] in (1,3) for w in ws),'deleted-A-window-closed')
                s.active(3);assert s.identity(b_name)==b_identity
                s.record['survivor_interaction']=s.interact(b_name)
                s.record['transitions'].append(s.delete(b_name))
            s.terminal();verify_independent();s.restart(expect_wizard=True)
            assert s.identity('default_wallet')=={'exists':False}
            if case=='delete-two':assert s.identity(b_name)=={'exists':False}
            s.active(3);s.record['deleted_identities_not_resurrected']='PASS'
            new=s.finish_watch_wizard('default_wallet');new_identity=s.identity('default_wallet')
            assert new_identity['exists'] and new_identity['identity_sha256']!=a['identity_sha256']
            s.interact('default_wallet');s.record['explicit_new_wallet_after_delete']=new_identity
        elif case=='failure':
            directory='/home/electroncash/.electron-cash/chipnet/wallets/failure'
            s.python("import os; os.chmod("+repr(directory)+",0o500)")
            try:
                s.delete_prompt(b_name);s.key('y')
                error=wait_native(s,lambda ws:next((w for w in ws if w['mapped'] and ('error' in w['name'].lower() or 'report' in w['name'].lower())),None),'native-delete-error')
                s.shot('native-deletion-failure');s.active(2)
                assert s.identity(b_name)==b_identity and s.identity('default_wallet')==a
                s.record['native_deletion_failure']={'error_window':error,'selected_wallet_intact':True,'other_wallet_intact':True,'session_active':True}
                s.key('Escape')
            finally:s.python("import os; os.chmod("+repr(directory)+",0o700)")
            s.interact('default_wallet');s.close(b_name,'wm')
            wait_native(s,lambda ws:not any('wallet_b' in w['name'] and w['wm_state'] in (1,3) for w in ws),'failed-wallet-closed')
            s.open_wallet(b_name);s.interact(b_name);assert s.identity(b_name)==b_identity
            s.record['native_failure_recovery']='PASS'
            s.close(b_name,'wm');wait_native(s,lambda ws:not any('wallet_b' in w['name'] and w['wm_state'] in (1,3) for w in ws),'B-closed-after-recovery')
            s.close('default_wallet','quit');s.terminal();verify_independent()
        else:raise AssertionError(('unknown last-GUI case',case))
        s.save()


def run_last_gui_cases(browser,output,verify_independent):
    for case in ('wm','quit','delete-two','delete-single','failure','wizard','transition','transition-cancel'):
        run_last_gui_case(case,browser,output,verify_independent)


def main():
    directory=Path(os.environ['CI_REPORT_DIR'])/'gui-session-lifecycle'
    directory.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
        try:
            with independent_workloads(directory) as verify:
                run_case('quit',browser,directory,verify)
                run_case('wm-delete',browser,directory,verify)
                last=directory/'last-gui';last.mkdir(exist_ok=True)
                run_last_gui_cases(browser,last,verify)
        finally:browser.close()


if __name__ == '__main__':main()

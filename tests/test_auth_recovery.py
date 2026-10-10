#!/usr/bin/env python3
"""Real durable auth + SAME Page recovery; existing native lifecycle harness."""
import hashlib
import json
import os
import subprocess
import shutil
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright
from test_gui_session_lifecycle import NativeStack, checked, wait_native, wait_running, ROOT
from test_support import remove_owned_volume


def cookie(stack):
    return next(c for c in stack.page.context.cookies() if c['name']=='ecd_session')


def token_identity(value):return hashlib.sha256(('evidence-only:'+value).encode()).hexdigest()


def metadata(stack):
    code="import sqlite3,json,os; p='/auth-data/sessions.sqlite'; c=sqlite3.connect(p); print(json.dumps({'sessions':c.execute('SELECT created,expires,remember,generation FROM sessions ORDER BY created').fetchall(),'uid':os.stat(p).st_uid,'gid':os.stat(p).st_gid,'file_mode':oct(os.stat(p).st_mode & 511),'directory_mode':oct(os.stat('/auth-data').st_mode & 511)})); c.close()"
    return json.loads(checked(['docker','exec','--user','10001:10001',stack.ids['auth-session'],'python3','-c',code],stack.env,15))


def refresh(stack):
    stack.ids={s:wait_running(stack.command,s,env=stack.env,cwd=ROOT) for s in stack.model['services']}
    stack.wallet=stack.ids['electron-cash'];stack.initial=stack.service_identity()


def guard_page(stack, page=None):
    """Fail rather than manufacture recovery with an old helper/new Page."""
    page=page or stack.page;context=page.context
    methods=[(page,n,getattr(page,n)) for n in ('goto','reload','close')]+[(context,'new_page',context.new_page)]
    def forbidden(*args,**kwargs):raise AssertionError('test-driven browser recovery is forbidden')
    for obj,name,_ in methods:setattr(obj,name,forbidden)
    def release():
        for obj,name,value in methods:setattr(obj,name,value)
    return release


def recover(stack, original, token, deadline, *, wizard=False):
    old_generation=stack.generation;started=time.monotonic()
    checked(stack.command+['up','-d','--wait','--no-build','--pull','never'],stack.env,180)
    ready=time.monotonic();refresh(stack)
    stack.page.wait_for_function('(old) => window.ecdGuiGeneration && window.ecdGuiGeneration !== old',arg=old_generation,timeout=40000)
    assert stack.page is original and not original.is_closed()
    assert cookie(stack)['value']==token
    assert metadata(stack)['sessions']==deadline
    stack.page.evaluate("async () => {window.ecdTestUI=(await import('/app/ui.js')).default}")
    stack.page.wait_for_function("window.ecdTestUI.rfb && window.ecdTestUI.rfb._rfbConnectionState==='connected'",timeout=15000)
    stack.generation=stack.state()[0];stack.active()
    if wizard:
        dialog=stack.dialog('Install Wizard');stack.click(dialog['x']+270,dialog['y']+62)
        stack.key('Control+a');stack.page.keyboard.type('harmless-recovery-probe')
        assert not stack.identity('default_wallet')['exists']
    else:stack.interact('default_wallet')
    assert time.monotonic()-ready<=40
    return {'same_page':True,'same_context':True,'test_navigation_forbidden':True,
        'original_token_identity':token_identity(token),'new_generation':stack.generation,
        'framebuffer_and_native_interaction':'PASS','ready_to_recovery_seconds':round(time.monotonic()-ready,3),
        'total_restart_seconds':round(time.monotonic()-started,3),'absolute_deadlines_unchanged':True}


def auth_restart(stack, token, deadlines, *, recreate=False, kill=False):
    before=stack.ids['auth-session']
    if kill:
        code="""import os,signal
from pathlib import Path
ids=[]
for p in Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:args=(p/'cmdline').read_bytes().split(b'\\0')
 except FileNotFoundError:continue
 if args[:2]==[b'python3',b'/home/authsession/server.py']:ids.append(int(p.name))
assert len(ids)==1
os.kill(ids[0],signal.SIGKILL)
"""
        checked(['docker','exec','--user','10001:10001',before,'python3','-c',code],stack.env,30)
    elif recreate:checked(stack.command+['up','-d','--no-deps','--force-recreate','--no-build','--pull','never','auth-session'],stack.env,120)
    else:checked(stack.command+['restart','auth-session'],stack.env,90)
    end=time.monotonic()+30
    while True:
        try:
            if stack.page.request.get(stack.url+'/auth/gui-session',timeout=3000).status==200:break
        except Exception:pass
        assert time.monotonic()<end,'auth restart did not become ready'
        stack.page.wait_for_timeout(200)
    refresh(stack)
    if recreate:assert stack.ids['auth-session']!=before
    assert cookie(stack)['value']==token and metadata(stack)['sessions']==deadlines


def backup_preserves_auth(s, original, token, deadlines):
    """Actual managed wallet backup/restore in this authenticated owned project."""
    with tempfile.TemporaryDirectory(prefix='ecd-auth-wallet-backup-') as temp:
        root=Path(temp);project=root/s.project;project.mkdir();(project/'scripts').mkdir()
        shutil.copy2(ROOT/'scripts/backup.sh',project/'scripts/backup.sh')
        (project/'docker').symlink_to(ROOT/'docker',target_is_directory=True)
        env=dict(s.env,COMPOSE_PROJECT_NAME=s.project,COMPOSE_FILE=str(ROOT/'docker-compose.yml'),
            COMPOSE_ENV_FILES=str(ROOT/'.env.example'),XDG_STATE_HOME=str(root/'state'),BACKUP_DIR=str(root/'backups'),
            ECD_TEST_RESOURCE_OWNER=s.env['CI_RESOURCE_OWNER'])
        password='test-only-backup-passphrase'
        before=s.identity('default_wallet')
        for operation,inputs in [('backup',password+'\n'+password+'\n'),('restore','y\n'+password+'\n')]:
            result=subprocess.run([str(project/'scripts/backup.sh'),operation,'auth-isolation'],cwd=project,env=env,
                text=True,input=inputs,capture_output=True,timeout=240)
            assert result.returncode==0,(operation,(result.stdout+result.stderr).replace(password,'[REDACTED]')[-3000:])
            if operation=='backup':
                archive=root/'backups/auth-isolation.ecd.gpg'
                code="mkdir -m 700 /tmp/gpg; export GNUPGHOME=/tmp/gpg; gpg --no-options --batch --quiet --pinentry-mode loopback --passphrase-fd 0 --decrypt /archive | tar -tzf -"
                unpack=subprocess.run(['docker','run','--rm','-i','--pull=never','--network','none','--read-only','--cap-drop=ALL',
                    '--security-opt','no-new-privileges:true','--tmpfs','/tmp:mode=1777',
                    '--mount',f'type=bind,src={archive},dst=/archive,readonly','--entrypoint','/bin/bash',
                    s.env['ELECTRON_CASH_IMAGE'],'-c',code],cwd=ROOT,env=env,text=True,input=password+'\n',capture_output=True,timeout=60)
                assert unpack.returncode==0 and 'wallets/default_wallet' in unpack.stdout
                assert 'sessions.sqlite' not in unpack.stdout and 'auth-data' not in unpack.stdout
        recover(s,original,token,deadlines)
        assert s.identity('default_wallet')==before


def edge_probes(s, token, requests, navigation_count, navigations, websockets):
    """Controlled HTTP fault/starting responses; no browser recovery injection."""
    cases=[(503,'unavailable'),(403,'origin rejection'),(200,'not-json'),
        (200,json.dumps({'state':'active','generation':s.generation,'ready':True})),
        (200,json.dumps({'state':'active','generation':'0'*32,'ready':False}))]
    seen=[];current=[cases[0]]
    def respond(route):
        status,body=current[0];seen.append(status)
        route.fulfill(status=status,body=body,headers={'Cache-Control':'no-store','Content-Type':'application/json'})
    s.page.route('**/auth/gui-session',respond)
    try:
        for case in cases:
            current[0]=case;count=len(seen);until=time.monotonic()+35
            # Exercise the existing visibility wake-up, never location/navigation.
            s.page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
            while len(seen)==count:
                assert time.monotonic()<until,'observer failed to complete controlled probe'
                s.page.wait_for_timeout(100)
            s.page.wait_for_timeout(200)
            assert len(s.events)==websockets and len(navigations)==navigation_count
            assert cookie(s)['value']==token and not s.page.locator('input[name=password]').count()
        assert s.page.evaluate('window.ecdGuiRecoveryState')=='starting'
    finally:s.page.unroute('**/auth/gui-session',respond)
    return {'controlled_503_403_malformed_old_generation_new_starting':'PASS',
        'not_native_service_readiness_proof':True,'no_redirect_reload_or_rfb_attempt':True}


def positive(browser, output, action, remember):
    label=action+('-remember' if remember else '-temporary')
    with NativeStack(browser,output,label,remember=remember,multiple_tabs=True) as s:
        original=s.page;token=cookie(s)['value'];deadlines=metadata(s)['sessions']
        assert len(deadlines)==1 and deadlines[0][2]==int(remember)
        assert round(deadlines[0][1]-deadlines[0][0])==(2592000 if remember else 1800)
        assert (cookie(s)['expires']>0)==remember
        permissions=metadata(s);assert permissions['uid']==permissions['gid']==10001 and permissions['file_mode']=='0o600' and permissions['directory_mode']=='0o700'
        auth_volume=s.model['volumes']['auth-session-data']['name']
        assert auth_volume.startswith(s.project+'_')
        assert json.loads(checked(['docker','volume','inspect',auth_volume],s.env,15))[0]['Labels']['com.docker.compose.project']==s.project
        raw_check="import sys,json; from pathlib import Path; t=sys.stdin.read().encode(); print(json.dumps(all(t not in p.read_bytes() for p in Path('/auth-data').glob('sessions.sqlite*'))))"
        scan=subprocess.run(['docker','exec','-i','--user','10001:10001',s.ids['auth-session'],'python3','-c',raw_check],cwd=ROOT,env=s.env,text=True,input=token,capture_output=True,timeout=15)
        assert scan.returncode==0 and json.loads(scan.stdout) is True
        for name,identifier in s.ids.items():
            mounts=json.loads(checked(['docker','inspect',identifier],s.env,15))[0]['Mounts']
            assert any(m['Destination']=='/auth-data' for m in mounts)==(name=='auth-session')
        requests=[];navigations=[]
        s.page.on('request',lambda request:requests.append(time.monotonic()) if urlsplit(request.url).path=='/auth/gui-session' else None)
        s.page.on('framenavigated',lambda frame:navigations.append(urlsplit(frame.url).path) if frame==s.page.main_frame else None)
        second=None;release_second=lambda:None
        if action=='quit' and remember:
            second=s.page.context.new_page()
            second.goto(s.url+'/vnc.html?autoconnect=true&reconnect=true&reconnect_delay=3000')
            second.wait_for_function('window.ecdGuiGeneration',timeout=10000)
        release=guard_page(s)
        if second:release_second=guard_page(s,second)
        try:
            extra={}
            if action=='quit':
                auth_restart(s,token,deadlines);auth_restart(s,token,deadlines,recreate=True);auth_restart(s,token,deadlines,kill=True)
                extra['restart_recreate_abrupt_loss']='PASS'
                for operation in ('stop','down'):
                    checked(s.command+[operation],s.env,120)
                    extra[operation+'-up']=recover(s,original,token,deadlines)
                if remember:
                    backup_preserves_auth(s,original,token,deadlines)
                    extra['managed_wallet_backup_restore_auth_exclusion']='PASS'
            if action=='wm':
                s.create_watch_wallet('survivor');s.close('survivor','wm')
                wait_native(s,lambda ws:not any('survivor' in w['name'] and w['wm_state'] in (1,3) for w in ws),'partial-close')
                s.active(2);s.interact('default_wallet');assert cookie(s)['value']==token
                extra['multi_wallet_partial_close']='PASS'
            identity=s.identity('default_wallet')
            if action=='delete':s.delete('default_wallet')
            else:s.close('default_wallet',action)
            s.terminal();websockets=len(s.events);navigation_count=len(navigations)
            # Wait for observed conservative outage probes, not a long blind sleep.
            if action=='quit' and remember:
                target=len(requests)+3;until=time.monotonic()+90
                while len(requests)<target:
                    assert time.monotonic()<until,'passive observer stopped during outage'
                    assert len(s.events)==websockets
                    s.page.wait_for_timeout(250)
                extra['extended_offline_passive_only']='PASS'
                extra['edge_probes']=edge_probes(s,token,requests,navigation_count,navigations,websockets)
            result=recover(s,original,token,deadlines,wizard=action=='delete')
            assert len(navigations)-navigation_count==1,'terminal recovery must navigate exactly once'
            if action!='delete':assert s.identity('default_wallet')==identity
            else:assert not s.identity('default_wallet')['exists']
            if second:
                second.wait_for_function('(generation) => window.ecdGuiGeneration === generation',arg=s.generation,timeout=40000)
                second.evaluate("async () => {window.ecdTestUI=(await import('/app/ui.js')).default}")
                second.wait_for_function("window.ecdTestUI.rfb && window.ecdTestUI.rfb._rfbConnectionState==='connected'",timeout=15000)
                assert not second.locator('input[name=password]').count()
                extra['multiple_tabs_same_token_recover_without_revocation']='PASS'
            result.update(case=label,remember=remember,permissions=permissions,raw_token_absent=True,
                auth_volume=auth_volume,project_scoped_volume_verified=True,
                post_terminal_websocket_attempts=0,passive_status_requests=len(requests),product_navigation_count=1,
                wallet_preserved_or_deleted_as_expected=True,additional=extra)
            (output/(label+'-recovery.json')).write_text(json.dumps(result,indent=2)+'\n')
            print('PASS same-tab '+label,flush=True)
        finally:release_second();release()


def negative(browser, output):
    with NativeStack(browser,output,'negative-auth') as s:
        original=s.page;identity=s.identity('default_wallet');token=cookie(s)['value']
        release=guard_page(s);results=[]
        def login(password):
            s.page.locator('input[name=password]').fill(password)
            s.page.locator('button[type=submit]').click()
            s.page.wait_for_url('**/vnc.html**',timeout=15000)
            s.page.wait_for_function('window.ecdGuiGeneration',timeout=15000)
            s.page.evaluate("async () => {window.ecdTestUI=(await import('/app/ui.js')).default}")
            s.page.wait_for_function("window.ecdTestUI.rfb && window.ecdTestUI.rfb._rfbConnectionState==='connected'",timeout=15000)
        def at_login():
            s.page.wait_for_url(s.url+'/',timeout=40000)
            s.page.locator('input[name=password]').wait_for()
            assert s.page is original
        try:
            # Remove ONLY the exact owned auth volume after scoped container removal.
            s.close('default_wallet','quit');s.terminal()
            volume=s.model['volumes']['auth-session-data']['name']
            checked(s.command+['down'],s.env,120);remove_owned_volume(volume)
            checked(s.command+['up','-d','--wait','--no-build','--pull','never'],s.env,180);refresh(s)
            at_login();assert s.identity('default_wallet')==identity
            login(s.env['BASIC_AUTH_PASSWORD']);results.append('auth-volume-only reset -> same-tab login; wallet unchanged')
            # Real expiry between the valid status decision and protected HTML.
            # No test-driven navigation/cookie changes manufacture this recovery.
            s.generation=s.state()[0];s.close('default_wallet','quit');s.terminal()
            raced=[]
            def expire_after_decision(route):
                try:response=route.fetch(timeout=3000)
                except Exception:route.abort('connectionfailed');return
                if not raced and response.status==200 and response.json().get('ready'):
                    refresh(s)
                    checked(['docker','exec','--user','10001:10001',s.ids['auth-session'],'python3','-c',"import sqlite3; c=sqlite3.connect('/auth-data/sessions.sqlite'); c.execute('UPDATE sessions SET expires=0'); c.commit(); c.close()"],s.env,15)
                    raced.append(True)
                route.fulfill(response=response)
            s.page.route('**/auth/gui-session',expire_after_decision)
            try:
                checked(s.command+['up','-d','--wait','--no-build','--pull','never'],s.env,180);refresh(s)
                at_login();assert raced
            finally:s.page.unroute('**/auth/gui-session',expire_after_decision)
            login(s.env['BASIC_AUTH_PASSWORD']);results.append('expiry between valid probe and protected document -> same-tab login with HTTP 401 preserved')
            # Missing/invalid cookies are deliberate negative fixtures only.
            s.page.context.clear_cookies();at_login();login(s.env['BASIC_AUTH_PASSWORD']);results.append('missing cookie -> same-tab login')
            s.page.context.add_cookies([{'name':'ecd_session','value':'invalid-test-only-token','url':s.url,'httpOnly':True,'sameSite':'Strict'}])
            at_login();login(s.env['BASIC_AUTH_PASSWORD']);results.append('deliberately invalid cookie -> same-tab login')
            expired=cookie(s)['value']
            checked(['docker','exec','--user','10001:10001',s.ids['auth-session'],'python3','-c',"import sqlite3; c=sqlite3.connect('/auth-data/sessions.sqlite'); c.execute('UPDATE sessions SET expires=0'); c.commit(); c.close()"],s.env,15)
            at_login();checked(s.command+['restart','auth-session'],s.env,90);refresh(s)
            login(s.env['BASIC_AUTH_PASSWORD']);results.append('absolute expiry remains rejected after restart')
            revoked=cookie(s)['value']
            response=s.page.request.post(s.url+'/auth/logout',headers={'Origin':s.url},max_redirects=0)
            assert response.status==303;at_login()
            checked(s.command+['restart','auth-session'],s.env,90);refresh(s)
            assert s.page.request.get(s.url+'/auth/gui-session',headers={'Cookie':'ecd_session='+revoked}).status==401
            login(s.env['BASIC_AUTH_PASSWORD']);results.append('logout remains revoked after restart')
            previous=cookie(s)['value'];old_password=s.env['BASIC_AUTH_PASSWORD']
            s.env['BASIC_AUTH_PASSWORD']='different-test-auth-password'
            checked(s.command+['up','-d','--no-deps','--force-recreate','--no-build','--pull','never','auth-session'],s.env,120);refresh(s)
            at_login();s.page.locator('input[name=password]').fill(old_password);s.page.locator('button[type=submit]').click()
            s.page.get_by_text('Invalid password.').wait_for();login(s.env['BASIC_AUTH_PASSWORD'])
            s.env['BASIC_AUTH_PASSWORD']=old_password
            checked(s.command+['up','-d','--no-deps','--force-recreate','--no-build','--pull','never','auth-session'],s.env,120);refresh(s);at_login()
            for old in (token,expired,revoked,previous):
                assert s.page.request.get(s.url+'/auth/gui-session',headers={'Cookie':'ecd_session='+old}).status==401
            login(old_password);assert s.identity('default_wallet')==identity
            s.generation=s.state()[0];s.interact('default_wallet')
            results.append('password change/back cannot revive previous sessions; old password rejected at changed generation')
            # Non-writable/corrupt storage returns 503, never 401/success or RAM fallback.
            checked(['docker','exec','--user','10001:10001',s.ids['auth-session'],'python3','-c',"import os; os.chmod('/auth-data',0o500)"],s.env,15)
            assert s.page.request.get(s.url+'/auth/gui-session').status==503
            checked(['docker','exec','--user','10001:10001',s.ids['auth-session'],'python3','-c',"import os; os.chmod('/auth-data',0o700); from pathlib import Path; Path('/auth-data/sessions.sqlite').write_bytes(b'corrupt-test-fixture')"],s.env,15)
            assert s.page.request.get(s.url+'/auth/gui-session').status==503
            assert checked(['docker','exec',s.ids['auth-session'],'python3','-c',"import urllib.request,urllib.error;\ntry: urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2)\nexcept urllib.error.HTTPError as e: print(e.code)"],s.env,15).strip()=='503'
            results.append('unwritable/corrupt owned database fails closed/unhealthy; no fallback or self-deletion')
            (output/'negative-recovery.json').write_text(json.dumps({'status':'PASS','same_page':True,'test_navigation_forbidden':True,'results':results,'raw_tokens_retained':False},indent=2)+'\n')
            print('PASS real same-tab invalidation/login: isolated auth-volume reset, missing cookie, expiry, logout and password change/back',flush=True)
        finally:release()


def main():
    output=Path(os.environ['CI_REPORT_DIR'])/'auth-recovery';output.mkdir(parents=True,exist_ok=True)
    focused=os.environ.get('ECD_FOCUSED_AUTH_CASE')
    assert not focused or focused in {action+suffix for action in ('quit','wm','delete') for suffix in ('-temporary','-remember')} | {'negative-auth'}
    assert not (focused and os.environ.get('CI_CLEANUP_FAILURE_FILE')), 'canonical auth acceptance cannot be filtered'
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
        try:
            for remember in (False,True):
                for action in ('quit','wm','delete'):
                    label=action+('-remember' if remember else '-temporary')
                    if not focused or focused==label:positive(browser,output,action,remember)
            if not focused or focused=='negative-auth':negative(browser,output)
        finally:browser.close()


if __name__=='__main__':main()

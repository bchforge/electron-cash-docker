#!/usr/bin/env python3
"""Real Qt/browser startup themes and environment-template delivery path."""
import json
import os
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

from test_gui_session_lifecycle import NativeStack, checked, windows, wait_native
from test_support import electron_cash_image

ROOT=Path(__file__).resolve().parents[1]


def inspect_theme(stack,expected,label):
    logs=checked(['docker','logs',stack.wallet],stack.env)
    marker=f'[+] Electron Cash GUI theme: {expected} (dark active: {expected=="dark"})'
    assert marker in logs,marker
    assert stack.python("import json; from pathlib import Path; print(json.loads(Path('/home/electroncash/.electron-cash/chipnet/config').read_text())['qt_gui_color_theme'])").strip()==expected
    box=stack.page.locator('#noVNC_container canvas').bounding_box();assert box
    filename=stack.output/(label+'-render.png');stack.page.screenshot(path=str(filename),timeout=10000)
    x=int(box['x']+700*box['width']/1600);y=int(box['y']+450*box['height']/900)
    code="import sys; from PyQt5.QtGui import QImage; im=QImage.fromData(sys.stdin.buffer.read()); assert not im.isNull(); total=sum((im.pixelColor(xx,yy).red()+im.pixelColor(xx,yy).green()+im.pixelColor(xx,yy).blue())/3 for xx in range("+str(x)+","+str(x+100)+") for yy in range("+str(y)+","+str(y+80)+")); print(total/8000)"
    sample=subprocess.run(['docker','exec','-i','--user','10001:10001',stack.wallet,'/opt/electroncash-venv/bin/python','-c',code],
        cwd=ROOT,env=stack.env,input=filename.read_bytes(),capture_output=True,timeout=30)
    assert sample.returncode==0,sample.stderr.decode(errors='replace')
    mean=float(sample.stdout)
    assert (mean<100 if expected=='dark' else mean>180),(expected,mean)
    before={w['id'] for w in windows(stack.wallet,stack.env)}
    stack.focus(stack.wallet_window('default_wallet'));stack.key('Control+o')
    dialog=wait_native(stack,lambda ws:next((w for w in ws if w['mapped'] and w['id'] not in before and not w['override_redirect']),None),'native-theme-open-dialog')
    stack.key('Escape');stack.active()
    return {'expected_native_theme':expected,'qt_diagnostic':marker,'visible_panel_mean_rgb':mean,
            'native_dialog':dialog,'usable_gui':'PASS','source_wallet_identity':stack.identity('default_wallet')}


def main():
    report=Path(os.environ['CI_REPORT_DIR'])/'theme-runtime';report.mkdir(parents=True,exist_ok=True)
    cases=[]
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,args=['--disable-dev-shm-usage'])
        try:
            for label,dark,language in [('missing',None,'en_US'),('false','false','en_US'),('empty','','es_ES'),('dark','true','es_ES'),('dark-en','true','en_US')]:
                stack=NativeStack(browser,report,'theme-'+label)
                generated=report/(label+'.env')
                text=(ROOT/'.env.example').read_text()
                text='\n'.join(line for line in text.splitlines() if not line.startswith(('DARK_MODE=','EC_LANGUAGE=')))+'\n'
                if dark is not None:text+='DARK_MODE='+dark+'\n'
                text+='EC_LANGUAGE='+language+'\n'
                if label=='false':
                    text=text.replace('CASHFUSION_FEE_BUDGET=0','CASHFUSION_FEE_BUDGET=500').replace('CASHFUSION_MIN_UTXO=1000','CASHFUSION_MIN_UTXO=2000')
                generated.write_text(text)
                stack.command[stack.command.index('--env-file')+1]=str(generated)
                stack.env['EC_LANGUAGE']=language
                stack.env.pop('DARK_MODE',None)
                with stack as s:
                    expected='dark' if dark=='true' else 'default'
                    actual=json.loads(checked(s.command+['config','--format','json'],s.env))['services']['electron-cash']['environment']
                    assert actual['DARK_MODE']==('false' if dark is None else dark)
                    if label=='false':
                        assert actual['CASHFUSION_FEE_BUDGET']=='500' and actual['CASHFUSION_MIN_UTXO']=='2000'
                        policy=json.loads(s.python("import json; from cashfusion_defaults import cashfusion_config_from_environment; print(json.dumps(cashfusion_config_from_environment()))"))
                        assert policy['limits']=={'fee_budget_satoshis':500,'minimum_input_satoshis':2000}
                        assert policy['enabled'] is True and policy['profile']['cashfusion_autofuse'] is False
                        original=s.identity('default_wallet')
                        checked(s.command+['stop'],s.env,90)
                        s.restart(expect_wallet='default_wallet')
                        assert s.identity('default_wallet')==original
                        again=json.loads(s.python("import json; from cashfusion_defaults import cashfusion_config_from_environment; print(json.dumps(cashfusion_config_from_environment()))"))
                        assert again==policy
                        cases.append({'case':'positive-limit-template-startup-restart','effective_policy':policy,'wallet_preserved':True})
                    cases.append(dict(case=label,language=language,effective_dark_mode=actual['DARK_MODE'],**inspect_theme(s,expected,label)))
                    if label=='dark-en':
                        s.create_watch_wallet('theme_watch')
                        first=s.identity('default_wallet');other=s.identity('theme_watch')
                        s.close('default_wallet','wm')
                        wait_native(s,lambda ws:not any('default_wallet' in w['name'] and w['wm_state'] in (1,3) for w in ws),'dark-A-closed')
                        s.active(2);s.interact('theme_watch');assert s.identity('theme_watch')==other
                        s.close('theme_watch','quit');s.terminal()
                        cases.append({'case':'dark-multi-wallet-workflow','two_distinct_identities':first!=other,'survivor_usable':True,'terminal':s.record['terminal']})
                    if label=='dark':
                        # Use the same persisted wallet: false and omitted must undo dark.
                        original=s.identity('default_wallet')
                        for value,suffix in [('false','dark-to-false'),(None,'dark-to-missing')]:
                            s.env['DARK_MODE']='true' if suffix=='dark-to-missing' else 'false'
                            checked(s.command+['up','-d','--wait','--no-build','--pull','never'],s.env,180)
                            if suffix=='dark-to-missing':
                                # Remove it from the generated .env as well; no live .env is touched.
                                generated.write_text('\n'.join(line for line in generated.read_text().splitlines() if not line.startswith('DARK_MODE='))+'\n')
                                s.env.pop('DARK_MODE',None)
                            s.restart(expect_wallet='default_wallet')
                            cases.append(dict(case=suffix,language=language,**inspect_theme(s,'default',suffix)))
                            assert s.identity('default_wallet')==original
        finally:browser.close()
    for value in ('invalid','1','yes'):
        command=['docker','run','--rm','--pull=never','--network','none','-e','USE_TOR=false','-e','DARK_MODE='+value,electron_cash_image()]
        result=subprocess.run(command,cwd=ROOT,text=True,errors='replace',capture_output=True,timeout=30)
        assert result.returncode!=0 and 'DARK_MODE must be true or false' in result.stdout+result.stderr
    (report/'results.json').write_text(json.dumps({'status':'PASS','image':electron_cash_image(),'cases':cases,
        'path':'versioned template -> generated disposable .env -> resolved Compose -> actual native Qt diagnostic + visible rendering'},indent=2)+'\n')
    print('PASS native light/dark Qt rendering, missing/empty/false/true startup, EN/ES, persisted dark reset and usable dialogs')


if __name__=='__main__':main()

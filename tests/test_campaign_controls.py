#!/usr/bin/env python3
"""Current pinned CashFusion consumers and deployment config, no funded rounds."""
import json
import os
import subprocess
from pathlib import Path

from test_support import electron_cash_image, resource_owner, unique_resource

ROOT=Path(__file__).resolve().parents[1]


def main():
    name=unique_resource('campaign-controls',kind='container')
    code=(ROOT/'tests/cashfusion_policy_runtime.py').read_text()
    result=subprocess.run(['docker','run','-i','--pull=never','--rm','--network','none','--name',name,
        '--label','com.bchforge.electron-cash-docker.test-owner='+resource_owner(),
        '--entrypoint','/opt/electroncash-venv/bin/python',electron_cash_image(),'-'],
        cwd=ROOT,text=True,input=code,capture_output=True,timeout=180)
    print(result.stdout,end='')
    assert result.returncode==0,result.stderr
    assert 'PASS native final-transaction fee boundaries' in result.stdout
    assert 'PASS actual installed native signing block' in result.stdout
    assert 'PASS real native manual setup rejection' in result.stdout
    for key in ('CASHFUSION_FEE_BUDGET','CASHFUSION_MIN_UTXO'):
        for value in ('-1','1.2','bad','2100000000000001'):
            negative=subprocess.run(['docker','run','--pull=never','--rm','--network','none','-e','USE_TOR=false','-e',key+'='+value,electron_cash_image()],
                cwd=ROOT,text=True,errors='replace',capture_output=True,timeout=30)
            assert negative.returncode!=0 and key in negative.stdout+negative.stderr,(key,value)
    report=os.environ.get('CI_REPORT_DIR')
    if report:
        directory=Path(report)/'campaign-controls';directory.mkdir(parents=True,exist_ok=True)
        (directory/'cashfusion-boundaries.json').write_text(json.dumps({'status':'PASS','image':electron_cash_image(),
            'native_runtime':'Electron Cash 4.4.6 patched consumers; real unsigned transaction and genuine Schnorr signing block',
            'enforcement_mocked':False,'public_funded_round_claimed':False,'stdout':result.stdout},indent=2)+'\n')


if __name__=='__main__':main()

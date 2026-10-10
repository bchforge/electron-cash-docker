#!/usr/bin/env python3
"""Check bilingual executable examples, required config and local file links."""
import re
import subprocess
import json
import os
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    security=(ROOT/'SECURITY.md').read_text()
    assert not (ROOT/'docs/release-security.md').exists(), 'retired release document recreated'
    assert not re.search(r'^#{1,6}\s+.*Caddy',security,re.M), 'retired Caddy section recreated'
    for token in ('FETCHED_NOT_ASSESSED','security/upstream-reviews.json',
                  'security-attestation.json','--evaluation','SECURITY_ATTESTATION',
                  'outside Git','no commit','requires real analysis'):
        assert token in security, 'missing external review documentation: '+token
    en=(ROOT/'docs/USER-GUIDE.md').read_text()
    es=(ROOT/'docs/USER-GUIDE-ES.md').read_text()
    blocks=lambda text:re.findall(r'```bash\n(.*?)```',text,re.S)
    assert blocks(en)==blocks(es), 'EN/ES executable examples differ'
    assert re.findall(r'```powershell\n(.*?)```',en,re.S)==re.findall(r'```powershell\n(.*?)```',es,re.S)
    required=('EC_LANGUAGE=en_US','EC_LANGUAGE=','NETWORK=mainnet','CASHFUSION_ENABLED=true',
              'CASHFUSION_AUTO_FUSE=false','CADDY_EDGE_BIND=127.0.0.1','CADDY_TLS_MODE=auto',
              'JSONRPC_HOST_PORT','HW_USB_GID','COMPOSE_FILE','BACKUP_DIR','stat -c')
    for token in required:
        assert token in en and token in es, token
    language_contracts=(
        (en, ('starts in English by default', 'new configuration',
              'any locale supported', 'All 38 official EC 4.4.6 locale codes are supported',
              'an empty value (`EC_LANGUAGE=`) selects System',
              'keep their saved Settings choice', 'changes survive restarts',
              'the ECD login reflects them on reload without restarting the container',
              'documentation is provided only in EN/ES')),
        (es, ('se inicia en inglés por defecto', 'configuración nueva',
              'cualquier código de idioma admitido', 'Se admiten los 38 códigos oficiales de EC 4.4.6',
              'un valor vacío (`EC_LANGUAGE=`) selecciona Sistema',
              'existentes conservan el idioma guardado',
              'Preferencias de Electron Cash: se conserva tras reiniciar',
              'el login ECD lo refleja al recargar, sin reiniciar el contenedor',
              'la documentación sigue solo en EN/ES')),
    )
    for text, phrases in language_contracts:
        normalized=' '.join(text.replace('**','').split())
        for phrase in phrases:
            assert phrase in normalized, f'missing language contract: {phrase}'
        assert not re.search(r'EC_LANGUAGE\s*=\s*es_ES', text), 'Spanish-specific language example'
        assert not re.search(r'English and Spanish are the only supported UI languages', text, re.I)
    for block in blocks(en):
        result=subprocess.run(['bash','-n'],input=block,text=True,capture_output=True)
        assert result.returncode==0,result.stderr
        for path in re.findall(r'(?:docker-compose[^\s:]*\.yml|scripts/[\w.-]+)',block):
            assert (ROOT/path).is_file(), path
    documents=[ROOT/'README.md',ROOT/'SECURITY.md',*sorted((ROOT/'docs').glob('*.md'))]
    for document in documents:
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',document.read_text()):
            if re.match(r'https?://|mailto:',target): continue
            path,_,anchor=target.partition('#')
            destination=document.parent/path if path else document
            assert destination.exists(), f'{document}: dead link {target}'
            if anchor and destination.suffix=='.md':
                headings=re.findall(r'^#{1,6}\s+(.+)$',destination.read_text(),re.M)
                slugs={re.sub(r'[^\w\s-]','',heading.lower()).replace(' ','-') for heading in headings}
                assert anchor in slugs,f'{document}: dead heading {target}'
    dockerfile=(ROOT/'docker/Dockerfile').read_text()
    assert 'GIT_SUBMODULE_SKIP=1 ./contrib/make_secp' in dockerfile
    from test_product_version import test_runtime_version_is_configured
    test_runtime_version_is_configured()
    sys.path.insert(0,str(ROOT/'docker'))
    from network_selection import custom_args, NetworkSelectionError
    for args in ('-L es_ES','-Lfr_FR','--lang=fr_FR','--language es_ES'):
        try:
            custom_args(args)
        except NetworkSelectionError as error:
            assert 'EC_LANGUAGE' in str(error)
        else:
            raise AssertionError('CLI bypass of language policy')
    sys.path.insert(0,str(ROOT/'scripts'))
    from ci import require_frozen_candidate, ValidationError
    from ci import validate_image_reuse, _context_input_manifest
    import stat
    inputs=_context_input_manifest(ROOT, ROOT/'docker/auth-session/Dockerfile')['inputs']
    descriptor={'context':str(ROOT),'configuration_sha256':'verified-config','inputs':inputs}
    proof={'status':'PASS','configuration_sha256':'verified-config','inputs':inputs,'image_id':'sha256:'+'a'*64,
           'input_modes':{p:format(stat.S_IMODE((ROOT/p).lstat().st_mode),'04o') for p in inputs}}
    validate_image_reuse(descriptor,proof)
    for key,value in [('status','FAIL'),('configuration_sha256','stale'),('inputs',{}),('input_modes',{}),('image_id','unverified')]:
        try:validate_image_reuse(descriptor,dict(proof,**{key:value}))
        except ValidationError:pass
        else:raise AssertionError('stale/unverified image reuse accepted: '+key)
    optimized=subprocess.run([sys.executable,'-O',str(ROOT/'scripts/ci.py'),'fast'],
                             text=True,capture_output=True,timeout=30)
    assert optimized.returncode!=0 and 'requires Python assertions' in optimized.stderr
    identity={'head':'base','source_fingerprint':'source','working_tree_diff_sha256':'diff',
              'untracked_source_manifest_sha256':'untracked'}
    require_frozen_candidate(identity,dict(identity))
    for key in identity:
        changed=dict(identity); changed[key]='different'
        try:
            require_frozen_candidate(identity,changed)
        except ValidationError:
            pass
        else:
            raise AssertionError('mutated source was accepted')
    env=dict(os.environ,BASIC_AUTH_PASSWORD='synthetic-doc-check',DISPLAY=':0',HW_USB_GID='10001')
    for overlays in ([],['headless'],['headless','rpc'],['gui'],['gui','hw']):
        command=['docker','compose','--env-file',str(ROOT/'.env.example'),'-f',str(ROOT/'docker-compose.yml')]
        for overlay in overlays: command+=['-f',str(ROOT/f'docker-compose.{overlay}.yml')]
        model=json.loads(subprocess.run(command+['config','--format','json'],env=env,check=True,
                                         text=True,capture_output=True).stdout)
        for name,service in model['services'].items():
            assert service.get('read_only') and not service.get('privileged'),name
            assert service.get('cap_drop')==['ALL'] and 'no-new-privileges:true' in service['security_opt'],name
            assert int(service['pids_limit'])>0 and int(service['mem_limit'])>0 and float(service['cpus'])>0,name
            assert service['logging']['options']=={'max-size':'10m','max-file':'3'},name
            assert not service.get('devices') or (name=='electron-cash' and 'hw' in overlays),name
    print('PASS bilingual examples/default contract, bash syntax, command files and local links')


if __name__=='__main__': main()

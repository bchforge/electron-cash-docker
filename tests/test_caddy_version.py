#!/usr/bin/env python3
"""Effective source/version selection and independent upstream advisory floor."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = '2.11.7'
DIGEST = '86e39de5fa0bc433a9cd574a00e7751059903401f3389c61f8937fd0ad0180f5'


def selected_model(version=None, digest=None, overlays=(), env_file=None):
    env = dict(os.environ, BASIC_AUTH_PASSWORD='caddy-version-test-only', DISPLAY=':0', HW_USB_GID='10001')
    env.pop('CADDY_VERSION', None)
    env.pop('CADDY_ARCHIVE_SHA256', None)
    if version is not None:
        env['CADDY_VERSION'] = version
    if digest is not None:
        env['CADDY_ARCHIVE_SHA256'] = digest
    cmd = ['docker', 'compose', '--profile', '*', '--env-file', str(env_file or ROOT / '.env.example'), '-f', str(ROOT / 'docker-compose.yml')]
    for overlay in overlays:
        cmd += ['-f', str(ROOT / f'docker-compose.{overlay}.yml')]
    return json.loads(subprocess.check_output(cmd + ['config', '--format', 'json'], env=env))


def static_main():
    import tempfile
    helper = ROOT / 'docker/caddy/verify-version.sh'
    for version in ('2.11.7', '2.11.8', '2.12.0', '3.0.0'):
        subprocess.run(['sh', str(helper), version, DIGEST], check=True, capture_output=True)
    for version in ('', 'latest', 'master', 'v2.11.7', '2.11', '2.11.7-rc1', '2.11.7;id', '2.11.7\n', '02.11.7', '1.99.99', '2.10.99', '2.11.4', '2.11.5', '2.11.6', '9999999.11.7'):
        result = subprocess.run(['sh', str(helper), version, DIGEST], capture_output=True)
        assert result.returncode != 0, version
    for digest in ('', 'a'*63, 'A'*64, DIGEST+';id'):
        assert subprocess.run(['sh', str(helper), VERSION, digest], capture_output=True).returncode != 0
    for overlays in ((), ('headless',), ('headless', 'rpc'), ('gui',), ('gui', 'hw')):
        model = selected_model(overlays=overlays)
        caddy = model['services']['caddy']
        for key, expected in [('CADDY_VERSION', VERSION), ('CADDY_ARCHIVE_SHA256', DIGEST)]:
            assert caddy['build']['args'][key] == caddy['environment'][key] == expected
        custom = selected_model('2.11.8', 'a'*64, overlays)['services']['caddy']
        assert custom['build']['args']['CADDY_VERSION'] == custom['environment']['CADDY_VERSION'] == '2.11.8'
        assert custom['build']['args']['CADDY_ARCHIVE_SHA256'] == 'a'*64
        for name in model['services']:
            if name != 'caddy':
                assert model['services'][name] == selected_model('2.11.8', 'a'*64, overlays)['services'][name], name
    with tempfile.TemporaryDirectory(prefix='ecd-caddy-config-') as tmp:
        old = Path(tmp) / 'old.env'
        old.write_text('\n'.join(line for line in (ROOT / '.env.example').read_text().splitlines()
                                 if not line.startswith(('CADDY_VERSION=', 'CADDY_ARCHIVE_SHA256='))) + '\n')
        assert selected_model(env_file=old)['services']['caddy']['build']['args']['CADDY_VERSION'] == VERSION
        empty = selected_model('', '')['services']['caddy']
        assert empty['build']['args']['CADDY_VERSION'] == empty['environment']['CADDY_VERSION'] == ''
    if (ROOT / '.env').is_file():
        local = selected_model(env_file=ROOT / '.env')['services']['caddy']
        for key in ('CADDY_VERSION', 'CADDY_ARCHIVE_SHA256'):
            assert local['build']['args'][key] == local['environment'][key]
        subprocess.run(['sh', str(helper), local['build']['args']['CADDY_VERSION'],
                        local['build']['args']['CADDY_ARCHIVE_SHA256']], check=True, capture_output=True)
    source = (ROOT / 'docker/caddy/Dockerfile').read_text()
    commands = '\n'.join(line for line in source.splitlines() if not line.lstrip().startswith('#'))
    assert 'go build -mod=readonly' in source and 'GOTOOLCHAIN=local' in source
    assert 'go mod tidy' not in commands and 'go get ' not in commands
    assert 'sha256sum -c -' in source and '${CADDY_VERSION}' in source
    assert 'CustomVersion=v${CADDY_VERSION}' in source
    assert 'GHSA-6365-7ppr-5r92' in helper.read_text()
    print('PASS Caddy source args across all overlays, safe omissions/empty/invalid inputs and independent advisory floor')


def main():
    static_main()
    assert os.environ.get('CI_CANDIDATE_IMAGES') == '1', 'requires actual candidate-image acceptance'
    image = os.environ['CADDY_IMAGE']
    def run(*args):
        return subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                               *args], text=True, capture_output=True, timeout=60)
    actual = run('--entrypoint', 'caddy', image, 'version')
    assert actual.returncode == 0 and actual.stdout.strip() == 'v'+VERSION, actual.stderr
    info = run('--entrypoint', 'caddy', image, 'build-info')
    assert info.returncode == 0 and 'go1.26.9' in info.stdout, info.stdout + info.stderr
    for module, version in [('github.com/quic-go/quic-go', 'v0.63.0'),
                            ('go.opentelemetry.io/otel', 'v1.46.0'),
                            ('golang.org/x/crypto', 'v0.57.0'), ('golang.org/x/net', 'v0.60.0')]:
        assert any(module in line and version in line for line in info.stdout.splitlines()), module
    modules = run('--entrypoint', 'caddy', image, 'list-modules')
    assert modules.returncode == 0
    for name in ('http.handlers.reverse_proxy', 'tls.issuance.acme', 'http.handlers.headers'):
        assert name in modules.stdout, name
    pins = run('--entrypoint', 'cat', image, '/etc/caddy/source-version', '/etc/caddy/source.sha256')
    assert pins.returncode == 0 and pins.stdout.splitlines() == [VERSION, DIGEST]
    deps = run('--entrypoint', 'cat', image, '/etc/caddy/package-deps')
    assert deps.returncode == 0 and 'github.com/caddyserver/caddy/v2/cmd/caddy' in deps.stdout
    assert not any(p.startswith('golang.org/x/crypto/openpgp') for p in deps.stdout.splitlines())
    for version in ('', 'latest', '2.11.4', '2.11.6', '2.11.8'):
        rejected = run('-e', 'CADDY_VERSION='+version, '-e', 'CADDY_ARCHIVE_SHA256='+DIGEST,
                       '-v', str(ROOT / 'docker/caddy-entrypoint.sh')+':/etc/caddy/entrypoint.sh:ro',
                       '--entrypoint', '/bin/sh', image, '/etc/caddy/entrypoint.sh')
        assert rejected.returncode != 0, version
        assert 'Starting session-authenticated' not in rejected.stdout
        assert 'Read-only file system' not in rejected.stderr, 'version guard ran after state writes'
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ecd-caddy-routing-') as tmp:
        os.chmod(tmp, 0o755)  # Public test config must be readable with all capabilities dropped.
        config = Path(tmp) / 'Caddyfile'
        config.write_text('''{
    admin off
    auto_https off
    log default {
        level ERROR
    }
}
:18080 {
    @allowed header Cookie ecd_test=allowed
    respond @allowed "ok" 200
    respond "denied" 401
}
:18081 {
    @wrong path /check
    respond @wrong "MISROUTED" 200
    respond "backend" 200
}
:18082 {
    forward_auth 127.0.0.1:18080 {
        uri /check
    }
    reverse_proxy 127.0.0.1:18081
}
''')
        # Real concurrent proxy/auth connections, no published port/network,
        # no wallet service or host credentials. Only private /tmp is writable.
        script = '''set -eu
export XDG_DATA_HOME=/tmp/data XDG_CONFIG_HOME=/tmp/config
caddy run --config /fixture/Caddyfile --adapter caddyfile >/tmp/caddy.log 2>&1 & server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" || true' EXIT
i=0
until curl -fs http://127.0.0.1:18081/ >/dev/null 2>&1; do
  kill -0 "$server" 2>/dev/null || { cat /tmp/caddy.log; exit 1; }
  i=$((i+1)); [ "$i" -lt 50 ] || { cat /tmp/caddy.log; exit 1; }; sleep .1
done
worker() {
  trap - EXIT
  n=0
  while [ "$n" -lt 10 ]; do
    body=/tmp/body-$1
    code=$(curl -sS -o "$body" -w '%{http_code}' -H 'Remote.User: allowed' -H 'Remote_User: allowed' http://127.0.0.1:18082/protected)
    [ "$code" = 401 ] && [ "$(cat "$body")" = denied ] || return 1
    code=$(curl -sS -o "$body" -w '%{http_code}' -H 'Cookie: ecd_test=allowed' http://127.0.0.1:18082/protected)
    [ "$code" = 200 ] && [ "$(cat "$body")" = backend ] || return 1
    n=$((n+1))
  done
}
pids=''
i=0
while [ "$i" -lt 8 ]; do worker "$i" & pids="$pids $!"; i=$((i+1)); done
for pid in $pids; do wait "$pid"; done
echo 'PASS 160 concurrent forward_auth/reverse_proxy requests; denied aliases never reach the backend'
'''
        routing = run('--pids-limit', '64', '--memory', '256m', '--cpus', '1',
                      '--tmpfs', '/tmp:size=16m,mode=1777',
                      '-v', tmp+':/fixture:ro', '--entrypoint', '/bin/sh', image, '-c', script)
        assert routing.returncode == 0, routing.stdout + routing.stderr
        assert 'PASS 160' in routing.stdout
    report = {'status': 'PASS', 'version': actual.stdout.strip(), 'go_version': 'go1.26.9',
              'source_sha256': DIGEST, 'build_info': info.stdout, 'modules': modules.stdout,
              'advisory': 'GHSA-6365-7ppr-5r92', 'operational_floor': '2.11.7',
              'old_or_mismatched_images_rejected_before_state_writes': True}
    report['concurrent_forward_auth_reverse_proxy_requests'] = 160
    report['routing_and_header_alias_negative_checks'] = 'PASS'
    report['GO-2026-5932'] = 'NOT_APPLICABLE: affected OpenPGP packages are absent from the actual build dependency graph'
    (Path(os.environ['CI_REPORT_DIR']) / 'caddy-version-proof.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS actual compiled Caddy v2.11.7 / Go 1.26.9, pinned modules, source provenance and prebuilt-image mismatch rejection')


if __name__ == '__main__':
    main()

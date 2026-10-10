#!/usr/bin/env python3
"""Small fail-closed supplement to the existing image scans, not a second scanner."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import urllib.request
import gzip
import io
import tarfile
import time
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'security/upstream-reviews.json'
# An intentional catalog change requires reviewing this independent coverage pin.
# Removing IDs, changing official URLs/kinds or dropping family links cannot bypass CI.
CATALOG_SHA256 = 'a8176f7699a67295991bc7e955c7083757f8f7dddcc63ce405fd9ed98bfde2cc'
FAMILIES = {'electron_cash', 'cashfusion', 'caddy', 'tor', 'novnc', 'python', 'go',
            'ubuntu', 'alpine', 'go_modules', 'python_dependencies', 'flipstarter', 'ledger'}
IMAGE_REPORTS = {'electron_cash': 'electron-cash', 'tor': 'tor', 'caddy': 'caddy',
                 'auth_session': 'auth-session', 'fail2ban': 'fail2ban', 'ledger': 'ledger'}
SOURCE_HOSTS = {'api.github.com', 'raw.githubusercontent.com', 'go.dev', 'vuln.go.dev',
                'www.python.org', 'ubuntu.com', 'secdb.alpinelinux.org',
                'www.torproject.org', 'download.torproject.org', 'forum.torproject.org', 'gitlab.com',
                'codeload.github.com'}


class SecurityFailure(RuntimeError):
    pass


class SecurityBlocked(RuntimeError):
    pass


def now():
    return dt.datetime.now(dt.timezone.utc)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True)+'\n')


def timestamp(value):
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError('timezone required')
        if result.utcoffset() != dt.timedelta(0):
            raise ValueError('UTC required')
        return result.astimezone(dt.timezone.utc)
    except (AttributeError, ValueError) as error:
        raise SecurityBlocked('invalid evidence timestamp') from error


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'v?\d+(?:\.\d+){2,3}', value):
        raise SecurityBlocked('unsupported component version: '+str(value))
    return tuple(map(int, value.lstrip('v').split('.')))


def check_floor(family, value):
    floors = {'caddy': ('2.11.7', 'GHSA-6365-7ppr-5r92 and subsequent auth/proxy fixes'),
              'tor': ('0.4.9.14', 'TROVE-2026-032/034/042/053/056/062/067 and client fixes'),
              'go': ('1.26.9', 'CVE-2026-78667 and CVE-2026-97031 (reviewed Go 1.26 line)')}
    if family in floors:
        floor, reason = floors[family]
        actual = version(value)
        if family == 'go' and actual[:2] == (1, 27) and actual[2] < 2:
            raise SecurityFailure('Go 1.27 also requires the 1.27.2 security patches')
        if actual < version(floor):
            raise SecurityFailure(f'{family} {value} is below reviewed {floor}: {reason}')


def semantic_source(raw, kind):
    """Hash security-relevant API fields, not downloads/reactions/avatar counters."""
    if kind == 'releases':
        data = json.loads(raw)
        items = data if isinstance(data, list) else [data]
        if len(items) >= 100:
            raise SecurityBlocked('release source pagination requires explicit review')
        result = [{k: item.get(k) for k in ('tag_name', 'name', 'body', 'published_at', 'draft', 'prerelease')}
                  for item in items]
    elif kind == 'advisories':
        items = json.loads(raw)
        if not isinstance(items, list) or len(items) >= 100:
            raise SecurityBlocked('advisory source incomplete or requires pagination')
        result = [{k: item.get(k) for k in ('ghsa_id', 'cve_id', 'summary', 'description',
                   'severity', 'vulnerabilities', 'updated_at', 'withdrawn_at', 'references')} for item in items]
    elif kind == 'commits':
        result = [{'sha': item['sha'], 'commit': item['commit']} for item in json.loads(raw)]
    elif kind == 'tor_notice':
        data = json.loads(raw)
        result = [{'id': p['id'], 'cooked': p['cooked'], 'updated_at': p['updated_at']}
                  for p in data['post_stream']['posts']]
    elif kind == 'tor_latest':
        matches = re.findall(rb'(0\.4\.9\.[0-9]+)', raw)
        if not matches:
            raise SecurityBlocked('cannot determine official Tor stable version')
        result = sorted(set(x.decode() for x in matches))
    elif kind == 'go_releases':
        # Scope the current supported lines; historic versions and navigation
        # changes are irrelevant, while a new patch changes this review digest.
        text = raw.decode()
        result = re.findall(r'go1\.(?:26|27)\.\d+', text)
        if not result:
            raise SecurityBlocked('Go release source has no supported-line identities')
        result = sorted(set(result))
    elif kind == 'rss':
        feed = ET.fromstring(raw)
        result = [{key: item.findtext(key) for key in ('title', 'link', 'description', 'pubDate', 'guid')}
                  for item in feed.findall('.//item')]
        if not result:
            raise SecurityBlocked('official vendor notice feed is empty/unparseable')
    elif kind == 'security_html':
        class VisibleText(HTMLParser):
            def __init__(self):
                super().__init__(); self.hidden=0; self.parts=[]
            def handle_starttag(self, tag, attrs):
                if tag in ('script','style'):self.hidden+=1
            def handle_endtag(self, tag):
                if tag in ('script','style') and self.hidden:self.hidden-=1
            def handle_data(self, data):
                if not self.hidden:self.parts.append(data)
        parser=VisibleText();parser.feed(raw.decode())
        result=' '.join(' '.join(parser.parts).split())
        if not all(token in result for token in ('Python Security','PSRT','Published advisories')):
            raise SecurityBlocked('official Python security article is missing or replaced')
    else:
        result = raw.decode('utf-8')
    return result


def fetch_source(source, directory):
    from urllib.parse import urlparse
    url = source['url']
    parsed = urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname not in SOURCE_HOSTS or parsed.username:
        raise SecurityFailure('unapproved official source URL')
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Electron-Cash-Docker-local-security-review',
                                                   'Accept': 'application/json, text/plain, */*'})
        with urllib.request.urlopen(req, timeout=30) as response:
            final = urlparse(response.url)
            if final.scheme != 'https' or final.hostname not in SOURCE_HOSTS:
                raise SecurityBlocked('official source redirected outside reviewed authorities')
            raw = response.read(10*1024*1024+1)
            encoding = response.headers.get('Content-Encoding', '')
            metadata = {'etag': response.headers.get('ETag'), 'last_modified': response.headers.get('Last-Modified')}
            metadata['final_url'] = response.url
        if not raw or len(raw) > 10*1024*1024:
            raise SecurityBlocked('official source empty or exceeds bounded review size')
        if encoding == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                raw = compressed.read(10*1024*1024+1)
            if len(raw) > 10*1024*1024:
                raise SecurityBlocked('compressed official source exceeds bounded review size')
        elif encoding not in ('', 'identity'):
            raise SecurityBlocked('unsupported official response encoding')
        semantic = semantic_source(raw, source.get('kind', 'text'))
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (source['id']+'.raw')).write_bytes(raw)
        payload = json.dumps(semantic, sort_keys=True, separators=(',', ':')).encode()
        receipt = {'source': source['id'], 'url': url, 'checked_at': now().isoformat(),
                   'raw_sha256': digest(raw), 'semantic_sha256': digest(payload), 'metadata': metadata,
                   'semantic': semantic, 'status': 'FETCHED'}
        save(directory / (source['id']+'.json'), receipt)
        return receipt
    except SecurityFailure:
        raise
    except Exception as error:
        receipt = {'source': source['id'], 'url': url, 'checked_at': now().isoformat(),
                   'status': 'BLOCKED', 'error': str(error)}
        save(directory / (source['id']+'.json'), receipt)
        return receipt


def load_catalog():
    try:
        raw = POLICY.read_bytes()
        if digest(raw) != CATALOG_SHA256:
            raise SecurityBlocked('official catalog differs from independently reviewed coverage pin')
        catalog = json.loads(raw)
        if catalog.get('schema_version') != 2 or set(catalog.get('components', {})) != FAMILIES:
            raise SecurityBlocked('invalid permanent official-source catalog')
        return catalog
    except (OSError, ValueError) as error:
        raise SecurityBlocked('official catalog missing/unreadable') from error


def canonical_digest(document):
    return digest(json.dumps(document, sort_keys=True, separators=(',', ':')).encode())


def load_attestation(report_dir):
    local = report_dir / 'security-attestation.json'
    configured = os.environ.get('SECURITY_ATTESTATION')
    path = Path(configured).resolve() if configured else local.resolve()
    if path == ROOT or ROOT in path.parents:
        raise SecurityBlocked('candidate attestation must be outside the source repository')
    try:
        policy = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise SecurityBlocked('explicit external candidate attestation missing/unreadable') from error
    return policy


def validate_reviews(policy, receipts, current=None):
    current = current or now()
    catalog = load_catalog()
    if policy.get('schema_version') != 1 or not policy.get('reviewer'):
        raise SecurityBlocked('missing accountable official-source review')
    if policy.get('catalog_sha256') != CATALOG_SHA256:
        raise SecurityBlocked('attestation does not cover the permanent catalog')
    if not policy.get('review_run_id') or not re.fullmatch(r'[0-9a-f]{64}', policy.get('candidate', '')):
        raise SecurityBlocked('review run/candidate identity missing')
    if set(policy.get('image_ids', {})) != set(IMAGE_REPORTS) or any(
            not re.fullmatch(r'sha256:[0-9a-f]{64}', value)
            for value in policy['image_ids'].values()):
        raise SecurityBlocked('approved immutable candidate images missing')
    reviewed_receipts = policy.get('reviewed_receipts', [])
    if not reviewed_receipts or canonical_digest(reviewed_receipts) != policy.get('reviewed_receipts_sha256'):
        raise SecurityBlocked('evaluated receipt bundle missing/altered')
    reviewed = timestamp(policy.get('reviewed_at'))
    expires = timestamp(policy.get('expires_at'))
    if reviewed > current or not reviewed < expires or expires <= current or expires-reviewed > dt.timedelta(days=7):
        raise SecurityBlocked('official-source review expired, future-dated or unbounded')
    components = policy.get('components', {})
    if set(components) != FAMILIES:
        raise SecurityBlocked('missing/unsupported official-source coverage: '+str(FAMILIES ^ set(components)))
    by_id = {r['source']: r for r in receipts}
    sources = {s['id']: s for s in policy.get('sources', [])}
    expected = {s['id']: s for s in catalog['sources']}
    if len(sources) != len(policy.get('sources', [])) or set(sources) != set(expected):
        raise SecurityBlocked('required source IDs omitted, duplicated or unsupported')
    for key, source in sources.items():
        if any(source.get(field) != expected[key][field] for field in ('url', 'kind')):
            raise SecurityBlocked('untrusted source URL/kind: '+key)
        if source.get('decision') != 'REVIEWED' or not source.get('assessment') or not source.get('limitations'):
            raise SecurityBlocked('source applicability was not evaluated: '+key)
    if set(by_id) != set(sources) or len(by_id) != len(receipts):
        raise SecurityBlocked('official-source receipts missing or duplicated')
    for key, source in sources.items():
        r = by_id[key]
        if r['status'] != 'FETCHED' or r['url'] != source['url']:
            raise SecurityBlocked('official source unavailable: '+key)
        checked = timestamp(r['checked_at'])
        if checked > current or current-checked > dt.timedelta(hours=24):
            raise SecurityBlocked('stale official source receipt: '+key)
        if r.get('semantic_sha256') != source.get('reviewed_sha256'):
            raise SecurityBlocked('official source changed since scoped review: '+key)
        actual = digest(json.dumps(r.get('semantic'), sort_keys=True, separators=(',', ':')).encode())
        if actual != r.get('semantic_sha256'):
            raise SecurityFailure('official source receipt content was altered: '+key)
    approved = {r.get('source'): r for r in reviewed_receipts}
    if len(approved) != len(reviewed_receipts) or set(approved) != set(expected):
        raise SecurityBlocked('evaluated source coverage missing/duplicated')
    for key, r in approved.items():
        if (r.get('status') != 'FETCHED' or r.get('url') != expected[key]['url'] or
                r.get('semantic_sha256') != sources[key].get('reviewed_sha256') or
                canonical_digest(r.get('semantic')) != r.get('semantic_sha256') or
                r.get('review_run_id') != policy['review_run_id'] or
                r.get('candidate') != policy['candidate']):
            raise SecurityBlocked('evaluated receipts belong to another review/candidate or were altered')
        checked = timestamp(r.get('checked_at'))
        if checked > reviewed or reviewed-checked > dt.timedelta(hours=24):
            raise SecurityBlocked('review did not evaluate fresh downloaded evidence')
    for family, review in components.items():
        if review.get('decision') != 'REVIEWED' or not review.get('assessment') or not review.get('limitations'):
            raise SecurityBlocked('incomplete assessment: '+family)
        required = catalog['components'][family]['sources']
        if (set(review.get('sources', [])) != set(required) or
                len(review.get('sources', [])) != len(required) or not review.get('versions')):
            raise SecurityBlocked('unsupported source coverage: '+family)


def official_preflight(report_dir, refresh_only=False, manifest=None):
    catalog = load_catalog()
    if ROOT == report_dir.resolve() or ROOT in report_dir.resolve().parents:
        raise SecurityBlocked('security evidence must be outside the source repository')
    if manifest is None:
        import ci
        candidate = ci.candidate_identity(report_dir)['source_fingerprint']
        run_id = report_dir.name
    else:
        candidate = manifest['candidate']['source_fingerprint']
        run_id = manifest.get('run_id', report_dir.name)
    directory = report_dir / 'official-sources'
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(lambda s: fetch_source(s, directory), catalog['sources']))
    for receipt in receipts:
        receipt.update(review_run_id=run_id, candidate=candidate)
        save(directory / (receipt['source']+'.json'), receipt)
    result = {'status': 'RUNNING', 'run_id': run_id, 'candidate': candidate,
              'receipts': receipts,
              'review_policy_sha256': digest(POLICY.read_bytes())}
    try:
        if any(r.get('status') != 'FETCHED' for r in receipts):
            raise SecurityBlocked('one or more required official sources unavailable')
        if not refresh_only:
            policy = load_attestation(report_dir)
            validate_reviews(policy, receipts)
            if policy['candidate'] != candidate:
                raise SecurityBlocked('attestation belongs to another candidate')
            verify_source_files(report_dir, result, {'candidate': {'source_fingerprint': candidate},
                                                    'run_id': run_id})
            save(report_dir / 'security-attestation.json', policy)
            result['attestation_sha256'] = digest((report_dir / 'security-attestation.json').read_bytes())
        result['status'] = 'FETCHED_NOT_ASSESSED' if refresh_only else 'PASS'
    except (SecurityBlocked, SecurityFailure) as error:
        result['status'] = 'BLOCKED' if isinstance(error, SecurityBlocked) else 'FAIL'
        result['error'] = str(error)
        raise
    finally:
        save(report_dir / 'official-source-review.json', result)
    return result


def verify_source_files(report_dir, official, manifest):
    from urllib.parse import urlparse
    if (official.get('run_id') != manifest.get('run_id', report_dir.name) or
            official.get('candidate') != manifest['candidate']['source_fingerprint'] or
            official.get('review_policy_sha256') != CATALOG_SHA256):
        raise SecurityFailure('source receipts belong to another run/candidate/catalog')
    catalog = load_catalog()
    sources = {s['id']: s for s in catalog['sources']}
    for receipt in official['receipts']:
        key = receipt['source']
        if key not in sources:
            raise SecurityFailure('unknown official source receipt')
        try:
            disk_receipt = json.loads((report_dir / 'official-sources' / (key+'.json')).read_text())
            raw = (report_dir / 'official-sources' / (key+'.raw')).read_bytes()
        except (OSError, ValueError) as error:
            raise SecurityFailure('downloaded source evidence missing') from error
        if (disk_receipt != receipt or digest(raw) != receipt.get('raw_sha256') or
                canonical_digest(semantic_source(raw, sources[key]['kind'])) != receipt.get('semantic_sha256') or
                receipt.get('review_run_id') != official['run_id'] or
                receipt.get('candidate') != official['candidate']):
            raise SecurityFailure('downloaded source evidence replaced or reused across runs')
        final = urlparse(receipt.get('metadata', {}).get('final_url', ''))
        if (final.scheme != 'https' or final.hostname not in SOURCE_HOSTS or
                final.username or final.port not in (None, 443)):
            raise SecurityFailure('download receipt has inconsistent official authority metadata')


def assess_caddy_advisories(receipt, installed):
    """Use upstream patched versions/ranges, including GHSA IDs without CVEs."""
    decisions = []
    for advisory in receipt['semantic']:
        for affected in advisory.get('vulnerabilities') or []:
            if advisory.get('withdrawn_at'):
                decision = 'WITHDRAWN_BY_UPSTREAM'
            else:
                patched = str(affected.get('patched_versions') or '').replace('v.', '').lstrip('v')
                if re.fullmatch(r'\d+\.\d+\.\d+', patched) and version(installed) >= version(patched):
                    decision = 'PATCHED_UPSTREAM_VERSION'
                else:
                    spec = affected.get('vulnerable_version_range', '')
                    match = re.fullmatch(r'\s*(<=|<)\s*v?(\d+\.\d+\.\d+)\s*', spec)
                    if match and (version(installed) > version(match[2]) or
                                  match[1] == '<' and version(installed) == version(match[2])):
                        decision = 'OUTSIDE_PUBLISHED_AFFECTED_RANGE'
                    else:
                        raise SecurityFailure('unhandled applicable/unsupported Caddy advisory '+advisory['ghsa_id'])
            decisions.append({'id': advisory['ghsa_id'], 'cve': advisory['cve_id'],
                'severity': advisory['severity'], 'affected': affected.get('vulnerable_version_range'),
                'patched': affected.get('patched_versions'), 'installed': installed, 'decision': decision})
    if not any(d['id'] == 'GHSA-6365-7ppr-5r92' for d in decisions):
        raise SecurityBlocked('required direct Caddy advisory is missing from upstream coverage')
    return decisions


def collect_psf_advisories(receipt, report_dir):
    commit = receipt['semantic'][0]['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise SecurityBlocked('PSF advisory revision is not immutable')
    url = 'https://codeload.github.com/psf/advisory-database/tar.gz/'+commit
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(10*1024*1024+1)
        if len(raw) > 10*1024*1024:
            raise SecurityBlocked('PSF database exceeds bounded input')
        records = []
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            members = archive.getmembers()
            if len(members) > 10000 or sum(m.size for m in members) > 50*1024*1024:
                raise SecurityBlocked('PSF advisory archive exceeds bounded expansion')
            for member in members:
                if member.isfile() and '/advisories/python/' in member.name and member.name.endswith('.json'):
                    if member.size > 1024*1024:
                        raise SecurityBlocked('PSF advisory record exceeds bounded size')
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise SecurityBlocked('PSF advisory member is unreadable')
                    data = json.load(stream)
                    records.append({k: data.get(k) for k in ('id', 'aliases', 'modified', 'affected', 'references')})
        if not records:
            raise SecurityBlocked('PSF official advisory database has no Python coverage')
        result = {'source_url': url, 'commit': commit, 'checked_at': now().isoformat(),
                  'archive_sha256': digest(raw), 'advisories': records,
                  'applicability_method': 'Upstream ranges retained; Ubuntu runtime evaluated using actual distro/source-package versions and fresh vendor scan/backport mapping, not the raw interpreter microversion.'}
        save(report_dir/'python-official-advisories.json', result)
        return result
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SecurityBlocked('PSF advisory database unavailable: '+str(error)) from error


def validate_inventory(inventory, policy):
    if set(inventory.get('families', {})) != FAMILIES:
        raise SecurityFailure('critical component family missing or unknown')
    if set(inventory.get('images', {})) != set(IMAGE_REPORTS):
        raise SecurityFailure('one or more actual candidate images are missing')
    for key, image in inventory['images'].items():
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image.get('id', '')) or not image.get('packages'):
            raise SecurityFailure('missing actual-image identity or OS/package SBOM: '+key)
    for family, record in inventory['families'].items():
        if not record.get('evidence') or not record.get('version') or not record.get('provenance'):
            raise SecurityFailure('component identity unproven: '+family)
        if record.get('origin') not in {'runtime', 'runtime-and-scanner', 'scanner', 'verified-build-inputs'}:
            raise SecurityFailure('unsupported identity coverage: '+family)
        check_floor(family, record['version'])
        accepted = policy['components'][family].get('versions', [])
        if not accepted or record['version'] not in accepted:
            raise SecurityBlocked('component version not covered by official review: '+family+' '+record['version'])


def validate_package_ecosystems(items):
    allowed = {'ubuntu', 'debian', 'alpine', 'python-pkg', 'gobinary', 'node-pkg'}
    if {p['coverage'] for p in items} - allowed:
        raise SecurityBlocked('new package ecosystem needs official-source coverage')
    for p in items:
        if p['coverage'] == 'node-pkg' and (p['Name'], p['Version']) != ('@novnc/novnc', '1.6.0'):
            raise SecurityBlocked('unreviewed bundled JavaScript component')


def inventory(ci, images, ids, report_dir, environment, trivy):
    result = {'schema_version': 1, 'generated_at': now().isoformat(), 'images': {}, 'families': {}}
    packages = []
    for key, report in IMAGE_REPORTS.items():
        document = json.loads((report_dir / (report+'.json')).read_text())
        if document.get('Metadata', {}).get('ImageID') != ids[key]:
            raise SecurityFailure('scanner SBOM does not bind to actual image: '+key)
        items = [{k: p.get(k) for k in ('ID', 'Name', 'Version', 'SrcName', 'SrcVersion', 'Identifier')}
                 | {'coverage': r['Type']} for r in document.get('Results', []) for p in r.get('Packages', [])]
        if not items or not any(p['coverage'] in {'ubuntu', 'alpine', 'debian'} for p in items):
            raise SecurityFailure('missing OS package inventory: '+key)
        validate_package_ecosystems(items)
        result['images'][key] = {'id': ids[key], 'reference': images[key], 'packages': items,
                                 'os': document['Metadata'].get('OS'), 'scan_report': report+'.json'}
        packages.extend(items)
        ci.checked([str(trivy), 'convert', '--format', 'cyclonedx', '--output',
                    str(report_dir / ('sbom-'+key+'.cdx.json')), str(report_dir / (report+'.json'))],
                   timeout=120, log_path=report_dir / 'inventory-commands.log')
    def probe(image, executable, *args):
        image = ids[next(key for key, reference in images.items() if reference == image)]
        return ci.checked(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                           '--pids-limit', '64', '--memory', '256m', '--cpus', '1',
                           '--security-opt', 'no-new-privileges:true', '-e', 'PYTHONDONTWRITEBYTECODE=1',
                           '--entrypoint', executable, image, *args], env=environment, timeout=60,
                          log_path=report_dir / 'inventory-commands.log').stdout.strip()
    wallet = json.loads(probe(images['electron_cash'], '/opt/electroncash-venv/bin/python', '-c',
        "import json,platform,hashlib,importlib.util; from pathlib import Path; from electroncash.version import PACKAGE_VERSION; "
        "fusion=Path(importlib.util.find_spec('electroncash_plugins.fusion').origin); "
        "print(json.dumps({'electron_cash':PACKAGE_VERSION,'python':platform.python_version(),"
        "'novnc':json.loads(Path('/opt/noVNC/package.json').read_text())['version'],"
        "'cashfusion_sha256':hashlib.sha256(fusion.read_bytes()).hexdigest(),"
        "'flipstarter_sha256':hashlib.sha256(Path('/preinstalled-plugins/flipstarter-1.5.zip').read_bytes()).hexdigest()}))"))
    caddy = probe(images['caddy'], 'caddy', 'version').lstrip('v')
    go_info = probe(images['caddy'], 'caddy', 'build-info')
    match = re.search(r'go(\d+\.\d+\.\d+)', go_info)
    if not match:
        raise SecurityFailure('actual Caddy executable has no verifiable Go toolchain identity')
    go = match.group(1)
    tor_info = probe(images['tor'], '/usr/local/bin/tor', '--version')
    tor_match = re.search(r'Tor version ([0-9.]+)', tor_info)
    if not tor_match:
        raise SecurityFailure('actual Tor binary version missing')
    tor = tor_match.group(1).rstrip('.')
    plugin = json.loads((ROOT / 'plugins.json').read_text())['plugins']
    if len(plugin) != 1 or plugin[0]['package_name'] != 'flipstarter' or wallet['flipstarter_sha256'] != plugin[0]['sha256']:
        raise SecurityFailure('unknown or unverified bundled external plugin')
    for name, expected in [('btchip-python', '0.1.32'), ('hidapi', '0.14.0.post4')]:
        actual = {p['Version'] for p in result['images']['ledger']['packages'] if p['Name'] == name}
        if actual != {expected}:
            raise SecurityFailure('critical hardware dependency missing or mismatched: '+name)
    for key, image in result['images'].items():
        if key != 'caddy' and image['os'] != {'Family': 'ubuntu', 'Name': '24.04'}:
            # Additional metadata fields are harmless, but a different distro
            # is never silently covered by the Ubuntu review.
            if not image['os'] or image['os'].get('Family') != 'ubuntu' or image['os'].get('Name') != '24.04':
                raise SecurityBlocked('unreviewed actual runtime distro: '+key)
    expected_modules = {'github.com/quic-go/quic-go': 'v0.63.0', 'go.opentelemetry.io/otel': 'v1.46.0',
                        'golang.org/x/crypto': 'v0.57.0', 'golang.org/x/net': 'v0.60.0'}
    for name, expected in expected_modules.items():
        if not any(name in line and expected in line for line in go_info.splitlines()):
            raise SecurityFailure('critical Caddy module drift: '+name)
    values = {'electron_cash': wallet['electron_cash'], 'cashfusion': wallet['electron_cash'],
              'novnc': wallet['novnc'], 'python': wallet['python'], 'caddy': caddy,
              'go': go, 'tor': tor, 'flipstarter': plugin[0]['version'],
              'ubuntu': '24.04', 'alpine': result['images']['caddy']['os']['Name'],
              'python_dependencies': 'requirements.txt', 'go_modules': 'Caddy '+caddy,
              'ledger': 'btchip-python 0.1.32 / hidapi 0.14.0.post4'}
    for family, value in values.items():
        result['families'][family] = {'version': value,
            'origin': 'runtime-and-scanner' if family not in {'ubuntu', 'alpine', 'python_dependencies', 'go_modules', 'ledger'} else 'scanner',
            'evidence': 'inventory-commands.log and per-image Trivy JSON/CycloneDX SBOM',
            'provenance': 'actual immutable candidate image; verified build input identities in gate manifest'}
    result['families']['cashfusion']['version_scope'] = 'bundled EC source revision, not an independent plugin release'
    result['families']['cashfusion']['runtime_source_sha256'] = wallet['cashfusion_sha256']
    result['families']['flipstarter']['runtime_zip_sha256'] = wallet['flipstarter_sha256']
    result['go_build_info'] = go_info
    result['coverage_limits'] = ['Source-built main Go module may be (devel); Caddy core identity is separately probed.',
        'noVNC/CashFusion/Tor are not inferred absent from package-scanner results.',
        'OS/Python vendor backports require distro package versions, not upstream microversion comparison.',
        'SBOM describes discovered packages, not arbitrary wallet/user data or an undisclosed-vulnerability guarantee.']
    result['build_input_files'] = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in
        [ROOT/'.env.example', ROOT/'requirements.txt', ROOT/'plugins.json', *sorted((ROOT/'docker').rglob('Dockerfile'))]}
    save(report_dir / 'component-inventory.json', result)
    return result


def await_external_review(report_dir, manifest):
    """Expose actual inventory for explicit external evaluation; never approve it."""
    configured = os.environ.get('SECURITY_ATTESTATION')
    path = Path(configured).resolve() if configured else report_dir / 'security-attestation.json'
    if path == ROOT or ROOT in path.parents:
        raise SecurityBlocked('candidate attestation must be outside the source repository')
    try:
        seconds = int(os.environ.get('CI_SECURITY_REVIEW_WAIT_SECONDS', '0'))
    except ValueError as error:
        raise SecurityBlocked('invalid external review wait bound') from error
    if not 0 <= seconds <= 3600:
        raise SecurityBlocked('external review wait must be between 0 and 3600 seconds')
    save(report_dir / 'security-review-ready.json', {
        'status': 'INVENTORIED_NOT_ASSESSED', 'candidate': manifest['candidate']['source_fingerprint'],
        'run_id': manifest.get('run_id', report_dir.name), 'image_ids': manifest['candidate_image_ids'],
        'inventory_sha256': digest((report_dir / 'component-inventory.json').read_bytes()),
        'attestation_path': str(path), 'wait_seconds': seconds})
    deadline = time.monotonic() + seconds
    while not path.is_file() and time.monotonic() < deadline:
        time.sleep(min(2, max(0, deadline-time.monotonic())))
    if not path.is_file():
        raise SecurityBlocked('explicit external evaluation required after actual candidate inventory')


def complete_security(ci, images, ids, report_dir, environment, trivy, manifest):
    try:
        sources = json.loads((report_dir / 'official-source-review.json').read_text())
        verify_source_files(report_dir, sources, manifest)
        policy = json.loads((report_dir/'security-attestation.json').read_text())
        validate_reviews(policy, sources['receipts'])
        if (policy['candidate'] != manifest['candidate']['source_fingerprint'] or
                policy['image_ids'] != ids or ids != manifest.get('candidate_image_ids')):
            raise SecurityBlocked('approved candidate/image identities differ from actual tested candidate')
        if digest((report_dir/'security-attestation.json').read_bytes()) != sources.get('attestation_sha256'):
            raise SecurityFailure('attestation replaced after preflight')
        result = inventory(ci, images, ids, report_dir, environment, trivy)
        validate_inventory(result, policy)
        validate_scan_artifacts(report_dir, ids, result)
        by_id = {r['source']: r for r in sources['receipts']}
        caddy = assess_caddy_advisories(by_id['caddy_advisories'], result['families']['caddy']['version'])
        psf = collect_psf_advisories(by_id['python_advisory_revision'], report_dir)
        assessment = {'status': 'PASS', 'candidate': manifest['candidate']['source_fingerprint'],
                      'run_id': manifest.get('run_id', report_dir.name),
                      'attestation_sha256': sources['attestation_sha256'],
                      'inventory_sha256': digest((report_dir/'component-inventory.json').read_bytes()),
                      'policy_sha256': digest(POLICY.read_bytes()), 'assessed_at': now().isoformat(),
                      'families': policy['components'], 'image_ids': ids,
                      'caddy_advisory_decisions': caddy, 'python_advisories_considered': len(psf['advisories']),
                      'scanner_policy': 'HIGH/CRITICAL fail unless exact active no-fix exception; lower severities retained separately',
                      'limits': result['coverage_limits']}
        save(report_dir / 'release-security-assessment.json', assessment)
        manifest['release_security'] = {'status': 'PASS', 'inventory': 'component-inventory.json',
            'assessment': 'release-security-assessment.json', 'official_sources': 'official-source-review.json'}
        files = ['security-attestation.json', 'official-source-review.json', 'component-inventory.json',
                 'release-security-assessment.json', 'python-official-advisories.json',
                 'inventory-commands.log', 'caddy-package-deps.txt']
        files += [name+'.json' for name in IMAGE_REPORTS.values()]
        files += ['sbom-'+key+'.cdx.json' for key in IMAGE_REPORTS]
        files += ['official-sources/'+s['id']+suffix for s in load_catalog()['sources']
                  for suffix in ('.json', '.raw')]
        manifest['release_security']['artifact_sha256'] = {
            name: digest((report_dir/name).read_bytes()) for name in files}
        ci.persist_manifest(manifest)
    except (SecurityFailure, SecurityBlocked, OSError, ValueError, KeyError, TypeError) as error:
        status = 'BLOCKED' if isinstance(error, SecurityBlocked) else 'FAIL'
        save(report_dir / 'release-security-assessment.json', {'status': status, 'error': str(error)})
        manifest['release_security'] = {'status': status, 'error': str(error)}
        ci.persist_manifest(manifest)
        raise


def verify_completion(manifest, report_dir):
    if manifest.get('release_security', {}).get('status') != 'PASS':
        raise SecurityFailure('mandatory release security assessment did not complete')
    try:
        assessment = json.loads((report_dir/'release-security-assessment.json').read_text())
        inventory_doc = json.loads((report_dir/'component-inventory.json').read_text())
        official = json.loads((report_dir/'official-source-review.json').read_text())
        policy = json.loads((report_dir/'security-attestation.json').read_text())
    except (OSError, ValueError) as error:
        raise SecurityFailure('required security evidence missing/unreadable') from error
    if (assessment.get('status') != 'PASS' or official.get('status') != 'PASS' or
            assessment.get('candidate') != manifest['candidate']['source_fingerprint'] or
            assessment.get('image_ids') != manifest.get('candidate_image_ids') or
            policy.get('candidate') != assessment.get('candidate') or
            policy.get('image_ids') != assessment.get('image_ids') or
            assessment.get('run_id') != manifest.get('run_id', report_dir.name) or
            assessment.get('attestation_sha256') != digest((report_dir/'security-attestation.json').read_bytes()) or
            official.get('attestation_sha256') != assessment.get('attestation_sha256') or
            assessment.get('policy_sha256') != digest(POLICY.read_bytes()) or
            assessment.get('inventory_sha256') != digest((report_dir/'component-inventory.json').read_bytes())):
        raise SecurityFailure('security evidence is stale, incomplete or belongs to another candidate')
    validate_inventory(inventory_doc, policy)
    validate_reviews(policy, official['receipts'])
    verify_source_files(report_dir, official, manifest)
    hashes = manifest['release_security'].get('artifact_sha256', {})
    required = {'security-attestation.json', 'official-source-review.json', 'component-inventory.json',
                'release-security-assessment.json', 'python-official-advisories.json',
                'inventory-commands.log', 'caddy-package-deps.txt'}
    required.update(name+'.json' for name in IMAGE_REPORTS.values())
    required.update('sbom-'+key+'.cdx.json' for key in IMAGE_REPORTS)
    required.update('official-sources/'+s['id']+suffix for s in load_catalog()['sources']
                    for suffix in ('.json', '.raw'))
    if set(hashes) != required:
        raise SecurityFailure('mandatory security artifacts missing from execution manifest')
    for name, sha in hashes.items():
        try:
            actual = digest((report_dir/name).read_bytes())
        except OSError as error:
            raise SecurityFailure('security artifact missing: '+name) from error
        if actual != sha:
            raise SecurityFailure('security artifact replaced: '+name)
    if {key: image['id'] for key, image in inventory_doc['images'].items()} != assessment['image_ids']:
        raise SecurityFailure('inventory image identities differ from tested candidate')
    validate_scan_artifacts(report_dir, assessment['image_ids'], inventory_doc)
    by_id = {r['source']: r for r in official['receipts']}
    if assess_caddy_advisories(by_id['caddy_advisories'], inventory_doc['families']['caddy']['version']) != assessment.get('caddy_advisory_decisions'):
        raise SecurityFailure('Caddy advisory assessment inconsistent')
    import ci
    ci.load_vulnerability_exceptions()  # Recheck expiry at final verification, too.


def validate_scan_artifacts(report_dir, ids, inventory_doc):
    for key, name in IMAGE_REPORTS.items():
        try:
            scan = json.loads((report_dir/(name+'.json')).read_text())
            sbom = json.loads((report_dir/('sbom-'+key+'.cdx.json')).read_text())
        except (OSError, ValueError) as error:
            raise SecurityFailure('actual-image scanner/SBOM artifact missing or unreadable') from error
        packages = [{k: p.get(k) for k in ('ID', 'Name', 'Version', 'SrcName', 'SrcVersion', 'Identifier')}
                    | {'coverage': row['Type']} for row in scan.get('Results', [])
                    for p in row.get('Packages', [])]
        if (scan.get('Metadata', {}).get('ImageID') != ids[key] or not packages or
                packages != inventory_doc['images'][key]['packages'] or
                sbom.get('bomFormat') != 'CycloneDX' or not sbom.get('components')):
            raise SecurityFailure('incomplete or mismatched actual-image scanner/SBOM evidence: '+key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['fetch', 'inventory', 'review', 'complete', 'verify'])
    parser.add_argument('--report-dir', type=Path, required=True)
    parser.add_argument('--evaluation', type=Path, help='responsibly evaluated, explicitly approved JSON')
    parser.add_argument('--trivy', type=Path, help='real Trivy executable for complete')
    args = parser.parse_args()
    try:
        import ci
        if ROOT == args.report_dir.resolve() or ROOT in args.report_dir.resolve().parents:
            raise SecurityBlocked('report directory must be outside Git source')
        if args.mode in ('inventory', 'complete', 'verify'):
            manifest = json.loads((args.report_dir/'gate-manifest.json').read_text())
            current_candidate = ci.candidate_identity(args.report_dir)['source_fingerprint']
            if manifest.get('candidate', {}).get('source_fingerprint') != current_candidate:
                raise SecurityBlocked('execution manifest does not cover current source candidate')
            if args.mode == 'verify':
                verify_completion(manifest, args.report_dir)
                print('PASS security evidence verification; full gate acceptance remains mandatory')
            else:
                if not args.trivy:
                    raise SecurityBlocked('--trivy is required for actual-image inventory')
                ci.assert_safe_docker_endpoint()
                if args.mode == 'inventory':
                    inventory(ci, manifest['candidate_images'], manifest['candidate_image_ids'],
                              args.report_dir, os.environ.copy(), args.trivy)
                    print('INVENTORIED_NOT_ASSESSED')
                else:
                    complete_security(ci, manifest['candidate_images'], manifest['candidate_image_ids'],
                                      args.report_dir, os.environ.copy(), args.trivy, manifest)
                    print('PASS security completion; full gate acceptance remains mandatory')
            return 0
        if args.mode == 'review':
            if not args.evaluation or ROOT in args.evaluation.resolve().parents:
                raise SecurityBlocked('--evaluation outside Git is required; fetch never approves')
            policy = json.loads(args.evaluation.read_text())
            report = json.loads((args.report_dir/'official-source-review.json').read_text())
            validate_reviews(policy, report['receipts'])
            candidate = ci.candidate_identity(args.report_dir)['source_fingerprint']
            if policy['candidate'] != candidate or report['candidate'] != candidate:
                raise SecurityBlocked('evaluation does not cover current candidate')
            verify_source_files(args.report_dir, report, {'candidate': {'source_fingerprint': candidate},
                                                         'run_id': report['run_id']})
            save(args.report_dir/'security-attestation.json', policy)
            report.update(status='PASS', attestation_sha256=digest((args.report_dir/'security-attestation.json').read_bytes()))
            save(args.report_dir/'official-source-review.json', report)
        else:
            report = official_preflight(args.report_dir, refresh_only=True)
            catalog = load_catalog()
            receipts = report['receipts']
            by_id = {r['source']: r for r in receipts}
            template = {'schema_version': 1, 'catalog_sha256': CATALOG_SHA256,
                        'reviewer': '', 'reviewed_at': None, 'expires_at': None,
                        'review_run_id': report['run_id'], 'candidate': report['candidate'],
                        'image_ids': {}, 'reviewed_receipts': receipts,
                        'reviewed_receipts_sha256': canonical_digest(receipts),
                        'sources': [s | {'reviewed_sha256': by_id[s['id']].get('semantic_sha256'),
                                        'decision': 'NOT_ASSESSED', 'assessment': '', 'limitations': ''}
                                    for s in catalog['sources']],
                        'components': {k: v | {'versions': [], 'decision': 'NOT_ASSESSED',
                                              'assessment': '', 'limitations': ''}
                                       for k, v in catalog['components'].items()}}
            template_path = args.report_dir/'security-evaluation.pending.json'
            if not template_path.exists():
                save(template_path, template)
        print(report['status'])
        for r in report['receipts']:
            print(r['source'], r['status'], r.get('semantic_sha256', ''), r.get('error', ''))
        return 0 if report['status'] == 'PASS' else 2
    except (SecurityFailure, SecurityBlocked, OSError, ValueError, KeyError, TypeError) as error:
        print('BLOCKED' if isinstance(error, SecurityBlocked) else 'FAIL', str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

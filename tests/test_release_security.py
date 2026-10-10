#!/usr/bin/env python3
"""Falsify security success when evidence, identities or official coverage fail."""
import copy
import datetime as dt
import json
import sys
import tempfile
import unittest
import urllib.error
import subprocess
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_security as security
import ci
import docker_ownership


class SecurityGateTests(unittest.TestCase):
    def test_immutable_inventory_probe_requires_completed_owned_image_claim(self):
        image_id = 'sha256:'+'a'*64
        claim = {'kind':'image', 'name':'candidate:unique', 'owner_token':'owner',
                 'preflight':'ABSENT', 'build_attempted':True, 'expected_id':image_id}
        with patch.dict('os.environ', {'CI_CANDIDATE_IMAGES':'1'}), patch.object(
                docker_ownership, '_docker', return_value=subprocess.CompletedProcess([],0,image_id+'\n','')):
            self.assertEqual(docker_ownership._verified_image_id(image_id,[claim],'owner'),image_id)
            for claims, owner in [([], 'owner'), ([claim], 'foreign'),
                                  ([claim | {'build_attempted':False}], 'owner'),
                                  ([claim | {'expected_id':'sha256:'+'b'*64}], 'owner')]:
                with self.assertRaises(docker_ownership.OwnershipError):
                    docker_ownership._verified_image_id(image_id,claims,owner)

    def test_actual_inventory_is_exposed_but_missing_evaluation_blocks(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ',
                {'CI_SECURITY_REVIEW_WAIT_SECONDS': '0'}, clear=True):
            root = Path(directory)
            security.save(root/'component-inventory.json', {'actual_inventory': True})
            manifest = {'candidate': {'source_fingerprint': 'c'*64},
                        'run_id': 'real-run', 'candidate_image_ids': {'caddy': 'sha256:'+'a'*64}}
            with self.assertRaises(security.SecurityBlocked):
                security.await_external_review(root, manifest)
            ready = json.loads((root/'security-review-ready.json').read_text())
            self.assertEqual(ready['status'], 'INVENTORIED_NOT_ASSESSED')
            self.assertEqual(ready['image_ids'], manifest['candidate_image_ids'])
            self.assertFalse((root/'security-attestation.json').exists())

    def test_real_novnc_node_package_is_covered_but_unknown_js_is_blocked(self):
        security.validate_package_ecosystems([{'coverage':'node-pkg','Name':'@novnc/novnc','Version':'1.6.0'}])
        with self.assertRaises(security.SecurityBlocked):security.validate_package_ecosystems(
            [{'coverage':'node-pkg','Name':'unreviewed-js','Version':'1.0.0'}])
        with self.assertRaises(security.SecurityBlocked):security.validate_package_ecosystems(
            [{'coverage':'unknown-ecosystem','Name':'unknown','Version':'1'}])

    def test_security_article_nonce_does_not_hide_real_content_changes(self):
        first=b'<h1>Python Security</h1><p>PSRT Published advisories</p><script nonce="one">dynamic()</script>'
        other=first.replace(b'nonce="one"',b'nonce="two"')
        self.assertEqual(security.semantic_source(first,'security_html'),security.semantic_source(other,'security_html'))
        changed=first.replace(b'advisories',b'advisories New critical issue')
        self.assertNotEqual(security.semantic_source(first,'security_html'),security.semantic_source(changed,'security_html'))

    def setUp(self):
        self.current = security.now()
        catalog = security.load_catalog()
        self.policy = copy.deepcopy(catalog)
        self.policy.update(schema_version=1, reviewer='Responsible test evaluator (fixture)',
                           catalog_sha256=security.CATALOG_SHA256, review_run_id='fixture-review',
                           candidate='c'*64,
                           image_ids={key:'sha256:'+'a'*64 for key in security.IMAGE_REPORTS})
        versions = {'electron_cash':'4.4.6','cashfusion':'4.4.6','caddy':'2.11.7','tor':'0.4.9.14',
                    'novnc':'1.6.0','python':'3.12.3','go':'1.26.9','ubuntu':'24.04','alpine':'3.23.6',
                    'go_modules':'Caddy 2.11.7','python_dependencies':'requirements.txt','flipstarter':'1.5',
                    'ledger':'btchip-python 0.1.32 / hidapi 0.14.0.post4'}
        for family, row in self.policy['components'].items():
            row.update(versions=[versions[family]], decision='REVIEWED',
                       assessment='Fixture scoped review against installed component and vendor notices',
                       limitations='Synthetic unit evidence; no release authorization')
        self.policy['reviewed_at'] = (self.current-dt.timedelta(hours=1)).isoformat()
        self.policy['expires_at'] = (self.current+dt.timedelta(days=1)).isoformat()
        self.receipts = []
        for s in self.policy['sources']:
            semantic = {'test_fixture': s['id']}
            sha = security.digest(json.dumps(semantic,sort_keys=True,separators=(',',':')).encode())
            s['reviewed_sha256'] = sha
            s.update(decision='REVIEWED', assessment='Fixture notice applicability evaluated',
                     limitations='Synthetic unit source only')
            self.receipts.append({'source':s['id'],'url':s['url'],'status':'FETCHED',
                                  'checked_at':self.current.isoformat(),'semantic':semantic,'semantic_sha256':sha})
        self.policy['reviewed_receipts'] = [r | {'checked_at':(self.current-dt.timedelta(hours=2)).isoformat(),
                                                'review_run_id':'fixture-review','candidate':'c'*64}
                                           for r in self.receipts]
        self.policy['reviewed_receipts_sha256'] = security.canonical_digest(self.policy['reviewed_receipts'])
        self.inventory = {'images': {key:{'id':'sha256:'+'a'*64,'packages':[{'Name':'fixture','Version':'1'}]}
                                     for key in security.IMAGE_REPORTS},
            'coverage_limits':['Synthetic unit evidence, not a released candidate'],
            'families': {family:{'version':row['versions'][0],'origin':'runtime',
                                'evidence':'unit fixture only','provenance':'unit fixture only'}
                         for family,row in self.policy['components'].items()}}

    def test_patched_complete_scoped_evidence_is_accepted(self):
        security.validate_reviews(self.policy,self.receipts,self.current)
        security.validate_inventory(self.inventory,self.policy)

    def test_known_bad_caddy_rejected_even_with_empty_scanner_findings(self):
        self.inventory['families']['caddy']['version']='2.11.4'
        self.inventory['scanner_findings']=[]
        with self.assertRaises(security.SecurityFailure):security.validate_inventory(self.inventory,self.policy)

    def test_known_tor_and_go_regressions_rejected(self):
        for family,value in [('tor','0.4.9.11'),('go','1.26.8'),('go','1.27.0')]:
            with self.assertRaises(security.SecurityFailure):security.check_floor(family,value)

    def test_missing_or_unknown_critical_component_is_fatal(self):
        for family in security.FAMILIES:
            changed=copy.deepcopy(self.inventory);del changed['families'][family]
            with self.assertRaises(security.SecurityFailure):security.validate_inventory(changed,self.policy)
        self.inventory['families']['unknown_plugin']={}
        with self.assertRaises(security.SecurityFailure):security.validate_inventory(self.inventory,self.policy)

    def test_unknown_version_or_claimed_identity_cannot_pass(self):
        self.inventory['families']['caddy']['version']='2.11.8'
        with self.assertRaises(security.SecurityBlocked):security.validate_inventory(self.inventory,self.policy)
        self.inventory['families']['caddy']['version']='2.11.7'
        self.inventory['families']['caddy']['origin']='claimed'
        with self.assertRaises(security.SecurityFailure):security.validate_inventory(self.inventory,self.policy)

    def test_missing_actual_image_sbom_or_identity_is_fatal(self):
        self.inventory['images']['caddy']['packages']=[]
        with self.assertRaises(security.SecurityFailure):security.validate_inventory(self.inventory,self.policy)

    def test_unavailable_official_source_is_blocked_not_pass(self):
        with tempfile.TemporaryDirectory() as t, patch.object(security.urllib.request,'urlopen',
                side_effect=urllib.error.URLError('unavailable test fixture')):
            receipt=security.fetch_source(self.policy['sources'][0],Path(t))
        self.assertEqual(receipt['status'],'BLOCKED')
        self.receipts[0]=receipt
        with self.assertRaises(security.SecurityBlocked):security.validate_reviews(self.policy,self.receipts,self.current)

    def test_missing_and_stale_source_coverage_is_blocked(self):
        with self.assertRaises(security.SecurityBlocked):security.validate_reviews(self.policy,self.receipts[1:],self.current)
        self.receipts[0]['checked_at']=(self.current-dt.timedelta(days=2)).isoformat()
        with self.assertRaises(security.SecurityBlocked):security.validate_reviews(self.policy,self.receipts,self.current)

    def test_expired_review_and_changed_source_are_blocked(self):
        changed=copy.deepcopy(self.policy);changed['expires_at']=(self.current-dt.timedelta(seconds=1)).isoformat()
        with self.assertRaises(security.SecurityBlocked):security.validate_reviews(changed,self.receipts,self.current)
        self.policy['sources'][0]['reviewed_sha256']='b'*64
        with self.assertRaises(security.SecurityBlocked):security.validate_reviews(self.policy,self.receipts,self.current)

    def test_forged_source_payload_is_fatal(self):
        self.receipts[0]['semantic']={'forged':'all green'}
        with self.assertRaises(security.SecurityFailure):security.validate_reviews(self.policy,self.receipts,self.current)

    def test_absent_family_or_unsupported_source_is_blocked(self):
        del self.policy['components']['cashfusion']
        with self.assertRaises(security.SecurityBlocked):security.validate_reviews(self.policy,self.receipts,self.current)

    def test_advisory_without_cve_version_floor_and_range_decision(self):
        receipt={'semantic':[{'ghsa_id':'GHSA-6365-7ppr-5r92','cve_id':None,'severity':'medium',
            'withdrawn_at':None,'vulnerabilities':[{'patched_versions':'v.2.11.5','vulnerable_version_range':'< v2.11.5'}]}]}
        self.assertEqual(security.assess_caddy_advisories(receipt,'2.11.7')[0]['decision'],'PATCHED_UPSTREAM_VERSION')
        with self.assertRaises(security.SecurityFailure):security.assess_caddy_advisories(receipt,'2.11.4')
        with self.assertRaises(security.SecurityBlocked):security.assess_caddy_advisories({'semantic':[]},'2.11.7')

    def test_missing_security_artifacts_and_zero_exit_are_not_pass(self):
        self.assertEqual(ci.gate_overall_status({},0),'FAIL')
        self.assertEqual(ci.gate_overall_status({'release_security':{'status':'PASS'},'cleanup':{'overall':'PASS'}},0),'FAIL')
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(security.SecurityFailure):security.verify_completion(
                {'release_security':{'status':'PASS'}},Path(t))

    def test_stale_db_and_unknown_severity_do_not_pass(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t);(path/'db').mkdir()
            (path/'db/metadata.json').write_text(json.dumps({'UpdatedAt':(self.current-dt.timedelta(days=2)).isoformat(),
                'NextUpdate':(self.current-dt.timedelta(days=1)).isoformat()}))
            self.assertFalse(ci.trivy_database_metadata(path)['valid'])
            with self.assertRaises(ci.ValidationError):ci.enforce_vulnerability_policy(
                [('image:test',[{'Severity':'UNKNOWN','VulnerabilityID':'fixture'}])],[],path,{'report_dir':str(path)})

    def test_unlinked_openpgp_requires_real_scoped_nonempty_package_proof(self):
        exceptions=ci.load_vulnerability_exceptions(today=dt.date(2026,10,9))
        finding={'Severity':'UNKNOWN','VulnerabilityID':'GO-2026-5932','PkgName':'golang.org/x/crypto',
                 'InstalledVersion':'v0.57.0','FixedVersion':''}
        with tempfile.TemporaryDirectory() as t:
            path=Path(t);manifest={'report_dir':str(path)}
            for content in (None,'','golang.org/x/crypto/openpgp\n'):
                if content is not None:(path/'caddy-package-deps.txt').write_text(content)
                with self.assertRaises(ci.ValidationError):ci.enforce_vulnerability_policy(
                    [('image:caddy',[finding])],exceptions,path,{'report_dir':str(path)})
            valid='github.com/caddyserver/caddy/v2/cmd/caddy\ngithub.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy\n'
            (path/'caddy-package-deps.txt').write_text(valid)
            ci.enforce_vulnerability_policy([('image:caddy',[finding])],exceptions,path,manifest)
            self.assertEqual(manifest['vulnerability_policy'],'PASS')
            (path/'caddy-package-deps.txt').write_text(valid+'golang.org/x/crypto/openpgp/packet\n')
            with self.assertRaises(ci.ValidationError):ci.enforce_vulnerability_policy(
                [('image:caddy',[finding])],exceptions,path,{'report_dir':str(path)})

    def test_catalog_cannot_be_reduced_or_redirected(self):
        for change in ('source', 'family', 'url', 'kind', 'duplicate'):
            altered=copy.deepcopy(self.policy)
            if change=='source':altered['sources'].pop()
            if change=='family':del altered['components']['ledger']
            if change=='url':altered['sources'][0]['url']='https://api.github.com/repos/attacker/empty/security-advisories'
            if change=='kind':altered['sources'][0]['kind']='text'
            if change=='duplicate':altered['sources'].append(altered['sources'][0])
            with self.subTest(change=change), self.assertRaises(security.SecurityBlocked):
                security.validate_reviews(altered,self.receipts,self.current)
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'catalog.json'
            catalog=security.load_catalog();catalog['sources'].pop()
            path.write_text(json.dumps(catalog))
            with patch.object(security,'POLICY',path), self.assertRaises(security.SecurityBlocked):
                security.load_catalog()

    def test_source_and_family_review_required_not_just_downloads(self):
        for target in (self.policy['sources'][0],self.policy['components']['tor']):
            saved=copy.deepcopy(target)
            for field in ('decision','assessment','limitations'):
                target[field]=''
                with self.assertRaises(security.SecurityBlocked):
                    security.validate_reviews(self.policy,self.receipts,self.current)
                target.update(saved)
        self.policy['components']['python']['sources']=['python_security']
        with self.assertRaises(security.SecurityBlocked):
            security.validate_reviews(self.policy,self.receipts,self.current)

    def test_review_run_candidate_and_bundle_tampering_blocked(self):
        for field in ('candidate','review_run_id','semantic'):
            altered=copy.deepcopy(self.policy)
            altered['reviewed_receipts'][0][field]='altered'
            # Even recomputing a bundle hash cannot mix reviews or change content.
            altered['reviewed_receipts_sha256']=security.canonical_digest(altered['reviewed_receipts'])
            with self.subTest(field=field), self.assertRaises(security.SecurityBlocked):
                security.validate_reviews(altered,self.receipts,self.current)
        del self.policy['image_ids']['ledger']
        with self.assertRaises(security.SecurityBlocked):
            security.validate_reviews(self.policy,self.receipts,self.current)

    def test_utc_boundary_and_maximum_weekly_expiry(self):
        for reviewed, expires in ((self.current.isoformat(),self.current.isoformat()),
                (self.policy['reviewed_at'],(self.current+dt.timedelta(days=8)).isoformat()),
                ('2026-10-09T12:00:00+01:00',self.policy['expires_at']),
                ('2026-10-09T12:00:00',self.policy['expires_at'])):
            altered=copy.deepcopy(self.policy);altered.update(reviewed_at=reviewed,expires_at=expires)
            with self.assertRaises(security.SecurityBlocked):
                security.validate_reviews(altered,self.receipts,self.current)

    def test_missing_external_attestation_blocks(self):
        with tempfile.TemporaryDirectory() as t, patch.dict('os.environ',{},clear=True):
            with self.assertRaises(security.SecurityBlocked):security.load_attestation(Path(t))

    def test_ephemeral_ci_evidence_cannot_be_written_under_git_source(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'reports'
            with patch.object(ci,'ROOT',Path(t)), patch.dict('os.environ',{'CI_REPORT_DIR':str(path)}):
                with self.assertRaises(ci.ValidationError):ci.report_directory('fixture')
            self.assertFalse(path.exists())

    def test_catalog_contains_only_durable_definitions(self):
        catalog=security.load_catalog()
        self.assertEqual(len(catalog['sources']),19)
        self.assertEqual(len(catalog['components']),13)
        for source in catalog['sources']:
            self.assertEqual(set(source),{'id','url','kind'})
        for row in catalog['components'].values():
            self.assertEqual(set(row),{'sources'})
        self.assertFalse({'reviewer','reviewed_at','expires_at'} & set(catalog))

    def completed_fixture(self, directory):
        """Real-shaped parsed notices and files; isolated from any release approval."""
        advisory={'ghsa_id':'GHSA-6365-7ppr-5r92','cve_id':None,'severity':'medium',
                  'withdrawn_at':None,'vulnerabilities':[{'patched_versions':'v.2.11.5',
                                                       'vulnerable_version_range':'< v2.11.5'}]}
        raw_by_kind={
            'advisories':json.dumps([advisory]).encode(),
            'releases':json.dumps([{'tag_name':'v2.11.7','name':'Security fixes',
                                   'body':'Fix authentication routing','published_at':'2026-10-09T00:00:00Z',
                                   'draft':False,'prerelease':False}]).encode(),
            'commits':json.dumps([{'sha':'d'*40,'commit':{'message':'Update official advisories'}}]).encode(),
            'tor_notice':json.dumps({'post_stream':{'posts':[{'id':1,'cooked':'Client security fixes',
                                                            'updated_at':'2026-10-09T00:00:00Z'}]}}).encode(),
            'tor_latest':b'Tor stable 0.4.9.14', 'go_releases':b'go1.26.9 go1.27.2',
            'rss':b'<rss><channel><item><title>Vendor security fix</title><guid>USN-fixture</guid></item></channel></rss>',
            'security_html':b'<h1>Python Security</h1><p>PSRT Published advisories</p>',
            'text':b'Official upstream fixture security notice'}
        receipts=[]
        for source in self.policy['sources']:
            raw=raw_by_kind[source['kind']]
            semantic=security.semantic_source(raw,source['kind'])
            sha=security.canonical_digest(semantic)
            source['reviewed_sha256']=sha
            receipt={'source':source['id'],'url':source['url'],'status':'FETCHED',
                     'metadata':{'final_url':source['url']},
                     'checked_at':self.current.isoformat(),'semantic':semantic,'semantic_sha256':sha,
                     'raw_sha256':security.digest(raw),'review_run_id':'fixture-execution','candidate':'c'*64}
            receipts.append(receipt)
            security.save(directory/'official-sources'/(source['id']+'.json'),receipt)
            (directory/'official-sources'/(source['id']+'.raw')).write_bytes(raw)
        reviewed=[r | {'checked_at':(self.current-dt.timedelta(hours=2)).isoformat(),
                       'review_run_id':'fixture-review'} for r in receipts]
        self.policy.update(reviewed_receipts=reviewed,reviewed_receipts_sha256=security.canonical_digest(reviewed))
        security.save(directory/'security-attestation.json',self.policy)
        security.save(directory/'official-source-review.json',{'status':'PASS','run_id':'fixture-execution',
            'candidate':'c'*64,'review_policy_sha256':security.CATALOG_SHA256,'receipts':receipts,
            'attestation_sha256':security.digest((directory/'security-attestation.json').read_bytes())})
        for key,name in security.IMAGE_REPORTS.items():
            package={'ID':'vendor-package@1','Name':'vendor-package','Version':'1','SrcName':'vendor-package',
                     'SrcVersion':'1','Identifier':None}
            self.inventory['images'][key]['packages']=[package | {'coverage':'ubuntu'}]
            security.save(directory/(name+'.json'),{'Metadata':{'ImageID':'sha256:'+'a'*64},
                'Results':[{'Type':'ubuntu','Packages':[package],'Vulnerabilities':[]}]})
            security.save(directory/('sbom-'+key+'.cdx.json'),{'bomFormat':'CycloneDX',
                'components':[{'name':'vendor-package','version':'1','type':'library'}]})
        (directory/'inventory-commands.log').write_text('Isolated actual-image probe fixture\n')
        (directory/'caddy-package-deps.txt').write_text('github.com/caddyserver/caddy/v2/cmd/caddy\n')
        manifest={'run_id':'fixture-execution','report_dir':str(directory),
                  'candidate':{'source_fingerprint':'c'*64},'candidate_image_ids':self.policy['image_ids']}
        def collect_inventory(*args):
            security.save(directory/'component-inventory.json',self.inventory)
            return self.inventory
        def collect_psf(*args):
            data={'commit':'d'*40,'advisories':[{'id':'PSF-fixture','affected':[]}],
                  'archive_sha256':'e'*64}
            security.save(directory/'python-official-advisories.json',data)
            return data
        with patch.object(security,'inventory',side_effect=collect_inventory), \
                patch.object(security,'collect_psf_advisories',side_effect=collect_psf):
            security.complete_security(ci,{},self.policy['image_ids'],directory,{},Path('/fixture/trivy'),manifest)
        return manifest

    def test_complete_and_final_verify_accept_evaluated_bound_fixture(self):
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);manifest=self.completed_fixture(directory)
            with patch.object(ci,'load_vulnerability_exceptions',return_value=[]):
                security.verify_completion(manifest,directory)
            self.assertEqual(manifest['release_security']['status'],'PASS')
            self.assertIn('security-attestation.json',manifest['release_security']['artifact_sha256'])

    def test_final_verification_rejects_every_replaced_security_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);manifest=self.completed_fixture(directory)
            for name in manifest['release_security']['artifact_sha256']:
                path=directory/name;original=path.read_bytes()
                path.write_bytes(original+b'\n')
                with self.subTest(artifact=name), self.assertRaises((security.SecurityFailure,security.SecurityBlocked)):
                    security.verify_completion(manifest,directory)
                path.write_bytes(original)

    def test_final_verification_rejects_candidate_image_run_and_missing_suite(self):
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);manifest=self.completed_fixture(directory)
            for changed in (dict(manifest,run_id='another-run'),
                    dict(manifest,candidate={'source_fingerprint':'f'*64}),
                    dict(manifest,candidate_image_ids={key:'sha256:'+'f'*64 for key in security.IMAGE_REPORTS})):
                with self.assertRaises(security.SecurityFailure):security.verify_completion(changed,directory)
            self.assertEqual(ci.gate_overall_status(manifest,0),'FAIL')

    def test_incomplete_scan_or_sbom_does_not_complete(self):
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);manifest=self.completed_fixture(directory)
            (directory/'sbom-ledger.cdx.json').write_text('{}')
            with self.assertRaises(security.SecurityFailure):
                security.validate_scan_artifacts(directory,manifest['candidate_image_ids'],self.inventory)
            (directory/'ledger.json').write_text('{}')
            with self.assertRaises(security.SecurityFailure):
                security.validate_scan_artifacts(directory,manifest['candidate_image_ids'],self.inventory)

    def test_complete_blocks_unapproved_images_and_never_calls_inventory(self):
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);manifest=self.completed_fixture(directory)
            changed={key:'sha256:'+'b'*64 for key in security.IMAGE_REPORTS}
            with patch.object(security,'inventory') as collect:
                with self.assertRaises(security.SecurityBlocked):
                    security.complete_security(ci,{},changed,directory,{},Path('/fixture/trivy'),manifest)
                collect.assert_not_called()
            self.assertEqual(manifest['release_security']['status'],'BLOCKED')
            self.assertEqual(ci.gate_overall_status(manifest,0),'FAIL')

    def test_metadata_cross_run_and_missing_download_are_fatal(self):
        with tempfile.TemporaryDirectory() as t:
            directory=Path(t);manifest=self.completed_fixture(directory)
            official=json.loads((directory/'official-source-review.json').read_text())
            for field,value in (('review_run_id','unrelated-run'),('candidate','d'*64),
                                ('metadata',{'final_url':'https://attacker.example/empty'})):
                changed=copy.deepcopy(official);changed['receipts'][0][field]=value
                receipt=changed['receipts'][0]
                security.save(directory/'official-sources'/(receipt['source']+'.json'),receipt)
                with self.subTest(field=field), self.assertRaises(security.SecurityFailure):
                    security.verify_source_files(directory,changed,manifest)
            receipt=official['receipts'][0]
            security.save(directory/'official-sources'/(receipt['source']+'.json'),receipt)
            (directory/'official-sources'/(receipt['source']+'.raw')).unlink()
            with self.assertRaises(security.SecurityFailure):
                security.verify_source_files(directory,official,manifest)


def static_main():
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(SecurityGateTests))
    assert result.wasSuccessful(),'release security falsification failed'


if __name__=='__main__':static_main()

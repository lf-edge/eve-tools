import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from diskcache import Cache
from scan import fallback as f, scanner

CVE = 'CVE-2026-10001'
OTHER = 'CVE-2026-10002'
SHA = 'a' * 40
REPO = 'https://github.com/example/library'


def apk(version='1.2.0-r0', name='library', distro='alpine-3.22', origin=None):
    return {'name': name, 'versionInfo': version, 'SPDXID': 'SPDX-package-'+name,
            'packageFileName': 'container-a', 'sourceInfo': 'acquired package info from APK DB: /lib/apk/db/installed',
            'externalRefs': [{'referenceType': 'purl', 'referenceLocator': f'pkg:apk/alpine/{name}@{version}?distro={distro}'+(f'&upstream={origin}' if origin else '')}]}


def source():
    return {'name': 'library', 'versionInfo': SHA, 'SPDXID': 'SPDX-source',
            'externalRefs': [{'referenceType': 'purl', 'referenceLocator': 'pkg:github/example/library@'+SHA}]}


def advisory(cve=CVE, start='1.0.0', fixed='1.3.0'):
    return {'cveMetadata': {'cveId': cve, 'state': 'PUBLISHED', 'datePublished': '2026-01-01T00:00:00Z', 'dateUpdated': '2026-01-02T00:00:00Z'},
            'containers': {'cna': {'title': 'Verified upstream issue', 'descriptions': [{'lang':'en','value':'Issue description'}],
            'affected': [{'product': 'library', 'versions': [{'version': start, 'lessThan': fixed, 'versionType':'semver','status':'affected'}]}],
            'metrics': [{'cvssV3_1': {'vectorString':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}}]}}}


class Client:
    def __init__(self, fixed='1.2.0-r2', ids=None):
        self.fixed = fixed
        self.ids = ids or [CVE]
        self.details = {c:advisory(c) for c in self.ids}
        self.requested = []
        self.git = []
    def secdb(self, release):
        self.requested.append(('release',release))
        return {'library': {'secfixes': {self.fixed: self.ids}}}
    def advisory(self,cve):
        self.requested.append(('cve',cve));return self.details[cve]
    def commit(self,repo,revision):
        self.requested.append(('commit',repo,revision));return self.git


class FallbackTests(unittest.TestCase):
    def run_pass(self, packages, primary=None, client=None):
        with tempfile.TemporaryDirectory() as d, Cache(d) as cache:
            return f.additive_pass(packages,primary or [],cache,{},client=client or Client())

    def test_adds_even_with_existing_findings_and_preserves_every_input(self):
        package=apk();primary=[{'package':package,'vulnerabilities':[{'id':'ALPINE-old','aliases':[OTHER],'details':'keep me','severity':[{'score':'old'}]}]}]
        snapshot=copy.deepcopy(primary);client=Client(ids=[CVE,OTHER])
        additions,audit=self.run_pass([package],primary,client)
        self.assertEqual(primary,snapshot)
        self.assertEqual([v['id'] for v in additions[0]['vulnerabilities']],[CVE])
        self.assertEqual(audit['added_findings'],1)
        self.assertNotIn(('cve',OTHER),client.requested)

    def test_backport_revision_and_fixed_version_suppress(self):
        for v in ['1.2.0-r2','1.2.0-r3','1.2.0-r10','1.2.1-r0','1.3.0-r0']:
            with self.subTest(version=v):
                c=Client();out,audit=self.run_pass([apk(v)],client=c)
                self.assertEqual(out,[])
                self.assertNotIn(('cve',CVE),c.requested)
                self.assertEqual(audit['packages'][0]['status'],'checked')

    def test_revision_ten_does_not_sort_before_two(self):
        self.assertEqual(self.run_pass([apk('1.2.0-r2')],client=Client('1.2.0-r10'))[1]['added_findings'],1)

    def test_not_yet_introduced_and_upstream_fixed_never_emit(self):
        for start,fixed in [('1.2.1','1.3.0'),('0','1.2.0')]:
            c=Client();c.details[CVE]=advisory(start=start,fixed=fixed)
            out,audit=self.run_pass([apk()],client=c)
            self.assertEqual(out,[]);self.assertEqual(audit['packages'][0]['status'],'unresolved')

    def test_explicit_unaffected_beats_affected(self):
        c=Client();c.details[CVE]['containers']['cna']['affected'][0]['versions'].append({'version':'1.2.0','status':'unaffected'})
        self.assertEqual(self.run_pass([apk()],client=c)[0],[])

    def test_unknown_cna_product_range_platform_or_module_is_not_evidence(self):
        for change in [{'product':'another product'}, {'versions':[]}, {'platforms':['Windows']}, {'modules':['9pfs']},
                       {'versions':[{'version':'1.0','lessThan':'1.3.0','versionType':'rpm','status':'affected'}]},
                       {'versions':[{'version':'1.0','lessThan':'1.3.0','versionType':'semver','status':'affected','changes':[{'at':'1.1','status':'unaffected'}]}]}]:
            c=Client();c.details[CVE]['containers']['cna']['affected'][0].update(change)
            with self.subTest(change=change):self.assertEqual(self.run_pass([apk()],client=c)[0],[])

    def test_distribution_packages_never_use_generic_upstream_as_override(self):
        for change in [{'description':'library (built from source)'}, {'comment':'backported fix'}, {'sourceInfo':'locally patched APK DB'}, {'versionInfo':'1.2.0'}]:
            pkg=apk();pkg.update(change);c=Client()
            out,audit=self.run_pass([pkg],client=c)
            self.assertEqual(out,[]);self.assertEqual(c.requested,[])
            self.assertEqual(audit['packages'][0]['status'],'unresolved')

    def test_qemu_img_does_not_inherit_9pfs_from_source_package(self):
        c=Client();out,audit=self.run_pass([apk(name='library-tools',origin='library')],client=c)
        self.assertEqual(out,[]);self.assertIn('subpackage',audit['packages'][0]['reason'])

    def test_missing_or_conflicting_distro_is_not_guessed(self):
        for distro in ['busybox-1.37.0','ubuntu-24.04','alpine-../x','alpine-3.22&distro=alpine-3.21']:
            c=Client();self.assertEqual(self.run_pass([apk(distro=distro)],client=c)[0],[]);self.assertEqual(c.requested,[])
        pkg=apk();release={'name':'alpine-release','versionInfo':'3.21.1','packageFileName':'container-a'}
        self.assertEqual(self.run_pass([pkg,release])[0],[])

    def test_mixed_container_releases_are_not_global(self):
        a=apk(distro='busybox-1.37.0');b=apk(distro='busybox-1.37.0');b['packageFileName']='container-b'
        releases=[{'name':'alpine-release','versionInfo':v,'packageFileName':k} for k,v in [('container-a','3.22.1'),('container-b','3.16.0')]]
        c=Client();out,audit=self.run_pass([a,b,*releases],client=c)
        self.assertEqual(len(out),2);self.assertIn(('release','v3.22'),c.requested);self.assertIn(('release','v3.16'),c.requested)

    def test_ambiguous_container_release_is_not_used(self):
        p=apk(distro='busybox-1.37.0');r=[{'name':'alpine-release','versionInfo':v,'packageFileName':'container-a'} for v in ['3.22.0','3.21.0']]
        self.assertEqual(self.run_pass([p,*r])[0],[])

    def test_earliest_backport_for_repeated_cve_wins(self):
        c=Client();c.secdb=lambda _: {'library':{'secfixes':{'1.2.0-r2':[CVE],'1.2.0-r10':[CVE]}}}
        self.assertEqual(self.run_pass([apk('1.2.0-r3')],client=c)[0],[])

    def test_invalid_versions_fail_closed(self):
        for fixed in ['garbage','1.2.0-r-2','']:
            out,audit=self.run_pass([apk()],client=Client(fixed))
            self.assertEqual(out,[]);self.assertEqual(audit['packages'][0]['status'],'unresolved')

    def test_source_requires_exact_commit_and_repo(self):
        self.assertEqual(f.exact_source(source()),(REPO,SHA))
        for purl in ['pkg:github/example/library@v1.2.0','pkg:github/example/library@aaaaaaa','pkg:apk/alpine/library@'+SHA,
                     'pkg:generic/library@'+SHA,'pkg:github/example/library@'+SHA+'&x=1']:
            p=source();p['externalRefs'][0]['referenceLocator']=purl
            self.assertIsNone(f.exact_source(p))
        p=source();p['comment']='dirty tree with local patches';self.assertIsNone(f.exact_source(p))

    def test_mismatched_commit_and_non_alpine_namespace_are_withheld(self):
        p=source();p['versionInfo']='b'*40
        self.assertIsNone(f.exact_source(p))
        p=apk();p['externalRefs'][0]['referenceLocator']=p['externalRefs'][0]['referenceLocator'].replace('apk/alpine/', 'apk/other/')
        self.assertIsNone(f.alpine_identity(p,{}))

    def test_malformed_evidence_does_not_drop_other_package_findings(self):
        c=Client();c.details[CVE]['containers']['cna']['affected']=[None]
        p=source();c.git=[{'id':OTHER}]
        out,audit=self.run_pass([apk(),p],client=c)
        self.assertEqual(audit['packages'][0]['status'],'unresolved')
        self.assertEqual(out[0]['vulnerabilities'][0]['id'],OTHER)

    def test_source_duplicates_withdrawn_and_existing_aliases(self):
        p=source();v={'id':'OSV-git','aliases':[CVE],'details':'source report'}
        c=Client();c.git=[v,copy.deepcopy(v),{'id':'OSV-withdrawn','withdrawn':'date'}]
        original=copy.deepcopy(c.git)
        out,audit=self.run_pass([p,p],client=c)
        self.assertEqual(audit['added_findings'],1);self.assertEqual(len(out),1);self.assertEqual(c.git,original)
        primary=[{'package':p,'vulnerabilities':[{'id':CVE}]}]
        self.assertEqual(self.run_pass([p],primary,c)[0],[])

    def test_one_metadata_failure_does_not_discard_verified_other_cve(self):
        c=Client(ids=[CVE,OTHER]);orig=c.advisory
        def get(cve):
            if cve==CVE:raise f.EvidenceUnavailable('unavailable')
            return orig(cve)
        c.advisory=get
        out,audit=self.run_pass([apk()],client=c)
        self.assertEqual(out[0]['vulnerabilities'][0]['id'],OTHER);self.assertEqual(audit['packages'][0]['status'],'unresolved')

    def test_failed_lookup_never_becomes_safe_or_vulnerable(self):
        c=Client();c.secdb=Mock(side_effect=f.EvidenceUnavailable('outage'))
        out,audit=self.run_pass([apk()],client=c)
        self.assertEqual(out,[]);self.assertEqual(audit['packages'][0]['status'],'unresolved')


class ClientTests(unittest.TestCase):
    def test_retries_and_success_cache(self):
        with tempfile.TemporaryDirectory() as d,Cache(d) as cache:
            session=Mock();response=Mock(status_code=200);response.json.return_value={'ok':True}
            session.get.side_effect=[Mock(status_code=429),Mock(status_code=503),response]
            sleep=Mock();client=f.EvidenceClient(cache,session,sleep)
            self.assertEqual(client.json('https://secdb.alpinelinux.org/v3.22/main.json'),{'ok':True})
            self.assertEqual(client.json('https://secdb.alpinelinux.org/v3.22/main.json'),{'ok':True})
            self.assertEqual(session.get.call_count,3);self.assertEqual(sleep.call_count,2)

    def test_errors_are_not_persisted_as_empty_results(self):
        with tempfile.TemporaryDirectory() as d,Cache(d) as cache:
            session=Mock();session.get.return_value=Mock(status_code=503)
            client=f.EvidenceClient(cache,session,Mock())
            for _ in range(2):
                with self.assertRaises(f.EvidenceUnavailable):client.json('https://secdb.alpinelinux.org/v3.22/main.json')
            self.assertEqual(session.get.call_count,3)
            new=f.EvidenceClient(cache,session,Mock())
            with self.assertRaises(f.EvidenceUnavailable):new.json('https://secdb.alpinelinux.org/v3.22/main.json')
            self.assertEqual(session.get.call_count,6)

    def test_redirects_and_permanent_errors_are_not_followed_or_retried(self):
        for status in [301,302,400,401,403,404]:
            with tempfile.TemporaryDirectory() as d,Cache(d) as cache:
                session=Mock();session.get.return_value=Mock(status_code=status)
                with self.assertRaises(f.EvidenceUnavailable):f.EvidenceClient(cache,session,Mock()).json('https://secdb.alpinelinux.org/v3.22/main.json')
                self.assertEqual(session.get.call_count,1);self.assertFalse(session.get.call_args.kwargs['allow_redirects'])

    def test_commit_requires_matching_repository_and_complete_pagination(self):
        with tempfile.TemporaryDirectory() as d,Cache(d) as cache:
            client=f.EvidenceClient(cache)
            good={'id':CVE,'affected':[{'ranges':[{'type':'GIT','repo':REPO+'.git'}]}]}
            wrong={'id':OTHER,'affected':[{'ranges':[{'type':'GIT','repo':'https://github.com/other/project'}]}]}
            client.json=Mock(side_effect=[{'vulns':[good],'next_page_token':'page2'},{'vulns':[wrong]}])
            self.assertEqual(client.commit(REPO,SHA),[good]);self.assertEqual(client.json.call_args.args[1]['page_token'],'page2')
            client.json=Mock(return_value={'vulns':[good],'next_page_token':'loop'})
            with self.assertRaises(f.EvidenceUnavailable):client.commit(REPO,SHA)
            client.json=Mock(side_effect=[{'vulns':[good],'next_page_token':'page2'},f.EvidenceUnavailable('outage')])
            with self.assertRaises(f.EvidenceUnavailable):client.commit(REPO,SHA)

    def test_wrong_release_rejected_and_parsed_feed_reused(self):
        with tempfile.TemporaryDirectory() as d,Cache(d) as cache:
            client=f.EvidenceClient(cache);client.json=Mock(return_value={'distroversion':'v3.21','packages':[]})
            with self.assertRaises(f.EvidenceUnavailable):client.secdb('v3.22')
            client.json=Mock(return_value={'distroversion':'v3.22','packages':[]})
            client.secdb('v3.22');client.secdb('v3.22');self.assertEqual(client.json.call_count,2)

    def test_rejected_or_mismatched_cve_metadata_is_not_used(self):
        with tempfile.TemporaryDirectory() as d,Cache(d) as cache:
            client=f.EvidenceClient(cache)
            for meta in [{'cveId':OTHER,'state':'PUBLISHED'},{'cveId':CVE,'state':'REJECTED'}]:
                client.json=Mock(return_value={'cveMetadata':meta})
                with self.assertRaises(f.EvidenceUnavailable):client.advisory(CVE)


class ScanIntegrationTests(unittest.TestCase):
    def test_primary_findings_unchanged_and_fallback_appends_to_same_package(self):
        p=apk();p['SPDXID']='SPDX-library'
        original={'id':'OSV-original','details':'unchanged','aliases':['CVE-2025-10001'],'severity':[{'type':'CVSS_V3','score':'original'}]}
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'scan.json'
            with patch.object(scanner,'parse_spdx',return_value=[p]),patch.object(scanner,'load_cvss_bt_cache',return_value={}),patch.object(scanner,'_query_osv',return_value={'vulns':[copy.deepcopy(original)]}),patch('scan.fallback.run_additive',return_value=[]) as fallback:
                scanner.scan_sbom('sbom','cvss','v3.22.0_packages.json',str(output),str(Path(d)/'cache'))
                baseline=json.loads(output.read_text());self.assertEqual(fallback.call_count,1)
                extra={'package':p,'vulnerabilities':[{'id':CVE,'details':'new'}]}
                fallback.return_value=[extra]
                scanner.scan_sbom('sbom','cvss','v3.22.0_packages.json',str(output),str(Path(d)/'cache'))
                after=json.loads(output.read_text());self.assertEqual(len(after),1)
                self.assertEqual(after[0]['vulnerabilities'][:-1],baseline[0]['vulnerabilities'])
                self.assertEqual(after[0]['vulnerabilities'][-1]['id'],CVE)
                fallback.side_effect=RuntimeError('network failure')
                scanner.scan_sbom('sbom','cvss','v3.22.0_packages.json',str(output),str(Path(d)/'cache'))
                self.assertEqual(json.loads(output.read_text()),baseline)


if __name__=='__main__':unittest.main()

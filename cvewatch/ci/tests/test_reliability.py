import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import requests
from diskcache import Cache
from scan import scanner as s
from scan import fallback


def response(data=None, status=200):
    return Mock(status_code=status, json=Mock(return_value={} if data is None else data), text='error')


def package(name='module', version='1.0.0', purl='pkg:golang/example.com/module@1.0.0'):
    return {'name': name, 'versionInfo': version, 'externalRefs': [{'referenceType':'purl','referenceLocator':purl}]}


class QueryTests(unittest.TestCase):
    def test_retries_network_429_and_5xx(self):
        good = response()
        with patch.object(s.requests, 'post', side_effect=[requests.Timeout(), response(status=429), response(status=503), good]) as post, patch.object(s.time, 'sleep') as sleep:
            self.assertIs(s._osv_post('https://api.osv.dev/v1/query', {}), good)
            self.assertEqual(post.call_count, 4)
            self.assertEqual(sleep.call_count, 3)

    def test_no_retry_on_bad_identity_and_bounded_failure(self):
        for error, count in [(response(status=400), 1), (response(status=503), 5)]:
            with patch.object(s.requests, 'post', return_value=error) as post, patch.object(s.time, 'sleep'):
                self.assertIsNone(s._osv_post('https://api.osv.dev/v1/query', {}))
                self.assertEqual(post.call_count, count)

    def test_failed_or_malformed_second_page_is_not_partial_success(self):
        for second in [None, response(['bad']), response({'vulns':'bad'}), response({'vulns':[{}]})]:
            with patch.object(s, '_osv_post', side_effect=[response({'vulns':[{'id':'CVE-first'}], 'next_page_token':'next'}), second]):
                self.assertIsNone(s.get_osv_vulnerabilities(name='x', ecosystem='Go', version='1.0.0'))

    def test_pagination_cycle_and_limit_fail_closed(self):
        with patch.object(s, '_osv_post', return_value=response({'vulns':[], 'next_page_token':'repeat'})):
            self.assertIsNone(s.get_osv_vulnerabilities(name='x', ecosystem='Go', version='1.0.0'))
            self.assertIsNone(s.get_osv_vulnerabilities(name='x', ecosystem='Go', version='1.0.0', max_pages=1))
        with patch.object(s, '_osv_post', return_value=response()):
            self.assertEqual(s.get_osv_vulnerabilities(name='x', ecosystem='Go', version='1.0.0', max_pages=1), {})

    def test_cache_ttl_empty_results_and_failures(self):
        info=s.extract_package_info(package())
        with tempfile.TemporaryDirectory() as d, Cache(d) as cache:
            with patch.object(s, 'get_osv_vulnerabilities', return_value={}) as query:
                self.assertEqual(s._query_osv(info, cache), {})
                calls=query.call_count
                self.assertEqual(s._query_osv(info, cache), {})
                self.assertEqual(query.call_count,calls)
                for key in cache:
                    _, expiry=cache.get(key, expire_time=True)
                    self.assertGreater(expiry, s.time.time()+28000)
                    self.assertLessEqual(expiry,s.time.time()+28800)
            cache.clear()
            with patch.object(s, 'get_osv_vulnerabilities', return_value=None):
                self.assertIsNone(s._query_osv(info,cache))
                self.assertEqual(len(cache),0)

    def test_scoped_npm_and_go_subpaths(self):
        npm=s.extract_package_info(package(purl='pkg:npm/%40scope/module@1.0.0?x=y'))
        self.assertEqual(npm['purl'],'pkg:npm/%40scope/module')
        self.assertEqual(npm['name'],'@scope/module')
        maven=s.extract_package_info(package(purl='pkg:maven/org.example/module@1.0.0'))
        self.assertEqual(maven['name'],'org.example:module')
        go=s.extract_package_info(package(purl='pkg:golang/example.com/module@v1.0.0#subpkg'))
        self.assertEqual(go['name'],'example.com/module')

    def test_alpine_release_and_origin_and_no_upstream_purl_override(self):
        pkg=package(name='openssh-server',version='9.0-r0',purl='pkg:apk/alpine/openssh-server@9.0-r0?distro=alpine-3.22&upstream=openssh')
        info=s.extract_package_info(pkg, 'v3.21')
        self.assertEqual((info['name'],info['ecosystem']),('openssh','Alpine:v3.22'))
        with tempfile.TemporaryDirectory() as d, Cache(d) as cache, patch.object(s,'get_osv_vulnerabilities',return_value={}) as query:
            self.assertEqual(s._query_osv(info,cache),{})
            query.assert_called_once_with(name='openssh',version='9.0-r0',ecosystem='Alpine:v3.22')


class ScanTests(unittest.TestCase):
    def scan(self, packages, data, directory, **kw):
        dest=Path(directory)/'scan.json'
        with patch.object(s,'parse_spdx',return_value=packages), patch.object(s,'load_cvss_bt_cache',return_value={}), patch.object(s,'_query_osv',return_value=data), patch.object(fallback,'run_additive',return_value=[]):
            s.scan_sbom('sbom','cvss','unused',str(dest),str(Path(directory)/'cache'),**kw)
        return json.loads(dest.read_text())

    def test_merged_container_copies_do_not_inherit_host_release(self):
        raw={**package(purl='pkg:apk/busybox/musl@1.2.3-r4?distro=busybox-1.35.0'),
             'name':'musl','versionInfo':'1.2.3-r4','SPDXID':'SPDXRef-old-musl'}
        scoped={**raw,'packageFileName':'containers/services/debug/lower'}
        host={**raw,'versionInfo':'1.2.5-r10','SPDXID':'SPDXRef-host-musl'}
        data={'SPDXID':'SPDXRef-DOCUMENT','packages':[raw,scoped,host],
              'relationships':[{'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':'SPDXRef-root'},
                               {'spdxElementId':'SPDXRef-root','relationshipType':'CONTAINS','relatedSpdxElement':'SPDXRef-host-musl'}]}
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'sbom.json';path.write_text(json.dumps(data))
            result=s.parse_spdx(path)
            self.assertEqual([(p['SPDXID'],p['packageFileName']) for p in result],
                             [('SPDXRef-old-musl','containers/services/debug/lower'),('SPDXRef-host-musl',None)])
            # Explicit root ownership wins when a package is shared by root and container.
            data['relationships'].append({'spdxElementId':'SPDXRef-root','relationshipType':'CONTAINS','relatedSpdxElement':'SPDXRef-old-musl'})
            path.write_text(json.dumps(data))
            self.assertEqual(len(s.parse_spdx(path)),3)
            # A root ID reused by a container cannot establish host ownership.
            data['packages'].append({'name':'sbom','SPDXID':'SPDXRef-root',
                                     'packageFileName':'containers/services/debug/lower'})
            path.write_text(json.dumps(data))
            remaining=s.parse_spdx(path)
            self.assertFalse(any(p['SPDXID']=='SPDXRef-old-musl' and not p['packageFileName'] for p in remaining))

    def test_failed_primary_scan_removes_old_success_and_saves_diagnostics(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'scan.json';output.write_text('[]')
            with self.assertRaises(s.ScanError):self.scan([package()],None,d)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(Path(str(output)+'.partial.json').read_text()),[])

    def test_bad_or_empty_sbom_is_an_error(self):
        for packages in (None,[]):
            with tempfile.TemporaryDirectory() as d, self.assertRaises(s.ScanError):self.scan(packages,{},d)

    def test_enrichment_does_not_mutate_advisory_and_includes_own_cve_id(self):
        advisory={'id':'CVE-2026-1234','aliases':[], 'upstream':['GO-2026-1']}
        original=copy.deepcopy(advisory)
        with tempfile.TemporaryDirectory() as d, patch.object(s,'parse_spdx',return_value=[package()]), patch.object(s,'load_cvss_bt_cache',return_value={'cve-2026-1234':{'CVSS':'9.8'}}), patch.object(s,'_query_osv',return_value={'vulns':[advisory]}), patch.object(fallback,'run_additive',return_value=[]):
            out=Path(d)/'scan.json'
            s.scan_sbom('sbom','cvss','unused',str(out),str(Path(d)/'cache'))
            self.assertEqual(json.loads(out.read_text())[0]['vulnerabilities'][0]['exploitability'],[{'CVSS':'9.8'}])
            self.assertEqual(advisory,original)

    def test_withdrawn_and_legacy_flat_secfixes(self):
        with tempfile.TemporaryDirectory() as d:
            # A flattened APKBUILD CVE list cannot prove this installed version is fixed.
            legacy=Path(d)/'alpine.json';legacy.write_text(json.dumps([{'pkgname':'module','secfixes':['CVE-keep']}]))
            rows=self.scan([package()],{'vulns':[{'id':'CVE-keep'},{'id':'CVE-withdrawn','withdrawn':'2026-01-01'}]},d)
            self.assertEqual([v['id'] for v in rows[0]['vulnerabilities']],['CVE-keep'])

    def test_mixed_container_release_scope(self):
        packages=[]
        for container, release in [('old','3.20.0'),('new','3.22.0')]:
            packages.extend([{'name':'alpine-release','versionInfo':release,'packageFileName':container},
                             {**package(purl='pkg:apk/alpine/module@1.0-r0'), 'packageFileName':container}])
        observed=[]
        def query(info,cache):observed.append(info);return {}
        with tempfile.TemporaryDirectory() as d, patch.object(s,'parse_spdx',return_value=packages), patch.object(s,'load_cvss_bt_cache',return_value={}), patch.object(s,'_query_osv',side_effect=query), patch.object(fallback,'run_additive',return_value=[]):
            s.scan_sbom('x','x','unused',str(Path(d)/'out'),str(Path(d)/'cache'))
        self.assertEqual([v['ecosystem'] for v in observed if v['name']=='module'],['Alpine:v3.20','Alpine:v3.22'])

    def test_atomic_output_error_is_not_success(self):
        with tempfile.TemporaryDirectory() as d, patch.object(s.os,'replace',side_effect=OSError('disk full')):
            with self.assertRaises(s.ScanError):s._write_results([],str(Path(d)/'scan.json'))
            self.assertEqual(list(Path(d).iterdir()),[])

    def test_cli_invalid_input_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            result=subprocess.run([sys.executable,str(Path(s.__file__)),'pr','missing','unused','unused',d],capture_output=True)
            self.assertEqual(result.returncode,2)
            self.assertFalse((Path(d)/'scan_results_pr.json').exists())


class KernelTests(unittest.TestCase):
    def archive(self,path,events,withdrawn=False):
        advisory={'id':'CVE-test','affected':[{'package':{'ecosystem':'Linux'},'ranges':[{'type':'ECOSYSTEM','events':events}]}]}
        if withdrawn:advisory['withdrawn']='2026-01-01'
        with zipfile.ZipFile(path,'w') as out:out.writestr('test.json',json.dumps(advisory))

    def test_disjoint_ranges_and_inclusive_end(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'kernel.zip'
            self.archive(p,[{'introduced':'5.0'},{'fixed':'5.1'},{'introduced':'6.0'},{'last_affected':'6.1'}])
            for version,match in [('4.9',False),('5.0',True),('5.1',False),('5.9',False),('6.0',True),('6.1',True),('6.2',False)]:
                self.assertEqual(bool(s.check_linux_kernel_vulns(version,p)),match,version)
            self.archive(p,[{'introduced':'0'}],withdrawn=True)
            self.assertEqual(s.check_linux_kernel_vulns('5.0',p),[])

    def test_live_linux_feed_repeated_fixes_are_valid(self):
        # CVE-2022-48747, observed in the actual Linux/all.zip image scan.
        events=[{'introduced':'5.5.0'},{'fixed':'5.10.96'},{'fixed':'5.15.19'}]
        for version, expected in [('5.5.0',True),('5.10.95',True),('5.10.96',False),('6.12.49',False)]:
            self.assertEqual(s.version_in_range(s.packaging_version.Version(version), events),expected)

    def test_unsorted_events_and_limits_follow_osv_timeline(self):
        events=[{'fixed':'6.2'},{'introduced':'6.0'},{'fixed':'5.2'},{'introduced':'5.0'}]
        for version,expected in [('4.9',False),('5.1',True),('5.3',False),('6.1',True),('6.2',False)]:
            self.assertEqual(s.version_in_range(s.packaging_version.Version(version),events),expected)
        target=s.packaging_version.Version('6.1')
        self.assertFalse(s.version_in_range(target,events+[{'limit':'6.0'}]))
        self.assertTrue(s.version_in_range(target,events+[{'limit':'6.0'},{'limit':'*'}]))

    def test_corrupt_database_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'kernel.zip';p.write_text('truncated')
            with self.assertRaises(s.ScanError):s.check_linux_kernel_vulns('5.0',p)

    def test_failed_refresh_preserves_old_archive_but_does_not_use_stale_data(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'Linux_all.zip';self.archive(p,[{'introduced':'0'}]);original=p.read_bytes()
            os.utime(p,(0,0))
            fake=Mock();fake.__enter__=Mock(return_value=fake);fake.__exit__=Mock(return_value=False)
            fake.iter_content.side_effect=requests.ConnectionError('broken')
            with patch.object(s.requests,'get',return_value=fake),self.assertRaises(s.ScanError):s.load_linux_kernel_db(d)
            self.assertEqual(p.read_bytes(),original)
            self.assertEqual(list(Path(d).glob('*.tmp')),[])


if __name__=='__main__':unittest.main()

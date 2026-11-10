import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import resolve_inputs as inputs
from scan import compare, fallback
from diskcache import Cache

CI=Path(__file__).resolve().parents[1]
ROOT=CI.parent.parent


def pr():
    return {'head':{'sha':'a'*40,'repo':{'clone_url':'https://github.com/fork/eve.git'}},
            'base':{'ref':'17.0-stable','repo':{'clone_url':'https://github.com/lf-edge/eve.git'}}}


class InputTests(unittest.TestCase):
    def test_pull_request_defaults_to_its_base(self):
        values=inputs.resolve({'pull_request':pr()},{},'lf-edge/eve')
        self.assertEqual(values,{'repo':'https://github.com/fork/eve.git','revision':'a'*40,'base_repo':'https://github.com/lf-edge/eve.git','base_ref':'17.0-stable'})

    def test_workflow_run_uses_associated_pr_and_rejects_stale_run(self):
        event={'workflow_run':{'head_sha':'a'*40,'pull_requests':[{'number':123}]}}
        values=inputs.resolve(event,{},'lf-edge/eve',get_pr=lambda repo,num:pr())
        self.assertEqual(values['base_ref'],'17.0-stable')
        event['workflow_run']['head_sha']='b'*40
        with self.assertRaises(inputs.InputError):inputs.resolve(event,{},'lf-edge/eve',get_pr=lambda repo,num:pr())
        for associations in ([],[{'number':1},{'number':2}]):
            event['workflow_run']['pull_requests']=associations
            with self.assertRaises(inputs.InputError):inputs.resolve(event,{},'lf-edge/eve')

    def test_explicit_inputs_and_no_empty_repo(self):
        values=inputs.resolve({}, {'repo':'https://github.com/lf-edge/eve.git','revision':'tag'},'lf-edge/eve')
        self.assertEqual(values['base_ref'],'master')
        with self.assertRaises(inputs.InputError):inputs.resolve({}, {},'lf-edge/eve')

    def test_output_injection_and_option_inputs_are_rejected(self):
        for key in ('repo','revision','base_repo','base_ref'):
            for bad in ('safe\nrepo=https://evil.invalid/x','-c core.sshCommand=evil','bad\x00value','bad\rvalue'):
                with self.subTest(key=key,bad=bad),self.assertRaises(inputs.InputError):
                    inputs.resolve({'pull_request':pr()},{key:bad},'lf-edge/eve')
        for url in ('file:///etc','ext::command','https://github.com@evil.invalid/repo','https://user:secret@github.com/o/r','https://github.com/o/r?x=y'):
            with self.subTest(url=url),self.assertRaises(inputs.InputError):inputs.resolve({'pull_request':pr()},{'repo':url},'lf-edge/eve')

    def test_workflow_keeps_build_code_off_scan_runner(self):
        workflow=yaml.safe_load((ROOT/'.github/workflows/cve-scan.yml').read_text())
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        self.assertEqual(workflow['jobs']['build']['strategy']['matrix']['role'],['pr','base'])
        scan=workflow['jobs']['pr-scan']
        self.assertIn('always()',scan['if'])
        self.assertEqual(scan['needs'],['resolve','build'])
        self.assertIn('BUILD_RESULT',scan['steps'][0]['env'])
        for job in workflow['jobs'].values():
            self.assertEqual(job['runs-on'],'ubuntu-latest')
            for step in job['steps']:
                if step.get('uses','').startswith('actions/checkout@'):
                    self.assertIs(step['with']['persist-credentials'],False)
                    self.assertEqual(step['with']['ref'],'${{ job.workflow_sha }}')
        scan_commands='\n'.join(step.get('run','') for step in scan['steps'])
        self.assertNotIn('build-input',scan_commands)
        self.assertIn('scan-inputs.sh',scan_commands)


    def test_relocated_workflows_resolve_tools_from_repository_root(self):
        commands=[]
        for name in ('cve-scan.yml', 'cve-tests.yml'):
            workflow=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
            for job in workflow['jobs'].values():
                for step in job['steps']:
                    command=step.get('run','')
                    commands.append(command)
                    for path in re.findall(r'cvewatch/ci/[A-Za-z0-9_./*-]+', command):
                        self.assertTrue(list(ROOT.glob(path)), path)
                    self.assertIsNone(re.search(r'(?<![\w/])ci/', command), command)
        self.assertTrue(any('cvewatch/ci/scan-inputs.sh' in command for command in commands))
        self.assertTrue(any('cvewatch/ci/build-input.sh' in command for command in commands))
        self.assertTrue(any('cvewatch/ci/resolve_inputs.py' in command for command in commands))


class CompareTests(unittest.TestCase):
    def row(self,purl,identifier,aliases=None):
        return {'package':{'name':'module','versionInfo':'1.0','externalRefs':[{'referenceType':'purl','referenceLocator':purl}]},'vulnerabilities':[{'id':identifier,'aliases':aliases or []}]}

    def run_compare(self,base,pr,ignore=None):
        with tempfile.TemporaryDirectory(prefix='scan with spaces ') as d:
            a,b=Path(d)/'base.json',Path(d)/'pr.json'
            a.write_text(json.dumps(base));b.write_text(json.dumps(pr))
            cmd=[sys.executable,str(CI/'scan/compare.py'),str(a),str(b)]
            if ignore:
                p=Path(d)/'ignore';p.write_text(ignore);cmd.append(str(p))
            return subprocess.run(cmd,capture_output=True,text=True)

    def test_alias_change_is_not_a_new_vulnerability(self):
        a=self.row('pkg:golang/example/a@1.0','GO-123',['CVE-2026-1234'])
        b=self.row('pkg:golang/example/a@1.1','CVE-2026-1234')
        self.assertEqual(self.run_compare([a],[b]).returncode,0)

    def test_different_namespace_is_not_suppressed_by_display_name(self):
        a=self.row('pkg:npm/%40a/module@1.0','CVE-2026-1234')
        b=self.row('pkg:npm/%40b/module@1.0','CVE-2026-1234')
        self.assertEqual(self.run_compare([a],[b]).returncode,1)
        self.assertEqual(self.run_compare([a],[b],'cve-2026-1234 # accepted\n').returncode,0)

    def test_duplicate_provider_aliases_report_once(self):
        a=self.row('pkg:golang/example/a@1.0','GO-123',['CVE-2026-1234'])
        b=self.row('pkg:golang/example/a@1.0','CVE-2026-1234')
        result=self.run_compare([],[a,b])
        self.assertEqual(result.returncode,1)
        self.assertIn('Found 1 vulnerabilities',result.stdout)


class RaceTests(unittest.TestCase):
    def test_concurrent_coverage_reports_have_distinct_staging_files(self):
        with tempfile.TemporaryDirectory() as d,Cache(str(Path(d)/'queries')) as cache:
            barrier=threading.Barrier(2)
            real_replace=os.replace
            sources=[]
            def replace(source,dest):
                sources.append(source)
                barrier.wait(timeout=5)
                real_replace(source,dest)
            audit={'added_findings':0,'counts':{},'packages':[]}
            with patch.object(fallback,'additive_pass',return_value=([],audit)),patch.object(fallback.os,'replace',side_effect=replace):
                with ThreadPoolExecutor(max_workers=2) as workers:
                    tasks=[workers.submit(fallback.run_additive,[],[],cache,{},'same.json') for _ in range(2)]
                    for task in tasks:self.assertEqual(task.result(),[])
            self.assertEqual(len(set(sources)),2)
            self.assertEqual(json.loads((Path(d)/'fallback-reports/same.json.coverage.json').read_text()),audit)
            self.assertEqual(list(Path(d).rglob('*.tmp')),[])


class ShellTests(unittest.TestCase):
    def run_shell(self,body,cwd):
        return subprocess.run(['bash','-c',f'set -euo pipefail\nsource "{CI}/pr-scan.sh" fixture HEAD\n'+body],cwd=cwd,text=True,capture_output=True)

    def test_failed_build_never_copies_stale_sbom(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'stale.json').write_text('{"packages":[]}')
            result=self.run_shell('''make() { if [[ "$*" == *sbom_info* ]]; then echo stale.json; else return 1; fi; }
if build_current_eve result.json version; then exit 99; fi
test ! -e result.json
''',d)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_cvss_download_is_bounded_atomic_and_selects_named_asset(self):
        for fail in (False, True):
            with tempfile.TemporaryDirectory() as d:
                body = r'''mkdir db
echo previous > db/cvss-bt.csv
curl() {
    local output="" bounded=false retried=false
    while [ "$#" -gt 1 ]; do
        case "$1" in
            --max-time) bounded=true; shift ;;
            --retry) retried=true; shift ;;
            -o) output="$2"; shift ;;
        esac
        shift
    done
    $bounded && $retried || return 99
    if [ -z "$output" ]; then
        echo '{"assets":[{"name":"wrong.zip","browser_download_url":"https://example.invalid/wrong"},{"name":"cvss-bt.csv","browser_download_url":"https://example.invalid/right"}]}'
    else
        [ "$1" = https://example.invalid/right ] || return 98
        echo downloaded > "$output"
        [ "$TEST_FAIL" = no ] || return 28
    fi
}
if download_cvss_db db; then
    [ "$TEST_FAIL" = no ] || exit 97
    [ "$(cat db/cvss-bt.csv)" = downloaded ] || exit 96
else
    [ "$TEST_FAIL" = yes ] || exit 95
    [ "$(cat db/cvss-bt.csv)" = previous ] || exit 94
fi
[ "$(find db -type f | wc -l)" -eq 1 ]
'''
                result=self.run_shell('TEST_FAIL='+('yes' if fail else 'no')+'\n'+body,d)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_metadata_evaluates_the_requested_architecture(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'kernel-version.mk').write_text('ifeq ($(ZARCH),amd64)\nKERNEL_VERSION=v6.1.10\nelse\nKERNEL_VERSION=v5.10.1\nendif\n')
            result=self.run_shell('get_source_kernel_version',d)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'v6.1.10')

    def test_stale_fork_base_is_fetched_and_build_products_are_isolated(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);upstream=d/'upstream';fork=d/'fork';work=d/'work';work.mkdir()
            env={**os.environ,'GIT_AUTHOR_NAME':'Test','GIT_AUTHOR_EMAIL':'test@example.invalid','GIT_COMMITTER_NAME':'Test','GIT_COMMITTER_EMAIL':'test@example.invalid'}
            def git(*args,cwd=d):
                return subprocess.check_output(['git',*args],cwd=cwd,env=env,stderr=subprocess.DEVNULL,text=True).strip()
            git('init','-q','-b','master',str(upstream));Path(upstream,'data').write_text('old')
            git('add','.',cwd=upstream);git('commit','-qm','old',cwd=upstream)
            git('clone','-q',str(upstream),str(fork))
            git('checkout','-qb','17.0-stable',cwd=upstream);Path(upstream,'data').write_text('stable')
            git('commit','-qam','stable',cwd=upstream);expected=git('rev-parse','HEAD',cwd=upstream)
            Path(fork,'pr-only-build-output').write_text('contamination')
            body='''EVE_REPO_DIR="$TEST_FORK"
TEMP_DIR="$TEST_WORK"
BASE_URL="$TEST_UPSTREAM"
BASE_REF=17.0-stable
build_current_eve() { test ! -e pr-only-build-output || return 1; git rev-parse HEAD > "$1"; echo 3.22.0 > "$2"; }
get_master_info
'''
            with patch.dict(os.environ,{'TEST_FORK':str(fork),'TEST_WORK':str(work),'TEST_UPSTREAM':str(upstream)}):
                result=self.run_shell(body,d)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((work/'master-sbom.json').read_text().strip(),expected)
            self.assertTrue((fork/'pr-only-build-output').exists())


class FullScanTests(unittest.TestCase):
    def run_flow(self, parallel, failed_scan=False, failed_upload=False):
        flow=(CI/'full-scan.sh').read_text().split('log_info "Start CVE scanning..."',1)[1]
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);(d/'scans').mkdir();(d/'logs').mkdir()
            stale=d/'scans/scan_results_bad.json';stale.write_text('stale')
            body = 'set -euo pipefail\n' + f'PARALLEL={str(parallel).lower()}\nUPLOAD=true\nALL_TAGS="good bad"\nSCAN_DIR="{d}/scans"\nLOG_DIR="{d}/logs"\n'
            body += 'log_info() { :; }; log_error() { :; }; log_warn() { :; }\n'
            body += 'run_scanner() { '
            if failed_scan: body += '[ "$1" != bad ] || return 1; '
            body += 'echo fresh > "$SCAN_DIR/scan_results_$1.json"; }\n'
            body += f'upload_scan() {{ echo "$1" >> "{d}/uploaded"; '
            body += ('[ "$1" != good ]; }\n' if failed_upload else 'return 0; }\n')
            result=subprocess.run(['bash','-c',body+flow],capture_output=True,text=True)
            return result.returncode, (d/'uploaded').read_text().splitlines() if (d/'uploaded').exists() else [], {p.name:p.read_text() for p in (d/'scans').iterdir()}

    def test_parallel_failure_does_not_upload_stale_result(self):
        status,uploaded,remaining=self.run_flow(True,failed_scan=True)
        self.assertEqual(status,1)
        self.assertEqual(uploaded,['good'])
        self.assertEqual(remaining,{'scan_results_bad.json':'stale'})

    def test_failed_upload_retains_result_and_fails_both_modes(self):
        for parallel in (False,True):
            status,uploaded,remaining=self.run_flow(parallel,failed_upload=True)
            self.assertEqual(status,1)
            self.assertEqual(uploaded,['good','bad'])
            self.assertEqual(remaining,{'scan_results_good.json':'fresh\n'})

    def test_success_only_removes_uploaded_files(self):
        for parallel in (False,True):
            status,uploaded,remaining=self.run_flow(parallel)
            self.assertEqual(status,0)
            self.assertEqual(uploaded,['good','bad'])
            self.assertEqual(remaining,{})


class ImageTests(unittest.TestCase):
    def test_failed_extraction_preserves_cache_and_commit_identity_controls_reuse(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);tools=d/'bin';tools.mkdir();out=d/'sbom.json';calls=d/'calls'
            docker=tools/'docker'
            docker.write_text("""#!/bin/bash
case "$1" in
 image|pull|rmi) exit 0 ;;
 run)
  echo "$3" >> "$CALLS"
  if [ "$BROKEN" = 1 ]; then echo '{"packages":'; exit 1; fi
  echo '{"packages":[{"name":"test","versionInfo":"1.0"}]}'
 ;;
esac
""")
            docker.chmod(0o755)
            def run(tag,broken=False):
                return subprocess.run(['bash',str(CI/'eve/get_sbom.sh'),tag,str(out)],cwd=d,capture_output=True,text=True,
                    env={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH'],'CALLS':str(calls),'BROKEN':'1' if broken else '0'})
            self.assertEqual(run('master-aaaaaaaa').returncode,0)
            original=out.read_bytes();marker=Path(str(out)+'.image').read_text()
            self.assertNotEqual(run('master-bbbbbbbb',True).returncode,0)
            self.assertEqual(out.read_bytes(),original)
            self.assertEqual(Path(str(out)+'.image').read_text(),marker)
            self.assertEqual(run('master-bbbbbbbb').returncode,0)
            self.assertIn('master-bbbbbbbb',Path(str(out)+'.image').read_text())
            count=len(calls.read_text().splitlines())
            self.assertEqual(run('master-bbbbbbbb').returncode,0)
            self.assertEqual(len(calls.read_text().splitlines()),count)
            self.assertEqual(sorted(p.name for p in d.glob('sbom.json*')),['sbom.json','sbom.json.image','sbom.json.lock'])

    def test_historical_cache_uses_recorded_commit_not_latest_month_commit(self):
        script=(CI/'historical-master.sh').read_text()
        a=script.index('    if [ -s "$SBOM_PATH" ]',script.index('for TARGET_DATE'))
        b=script.index('    log_info "  Commit:',a)
        code=script[a:b]
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);sbom=d/'sbom.json';sbom.write_text('{"packages":[{}]}')
            Path(str(sbom)+'.commit.json').write_text(json.dumps({'sha':'a'*40,'date':'2025-02-01'}))
            image=Path(str(sbom)+'.image');image.write_text('lfedge/eve:0.0.0-master-aaaaaaaa-kvm-amd64\n')
            prefix=f"""set -euo pipefail
SBOM_PATH="{sbom}"
FOUND_COMMIT_SHA=""
MONTH_LABEL=2025-02
TARGET_DATE=2025-02-28
MONTH_START=2025-02-01
FAILED=0
get_sbom_for_month() {{ FOUND_COMMIT_SHA={'b'*40}; }}
log_error() {{ :; }}
"""
            def run():
                return subprocess.run(['bash','-c',prefix+'for run in once; do\n'+code+'done\necho "$FOUND_COMMIT_SHA"'],capture_output=True,text=True)
            result=run();self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'a'*40)
            image.write_text('lfedge/eve:0.0.0-master-cccccccc-kvm-amd64\n')
            result=run();self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'b'*40)


if __name__=='__main__':unittest.main()

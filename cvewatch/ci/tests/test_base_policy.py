# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import base_policy

CI = Path(__file__).resolve().parents[1]


class BasePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='base policy ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'upstream'
        self.output = self.root / 'policy' / 'ignore'
        self.env = {**os.environ, 'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.invalid',
                    'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.invalid'}
        subprocess.run(['git', 'init', '-q', '-b', 'master', str(self.repo)], check=True)
        (self.repo / 'README').write_text('fixture\n')
        self.initial = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args],
                                       env=self.env, stderr=subprocess.PIPE, text=True).strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def test_reads_current_base_tip_and_preserves_pinned_snapshot(self):
        self.git('checkout', '-qb', '17.0-stable')
        (self.repo / '.cve-ignore').write_text('CVE-approved\n')
        approved = self.commit()
        self.assertEqual(base_policy.pin_base(str(self.repo), '17.0-stable'), approved)
        (self.repo / '.cve-ignore').write_text('CVE-later\n')
        later = self.commit()
        base_policy.export_policy(str(self.repo), '17.0-stable', self.output, approved)
        self.assertEqual(self.output.read_text(), 'CVE-approved\n')
        self.assertEqual(Path(str(self.output) + '.commit').read_text().strip(), approved)
        self.assertEqual(base_policy.export_policy(str(self.repo), '17.0-stable', self.output), later)
        self.assertEqual(self.output.read_text(), 'CVE-later\n')

    def test_missing_policy_means_no_exceptions_and_clears_stale_contents(self):
        self.output.parent.mkdir()
        self.output.write_text('CVE-stale\n')
        base_policy.export_policy(str(self.repo), 'master', self.output)
        self.assertEqual(self.output.read_bytes(), b'')

    def test_fetch_failure_removes_stale_policy_and_provenance(self):
        base_policy.export_policy(str(self.repo), 'master', self.output)
        with self.assertRaises(subprocess.CalledProcessError):
            base_policy.export_policy(str(self.root / 'missing'), 'master', self.output, self.initial)
        self.assertFalse(self.output.exists())
        self.assertFalse(Path(str(self.output) + '.commit').exists())

    def test_missing_branch_is_not_an_empty_policy(self):
        with self.assertRaises(subprocess.CalledProcessError):
            base_policy.export_policy(str(self.repo), 'missing', self.output)
        self.assertFalse(self.output.exists())

    def test_symlink_policy_is_rejected_without_following_it(self):
        secret = self.root / 'outside'; secret.write_text('CVE-unapproved\n')
        (self.repo / '.cve-ignore').symlink_to(secret)
        self.commit()
        with self.assertRaisesRegex(ValueError, 'regular file'):
            base_policy.export_policy(str(self.repo), 'master', self.output)
        self.assertFalse(self.output.exists())

    def test_oversized_or_non_utf8_policy_fails_closed(self):
        for contents in (b'x' * (1024 * 1024 + 1), b'\xff'):
            (self.repo / '.cve-ignore').write_bytes(contents)
            self.commit()
            with self.assertRaises(ValueError):
                base_policy.export_policy(str(self.repo), 'master', self.output)
            self.assertFalse(self.output.exists())

    def test_full_commit_and_literal_branch_names_are_required(self):
        for commit in ('HEAD', 'a' * 39, '-c', 'a' * 40 + '\n'):
            with self.assertRaises(ValueError):
                base_policy.export_policy(str(self.repo), 'master', self.output, commit)
        for branch in ('*', 'master\n', '../master'):
            with self.assertRaises(subprocess.CalledProcessError):
                base_policy.pin_base(str(self.repo), branch)

    def test_pr_and_build_artifact_exceptions_cannot_bypass_gate(self):
        # Use real Git policy retrieval, scan orchestration, and comparison.
        # Stub feed/scanning work to provide one deterministic new finding.
        scripts = self.root / 'ci'; scripts.mkdir(); (scripts / 'scan').mkdir()
        for name in ('scan-inputs.sh', 'compare.sh', 'scan/compare.py'):
            shutil.copyfile(CI / name, scripts / name)
        (scripts / 'common.sh').write_text('''setup_common_env() {
    SCAN_DIR=out/scans; CACHE_SOURCE_DIR=out/cache; TEMP_DIR=unused; ALPINE_CACHE=unused
    mkdir -p "$SCAN_DIR" "$CACHE_SOURCE_DIR"
}
setup_python_env() { :; }
cleanup_files() { :; }
download_cvss_db() { :; }
log_info() { :; }
log_error() { echo "$*" >&2; }
run_cve_scanner() { cp "$2" "$SCAN_DIR/scan_results_$1.json"; }
''')
        new = [{'package': {'name': 'demo'}, 'vulnerabilities': [{'id': 'CVE-new'}]}]
        for role, rows in (('pr', new), ('base', [])):
            folder = self.root / role; folder.mkdir()
            (folder / 'sbom.json').write_text(json.dumps(rows))
            (folder / 'kernel-version').write_text('6.1.1')
            (folder / 'cve-ignore').write_text('CVE-new\n')
        # A PR can add the ignore file, but it is absent from the base tip.
        self.git('checkout', '-qb', 'feature')
        (self.repo / '.cve-ignore').write_text('CVE-new\n'); self.commit()
        base_policy.export_policy(str(self.repo), 'master', self.output)
        command = ['bash', str(scripts / 'scan-inputs.sh'), 'pr', 'base', str(self.output)]
        def gate():
            return subprocess.run(command, cwd=self.root, capture_output=True, text=True)
        result = gate()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        # Only a separately merged base exception changes the outcome.
        self.git('checkout', 'master')
        (self.repo / '.cve-ignore').write_text('CVE-new\n'); self.commit()
        base_policy.export_policy(str(self.repo), 'master', self.output)
        result = gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.output.unlink()
        self.assertEqual(gate().returncode, 2)

    def test_baseline_build_uses_resolved_sha_if_branch_advances(self):
        (self.repo / 'README').write_text('later\n'); self.commit()
        work = self.root / 'work'; work.mkdir()
        source = self.root / 'source'
        subprocess.run(['git', 'init', '-q', str(source)], check=True)
        body = '''set -euo pipefail
source "$CI_SCRIPT" fixture HEAD
EVE_REPO_DIR="$TEST_SOURCE"; TEMP_DIR="$TEST_WORK"
BASE_URL="$TEST_REPO"; BASE_REF=master
build_current_eve() { git rev-parse HEAD > "$1"; echo 3.22.0 > "$2"; }
get_master_info
'''
        result = subprocess.run(['bash', '-c', body], cwd=self.root, capture_output=True, text=True,
                                env={**self.env, 'CI_SCRIPT': str(CI / 'pr-scan.sh'),
                                     'TEST_SOURCE': str(source), 'TEST_WORK': str(work),
                                     'TEST_REPO': str(self.repo), 'BASE_SHA': self.initial})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((work / 'master-sbom.json').read_text().strip(), self.initial)


if __name__ == '__main__':
    unittest.main()

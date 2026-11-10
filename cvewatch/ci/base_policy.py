#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Read approved exceptions from Git objects, without executing source code."""
import argparse
import os
import re
import subprocess
import tempfile
from pathlib import Path


def git(*args):
    return subprocess.run(
        ['git', '-c', 'core.hooksPath=/dev/null', *map(str, args)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'}).stdout


def check_commit(commit):
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Expected a full base commit SHA')
    return commit


def pin_base(repository, branch):
    ref = 'refs/heads/' + branch
    git('check-ref-format', ref)
    lines = git('ls-remote', '--exit-code', '--refs', '--', repository, ref).decode().splitlines()
    matches = [line.split()[0] for line in lines if line.split()[1:] == [ref]]
    if len(matches) != 1:
        raise ValueError('Cannot resolve a unique base branch tip')
    return check_commit(matches[0])


def export_policy(repository, branch, output, commit=None):
    output = Path(output)
    marker = Path(str(output) + '.commit')
    # A failed fetch must not leave a previous policy available for reuse.
    output.unlink(missing_ok=True)
    marker.unlink(missing_ok=True)
    commit = check_commit(commit) if commit else pin_base(repository, branch)
    with tempfile.TemporaryDirectory(prefix='cve-base-policy-') as temp:
        git('init', '--bare', '--template=', temp)
        git('-C', temp, 'remote', 'add', 'origin', repository)
        # Fetch commit/tree metadata and lazily obtain only the policy blob,
        # rather than downloading EVE's entire source/vendor tree.
        git('-C', temp, 'config', 'remote.origin.promisor', 'true')
        git('-C', temp, 'config', 'remote.origin.partialclonefilter', 'blob:none')
        git('-C', temp, 'fetch', '--depth=1', '--no-tags', '--filter=blob:none', 'origin', commit)
        fetched = git('-C', temp, 'rev-parse', 'FETCH_HEAD').decode().strip()
        if fetched != commit:
            raise ValueError('Fetched base commit does not match the pinned revision')
        entry = git('-C', temp, 'ls-tree', commit, '--', '.cve-ignore').decode().strip()
        policy = b''
        if entry:
            metadata, name = entry.split('\t', 1)
            mode, kind, oid = metadata.split()
            if name != '.cve-ignore' or mode not in ('100644', '100755') or kind != 'blob':
                raise ValueError('Base .cve-ignore must be a regular file')
            if int(git('-C', temp, 'cat-file', '-s', oid)) > 1024 * 1024:
                raise ValueError('Base .cve-ignore exceeds 1 MiB')
            policy = git('-C', temp, 'cat-file', 'blob', oid)
            policy.decode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(policy)
    marker.write_text(commit + '\n')
    return commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository')
    parser.add_argument('branch')
    parser.add_argument('output')
    parser.add_argument('--commit', help='Previously resolved base branch tip')
    args = parser.parse_args()
    try:
        commit = export_policy(args.repository, args.branch, args.output, args.commit)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(2, f'Cannot load approved base policy: {exc}\n')
    print(f'Approved exception policy: {args.repository} {args.branch} at {commit}')


if __name__ == '__main__':
    main()

# CVE Watch

Tools for scanning EVE-OS for vulnerabilities and gating Pull Requests.

Run local commands below from the `cvewatch/` directory. The reusable workflow
lives at the repository root in `.github/workflows/cve-scan.yml`.

## GitHub Action Usage

Use this workflow in the EVE repository to block PRs that introduce new vulnerabilities.

Create `.github/workflows/cve-gate.yml`:

```yaml
name: CVE PR Gate

on:
  pull_request:

jobs:
  cve-scan:
    name: Scan PR for Vulnerabilities
    uses: lf-edge/eve-tools/.github/workflows/cve-scan.yml@master # Pin a reviewed release or commit SHA.
    with:
      eve-repo-url: ${{ github.event.pull_request.head.repo.clone_url }}
      eve-revision: ${{ github.event.pull_request.head.sha }}
      eve-base-ref: ${{ github.event.pull_request.base.ref }}
```

The baseline is the tip of `eve-base-ref` (default `master`) fetched from
`eve-base-repo-url` (default `https://github.com/lf-edge/eve.git`), so a PR
against a stable branch is compared with that branch rather than with master.

### Ignoring vulnerabilities

The PR gate reads `.cve-ignore` from the **tip of the target base branch**,
pinned when the run resolves its inputs. The baseline SBOM uses that same commit.
The trusted scan job retrieves the policy directly from Git without running
source code; ignore files supplied by PR or baseline build artifacts are ignored.

Submit exception changes in a **separate PR**, get them reviewed and merged into
the base branch, then rerun the affected PR's scan. An exception added in the PR
being scanned cannot suppress that PR's findings. The scanner does not enforce
that exception PRs contain only policy edits; reviewers enforce that workflow.

A base commit with no `.cve-ignore` means no exceptions. A failed policy fetch or
invalid policy file fails the scan instead of silently changing the policy.
The report artifact includes the applied policy and its base commit SHA.

Use one vulnerability ID per line (`CVE-...`, `GHSA-...`, ...). `#` starts a
comment; blank lines are skipped. Matching is case-insensitive and includes
advisory aliases, so a CVE ID matches the corresponding GHSA entry and vice versa.

```
# false positive, code path not built into EVE
CVE-2025-12345
GHSA-xxxx-yyyy-zzzz  # accepted risk, tracked in issue #1234
```

## Local Usage

You can run the PR scanner locally to check a branch before pushing.

```bash
# Usage: ./ci/pr-scan.sh <GIT_URL> [REVISION] [BASE_URL] [BASE_REF]
./ci/pr-scan.sh https://github.com/lf-edge/eve.git my-feature-branch
./ci/pr-scan.sh https://github.com/me/eve.git my-backport https://github.com/lf-edge/eve.git 17.0-stable
```

## Full Scan with Upload

Scans all supported EVE LTS tags + master and uploads results to a CVEWatch instance.

```bash
# Required environment variables
export CVEWATCH_URL=https://cvewatch.example.com   # Your CVEWatch server URL
export CVEWATCH_TOKEN=<upload-token>       # Generate via UI: Profile → Upload Tokens

# Run once
./ci/full-scan.sh --upload

# Parallel scanning (faster, one scanner per tag)
./ci/full-scan.sh --upload --parallel
```

### Automated Daily Scan (cron)

```bash
sudo crontab -e
```

```cron
0 3 * * * cd /path/to/eve-tools/cvewatch/ci && CVEWATCH_URL=https://cvewatch.example.com CVEWATCH_TOKEN=<token> ./full-scan.sh --upload --parallel >> /var/log/cvewatch-scan.log 2>&1
```

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--upload` | Upload scan results to `CVEWATCH_URL` |
| `-p`, `--parallel` | Run scanners in parallel |
| `-f`, `--fetch-only` | Fetch SBOMs and Alpine data only, skip scanning |

## Scan correctness and CI trust boundary

The reusable workflow resolves both sides of a PR automatically, including the
associated PR for a `workflow_run` event. Explicit inputs override event values.
A run whose PR head has changed, or which has no unambiguous associated PR,
fails instead of guessing a revision. Existing callers must update their pinned
workflow reference to receive these changes.

PR and baseline SBOMs are built in separate disposable GitHub-hosted jobs. A
third job checks out the scanner at the reusable workflow's own commit and scans
only the resulting data artifacts. Tokens have read-only repository access,
checkout credentials are not persisted, and the build commands receive no
explicit API token. This prevents a PR build from modifying the baseline tree
or the scanner used by the gate. GitHub.com is required for the documented
[`job.workflow_sha`/`job.workflow_repository` contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context).

This is still a source-controlled build: malicious PR code can fabricate its
own SBOM. The approved exception policy comes independently from the pinned
base branch. Protect workflow/build configuration and review policy changes
through your normal code-review rules. The local `pr-scan.sh`
helper runs repository build commands on your machine; use the isolated CI
workflow for untrusted forks. No production secrets are needed for PR scans.

Scanner behavior shared with CVEWatch:

- Normalize Go standard-library/toolchain versions for OSV while preserving the
  actual binary version in the output. Development/unknown Go versions do not
  become queries for every version.
- Scope Alpine queries by container release and source package, and Debian
  queries by release/source package. A flattened list of APKBUILD CVEs is not
  proof that an installed package revision is patched.
- Retry transient OSV errors and expire query results after eight hours. Failed,
  malformed, or incomplete paginated responses are not cached as successes.
- Add conservative fallback findings only with verified Alpine revision plus
  upstream affected-version evidence, or an exact source commit/repository.
  Patched distro packages are not overridden by guessed upstream matches.
- Exclude withdrawn advisories; include the advisory's own CVE ID when enriching
  exploitability. Compare aliases within a package identity so different
  advisory providers do not create duplicate "new" CVEs.

Primary lookup failures for supported, versioned identities make the scan fail.
Partial findings are retained as `*.partial.json`; they cannot pass the gate or
be uploaded as a completed scan. Unsupported identities/missing distro releases
and supplemental fallback uncertainty remain explicit coverage limitations,
not proof that a package is safe. Supplemental coverage reports are written to
`out/cache/osv/fallback-reports/` and included in the CI artifact.

The original scanner CLI is retained:

```bash
python ci/scan/scanner.py LABEL sbom.json cvss-bt.csv unused out/scans \
  --kernel-version 6.1.155
```

`LABEL` names the output; it is never treated as a Git revision. Supply the
kernel from the exact source revision when the SBOM omits it. PR, daily, and
historical wrappers do this automatically. The old Alpine DB positional
argument remains accepted for compatibility; flat secfixes are no longer used
to suppress results. Daily and historical scans retain failed uploads for
retry, delete only successfully uploaded result files, and exit nonzero on
failures. Concurrent runs of the same wrapper/output directory are rejected;
parallel tag workers share expiring query caches safely.

## Regression tests

```bash
python -m pip install -r ci/requirements-test.txt
python -m unittest discover -s ci/tests -v
for script in ci/*.sh ci/eve/*.sh ci/alpine/*.sh; do bash -n "$script"; done
```

CI runs these tests on Python 3.10 and 3.13. Tests use local Git repositories and
mock public API/build/image responses; they do not build EVE, probe production,
or send CVEWatch uploads.

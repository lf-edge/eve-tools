#!/bin/bash
# Scan data artifacts on a fresh runner, without executing anything from EVE.
set -euo pipefail
CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PR_DIR="${1:?PR artifacts required}"
BASE_INPUT_DIR="${2:?baseline artifacts required}"
BASE_POLICY="${3:?approved base ignore policy required}"
[[ -f "$BASE_POLICY" && ! -L "$BASE_POLICY" ]] || { echo "Missing approved base policy" >&2; exit 2; }
source "$CI_DIR/common.sh"
setup_common_env
trap 'cleanup_files "$TEMP_DIR" "$ALPINE_CACHE"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
download_cvss_db "$CACHE_SOURCE_DIR"
for role in pr base; do
    dir="$PR_DIR"
    [ "$role" != base ] || dir="$BASE_INPUT_DIR"
    kernel=$(cat "$dir/kernel-version")
    [[ "$kernel" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { log_error "Invalid $role kernel version"; exit 2; }
    # File contents are only data. No artifact-derived paths or commands run.
    run_cve_scanner "$role" "$dir/sbom.json" unused "$SCAN_DIR" "$CACHE_SOURCE_DIR/cvss-bt.csv" "$kernel"
done
# Ignore files supplied by either build artifact are deliberately not consulted.
args=("$SCAN_DIR/scan_results_base.json" "$SCAN_DIR/scan_results_pr.json" out/scan_report.txt "$BASE_POLICY")
bash "$CI_DIR/compare.sh" "${args[@]}"

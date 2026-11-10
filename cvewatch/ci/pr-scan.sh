#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Scan a PR for vulnerabilities and compare with the tip of its base branch.
# Usage: ./pr-scan.sh <GIT_URL> [REVISION] [BASE_URL] [BASE_REF]

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <GIT_URL> [REVISION] [BASE_URL] [BASE_REF]"
    echo "Example: $0 https://github.com/lf-edge/eve.git master"
    exit 1
fi

GIT_URL="$1"
REVISION="${2:-HEAD}"
[[ "$GIT_URL" != -* && "$REVISION" != -* ]] || { echo "Invalid repository or revision" >&2; exit 2; }
BASE_URL="${3:-https://github.com/lf-edge/eve.git}"
BASE_REF="${4:-master}"

# Directories
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# cd "$BASE_DIR"
source "$BASE_DIR/common.sh"

SCAN_DIR="out/scans"
CACHE_SOURCE_DIR="out/cache/data-source"
REPORT_FILE="out/scan_report.txt"
TEMP_DIR=""
ALPINE_CACHE=""
EVE_REPO_DIR=""

setup_environment() {
    setup_common_env
}

cleanup() {
    if [ -n "$TEMP_DIR" ]; then
        if [[ "$TEMP_DIR" == /tmp/* ]]; then
             cleanup_files "$TEMP_DIR"
        fi
    fi
    cleanup_files "$ALPINE_CACHE"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM


build_current_eve() {
    local sbom_dest="$1"
    local version_dest="$2"

    log_info "Building SBOM..."
    # Explicitly propagate failure: this function is invoked in an `if`,
    # which disables bash errexit inside the function.
    log_cmd make HV=kvm PLATFORM=generic ZARCH=amd64 LINUXKIT_PKG_TARGET=build pkgs sbom || return 1

    log_info "Getting SBOM path..."
    local sbom_rel_path
    if ! sbom_rel_path=$(make HV=kvm PLATFORM=generic ZARCH=amd64 sbom_info 2>/dev/null); then
        log_error "make sbom_info failed"
        return 1
    fi

    if [ -z "$sbom_rel_path" ] || [ ! -f "$sbom_rel_path" ]; then
        log_error "SBOM file not found after build."
        return 1
    fi

    log_info "Found SBOM at $sbom_rel_path"
    cp "$sbom_rel_path" "$sbom_dest" || return 1

    read_source_metadata "$version_dest" "${sbom_dest%.json}-kernel-version"
}

read_source_metadata() {
    local version_dest="$1"
    local kernel_dest="$2"
    # Get Alpine version
    if [ -f "pkg/alpine/Dockerfile" ]; then
        local alpine_version
        alpine_version=$(grep -oE "ARG ALPINE_VERSION=[0-9]+\.[0-9]+" pkg/alpine/Dockerfile | head -n 1 | cut -d= -f2)
        if [ -n "$alpine_version" ]; then
            if [[ ! "$alpine_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                alpine_version="${alpine_version}.0"
            fi
            echo "$alpine_version" > "$version_dest"
        else
            log_error "Could not find ALPINE_VERSION in Dockerfile"
            return 1
        fi
    else
        log_error "pkg/alpine/Dockerfile not found"
        return 1
    fi
    get_source_kernel_version > "$kernel_dest" || return 1

}

# Clone EVE from GIT_URL and checkout REVISION
clone_and_build_eve() {
    log_info "Cloning EVE from $GIT_URL..."
    EVE_REPO_DIR="$TEMP_DIR/eve"
    log_cmd git clone -- "$GIT_URL" "$EVE_REPO_DIR"

    pushd "$EVE_REPO_DIR" > /dev/null
    if [ "$REVISION" != "HEAD" ]; then
        log_info "Checking out $REVISION..."
        log_cmd git checkout "$REVISION"
    fi

    local commit_info
    commit_info=$(git log -1 --format='%h %s')
    echo "$commit_info" > "$TEMP_DIR/pr-commit-info"
    log_info "PR Commit: $commit_info"

    # Save the CVE ignore file from the PR revision, if present. The repo
    # tree may be re-checked out to master later, so keep a copy.
    if [ -f ".cve-ignore" ]; then
        cp ".cve-ignore" "$TEMP_DIR/cve-ignore"
        log_info "Found .cve-ignore in the EVE repo"
    fi

    if ! build_current_eve "$TEMP_DIR/pr-sbom.json" "$TEMP_DIR/pr-alpine-version"; then
        log_error "Failed to build PR version"
        popd > /dev/null
        exit 1
    fi

    popd > /dev/null
}

get_master_info() {
    local master_sbom_path="$TEMP_DIR/master-sbom.json"
    local master_version_path="$TEMP_DIR/master-alpine-version"
    local base_tree="$TEMP_DIR/base-eve"
    local base_sha
    # Pin the upstream branch once, before selecting an image or metadata.
    # Use a separate worktree so PR build products cannot contaminate baseline.
    log_cmd git -C "$EVE_REPO_DIR" fetch "$BASE_URL" "refs/heads/$BASE_REF" || return 1
    base_sha=$(git -C "$EVE_REPO_DIR" rev-parse FETCH_HEAD) || return 1
    log_cmd git -C "$EVE_REPO_DIR" worktree add --detach "$base_tree" "$base_sha" || return 1
    git -C "$base_tree" log -1 --format='%h %s' > "$TEMP_DIR/master-commit-info"
    log_info "Baseline: $BASE_URL $BASE_REF ($base_sha)"
    pushd "$base_tree" > /dev/null
    if [ "$BASE_URL" = "https://github.com/lf-edge/eve.git" ] && [ "$BASE_REF" = master ] &&
       log_cmd bash "$BASE_DIR/eve/get_sbom.sh" "master-${base_sha:0:8}" "$master_sbom_path"; then
        read_source_metadata "$master_version_path" "$TEMP_DIR/master-sbom-kernel-version" || return 1
    else
        log_info "Building the pinned baseline from source"
        build_current_eve "$master_sbom_path" "$master_version_path" || return 1
    fi
    popd > /dev/null
    : # Distro release is derived per package/container by the scanner.
}

run_scans() {
    local cvss_bt_path="$CACHE_SOURCE_DIR/cvss-bt.csv"

    # Get versions
    local pr_version
    pr_version=$(cat "$TEMP_DIR/pr-alpine-version")
    local pr_db_path="$CACHE_SOURCE_DIR/alpine_packages_${pr_version}.json"

    local master_version
    master_version=$(cat "$TEMP_DIR/master-alpine-version")
    local master_db_path="$CACHE_SOURCE_DIR/alpine_packages_${master_version}.json"

    local pr_commit="Unknown"
    [ -f "$TEMP_DIR/pr-commit-info" ] && pr_commit=$(cat "$TEMP_DIR/pr-commit-info")

    local master_commit="Unknown"
    [ -f "$TEMP_DIR/master-commit-info" ] && master_commit=$(cat "$TEMP_DIR/master-commit-info")

    # Scan PR
    log_info "------------------------------------------------------------"
    log_info "Starting PR Scan (Alpine v$pr_version)..."
    log_info "Commit: $pr_commit"
    log_info "PR SBOM Checksum: $(md5sum "$TEMP_DIR/pr-sbom.json" | awk '{print $1}')"
    log_info "------------------------------------------------------------"
    local pr_sbom_path="$TEMP_DIR/pr-sbom.json"

    if ! run_cve_scanner "pr" "$pr_sbom_path" "$pr_db_path" "$TEMP_DIR" "$cvss_bt_path" "$(cat "$TEMP_DIR/pr-sbom-kernel-version")"; then
        log_error "PR scan failed"
        exit 1
    fi
    log_info "------------------------------------------------------------"
    log_info "PR Scan Finished."
    log_info "------------------------------------------------------------"

    # Scan Master
    log_info "------------------------------------------------------------"
    log_info "Starting Baseline Scan (Alpine v$master_version)..."
    log_info "Commit: $master_commit"
    log_info "Baseline SBOM Checksum: $(md5sum "$TEMP_DIR/master-sbom.json" | awk '{print $1}')"
    log_info "------------------------------------------------------------"
    local master_sbom_path="$TEMP_DIR/master-sbom.json"

    if ! run_cve_scanner "master" "$master_sbom_path" "$master_db_path" "$TEMP_DIR" "$cvss_bt_path" "$(cat "$TEMP_DIR/master-sbom-kernel-version")"; then
        log_error "Baseline scan failed"
        exit 1
    fi
    log_info "------------------------------------------------------------"
    log_info "Baseline Scan Finished."
    log_info "------------------------------------------------------------"
}

run_compare() {
    log_info "Comparing results..."
    if [ -f "$TEMP_DIR/cve-ignore" ]; then
        log_info "Applying CVE ignore list from the EVE repo (.cve-ignore)"
        log_cmd "$BASE_DIR/compare.sh" "$TEMP_DIR/scan_results_master.json" "$TEMP_DIR/scan_results_pr.json" "$REPORT_FILE" "$TEMP_DIR/cve-ignore"
    else
        log_cmd "$BASE_DIR/compare.sh" "$TEMP_DIR/scan_results_master.json" "$TEMP_DIR/scan_results_pr.json" "$REPORT_FILE"
    fi
}

# Main execution
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    trap - EXIT INT TERM
    return 0
fi
LOG_FILE="$LOG_DIR/pr-scan.log"
export LOG_FILE

setup_environment

log_info "Running PR scan..."
download_cvss_db "$CACHE_SOURCE_DIR"

log_info "Building EVE from $GIT_URL : $REVISION "
clone_and_build_eve

log_info "Getting Baseline Info..."
get_master_info

log_info "Running Scans..."
run_scans
log_info "Scan Phase Completed."

# Compare results (allow failure to propagate, output to stdout)
set +e
run_compare
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
    log_error "Comparison failed (Exit code: $EXIT_CODE)"
    exit $EXIT_CODE
fi

log_info "Done."

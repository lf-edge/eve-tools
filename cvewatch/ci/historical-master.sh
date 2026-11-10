#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Scan historical master commits month-by-month going back from today to a given date.
# For each month, find a master commit (merged PR), get SBOM via docker, scan, and optionally upload.
#
# Usage: ./historical-master.sh <START_DATE> [-u|--upload]
# Example: ./historical-master.sh 2024-06-01 --upload

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <START_DATE> [-u|--upload] [-n|--dry-run]"
    echo "  START_DATE: Go back from today to this date (YYYY-MM-DD)"
    echo "  -u|--upload: Upload scan results to cvewatch (requires CVEWATCH_URL and CVEWATCH_TOKEN)"
    echo "  -n|--dry-run: Fetch SBOMs and Alpine info but skip vulnerability scanning and upload"
    echo ""
    echo "Example: $0 2024-06-01 --upload"
    echo "         $0 2024-06-01 --dry-run"
    exit 1
fi

START_DATE="$1"
shift

# Validate date format
if ! date -d "$START_DATE" +%Y-%m-%d >/dev/null 2>&1; then
    echo "Error: Invalid date format '$START_DATE'. Use YYYY-MM-DD."
    exit 1
fi

UPLOAD=false
DRY_RUN=false
while [[ $# -gt 0 ]]; do
  case $1 in
    -u|--upload)
      UPLOAD=true
      shift
      ;;
    -n|--dry-run)
      DRY_RUN=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Directories
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BASE_DIR/common.sh"

LOG_DIR="${LOG_DIR:-out/logs}"
SCAN_DIR="out/scans/historical"
CACHE_SOURCE_DIR="out/cache/data-source"
SBOM_CACHE_DIR="out/cache/sbom/historical"
TEMP_DIR=""
ALPINE_CACHE=""

EVE_COMMITS_API="https://api.github.com/repos/lf-edge/eve/commits"
EVE_DOCKER_IMAGE_PREFIX="lfedge/eve:0.0.0-master-"
EVE_DOCKER_IMAGE_SUFFIX="-kvm-amd64"

# GitHub API results per page (fetch more to filter for merges)
GH_PAGE_SIZE=100
# Max pages to paginate through before giving up on a month
MAX_PAGES=5

INTERRUPTED=false

cleanup() {
    if [ "$INTERRUPTED" = true ]; then
        log_info "Interrupted by user. Cleaning up..."
    fi
    cleanup_files "$TEMP_DIR" "$ALPINE_CACHE"
}

handle_interrupt() {
    INTERRUPTED=true
    exit 130
}

trap cleanup EXIT
trap handle_interrupt INT TERM

setup_environment() {
    setup_common_env
    mkdir -p "$SCAN_DIR" "$SBOM_CACHE_DIR"
}

# Fetch a page of commits from the GitHub API.
# Args:
#   $1: until date (ISO 8601)
#   $2: page number (1-based)
# Outputs: raw JSON array of commits
fetch_commits_page() {
    local until_date="$1"
    local page="$2"

    local api_url="${EVE_COMMITS_API}?sha=master&until=${until_date}&per_page=${GH_PAGE_SIZE}&page=${page}"

    local curl_args=(-s -f)
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi

    local response
    if ! response=$(curl "${curl_args[@]}" "$api_url"); then
        log_error "Failed to fetch commits page $page from GitHub API"
        return 1
    fi
    echo "$response"
}

# Try to get an SBOM for a given month by walking through master commits.
# EVE uses rebase-merge, so each commit on master IS the tip of a merged PR
# (1 parent each). Paginates through the GitHub commit API automatically.
# For each page, tries docker pull + SBOM extraction on each commit.
# If all commits on a page fail, fetches the next page. Stops when:
#   - An SBOM is successfully extracted, OR
#   - A commit's date falls before the start of the target month, OR
#   - MAX_PAGES pages have been exhausted.
#
# Args:
#   $1: Month label (YYYY-MM)
#   $2: Until date (YYYY-MM-DD) — end of the month window
#   $3: Since date (YYYY-MM-DD) — start of the month window (1st of the month)
#   $4: Output SBOM path
# Outputs:
#   Sets FOUND_COMMIT_SHA (full), FOUND_COMMIT_SHORT, FOUND_COMMIT_DATE globals
get_sbom_for_month() {
    local month_label="$1"
    local until_date="${2}T23:59:59Z"
    local since_date="$3"
    local sbom_dest="$4"
    local tried=0

    for ((page = 1; page <= MAX_PAGES; page++)); do
        log_info "  [$month_label] Fetching commits page $page..."

        local raw_commits
        if ! raw_commits=$(fetch_commits_page "$until_date" "$page"); then
            log_error "  [$month_label] API request failed on page $page"
            return 1
        fi

        local page_count
        page_count=$(echo "$raw_commits" | jq 'length')
        if [ "$page_count" -eq 0 ] || [ "$page_count" = "null" ]; then
            log_warn "  [$month_label] No more commits returned on page $page"
            break
        fi

        log_info "  [$month_label] Page $page: $page_count commits"

        for ((i = 0; i < page_count; i++)); do
            local full_sha sha commit_date commit_msg
            full_sha=$(echo "$raw_commits" | jq -r ".[$i].sha")
            sha=$(echo "$full_sha" | cut -c 1-8)
            commit_date=$(echo "$raw_commits" | jq -r ".[$i].commit.committer.date")
            commit_msg=$(echo "$raw_commits" | jq -r ".[$i].commit.message" | head -n 1)

            # Check if this commit is still within our month window
            local commit_day
            commit_day=$(echo "$commit_date" | cut -dT -f1)
            if [[ "$commit_day" < "$since_date" ]]; then
                log_info "  [$month_label] Commit $sha ($commit_day) is before $since_date, stopping"
                log_error "  [$month_label] Exhausted all commits in month window (tried $tried)"
                return 1
            fi

            tried=$((tried + 1))
            log_info "  [$month_label] Trying commit #$tried: $sha ($commit_date): $commit_msg"

            if ! bash "$BASE_DIR/eve/get_sbom.sh" "master-$sha" "$sbom_dest"; then
                log_warn "  [$month_label] SBOM unavailable for $sha, trying previous commit..."
                continue
            fi
            # Bind cached bytes to the commit actually pulled, which may be
            # older than the newest commit in this month.
            jq -n --arg sha "$full_sha" --arg date "$commit_date" '{sha:$sha,date:$date}' > "$sbom_dest.commit.json.tmp"
            mv "$sbom_dest.commit.json.tmp" "$sbom_dest.commit.json"

            # Success
            FOUND_COMMIT_SHA="$full_sha"
            FOUND_COMMIT_SHORT="$sha"
            FOUND_COMMIT_DATE="$commit_date"
            log_info "  [$month_label] Got SBOM from commit $sha ($commit_date)"
            return 0
        done

        log_info "  [$month_label] No usable commit on page $page, fetching next page..."
        sleep 1  # rate-limit courtesy
    done

    log_error "  [$month_label] Failed to get SBOM after $MAX_PAGES pages ($tried commits tried)"
    return 1
}

# Get the Alpine version for a specific commit SHA on master
# Args:
#   $1: Commit SHA (full or short)
get_alpine_version_for_commit() {
    local sha="$1"
    local file_path="pkg/alpine/Dockerfile"
    local raw_url="https://raw.githubusercontent.com/lf-edge/eve/${sha}/${file_path}"

    local response
    if ! response=$(curl -s -f "$raw_url"); then
        log_error "Failed to fetch Dockerfile from $raw_url"
        return 1
    fi

    local alpine_version
    alpine_version=$(echo "$response" | grep -oE "ARG ALPINE_VERSION=[0-9]+\.[0-9]+" | head -n 1 | cut -d= -f2)
    if [ -n "$alpine_version" ]; then
        if [[ ! "$alpine_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            alpine_version="${alpine_version}.0"
        fi
        echo "$alpine_version"
        return 0
    else
        log_error "Could not find ALPINE_VERSION in Dockerfile for commit $sha"
        return 1
    fi
}

upload_scan() {
    local label="$1"
    local scan_file="$2"

    if [ ! -f "$scan_file" ]; then
        log_error "Scan file not found: $scan_file"
        return 1
    fi

    local curl_args=(
        -s -S
        -X POST
        -H "Authorization: Bearer ${CVEWATCH_TOKEN}"
        -F "file=@${scan_file}"
        -F "version=${label}"
        -F "master=true"
        -w "\n%{http_code}"
    )

    log_info "  Uploading scan for $label..."
    local response
    response=$(curl "${curl_args[@]}" "${CVEWATCH_URL}/api/v1/scan")
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "202" ] || [ "$http_code" = "201" ]; then
        local scan_id
        scan_id=$(echo "$body" | jq -r '.id // empty')
        log_info "  Upload successful for $label (scan ID: ${scan_id:-unknown})"
    else
        log_error "  Upload failed for $label (HTTP $http_code): $body"
        return 1
    fi
}

# Generate a list of month-end dates from START_DATE to today
# Each entry is the last day of that month, used as the "until" date for commit queries
generate_month_targets() {
    local start="$1"
    local today
    today=$(date +%Y-%m-%d)

    # Start from the first day of the start month
    local current
    current=$(date -d "$start" +%Y-%m-01)

    local targets=()
    while [[ "$current" < "$today" ]] || [[ "$current" == "$today" ]]; do
        # Last day of this month
        local last_day
        last_day=$(date -d "$current +1 month -1 day" +%Y-%m-%d)

        # Don't exceed today
        if [[ "$last_day" > "$today" ]]; then
            last_day="$today"
        fi

        targets+=("$last_day")

        # Move to first day of next month
        current=$(date -d "$current +1 month" +%Y-%m-01)
    done

    echo "${targets[@]}"
}

# ============================================================
# Main execution
# ============================================================

if [ "$UPLOAD" = true ]; then
    if [ -z "${CVEWATCH_URL:-}" ]; then
        log_error "CVEWATCH_URL environment variable is required for upload mode"
        exit 1
    fi
    if [ -z "${CVEWATCH_TOKEN:-}" ]; then
        log_error "CVEWATCH_TOKEN environment variable is required for upload mode"
        exit 1
    fi
    log_info "Upload mode enabled. Target: $CVEWATCH_URL"
fi

LOG_FILE="$LOG_DIR/historical-master.log"
export LOG_FILE

setup_environment
exec 9>"$SCAN_DIR/.historical-scan.lock"
flock -n 9 || { log_error "Another historical scan is using $SCAN_DIR"; exit 1; }
if [ "$DRY_RUN" = false ]; then
    download_cvss_db "$CACHE_SOURCE_DIR"


fi

log_info "============================================================"
log_info "Historical Master Scan"
log_info "  Start date: $START_DATE"
log_info "  Today:      $(date +%Y-%m-%d)"
log_info "  Upload:     $UPLOAD"
log_info "  Dry run:    $DRY_RUN"
log_info "============================================================"

# Generate month targets (going from START_DATE forward to today)
MONTH_TARGETS=$(generate_month_targets "$START_DATE")
MONTH_COUNT=$(echo "$MONTH_TARGETS" | wc -w)
log_info "Will process $MONTH_COUNT month(s)"

SUCCEEDED=0
FAILED=0

for TARGET_DATE in $MONTH_TARGETS; do
    MONTH_LABEL=$(date -d "$TARGET_DATE" +%Y-%m)
    # Compute month boundaries
    MONTH_START=$(date -d "$TARGET_DATE" +%Y-%m-01)
    log_info "============================================================"
    log_info "Processing month: $MONTH_LABEL ($MONTH_START to $TARGET_DATE)"
    log_info "============================================================"

    # Try to get SBOM from the most recent merge commit, falling back to earlier merges.
    # get_sbom_for_month paginates through the GitHub API automatically.
    SBOM_PATH="$SBOM_CACHE_DIR/eve-sbom-master-${MONTH_LABEL}.json"
    FOUND_COMMIT_SHA=""
    FOUND_COMMIT_SHORT=""
    FOUND_COMMIT_DATE=""

    if [ -s "$SBOM_PATH" ] && [ -f "$SBOM_PATH.commit.json" ] &&
       jq -e '.sha | test("^[0-9a-f]{40}$")' "$SBOM_PATH.commit.json" >/dev/null 2>&1 &&
       jq -e '.packages | type == "array" and length > 0' "$SBOM_PATH" >/dev/null 2>&1; then
        FOUND_COMMIT_SHA=$(jq -r .sha "$SBOM_PATH.commit.json")
        FOUND_COMMIT_SHORT="${FOUND_COMMIT_SHA:0:8}"
        FOUND_COMMIT_DATE=$(jq -r .date "$SBOM_PATH.commit.json")
        # A crash between SBOM replacement and metadata publication invalidates
        # the cache; never relabel those bytes with another commit.
        if [ "$(cat "$SBOM_PATH.image" 2>/dev/null || true)" != "lfedge/eve:0.0.0-master-$FOUND_COMMIT_SHORT-kvm-amd64" ]; then
            FOUND_COMMIT_SHA=""
        fi
    fi
    if [ -z "$FOUND_COMMIT_SHA" ]; then
        if ! get_sbom_for_month "$MONTH_LABEL" "$TARGET_DATE" "$MONTH_START" "$SBOM_PATH"; then
            log_error "Could not get SBOM for $MONTH_LABEL from any merge commit, skipping..."
            FAILED=$((FAILED + 1))
            continue
        fi
    fi

    log_info "  Commit: $FOUND_COMMIT_SHORT ($FOUND_COMMIT_DATE)"

    # Get Alpine version for this commit
    ALPINE_VERSION=""
    if ! ALPINE_VERSION=$(get_alpine_version_for_commit "$FOUND_COMMIT_SHA"); then
        log_warn "  Failed to get Alpine version for commit $FOUND_COMMIT_SHORT, skipping scan..."
        FAILED=$((FAILED + 1))
        continue
    fi

    ALPINE_TAG="v${ALPINE_VERSION}"
    DB_PATH="$CACHE_SOURCE_DIR/alpine_packages_${ALPINE_VERSION}.json"

    log_info "  Alpine version: $ALPINE_VERSION"

    # Generate Alpine package DB
    if ! generate_alpine_db "$ALPINE_TAG" "$DB_PATH"; then
        log_warn "  Failed to generate Alpine DB for $ALPINE_TAG, skipping scan..."
        FAILED=$((FAILED + 1))
        continue
    fi

    SCAN_LABEL="master-${MONTH_LABEL}-${FOUND_COMMIT_SHORT}"

    if [ "$DRY_RUN" = true ]; then
        log_info "  [DRY RUN] Skipping scan and upload for $SCAN_LABEL"
    else
        # Run scanner
        CVSS_BT_PATH="$CACHE_SOURCE_DIR/cvss-bt.csv"

        if ! KERNEL_VERSION=$(get_kernel_version_for_commit "$FOUND_COMMIT_SHA" "$TEMP_DIR/kernel-source"); then
            log_error "Could not resolve kernel for $FOUND_COMMIT_SHA"
            FAILED=$((FAILED + 1))
            continue
        fi
        log_info "  Running CVE scan for $SCAN_LABEL..."
        if ! run_cve_scanner "$SCAN_LABEL" "$SBOM_PATH" "$DB_PATH" "$SCAN_DIR" "$CVSS_BT_PATH" "$KERNEL_VERSION"; then
            log_error "  Scan failed for $SCAN_LABEL"
            FAILED=$((FAILED + 1))
            continue
        fi
        log_info "  Scan completed for $SCAN_LABEL"

        # Upload if enabled
        if [ "$UPLOAD" = true ]; then
            SCAN_FILE="${SCAN_DIR}/scan_results_${SCAN_LABEL}.json"
            if upload_scan "$SCAN_LABEL" "$SCAN_FILE"; then
                rm -f "$SCAN_FILE"
            else
                log_error "Upload failed for $SCAN_LABEL; retaining its result"
                FAILED=$((FAILED + 1))
                continue
            fi
        fi
    fi

    SUCCEEDED=$((SUCCEEDED + 1))
    log_info "  Done with $MONTH_LABEL"

    # Be nice to GitHub API
    sleep 1
done

log_info "============================================================"
log_info "Historical Master Scan Complete"
log_info "  Succeeded: $SUCCEEDED / $MONTH_COUNT"
log_info "  Failed:    $FAILED / $MONTH_COUNT"
log_info "============================================================"

if [ "$FAILED" -gt 0 ]; then
    log_error "Some months failed. Check the log for details: $LOG_FILE"
    exit 1
fi

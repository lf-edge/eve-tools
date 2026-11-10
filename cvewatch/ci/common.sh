#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Common functions for CVE scanning scripts

# Logging configuration
LOG_DIR="${LOG_DIR:-out/logs}"
mkdir -p "$LOG_DIR"
LOG_DIR="$(cd "$LOG_DIR" && pwd)"

# Define LOG_FILE if not set. If set by caller, use it.
if [ -z "${LOG_FILE:-}" ]; then
    LOG_FILE="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).log"
fi

# Log message to both console and file
# Usage: log <level> <dest> <message>
log() {
    local level="$1"
    local dest="$2" # stdout or stderr
    shift 2
    local message="$*"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local formatted_message="[$timestamp] [$level] $message"

    # Print to terminal
    if [ "$dest" = "stderr" ]; then
        echo "$formatted_message" >&2
    else
        echo "$formatted_message"
    fi

    # Append to log file
    echo "$formatted_message" >> "$LOG_FILE"
}

log_info() {
    log "INFO" "stdout" "$@"
}

log_warn() {
    log "WARN" "stderr" "$@"
}

log_error() {
    log "ERROR" "stderr" "$@"
}

# Executes a command, logging its output to both stdout and the log file.
# Usage: log_cmd <command> [args...]
log_cmd() {
    "$@" 2>&1 | tee -a "$LOG_FILE"
    local status=${PIPESTATUS[0]}
    if [ $status -ne 0 ]; then
        log_error "Command failed with status $status: $*"
        return $status
    fi
    return 0
}

# Sets up Python virtual environment and installs dependencies
setup_python_env() {
    if [ ! -d ".venv" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv .venv
    fi
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    else
        log_error ".venv/bin/activate not found."
        exit 1
    fi

    log_info "Installing Python dependencies..."
    pip3 install -r "$(dirname "${BASH_SOURCE[0]}")/requirements.txt"
}

# Downloads the CVSS database
# Args:
#   $1: Target directory for the database
#   $2: (Optional) URL to fetch from
download_cvss_db() {
    local cache_dir="$1"
    local cvss_url="${2:-https://api.github.com/repos/t0sche/cvss-bt/releases/latest}"
    local target_file="$cache_dir/cvss-bt.csv"

    log_info "Downloading cvss-bt.csv..."
    local download_url
    if ! download_url=$(curl -fsSL --connect-timeout 10 --max-time 30 \
        --retry 2 --retry-all-errors --retry-max-time 90 "$cvss_url" | \
        jq -er '[.assets[] | select(.name == "cvss-bt.csv")][0].browser_download_url'); then
        log_error "Failed to resolve the CVSS database download"
        return 1
    fi
    if [[ "$download_url" != https://* ]]; then
        log_error "Invalid CVSS database URL"
        return 1
    fi
    local download_tmp
    download_tmp=$(mktemp "${target_file}.XXXXXX") || return 1
    if ! curl -fsSL --connect-timeout 10 --max-time 300 \
        --retry 2 --retry-all-errors --retry-max-time 600 \
        -o "$download_tmp" "$download_url"; then
        rm -f "$download_tmp"
        log_error "Failed to download CVSS database"
        return 1
    fi
    mv "$download_tmp" "$target_file"
    log_info "Successfully downloaded cvss-bt.csv to $cache_dir"
}

# Retrieves the Alpine version from a remote EVE repository tag/branch
# Args:
#   $1: The tag or branch name (e.g., "master" or "10.4.5-lts")
get_remote_alpine_version() {
    local tag="$1"
    if [[ "$tag" =~ ^master-([0-9a-f]{8,40})$ ]]; then
        tag="${BASH_REMATCH[1]}"
    fi

    local file_path="pkg/alpine/Dockerfile"
    local raw_url="https://raw.githubusercontent.com/lf-edge/eve/${tag}/${file_path}"

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
        log_error "Could not find ALPINE_VERSION in Dockerfile"
        return 1
    fi
}

# Builds the Alpine package info DB
# Args:
#   $1: Alpine tag (e.g., "v3.16.0")
#   $2: Output DB path
generate_alpine_db() {
    local alpine_tag="$1"
    local db_path="$2"
    # Locate script relative to this common.sh file
    local common_dir
    common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local script_path="$common_dir/alpine/build_package_info.sh"

    if [ ! -f "$script_path" ]; then
        log_error "Build script not found at $script_path"
        return 1
    fi

    log_info "Generating Alpine DB for $alpine_tag..."
    if ! bash "$script_path" "$alpine_tag" "$db_path"; then
        log_error "Failed to build Alpine package info for $alpine_tag"
        return 1
    fi
}

# Runs the CVE scanner
# Args:
#   $1: EVE argument (tag/version name) - used for output filename
#   $2: Path to the SBOM (spdx.json)
#   $3: Path to the Alpine packages DB (json)
#   $4: Output directory for scan results
#   $5: (Optional) Path to CVSS DB (defaults to out/cache/data-source/cvss-bt.csv)
run_cve_scanner() {
    local eve_arg="$1"
    local sbom_path="$2"
    local db_path="$3"
    local output_dir="$4"
    local cvss_bt_path="${5:-out/cache/data-source/cvss-bt.csv}"
    local kernel_version="${6:-}"
    local extra_args=()
    if [ -n "$kernel_version" ]; then
        extra_args+=(--kernel-version "$kernel_version")
    fi

    log_info "Running scanner for $eve_arg..."
    # Locate scanner script relative to this common.sh file
    local common_dir
    common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local scanner_script="$common_dir/scan/scanner.py"

    if [ ! -f "$scanner_script" ]; then
        log_error "Scanner script not found at $scanner_script"
        return 1
    fi

    if ! log_cmd python3 "$scanner_script" "$eve_arg" "$sbom_path" "$cvss_bt_path" "$db_path" "$output_dir" "${extra_args[@]}"; then
        log_error "Scanner failed for $eve_arg"
        return 1
    fi
}

# Sets up the common environment variables and directories
# Usage: setup_common_env
setup_common_env() {
    setup_python_env

    # Use default values if variables are not set
    SCAN_DIR="${SCAN_DIR:-out/scans}"
    CACHE_SOURCE_DIR="${CACHE_SOURCE_DIR:-out/cache/data-source}"
    LOG_DIR="${LOG_DIR:-out/logs}"

    mkdir -p "$SCAN_DIR"
    mkdir -p "$CACHE_SOURCE_DIR"
    mkdir -p "$LOG_DIR"

    # Create temp directories if not already set
    if [ -z "${TEMP_DIR:-}" ]; then
        TEMP_DIR=$(mktemp -d)
    fi
    if [ -z "${ALPINE_CACHE:-}" ]; then
        ALPINE_CACHE=$(mktemp)
    fi
}

# Cleans up temporary files and directories
# Usage: cleanup_files <path1> [path2] ...
cleanup_files() {
    for path in "$@"; do
        if [ -n "$path" ] && [ -d "$path" ]; then
            rm -rf "$path"
        elif [ -n "$path" ] && [ -f "$path" ]; then
            rm -f "$path"
        fi
    done
}

# Evaluate kernel metadata in an already checked-out source tree. Only build
# jobs call this; the fresh scan job never executes artifact-provided makefiles.
get_source_kernel_version() {
    local kernel_version
    kernel_version=$(make --no-print-directory -s -f - HV=kvm PLATFORM=generic ZARCH=amd64 cvewatch_kernel <<'MAKE'
include kernel-version.mk
.PHONY: cvewatch_kernel
cvewatch_kernel:
	@echo $(KERNEL_VERSION)
MAKE
    ) || return 1
    [[ "$kernel_version" =~ ^v?[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || return 1
    printf '%s\n' "$kernel_version"
}

# Historical scans need metadata from their recorded commit, never today's
# master. A sparse checkout fetches only the kernel metadata files.
get_kernel_version_for_commit() {
    local sha="$1"
    local source_dir="$2"
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
    if [ ! -d "$source_dir/.git" ]; then
        git init -q "$source_dir" || return 1
        git -C "$source_dir" remote add origin https://github.com/lf-edge/eve.git || return 1
        git -C "$source_dir" sparse-checkout init --no-cone || return 1
        git -C "$source_dir" sparse-checkout set /kernel-version.mk /kernel-commits.mk || return 1
    fi
    git -C "$source_dir" fetch --quiet --depth 1 --filter=blob:none origin "$sha" || return 1
    git -C "$source_dir" checkout --quiet --detach FETCH_HEAD || return 1
    (cd "$source_dir" && get_source_kernel_version)
}

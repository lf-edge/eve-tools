#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This script build Alpine package information database for a given Alpine tag.
# Retrieves package metadata from the Alpine aports repository matching
# the specified Alpine version.
set -euo pipefail

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CI_DIR="$(dirname "$SCRIPT_DIR")"

# Source common functions if available
if [ -f "$CI_DIR/common.sh" ]; then
    source "$CI_DIR/common.sh"
fi

ALPINE_TAG="${1:-}"
DB_PATH="${2:-}"

if [ -z "$ALPINE_TAG" ] || [ -z "$DB_PATH" ]; then
    log_error "Alpine tag and DB path are required"
    log_error "Usage: $0 <ALPINE_TAG> <DB_PATH>"
    exit 1
fi

CACHE_SOURCE_DIR="out/cache/data-source"
mkdir -p "$(dirname "$DB_PATH")" || { log_error "Failed to create DB directory"; exit 1; }
mkdir -p "$CACHE_SOURCE_DIR" || { log_error "Failed to create source cache directory"; exit 1; }

process_ref() {
    local ref="$1"
    local ref_type="$2"
    local aports_dir="$3"
    local db_path="$4"
    local cpe_dict="$5"

    log_info "=========================================="
    log_info "Checking out $ref_type: $ref"

    if ! git -C "$aports_dir" checkout --force "$ref" 2>/dev/null; then
        log_error "Failed to checkout $ref"
        return 1
    fi

    if python3 "$SCRIPT_DIR/get_package_info.py" "$ref" "$aports_dir" "$db_path" "$cpe_dict"; then
        log_info "SUCCESS: Processed $ref"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 2 ]; then
            log_warn "Partially processed $ref (some files failed)"
            return 2
        else
            log_error "Failed to process $ref (exit code: $exit_code)"
            return 1
        fi
    fi
}

# check if DB already exists before doing anything
if [ -f "$DB_PATH" ]; then
    log_info "SKIP: Database already exists at $DB_PATH"
    exit 0
fi

log_info "Building package info for Alpine tag: $ALPINE_TAG"

# download NIST CPE dictionary if not exists
CPE_DICT="$CACHE_SOURCE_DIR/official-cpe-dictionary_v2.3.xml.gz"
if [ ! -f "$CPE_DICT" ]; then
    log_info "Downloading NIST CPE dictionary..."
    if ! curl -L -o "$CPE_DICT" "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"; then
        log_warn "Failed to download CPE dictionary, vendor lookup may be limited"
    else
        log_info "CPE dictionary downloaded successfully"
    fi
else
    log_info "Using cached CPE dictionary"
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

# clone the aports repository
log_info "Cloning aports repository..."
if ! git clone --depth 1 --branch "$ALPINE_TAG" https://github.com/alpinelinux/aports.git "$TMP_DIR/aports"; then
    log_error "Failed to clone aports repository"
    exit 1
fi

# process the Alpine version
if process_ref "$ALPINE_TAG" "tag" "$TMP_DIR/aports" "$DB_PATH" "$CPE_DICT"; then
    exit 0
else
    exit $?
fi

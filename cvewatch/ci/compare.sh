#!/bin/bash
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Compare two scan results files and fail if new vulnerabilities are found.
# usage: ./compare.sh <master_scan.json> <pr_scan.json> [report_file] [ignore_file]

set -euo pipefail

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <master_scan.json> <pr_scan.json> [report_file] [ignore_file]" >&2
    exit 1
fi

MASTER_FILE="$1"
PR_FILE="$2"
REPORT_FILE="${3:-}"
IGNORE_FILE="${4:-}"

setup_python_env

COMPARE_SCRIPT="$SCRIPT_DIR/scan/compare.py"
if [ ! -f "$COMPARE_SCRIPT" ]; then
    log_error "Error: Cannot find compare script at $COMPARE_SCRIPT"
    exit 1
fi

# Run comparison
log_info "Running comparison between master and PR scan results..."

RUN_CMD=(python3 "$COMPARE_SCRIPT" "$MASTER_FILE" "$PR_FILE")
if [ -n "$IGNORE_FILE" ]; then
    if [ ! -f "$IGNORE_FILE" ]; then
        log_error "Ignore file not found: $IGNORE_FILE"
        exit 1
    fi
    RUN_CMD+=("$IGNORE_FILE")
fi
if [ -n "$REPORT_FILE" ]; then
    "${RUN_CMD[@]}" 2>&1 | tee "$REPORT_FILE"
else
    log_cmd "${RUN_CMD[@]}"
fi

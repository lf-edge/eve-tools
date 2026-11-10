#!/bin/bash
# Build one side of the comparison. CI runs each side on a separate runner.
set -euo pipefail
CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLE="${1:?role required}"
REPO="${2:?repository required}"
REF="${3:?revision required}"
DEST="${4:?destination required}"
[[ "$ROLE" = pr || "$ROLE" = base ]] || exit 2
[[ "$REPO" != -* && "$REF" != -* ]] || exit 2
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"
source "$CI_DIR/pr-scan.sh" "$REPO" "$REF" "$REPO" "$REF"
TEMP_DIR=$(mktemp -d)
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$ROLE" = pr ]; then
    clone_and_build_eve
    prefix=pr
else
    EVE_REPO_DIR="$TEMP_DIR/source"
    git init -q "$EVE_REPO_DIR"
    get_master_info
    prefix=master
fi
cp "$TEMP_DIR/$prefix-sbom.json" "$DEST/sbom.json"
cp "$TEMP_DIR/$prefix-sbom-kernel-version" "$DEST/kernel-version"
cp "$TEMP_DIR/$prefix-commit-info" "$DEST/commit-info"

#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
# Extract an SBOM without ever publishing a truncated cached result.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
EVE_TAG="${1:?EVE tag required}"
SBOM_PATH="${2:?SBOM path required}"
mkdir -p "$(dirname "$SBOM_PATH")"
# The SBOM and its image marker are a pair. Serialize readers/writers of this
# path so two extractions cannot publish another image's marker over our bytes.
# Keep the lock inode after exit; removing it would let a third process bypass
# an existing waiter on the unlinked inode.
exec 8>"$SBOM_PATH.lock"
flock -w 120 8 || { log_error "SBOM cache path is busy"; exit 1; }

if [ "$EVE_TAG" = master ]; then
    sha=$(curl -fsS 'https://api.github.com/repos/lf-edge/eve/commits/master' | jq -er .sha)
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { log_error 'Invalid master SHA'; exit 1; }
    EVE_TAG="master-${sha:0:8}"
fi
if [[ "$EVE_TAG" =~ ^master-([0-9a-f]{8,40})$ ]]; then
    image="lfedge/eve:0.0.0-master-${BASH_REMATCH[1]:0:8}-kvm-amd64"
else
    image="lfedge/eve:$EVE_TAG"
fi
# A cache entry is valid only for the same immutable image identity.
if [ -s "$SBOM_PATH" ] && [ -f "$SBOM_PATH.image" ] &&
   [ "$(cat "$SBOM_PATH.image")" = "$image" ] &&
   jq -e '.packages | type == "array" and length > 0' "$SBOM_PATH" >/dev/null 2>&1; then
    log_info "Using cached SBOM for $image"
    exit 0
fi
sbom_tmp=$(mktemp "${SBOM_PATH}.XXXXXX")
remove_image=false
cleanup() {
    rm -f "$sbom_tmp"
    if [ "$remove_image" = true ]; then
        docker rmi "$image" >/dev/null 2>&1 || log_warn "Could not remove $image"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! docker image inspect "$image" >/dev/null 2>&1; then
    remove_image=true
fi
docker pull "$image"
docker run --rm "$image" sbom > "$sbom_tmp"
jq -e '.packages | type == "array" and length > 0' "$sbom_tmp" >/dev/null
mv "$sbom_tmp" "$SBOM_PATH"
printf '%s\n' "$image" > "$SBOM_PATH.image"
log_info "Saved SBOM for $image"

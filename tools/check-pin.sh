#!/usr/bin/env bash
# Verify a schema pin against authoritative master, independent of caller refs.
set -euo pipefail

if [[ $# -ne 1 || ! "${1:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: usage: bash tools/check-pin.sh <full-40-hex-schema-pin> (lowercase)" >&2
    exit 1
fi
pin="$1"
# Repository-local environment must not redirect Git into the caller's checkout.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_SHALLOW_FILE GIT_REPLACE_REF_BASE GIT_GRAFT_FILE
scratch="$(mktemp -d)" || {
    echo "error: could not create temporary repository for pin verification" >&2
    exit 1
}
trap 'rm -rf "$scratch"' EXIT
git init --bare --quiet "$scratch" || {
    echo "error: could not initialize temporary repository for pin verification" >&2
    exit 1
}
# Fetch complete master history. Fetch the pin too so an existing branch-only
# commit fails the ancestry check rather than merely appearing to be unknown.
git -C "$scratch" fetch --quiet --no-tags --no-auto-maintenance --filter=blob:none \
    https://github.com/wendylabsinc/service-protos.git \
    '+refs/heads/master:refs/heads/master' "$pin:refs/heads/contract-pin" || {
    echo "error: could not fetch service-protos master and pinned commit $pin" >&2
    exit 1
}
git -C "$scratch" merge-base --is-ancestor "$pin" refs/heads/master || {
    echo "error: shared contract pin $pin is not an ancestor of service-protos master, or ancestry could not be verified" >&2
    exit 1
}
echo "Verified shared contract pin $pin on service-protos master"

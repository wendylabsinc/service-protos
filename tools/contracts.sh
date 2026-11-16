#!/usr/bin/env bash
# Fetch this runner and its support from source main, separately from schemas.
set -euo pipefail
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/contracts.py" "$@"

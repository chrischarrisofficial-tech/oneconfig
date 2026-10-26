#!/usr/bin/env bash
# Fetch STIG Manager's checklist parser (NUWCDIVNPT/stig-manager-client-modules, MIT) for tests/test_cklb.py, which
# checks that STIG Manager reads OneConfig's .cklb files. Needs Node.js to run.
# Output: ~/.cache/oneconfig-stigmanager (override with ONECONFIG_STIGMANAGER=<somewhere>/oneconfig-stigmanager)
set -euo pipefail
COMMIT=d835d6e3342408b3cf146c90554997cfda22ea64
OUT=${ONECONFIG_STIGMANAGER:-$HOME/.cache/oneconfig-stigmanager}
case "$OUT" in */oneconfig-stigmanager) ;; *) echo "refusing to delete $OUT: the folder must be named oneconfig-stigmanager" >&2; exit 1;; esac
rm -rf "$OUT" && mkdir -p "$OUT" && cd "$OUT"
git init -q && git remote add origin https://github.com/NUWCDIVNPT/stig-manager-client-modules
git fetch -q --depth 1 origin "$COMMIT" && git checkout -q FETCH_HEAD
echo "Fetched $OUT"

#!/usr/bin/env bash
# Fetch Palo Alto's PAN-OS configuration specs (MIT) for tests/test_syntax.py.
# Output: ~/.cache/oneconfig-panspec/specs (override with ONECONFIG_PANSPEC=<somewhere>/oneconfig-panspec/specs)
set -euo pipefail
COMMIT=ee44e33cf576db65645123c4dc6eff6407e040ac   # PaloAltoNetworks/pan-os-codegen, the version the tests were written against
OUT=$(dirname "${ONECONFIG_PANSPEC:-$HOME/.cache/oneconfig-panspec/specs}")
case "$OUT" in */oneconfig-panspec) ;; *) echo "refusing to delete $OUT: the folder above specs/ must be named oneconfig-panspec" >&2; exit 1;; esac
rm -rf "$OUT" && mkdir -p "$OUT" && cd "$OUT"
git init -q src && cd src && git remote add origin https://github.com/PaloAltoNetworks/pan-os-codegen
git sparse-checkout set specs LICENSE.md
git fetch -q --depth 1 --filter=blob:none origin "$COMMIT" && git checkout -q FETCH_HEAD
mv specs LICENSE.md "$OUT"/ && cd "$OUT" && rm -rf src
echo "Fetched $OUT/specs"

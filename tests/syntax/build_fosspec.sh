#!/usr/bin/env bash
# Fetch Fortinet's FortiOS configuration schema (from their Ansible collection, GPL-3.0; used by the tests only,
# never shipped) and condense it to one JSON file for tests/test_syntax.py.
# Output: ~/.cache/oneconfig-fosspec/spec.json (override with ONECONFIG_FOSSPEC=<somewhere>/oneconfig-fosspec/spec.json)
set -euo pipefail
COMMIT=5174d341626cb099a079b18276906f3f91f4a110   # fortinet-ansible-dev/ansible-galaxy-fortios-collection, the version the tests were written against
SPEC=${ONECONFIG_FOSSPEC:-$HOME/.cache/oneconfig-fosspec/spec.json}
OUT=$(dirname "$SPEC")
case "$OUT" in */oneconfig-fosspec) ;; *) echo "refusing to delete $OUT: the folder must be named oneconfig-fosspec" >&2; exit 1;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$OUT" && mkdir -p "$OUT" && cd "$OUT"
git init -q src && cd src && git remote add origin https://github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection
git sparse-checkout set plugins/modules LICENSE
git fetch -q --depth 1 --filter=blob:none origin "$COMMIT" && git checkout -q FETCH_HEAD
cp LICENSE "$OUT"/
python3 -I "$HERE/fosspec.py" --extract "$OUT/src/plugins/modules" "$SPEC"
cd "$OUT" && rm -rf src
echo "Wrote $SPEC"

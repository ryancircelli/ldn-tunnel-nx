#!/usr/bin/env bash
# Regenerates test/layout/types.json from the sysmodule's types.hpp.
# Usage: tools/dump-layout.sh [path/to/ryu_ldn_nx]
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="${1:-$here/../ryu_ldn_nx}"
out="$(mktemp -d)"
g++ -std=c++17 -Wno-invalid-offsetof -I"$repo/sysmodule/source" "$here/test/layout/dump.cpp" -o "$out/dump"
"$out/dump" > "$here/test/layout/types.json"
rm -rf "$out"
echo "wrote test/layout/types.json"

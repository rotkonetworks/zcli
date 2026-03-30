#!/bin/sh
# build ring-vrf-wasm for zafu extension
# output goes to zafu's public/ dir for lazy loading by pro users
set -e

OUT_DIR="${1:-/steam/rotko/zafu/apps/extension/public/ring-vrf-wasm}"

cd "$(dirname "$0")"
wasm-pack build --target web --release --out-dir "$OUT_DIR"

SIZE=$(wc -c < "$OUT_DIR/ring_vrf_wasm_bg.wasm")
echo "ring-vrf-wasm: ${SIZE} bytes -> $OUT_DIR"

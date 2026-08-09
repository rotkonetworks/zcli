#!/bin/sh
# build voting-wasm for zafu extension
# output goes to zafu's public/ dir for lazy loading when the vote-cast UI opens
set -e

OUT_DIR="${1:-/steam/rotko/zafu/apps/extension/public/voting-wasm}"

cd "$(dirname "$0")"
wasm-pack build --target web --release --out-dir "$OUT_DIR"

SIZE=$(wc -c < "$OUT_DIR/voting_wasm_bg.wasm")
echo "voting-wasm: ${SIZE} bytes -> $OUT_DIR"

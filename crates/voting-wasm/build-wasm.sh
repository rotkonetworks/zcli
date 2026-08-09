#!/bin/sh
# build voting-wasm (PARALLEL / rayon) for zafu extension
# output goes to zafu's public/ dir for lazy loading when the vote-cast UI opens
#
# Mirrors crates/zcash-wasm's `cargo wasm-parallel` recipe (see
# apps/extension/packages/zcash-wasm/BUILD_PROVENANCE.md in the zafu repo):
# nightly + -Zbuild-std is required for std::thread support on wasm32, and
# the +atomics/shared-memory codegen flags live in the WORKSPACE
# .cargo/config.toml (not RUSTFLAGS - setting RUSTFLAGS on the command line
# REPLACES that array wholesale and silently drops shared memory).
set -e

OUT_DIR="${1:-/steam/rotko/zafu/apps/extension/public/voting-wasm}"

cd "$(dirname "$0")"
unset RUSTFLAGS
RUSTUP_TOOLCHAIN=nightly cargo build -p voting-wasm --target wasm32-unknown-unknown \
  --release --features parallel -Zbuild-std=panic_abort,std

wasm-bindgen ../../target/wasm32-unknown-unknown/release/voting_wasm.wasm \
  --out-dir "$OUT_DIR" --target web

# LOCAL PATCH: wasm-bindgen-rayon's workerHelpers.js snippet emits
# `import('../../..')`, a directory import Chrome extensions reject. Rewrite
# it to the concrete voting_wasm.js URL, same fix as zafu-wasm's snippet.
SNIPPET=$(find "$OUT_DIR/snippets" -iname workerHelpers.js | head -1)
if [ -n "$SNIPPET" ] && grep -q "await import('../../..');" "$SNIPPET"; then
  perl -0pi -e "s{const pkg = await import\('\.\./\.\./\.\.'\);}{// LOCAL PATCH — stock emits \`import('../../..')\` (a directory import)\n  // which Chrome extensions reject; resolve the concrete file. Mirrors the\n  // same patch applied to zafu-wasm's snippet (packages/zcash-wasm/BUILD_PROVENANCE.md).\n  const wbgRayonBase = new URL('../../..', import.meta.url).href;\n  const pkg = await import(wbgRayonBase.endsWith('/') ? wbgRayonBase + 'voting_wasm.js' : wbgRayonBase);}" "$SNIPPET"
  echo "voting-wasm: patched directory import in $SNIPPET"
fi

SIZE=$(wc -c < "$OUT_DIR/voting_wasm_bg.wasm")
echo "voting-wasm (parallel): ${SIZE} bytes -> $OUT_DIR"
echo "verify: grep -q 'export function initThreadPool' $OUT_DIR/voting_wasm.js"

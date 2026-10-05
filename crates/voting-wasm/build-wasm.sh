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

TARGET_DIR="${CARGO_TARGET_DIR:-../../target}"
wasm-bindgen "$TARGET_DIR/wasm32-unknown-unknown/release/voting_wasm.wasm" \
  --out-dir "$OUT_DIR" --target web

# binaryen 130 (BUILD_PROVENANCE.md in zafu); WASM_OPT overrides the binary.
"${WASM_OPT:-wasm-opt}" -Oz --enable-threads --enable-bulk-memory --enable-simd \
  --enable-mutable-globals --enable-nontrapping-float-to-int \
  "$OUT_DIR/voting_wasm_bg.wasm" -o "$OUT_DIR/voting_wasm_bg.wasm"

# LOCAL PATCH: wasm-bindgen-rayon's workerHelpers.js snippet emits
# `import('../../..')`, a directory import Chrome extensions reject. Rewrite
# it to the concrete voting_wasm.js URL, same fix as zafu-wasm's snippet.
SNIPPET=$(find "$OUT_DIR/snippets" -iname workerHelpers.js | head -1)
if [ -n "$SNIPPET" ] && grep -q "await import('../../..');" "$SNIPPET"; then
  perl -0pi -e "s{const pkg = await import\('\.\./\.\./\.\.'\);}{// LOCAL PATCH — stock emits \`import('../../..')\` (a directory import)\n  // which Chrome extensions reject; resolve the concrete file. Mirrors the\n  // same patch applied to zafu-wasm's snippet (packages/zcash-wasm/BUILD_PROVENANCE.md).\n  const wbgRayonBase = new URL('../../..', import.meta.url).href;\n  const pkg = await import(wbgRayonBase.endsWith('/') ? wbgRayonBase + 'voting_wasm.js' : wbgRayonBase);}" "$SNIPPET"
  echo "voting-wasm: patched directory import in $SNIPPET"
fi

# LOCAL PATCH: where `Atomics.waitAsync` is missing (Firefox), js-sys's
# futures executor falls back to a helper worker that runs `Atomics.wait`.
# Stock glue starts it from a blob: URL, which the extension CSP
# (`script-src 'self'`, so no blob: workers) refuses. Ship the same script as
# a file next to the glue and point the link at it.
GLUE="$OUT_DIR/voting_wasm.js"
BLOB_LINK='const ret = typeof URL.createObjectURL === '"'"'undefined'"'"' ? "data:application/javascript," + encodeURIComponent(val) : URL.createObjectURL(new Blob([val], { type: "text/javascript" }));'
if grep -qF "$BLOB_LINK" "$GLUE"; then
  cat > "$OUT_DIR/wait_async_worker.js" <<'WORKER'
// Atomics.waitAsync fallback helper for js-sys's futures executor (see
// build-wasm.sh). Same script the stock glue would start from a blob: URL.
onmessage = function (ev) {
  let [ia, index, value] = ev.data;
  ia = new Int32Array(ia.buffer);
  let result = Atomics.wait(ia, index, value);
  postMessage(result);
};
WORKER
  BLOB_LINK="$BLOB_LINK" perl -0pi -e 's{\Q$ENV{BLOB_LINK}\E}{// LOCAL PATCH: extension CSP refuses blob: workers; load the shipped copy.\n            void val;\n            const ret = new URL("./wait_async_worker.js", import.meta.url).href;}' "$GLUE"
  grep -q 'wait_async_worker.js' "$GLUE" || { echo "voting-wasm: waitAsync patch did not apply" >&2; exit 1; }
  echo "voting-wasm: waitAsync fallback worker -> $OUT_DIR/wait_async_worker.js"
else
  echo "voting-wasm: waitAsync blob link not found in glue; check the polyfill patch" >&2
  exit 1
fi

SIZE=$(wc -c < "$OUT_DIR/voting_wasm_bg.wasm")
echo "voting-wasm (parallel): ${SIZE} bytes -> $OUT_DIR"
echo "verify: grep -q 'export function initThreadPool' $OUT_DIR/voting_wasm.js"

#!/usr/bin/env bash
# Stand up a throwaway zebrad Regtest chain with NU6.3 (Ironwood) live from
# block 1, run the ironwood money-path end-to-end test against it, and tear the
# node back down.
#
#   deploy/regtest/run-ironwood-e2e.sh
#
# The test asserts on absolute ironwood-tree sizes, so it needs a FRESH chain:
# this script always starts a new ephemeral node (zebrad's `[state] ephemeral`
# keeps the whole chain in a temp dir that is removed on exit).
#
# Set ZEBRAD to an existing binary to skip the (long) zebra build:
#   ZEBRAD=/path/to/zebrad deploy/regtest/run-ironwood-e2e.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="$REPO_ROOT/deploy/regtest/zebrad-regtest.toml"
WORK="${REGTEST_WORK:-${TMPDIR:-/tmp}/zcli-regtest-ironwood}"
RPC="http://127.0.0.1:28232"

mkdir -p "$WORK"

# ---------------------------------------------------------------------------
# 1. a zebrad that knows about NU6.3
# ---------------------------------------------------------------------------
# Any Zebra with `Nu6_3` in zebra-chain/src/parameters/network_upgrade.rs will
# do (verified against zebrad 6.2.3, commit da29357). Zebra needs no
# `zcash_unstable` cfg: its Ironwood support is unconditional.
if [ -z "${ZEBRAD:-}" ]; then
    if [ ! -d "$WORK/zebra" ]; then
        echo "==> cloning zebra into $WORK/zebra"
        git clone --depth 1 https://github.com/ZcashFoundation/zebra "$WORK/zebra"
    fi
    echo "==> building zebrad (release)"
    cargo build --release -p zebrad --manifest-path "$WORK/zebra/Cargo.toml"
    ZEBRAD="$WORK/zebra/target/release/zebrad"
fi

echo "==> using $ZEBRAD ($("$ZEBRAD" --version))"

# ---------------------------------------------------------------------------
# 2. start the regtest node
# ---------------------------------------------------------------------------
"$ZEBRAD" --config "$CONFIG" start >"$WORK/zebrad.log" 2>&1 &
ZEBRAD_PID=$!
trap 'kill "$ZEBRAD_PID" 2>/dev/null || true' EXIT

echo "==> waiting for the RPC endpoint at $RPC"
for _ in $(seq 1 60); do
    if curl -sf -X POST -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
        "$RPC" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

curl -s -X POST -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
    "$RPC" | grep -q '"37a5165b"' \
    || { echo "node does not report the NU6.3 branch id; see $WORK/zebrad.log"; exit 1; }

# ---------------------------------------------------------------------------
# 3. run the end-to-end test
# ---------------------------------------------------------------------------
# NO RUSTFLAGS. NU6.3 is ungated in the upstream crates we now depend on, so
# the old `--cfg zcash_unstable="nu6.3"` is not merely unnecessary, it is a
# hazard: setting RUSTFLAGS on the command line REPLACES the rustflags array in
# .cargo/config.toml wholesale. See packages/zcash-wasm/BUILD_PROVENANCE.md.
#
# --release is needed because this builds a Halo 2 proving key and proves two
# ironwood bundles.
#
# The test must actually RUN. A run that reports "0 tests" is a FAILURE, not a
# pass - that is exactly what the removed cfg gate used to cause.
cd "$REPO_ROOT"
ZEBRAD_RPC="$RPC" \
    cargo test --release -p zafu-wasm --test regtest_ironwood_e2e \
    -- --ignored --nocapture

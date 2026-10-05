#!/usr/bin/env bash
# Initialize (and optionally start) a single-validator vote-sdk chain for
# `local_chain_e2e`, on ports that never collide with other local chains.
#
# Every port the node, its helper and its auto-injection loop use is pinned
# here, including `[vote] comet_rpc` and `[helper] chain_api_port`. Their
# defaults (26657, 1317) are also the defaults of every other cosmos/comet
# chain on a dev box, so a node left on them talks to whatever else is
# listening there.
#
#   VOTE_SDK=/path/to/vote-sdk   checkout at the pinned tag (for scripts/init.sh)
#   SVOTED=/path/to/svoted       built with -tags halo2,redpallas
#   SVOTE_HOME=/path/to/home     wiped and recreated
#   VM_PRIVKEYS=<64 hex>         vote-manager key (any throwaway secp256k1 key)
#   PORT_PREFIX=2                ports become 2xxxx: REST 21317, comet RPC 27657
#
#   local-vote-chain.sh init     init only
#   local-vote-chain.sh start    init, then run svoted in the background and
#                                wait for blocks (log: $SVOTE_HOME/svoted.log)
set -euo pipefail

: "${VOTE_SDK:?VOTE_SDK}" "${SVOTED:?SVOTED}" "${SVOTE_HOME:?SVOTE_HOME}" "${VM_PRIVKEYS:?VM_PRIVKEYS}"
P="${PORT_PREFIX:-2}"
REST="${P}1317"
RPC="${P}7657"

bindir="$(mktemp -d)"
trap 'rm -rf "$bindir"' EXIT
ln -s "$(realpath "$SVOTED")" "$bindir/svoted"
export PATH="$bindir:$PATH"

SVOTED_HOME="$SVOTE_HOME" VM_PRIVKEYS="$VM_PRIVKEYS" bash "$VOTE_SDK/scripts/init.sh"

app="$SVOTE_HOME/config/app.toml"
cfg="$SVOTE_HOME/config/config.toml"
sed -i \
  -e "s|^address = \"tcp://0.0.0.0:1317\"|address = \"tcp://127.0.0.1:${REST}\"|" \
  -e "s|^address = \"localhost:9190\"|address = \"localhost:${P}9190\"|" \
  -e "s|^address = \"localhost:9191\"|address = \"localhost:${P}9191\"|" \
  -e "s|^comet_rpc = .*|comet_rpc = \"http://127.0.0.1:${RPC}\"|" \
  -e "s|^chain_api_port = .*|chain_api_port = ${REST}|" \
  "$app"
sed -i \
  -e "s|^proxy_app = .*|proxy_app = \"tcp://127.0.0.1:${P}7658\"|" \
  -e "s|^laddr = \"tcp://127.0.0.1:26657\"|laddr = \"tcp://127.0.0.1:${RPC}\"|" \
  -e "s|^laddr = \"tcp://0.0.0.0:26656\"|laddr = \"tcp://127.0.0.1:${P}7656\"|" \
  -e "s|^pprof_laddr = .*|pprof_laddr = \"localhost:${P}6060\"|" \
  "$cfg"

# Refuse to start with any default port left over (a renamed key upstream
# would otherwise silently fall back to the shared defaults).
for want in "comet_rpc = \"http://127.0.0.1:${RPC}\"" "chain_api_port = ${REST}" \
  "address = \"tcp://127.0.0.1:${REST}\""; do
  grep -qF "$want" "$app" || { echo "app.toml: missing '$want'" >&2; exit 1; }
done
grep -qF "laddr = \"tcp://127.0.0.1:${RPC}\"" "$cfg" || { echo "config.toml: rpc laddr not pinned" >&2; exit 1; }
if grep -nE '(:|")(26657|26656|26658|1317|9090|9091|9190|9191)"' "$app" "$cfg"; then
  echo "a default port is still configured (above)" >&2
  exit 1
fi

[ "${1:-init}" = "start" ] || exit 0

SVOTE_PIR_URL=disabled nohup "$SVOTED" start --home "$SVOTE_HOME" >"$SVOTE_HOME/svoted.log" 2>&1 &
echo "svoted pid $!"
for _ in $(seq 1 90); do
  if curl -sf "http://127.0.0.1:${REST}/cosmos/base/tendermint/v1beta1/blocks/latest" >/dev/null; then
    echo "chain up: REST http://127.0.0.1:${REST}, comet tcp://127.0.0.1:${RPC}"
    exit 0
  fi
  sleep 2
done
tail -50 "$SVOTE_HOME/svoted.log" >&2
exit 1

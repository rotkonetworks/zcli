# zidecar

Ligerito-powered Zcash light server with real-time header chain proofs. Speaks
the canonical [lightwalletd](https://github.com/zcash/lightwalletd) gRPC
protocol so any zcash-sdk wallet (Zashi, ywallet, ...) can point at it as a
drop-in replacement.

## What it is

zidecar is a stateless gRPC facade that sits in front of a full
[Zebra](https://github.com/ZcashFoundation/zebra) node and translates between
Zebra's admin-oriented JSON-RPC and the lightwalletd CompactTxStreamer wire
protocol. It performs the protocol translation, bandwidth optimization
(compact blocks), and hardening that mobile-facing endpoints need but full
nodes don't provide on their own.

It also serves zidecar's own `ZidecarService` (proofs / state-root queries)
and the optional FROST relay used by zcli's multi-signature flow.

## CompactTxStreamer coverage

20/20 of the canonical lightwalletd RPCs are implemented:

| RPC | Notes |
|---|---|
| `GetLatestBlock` | unary |
| `GetBlock` / `GetBlockNullifiers` | unary; nullifier-only variant for spend-before-sync |
| `GetBlockRange` / `GetBlockRangeNullifiers` | server-streaming; capped at 10 000 blocks per request |
| `GetTransaction` | unary |
| `SendTransaction` | unary; bypasses the outbound retry policy |
| `GetTaddressTxids` / `GetTaddressTransactions` | server-streaming; ranges capped |
| `GetTaddressBalance` / `GetTaddressBalanceStream` | unary + client-streaming |
| `GetMempoolTx` | server-streaming with exclude-suffix filter (max 256 suffixes, 32 bytes each) |
| `GetMempoolStream` | long-poll, terminates on chain-tip change |
| `GetTreeState` / `GetLatestTreeState` | unary |
| `GetSubtreeRoots` | server-streaming |
| `GetAddressUtxos` / `GetAddressUtxosStream` | unary + server-streaming |
| `GetLightdInfo` | unary; reports `taddr_support=true` and `chainName=main\|test` |
| `Ping` | unary, testing only |

Wire format follows canonical lightwalletd byte order (protocol-order /
little-endian on the wire) for every txid, block hash, Sapling
commitment-u, ephemeral key, and Sapling spend nullifier.
Orchard fields pass through Zebra's encoding unchanged.

## Running

```sh
zidecar \
    --zebrad-rpc http://127.0.0.1:8232 \
    --listen 0.0.0.0:50051 \
    --db-path ./zidecar.db
```

Flags worth knowing:

| Flag | Default | Effect |
|---|---|---|
| `--zebrad-rpc` | `http://127.0.0.1:8232` | upstream Zebra JSON-RPC endpoint |
| `--listen` | `0.0.0.0:50051` | gRPC listen address (gRPC-web is enabled) |
| `--testnet` | false | switches `chainName` to `"test"` and the Sapling activation height to testnet's |
| `--mempool-cache-ttl` | `0` | per-request `getrawmempool` cache; enable on public nodes |
| `--zidecar-rpc` | **false (opt-in)** | enable the rotko ZidecarService (ligerito proofs, NOMT, FROST sign anchors); opens `--db-path` RocksDB and spawns 4 background tasks |
| `--frost-relay` | **false (opt-in)** | enable the FROST multisig relay gRPC surface |
| `--auth-token` (env `ZIDECAR_AUTH_TOKEN`) | unset | require `Authorization: Bearer <token>` on every gRPC request; when unset the server is anonymous-readable (the Zashi-compatible default) |
| `--db-path` | `./zidecar.db` | RocksDB cache path (only opened when `--zidecar-rpc`) |
| `--start-height` | `orchard activation` | proof start height (only used when `--zidecar-rpc`) |

The default `zidecar` binary with no flags is a drop-in lightwalletd
replacement: lwd surface only, no auth, no RocksDB, no background proof
generation, no FROST relay. Add the extras when you need them.

## Operational defaults

| Default | Value | Reasoning |
|---|---|---|
| Inbound timeout | 30 s | bounds unary latency; server-streaming RPCs unaffected (TimeoutLayer races response-future construction, not each yielded message) |
| Concurrency limit | 256 in-flight | bounds per-process load; new requests queue rather than fail-fast (matches wallet retry semantics) |
| Block range cap | 10 000 blocks | bounds upstream Zebra fanout per request |
| Mempool seen-set cap | 50 000 per stream | bounds memory under a stalled chain |
| sendrawtransaction retry | none | at-most-once submission |
| Upstream error detail | scrubbed | `Status::unavailable("upstream node unavailable")` instead of leaking the Zebra URL via reqwest's Display impl |

## Architecture notes

zidecar is built as a Tower-shaped server: outbound (`ZebradClient`) uses
`Buffer<Retry<Inner>>` for upstream backpressure + retry; inbound stacks
`TraceLayer → TimeoutLayer → ConcurrencyLimitLayer` around the tonic server.
Cross-cutting concerns live at the boundary, not duplicated inside handlers.

The compact-block builder (`src/compact.rs`) is per-block: for each
`getrawtransaction` in the block, it extracts the Orchard actions, Sapling
spends, and Sapling outputs; `to_lwd_block` groups them per-txid into
`CompactTx` entries while reversing display-order Zebra bytes to
protocol-order lightwalletd wire bytes.

## Compatibility scope

Confirmed wire-compatible with Zashi (zcash-sdk 2.x) via the audit pass that
informed the 0.7.0 release. Behavior MAY still diverge from canonical
lightwalletd in places that the SDK doesn't observe — see the limitations
below — but those are non-blocking for shielded sync.

### Known limitations

- `LightdInfo.vendor` is `"zidecar/rotkonetworks"` and `git_commit` is
  `v{version}-{hash}` rather than a bare hash. SDKs treat both as opaque.
- `CompactTx.fee` is always 0. Canonical lwd also doesn't compute fees;
  the SDK doesn't read this field.
- `GetBlockNullifiers` zeros (rather than drops) the non-nullifier action
  fields. Byte-equivalent on the wire (proto3 omits empty bytes), but
  `ChainMetadata` is still emitted — canonical lwd clears it.
- No built-in TLS or auth. Run behind a reverse proxy that terminates TLS
  and rate-limits at the IP level for public exposure.

## License

MIT.

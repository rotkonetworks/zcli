# zidecar

A Rust gRPC server that fronts a [Zebra](https://github.com/ZcashFoundation/zebra)
full node. Runs in one of two modes:

- **`zidecar`** (default) — drop-in [lightwalletd](https://github.com/zcash/lightwalletd)
  replacement. All 20 `CompactTxStreamer` RPCs, wire-compatible with the
  Zcash SDK (Zashi, ywallet, ...).
- **`zidecar --zidecar-rpc`** — also exposes the rotko-specific surface:
  Ligerito header-chain proofs, NOMT commitment/nullifier inclusion proofs,
  FROST checkpoints at epoch boundaries, plus a few SaaS-flavored endpoints
  (license issuance, zigner sign anchors, anonymous pro membership ring).

The first mode is the obvious one and what most operators want. The second
is what [zafu](https://github.com/rotkonetworks/zeratul) (rotko's desktop
wallet) consumes when it wants trustless sync — cryptographic guarantees
about chain completeness instead of trusting the server's word.

## Quick start

```sh
# pure lightwalletd replacement — points at a local Zebra
zidecar --zebrad-rpc http://127.0.0.1:8232

# also expose the trustless-sync + proof surface for zafu
zidecar --zebrad-rpc http://127.0.0.1:8232 --zidecar-rpc

# lock the server down with a bearer token
ZIDECAR_AUTH_TOKEN=secret zidecar --zidecar-rpc --frost-relay
```

The default listens on `0.0.0.0:50051` and accepts both HTTP/2 gRPC and
HTTP/1.1 gRPC-web. With no flags it opens no on-disk state, spawns no
background work, and requires no auth — just a forwarder to Zebra.

## Two modes

```
                  ┌───────────────────────────┐
                  │           zidecar         │
                  │                           │
   wallet ──gRPC──┤  ┌─CompactTxStreamer─┐    │
   (Zashi)        │  │  20 lwd RPCs      │    │
                  │  └───────────────────┘    │
                  │  (always on, no auth      │
                  │   by default)             │
                  │                           │
   zafu ────gRPC──┤  ┌─Zidecar (opt-in)─┐     │       ┌──────────┐
                  │  │  proofs, NOMT,   ├─────┼──RPC──┤  Zebra   │
                  │  │  FROST anchors   │     │       └──────────┘
                  │  └──────────────────┘     │
                  │  ┌─FrostRelay opt-in┐     │
   multisig ─gRPC─┤  │  dumb msg switch │     │
   parties        │  └──────────────────┘     │
                  └───────────────────────────┘
```

Every surface is multiplexed on the same gRPC port (default `50051`). The
tonic router dispatches by service name. When `--auth-token` is set, the
bearer check applies uniformly to every registered service.

## Lightwalletd surface (CompactTxStreamer)

All 20 canonical RPCs:

| RPC | Notes |
|---|---|
| `GetLatestBlock` | unary |
| `GetBlock` / `GetBlockNullifiers` | unary; nullifier-only variant for spend-before-sync |
| `GetBlockRange` / `GetBlockRangeNullifiers` | server-streaming; capped at 10 000 blocks per request |
| `GetTransaction` | unary |
| `SendTransaction` | unary; bypasses the outbound retry policy (at-most-once) |
| `GetTaddressTxids` / `GetTaddressTransactions` | server-streaming; ranges capped |
| `GetTaddressBalance` / `GetTaddressBalanceStream` | unary + client-streaming |
| `GetMempoolTx` | server-streaming; exclude-suffix filter (max 256 × 32 B) |
| `GetMempoolStream` | long-poll; ends on chain-tip change |
| `GetTreeState` / `GetLatestTreeState` | unary |
| `GetSubtreeRoots` | server-streaming |
| `GetAddressUtxos` / `GetAddressUtxosStream` | unary + server-streaming |
| `GetLightdInfo` | unary; `chainName=main\|test`, `taddr_support=true` |
| `Ping` | unary, testing only |

**Wire format:** protocol-order (little-endian) bytes on every txid, block
hash, Sapling cmu, ephemeral key, and Sapling spend nullifier — matches
canonical lightwalletd and [Zaino](https://github.com/zingolabs/zaino).
Orchard fields pass through Zebra's encoding unchanged (Zebra doesn't
pre-reverse Orchard). `CompactBlock.header` is empty per the proto comment.
`CompactTx.index` is the position-in-block (incl. coinbase + transparent-
only), not position-in-shielded-set.

## ZidecarService surface (opt-in, `--zidecar-rpc`)

Five groups of RPCs that wallet clients use only if they want the
trustless-sync guarantees zidecar adds on top of lwd:

### Cryptographic chain proofs

| RPC | Returns |
|---|---|
| `GetHeaderProof` | Ligerito polynomial-commitment proof for a height range; verifier reconstructs cumulative chain work in O(log n) without downloading every header |
| `GetTrustlessStateProof` | FROST checkpoint + state-transition proof — the main endpoint for fully-trustless sync |
| `GetCheckpoint` | FROST-threshold-signed tip for an epoch boundary (1024 blocks); your trust root |
| `GetEpochBoundary` / `GetEpochBoundaries` | Epoch boundary hashes for chain continuity between proofs |

### NOMT state proofs

| RPC | Proves |
|---|---|
| `GetCommitmentProof` (+ batch) | "cmx is in the commitment tree at position N" |
| `GetNullifierProof` (+ batch) | "nullifier is / isn't in the spent-nullifier set" |

[NOMT](https://github.com/thrumdev/nomt) — Nearly Optimal Merkle Trie —
backs the commitment and nullifier state.

### Privacy-preserving block reads

| RPC | Notes |
|---|---|
| `GetCompactBlocks` | Zidecar's own compact-Orchard wire format (not lwd's) |
| `GetVerifiedBlocks` | Same, with a merkle path binding the action data to the block header |
| `GetBlockTransactions` | All txs at a height — client hides which specific tx it cares about |
| `GetMempoolStream` | Compact actions for unconfirmed txs (`height=0`); enables local trial-decryption + nullifier checks without revealing which note the client is scanning for |

### Standard chain queries

`GetTip`, `GetSyncStatus`, `GetTransaction`, `SendTransaction`,
`GetTreeState`, `GetAddressUtxos`, `GetTaddressTxids`, `SubscribeBlocks`
(live tip feed). Some overlap with the lwd surface, but emitted in
zidecar's typed message shapes.

### Rotko account / identity layer

| RPC | What it does |
|---|---|
| `GetLicense` | Watches for an on-chain payment to a known address and signs a pro-tier license for the paying ZID |
| `SignAnchor` | ed25519 signature for [zigner](https://github.com/rotkonetworks/zigner) hardware-wallet attestation; requires `ZCLI_SIGNING_KEY` env on the server |
| `GetProRing` | Anonymous-membership Ring-VRF proof for pro subscribers; rotates daily; lets clients prove "I'm a pro" without revealing which one |

## FROST relay surface (opt-in, `--frost-relay`)

A deliberately-dumb message switch for FROST threshold-signing ceremonies:

| RPC | What it does |
|---|---|
| `CreateRoom` | Open a session with `(threshold, max_signers, ttl)`; returns a human-readable code (`"alpha-bravo-charlie"`) |
| `JoinRoom` | Server-streaming subscription; participant identified by ephemeral ed25519 pubkey |
| `SendMessage` | Push an opaque payload to all room participants; returns a monotonic sequence number |

The relay does **not** parse, validate, or understand FROST protocol
messages. It forwards bytes. Confidentiality and authenticity come from
the participants signing their own messages; the relay can only censor
(drop / delay) or observe metadata. zcli's multisig flow uses this when
N signers can't reach each other directly (NAT, mobile, async availability)
but all share a trusted zidecar endpoint.

## Auth (opt-in, `--auth-token`)

Set `--auth-token <TOKEN>` (or `ZIDECAR_AUTH_TOKEN` env) to require
`Authorization: Bearer <token>` on every gRPC request to every surface.
Same token gates all three (lwd, zidecar, FROST). When unset, the server
accepts anonymous requests — the Zashi-compatible default. Suitable for
"public lwd endpoint" deployments; flip on for private rotko / zafu use.

## Flags

| Flag | Default | Effect |
|---|---|---|
| `--zebrad-rpc` | `http://127.0.0.1:8232` | Upstream Zebra JSON-RPC endpoint |
| `--listen` | `0.0.0.0:50051` | gRPC listen address (gRPC-web is enabled) |
| `--testnet` | false | `chainName="test"`; testnet Sapling activation height |
| `--mempool-cache-ttl` | `0` | Per-request `getrawmempool` cache; enable on public nodes |
| `--zidecar-rpc` | **opt-in** | Register the ZidecarService surface; open RocksDB at `--db-path`; spawn 4 background proof tasks |
| `--frost-relay` | **opt-in** | Register the FROST relay surface |
| `--auth-token` / `ZIDECAR_AUTH_TOKEN` | unset | Require bearer-token auth on every gRPC request |
| `--db-path` | `./zidecar.db` | RocksDB cache path (only opened with `--zidecar-rpc`) |
| `--start-height` | orchard activation | Proof start height (only used with `--zidecar-rpc`) |

## Operational defaults

| Default | Value | Reasoning |
|---|---|---|
| Inbound timeout | 30 s | Bounds unary latency; server-streaming RPCs unaffected (TimeoutLayer races response-future construction, not each yielded message) |
| Concurrency limit | 256 in-flight | Bounds per-process load; new requests queue rather than fail-fast (matches wallet retry semantics) |
| Block range cap | 10 000 blocks | Bounds upstream Zebra fanout per request |
| Mempool seen-set cap | 50 000 per stream | Bounds memory under a stalled chain |
| `sendrawtransaction` retry | none | At-most-once submission |
| Upstream error detail | scrubbed | `Status::unavailable("upstream node unavailable")` instead of leaking the Zebra URL via reqwest's Display impl |
| Stream cancellation | per-RPC | Every per-iteration Zebra await is raced against client-disconnect (`tx.closed()`); detached worker tasks bail immediately when the client drops |

## Architecture

zidecar is built as a Tower-shaped gRPC server:

**Outbound** (`src/zebrad.rs`): `Buffer<Retry<ZebradInner>>` — a bounded
mpsc queue with retry on transient transport errors. `sendrawtransaction`
and `submitblock` bypass the retry policy for at-most-once semantics.
`reqwest::Error::Display` URLs are scrubbed at the `From<ZidecarError>
for tonic::Status` boundary so the internal Zebra endpoint doesn't leak
to anonymous clients.

**Inbound** (`src/main.rs`, `src/middleware.rs`): three Tower layers wrap
the tonic server uniformly across every surface:

```rust
Server::builder()
    .accept_http1(true)                             // gRPC-web support
    .layer(middleware::trace_layer())               // per-RPC tracing
    .layer(middleware::timeout_layer(30s))          // unary timeout
    .layer(middleware::concurrency_limit_layer(256))// in-flight cap
```

**Bind** happens synchronously via `tokio::net::TcpListener::bind` before
serving so `EADDRINUSE` / permission errors propagate from `main()`
immediately rather than panicking from the spawned server task.

**Compact-block builder** (`src/compact.rs`): per-block, iterates
`block.tx` from `getrawtransaction`, threads each tx's block position
through `extract_tx_shielded`, and groups Orchard actions + Sapling
spends + Sapling outputs into per-txid buckets that `to_lwd_block`
emits as one `CompactTx` per source tx with the correct
position-in-block index.

## Comparison

| | zidecar | Go [lightwalletd](https://github.com/zcash/lightwalletd) | [Zaino](https://github.com/zingolabs/zaino) |
|---|---|---|---|
| Language | Rust | Go | Rust |
| Upstream | Zebra JSON-RPC | zcashd/zebra JSON-RPC | Zebra `ReadStateService` (in-process) + JSON-RPC fallback |
| Co-host with Zebra | optional | optional | required for the State backend |
| `CompactTxStreamer` coverage | 20/20 | 20/20 (reference) | 20/20 |
| Wire byte order | LE protocol order (matches Zaino/canonical) | reference | reference |
| Tower middleware (trace/timeout/concurrency) | yes | n/a (Go) | none |
| gRPC-web | yes | no | no |
| Per-RPC stream cancellation | yes | no | no |
| Block-range cap | 10 000 | none | none |
| Bearer-token auth | opt-in | none | cookie auth on JSON-RPC only |
| Retry policy on `sendrawtransaction` | bypassed | n/a | n/a |
| Upstream URL leak in errors | scrubbed | n/a | leaks via `{err:?}` |
| Trustless-sync proofs (Ligerito, FROST) | yes (opt-in) | no | no |
| NOMT inclusion proofs | yes (opt-in) | no | no |

**Honest framing:** Zaino is the upstream strategic Rust lightwalletd
replacement (Zingo Labs, integrated into Zebra's QA framework). Its
architecture is more ambitious — direct `ReadStateService` integration
gives in-process backpressure and avoids JSON serialization on the hot
path. If you want a pure lwd-shim in Rust and you're OK with Zaino's
deployment constraints, use Zaino. zidecar's reason to exist is the
**trustless-sync stack** (Ligerito header proofs, NOMT commitment +
nullifier proofs, FROST checkpoints) plus the rotko-specific surfaces
(license, zigner, pro ring) — none of which are in scope for Zaino or
canonical lightwalletd.

## Compatibility scope

- **Zashi (zcash-sdk 2.x):** wire-confirmed end-to-end by a side-by-side
  diff against Zaino (every byte-order, field-name, and message-shape
  decision matches). Has not yet been smoke-tested against a live Zashi
  build pointed at a running zidecar.
- **ywallet:** wire-compatible by the same reasoning, untested.
- **Browser clients via gRPC-web:** `tonic_web::enable(...)` wraps every
  registered service. Zaino does not enable gRPC-web; zidecar does.

### Known limitations

- `LightdInfo.vendor` is `"zidecar/rotkonetworks"` and `git_commit` is
  `v{version}-{hash}` rather than a bare hash. SDKs treat both as opaque.
- `CompactTx.fee` is always 0 (matches canonical lwd and Zaino — neither
  computes fees).
- No built-in TLS. Run behind a reverse proxy (Caddy, nginx, Cloudflare)
  that terminates TLS and rate-limits at the IP level for public exposure.
- The `ZebradService` poll_ready is always Ready — real backpressure on
  the upstream Zebra path comes from the outer `Buffer` and the inbound
  `ConcurrencyLimitLayer`. Real `poll_ready` propagation would require
  linking `zebra-state` directly (Zaino's pattern), which only works when
  co-hosted with Zebra.

## Building

```sh
git clone https://github.com/rotkonetworks/zcli
cd zcli
cargo build -p zidecar --release
./target/release/zidecar --help
```

Requires Rust 1.85+. Builds protobuf via `tonic-build` at compile time;
no separate `protoc` step needed.

## Tests

```sh
cargo test -p zidecar --lib
```

27 unit tests cover the pure-function core: byte-order reversal,
compact-block grouping, header-bytes parsing across CompactSize prefix
shapes, range-bound validation, sapling/orchard pool extraction. Live
integration tests against a running Zebra are gated behind `#[ignore]`
in `tests/zebrad_integration.rs`.

## License

MIT.

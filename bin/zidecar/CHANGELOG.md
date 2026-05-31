# Changelog

All notable changes to **zidecar** are documented here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
SemVer with pre-1.0 minor bumps treated as breaking.

## [0.7.0] - 2026-06-01

First release where any zcash-sdk wallet (Zashi, ywallet, etc.) can point at
zidecar as a drop-in replacement for canonical lightwalletd. Brings the
`CompactTxStreamer` surface to all 20 RPCs and corrects three on-wire
conformance bugs that prevented earlier versions from serving Sapling
clients.

### Added

- Full `CompactTxStreamer` parity — implements the four remaining RPCs that
  earlier versions omitted: `GetMempoolTx`, `GetTaddressTransactions`,
  `GetBlockNullifiers`, `GetBlockRangeNullifiers`. Plus the five
  Zashi-required RPCs added in 0.6.1: `GetTaddressTxids`,
  `GetTaddressBalance` (+ stream), `GetMempoolStream`, `GetLatestTreeState`,
  `Ping`. Net: 20/20 of the canonical lightwalletd surface.
- Sapling depth in `CompactBlock` — previously only Orchard actions were
  emitted, leaving sapling-using wallets blind to incoming notes and spends.
  `CompactBlock.vtx[].spends` and `.outputs` are now populated; the
  canonical block header bytes (140 + Equihash solution) populate
  `CompactBlock.header`.
- Tower-shaped server bootstrap with `TraceLayer`, `TimeoutLayer`
  (30s default), and `ConcurrencyLimitLayer` (256 in-flight default). Cross-
  cutting concerns live at the boundary, not duplicated inside handlers.
- 27 unit tests covering pure helpers: `extract_header_bytes` across the
  three CompactSize prefix shapes, `extract_tx_shielded` across mixed/
  transparent-only pools, `to_lwd_block` grouping + asymmetric byte-order
  reversal, `strip_to_nullifiers`, `parse_taddress_filter`,
  `parse_block_range` bounds.

### Fixed

- **Wire byte-order corrected.** Every txid, block hash, Sapling cmu,
  ephemeral key, and Sapling spend nullifier was emitting Zebra's
  display-order (big-endian) bytes, but the lightwalletd proto requires
  protocol-order (little-endian) — `compact_formats.proto` literally says
  *"This byte array MUST be in protocol order and MUST NOT be reversed."*
  Sapling trial decryption silently produced zero hits because `cmu`
  wasn't on the Jubjub curve under the SDK's expected encoding. Orchard
  fields pass through unchanged (Zebra doesn't pre-reverse them).
- **`LightdInfo.chainName` now emits `"main"`/`"test"`** rather than
  `"mainnet"`/`"testnet"`. The Zcash SDK rejects unknown network strings,
  so the longer form made every wallet refuse to sync.
- **`CompactTx.index` is now the position-within-block** rather than the
  position-within-shielded-only-set. SDKs use `index == 0` to identify the
  coinbase transaction; the previous behavior misidentified which tx was
  coinbase when transparent-only txs appeared before the first shielded
  tx in a block.

### Security

- **`MAX_BLOCK_RANGE_DELTA = 10_000`** ceiling on every range-accepting
  RPC (`GetBlockRange`, `GetBlockRangeNullifiers`, `GetTaddressTxids`,
  `GetTaddressTransactions`). Previously `start=0,end=u32::MAX` would
  queue billions of upstream Zebra RPCs inside a single spawned task; the
  gRPC concurrency limit did not bound this because the handler returned
  `Response<Stream>` synchronously, freeing the slot while the worker
  kept going.
- **Upstream Zebra URL no longer leaks in error responses.** Every
  `reqwest::Error::Display` impl embeds the request URL by default, so any
  connect/timeout/5xx from Zebra surfaced
  `Status::internal("...http://10.7.0.201:8232/...")` to anonymous
  clients. `ZebradTransport` errors now map to
  `Status::unavailable("upstream node unavailable")` with no detail;
  detail remains visible via server-side tracing.
- **`sendrawtransaction` and `submitblock` bypass the retry policy.**
  At-most-once semantics — replay on a flapping zebrad could
  double-broadcast in pathological cases.
- **`GetMempoolStream` seen-txid set capped at 50_000** per stream. End
  the stream and let the client reconnect when hit, so a stalled chain
  can't grow memory unboundedly.
- **`GetMempoolTx` exclude list capped at 256 suffixes**; empty suffixes
  rejected (they would silently filter every transaction).

### Changed

- Tower outbound `ZebradRetryPolicy` now consults a
  `NON_IDEMPOTENT_METHODS` list to gate retries (`sendrawtransaction`,
  `submitblock`).

## [0.6.1] - 2026-05-30

- First wave of Zashi-required RPCs: `GetTaddressTxids`,
  `GetTaddressBalance` (+ client-streaming variant), `GetMempoolStream`,
  `GetLatestTreeState`, `Ping`. 16/20 lightwalletd surface coverage.
- New `get_address_balance` on the internal Zebra JSON-RPC client.
- `LightdInfo.taddr_support = true` now backed by real handlers (was a lie
  in 0.6.0).

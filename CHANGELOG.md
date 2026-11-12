# Changelog

Release notes for zcli, zclid and zidecar. Earlier releases (v0.9.0 and
before) keep their notes in the annotated git tags (`git show v0.9.0`).

## v0.11.0 - 2026-11-12

Upgrade order: no required order. zidecar's RPC changes are additive (a
burial field on `GetFlyClientProof`); no RPC was removed.

### NU7

- Zakura Common 4.0.0: NU7's mainnet activation (3,543,405) is built in.
  Wallets bind NU7 from that height and refuse an NU6.3 transaction there;
  they also build on whatever branch the node reports.
- `zcli --testnet` is back, with NU7 on testnet.

### zidecar

- FlyClient: the history index loads its stored leaves only after zebrad
  reports its upgrade schedule, and reloads when the schedule changes. A
  build that did not know NU7 and restarted past its activation stalled and
  served no proof ("epoch not indexed").
- `GetFlyClientProof` takes a burial depth and opens the note tree roots that
  many blocks under the tip, so a one-block reorg cannot move them.
- Optional Zakura Indexer push streams for the tip and the mempool
  (`--zakura-indexer-url`).
- `GetLightdInfo` reports the full git commit (overridable with
  `ZIDECAR_GIT_HASH` for builds without `.git`).

### zcli

- Multisig: hold a share of a zafu or escrow vault and co-sign its payouts;
  a joiner tagged into a session learns t-of-n from the host's first round.
- Merchant watch-only (`-w`): create and watch without the spending key on
  the merchant host.

### Workspace

- The voting crates (zcash-voting, pir-client, voting-wasm) and poker leave
  the main workspace and build in their own, so the wallet stack can move to
  Common 4.0 while voting stays on the stack its live chain runs.
- The FlyClient verifier is its own crate, `zync-flyclient`.

## v0.10.0 - 2026-10-05

Upgrade order: **clients first.** zcli and zclid 0.9.0 cannot sync against a
v0.10.0 zidecar (they need a Ligerito header proof that no longer exists).
Upgrade every zcli/zclid to v0.10.0 before moving a server to v0.10.0.
zcli v0.10.0 syncs against both v0.9.0 and v0.10.0 servers.

### Removed: NOMT and Ligerito

- The Ligerito header proofs and the NOMT state proofs are gone. Neither
  proved anything about Zcash: the header proof bound values the prover
  chose, and the NOMT proofs bound zidecar's own database.
- The `ligerito*` crates leave the workspace; they continue in their own
  repository. Projects that use `zcli/crates/ligerito` by path need
  repointing.
- zync-core drops the prover, trace, verifier, nomt and actions modules.

### Chain verification via FlyClient

- zidecar builds a ZIP-221 history index (`--zidecar-rpc --flyclient
  nu6.3|nu5`, mainnet) and serves `GetFlyClientProof`. Before a block's leaf
  is added, its header's commitment must open to the tree built so far; on
  a mismatch the index stops and the RPC answers UNAVAILABLE.
- The epoch schedule follows network upgrades from zebrad's
  `getblockchaininfo`, so a new upgrade is indexed without a zidecar release.
- `zcli signer verify` checks the chain with FlyClient (sampled headers with
  valid Equihash, MMR paths, epochs linked down to the anchor) and binds the
  FlyClient tip to the cross-verified server tip.

### Privacy: notes are no longer sent to the server

- zcli sync used to send received notes' commitments and positions, and the
  nullifiers of unspent notes, to zidecar for NOMT proofs. It no longer
  does: spends and notes are found by scanning blocks locally.

### zidecar: 10 RPCs dropped, with a legacy shim

- Removed: GetHeaderProof, GetTrustlessStateProof, GetVerifiedBlocks,
  GetCheckpoint, GetEpochBoundary, GetEpochBoundaries, GetCommitmentProof,
  GetCommitmentProofs, GetNullifierProof, GetNullifierProofs.
- A shim answers those paths with UNIMPLEMENTED and a message naming the
  retired method and asking the client to upgrade past 0.9.0 (gRPC and
  gRPC-web). zafu 28.x treats it as "proof verification unavailable, will
  retry" and keeps syncing.
- Storage is a small sled store for the FlyClient history leaves; the NOMT
  database is no longer opened. `CompactBlock.actions_root` and the
  SyncStatus epoch fields are reserved.
- `--start-height` and `--ironwood-activation` are removed.

### zcli / zclid

- Sync no longer fetches a header proof or folds an actions commitment; it
  refuses a sync point if the server skipped a height.
- `--no-verify` (which skipped the removed checks) is removed.

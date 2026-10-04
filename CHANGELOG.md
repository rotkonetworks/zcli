# Changelog

Release notes for zcli, zclid and zidecar. Earlier releases (v0.9.0 and
before) keep their notes in the annotated git tags (`git show v0.9.0`).

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

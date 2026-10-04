# FlyClient over the ZIP-221 history tree

Status: implemented natively (no ligerito wrapper) on `feat/flyclient`.
Code: `crates/zync-core/src/flyclient/` (verifier, MMR store, sampling),
`bin/zidecar/src/history.rs` (index + proof builder),
`bin/zidecar/src/grpc_service/flyclient.rs` (`GetFlyClientProof`),
`bin/zcli/src/main.rs` (`signer verify`, step 5).
References: FlyClient (Bünz, Kiffer, Luu, Zamani 2019); ZIP-221; ZIP-244;
`zcash_history` 0.6 (V3 nodes for Ironwood).

## Problem

The ligerito header proof proves a trace of headers from a configured
`start_height`, but its public outputs (block hashes, state roots) are values
the prover chose: nothing ties them to what consensus committed (see
`ligerito-evaluation-binding.md`). Proving Equihash for every header in-circuit
does not scale, which is why the anchor sat at a configured start.

## What we built instead

Every header since Heartwood commits to a Merkle mountain range over the
blocks of its own network-upgrade epoch. Each node carries subtree work,
first/last note commitment tree roots and shielded transaction counts.
FlyClient checks a logarithmic number of headers, chosen by work, and their
MMR paths.

What that binds, and what it does not:

- **The header chain** (block hashes, times, targets, work of the leaves) is
  bound by proof of work: every sampled leaf must match a header with a valid
  Equihash solution, at a work point the server did not choose.
- **The tree's other fields** (note commitment tree roots, transaction counts)
  are only as good as the committing header. A server can mine one block on
  top of the honest chain whose commitment opens to a fabricated tree whose
  leaves copy honest headers: every sample passes, honest nodes reject the
  block, a lone light client cannot tell. So treat `end_orchard_root`,
  `end_ironwood_root` and the counts as proven only when the committing header
  is a block independent nodes report (`zcli signer verify` requires the
  FlyClient tip to be the cross-verified tip, or confirmed by >2/3 of
  `--verify-endpoints`), or is buried under enough work that faking it costs
  more than it gains. This is FlyClient's own "connected to at least one
  honest node" assumption, made explicit.

Per epoch, newest first, the verifier (`verify_flyclient`) checks:

1. the committing header (the tip, or an older epoch's last block) has a
   valid Equihash (200, 9) solution and meets its target and the pow limit;
2. the peaks bag into a root whose hash opens the header's commitment field:
   `hashLightClientRoot` directly for Heartwood/Canopy (V1 nodes),
   `hashBlockCommitments = BLAKE2b("ZcashBlockCommit", root ‖ authDataRoot ‖ 0³²)`
   from NU5 on;
3. every opened leaf matches its PoW-checked header (hash, time, nBits, work),
   sits at the right height, and folds up an authenticated path to its peak;
4. every Fiat-Shamir sample point lies inside the cumulative-work interval of
   some opened leaf, computed from the left siblings' and left peaks' work
   along authenticated paths — so the server cannot answer a sample with a
   block of its choosing;
5. the tree's last leaf is the committing header's parent; each epoch's
   activation block's parent is the previous epoch's committing block; the
   oldest epoch's first block is a compiled anchor hash.

The server (`HistoryIndex`) rebuilds each epoch from zebrad and, before adding
a block's leaf, checks that the block's own header commits to the tree built
so far (fail closed: on a mismatch it stops serving). It verifies every proof
with the client's verifier before sending it.

## Corrections to the earlier version of this note

- **The tree is per epoch, not one tree from Heartwood.** It restarts at every
  upgrade (Heartwood, Canopy, NU5, NU6, NU6.1, NU6.2, NU6.3). Block `n`
  commits to blocks `activation..n-1` of its epoch; an activation block
  commits to the previous epoch's complete tree (zebra's `HistoryTree::push`).
  We commit older epochs through their last block instead (equally valid, and
  the link is a plain `hashPrevBlock` check).
- **Node versions differ by epoch.** V1 for Heartwood/Canopy, V2 (adds Orchard)
  for NU5–NU6.2, V3 (adds Ironwood) for NU6.3. `zcash_history` 0.6 has all
  three.
- **Two header-binding modes**, as above; the old note only described the NU5
  one.
- **Anchors.** NU5 activation (already compiled into zync) or NU6.3 activation
  (`IRONWOOD_ACTIVATION_HASH_MAINNET`, `00000000001a8b54…8128d761`, checked
  against blockchair, zec.rocks and zcash.rotko.net). With the NU6.3 anchor the server only
  indexes the current epoch.
- **Native, not ligerito.** A FlyClient proof is already logarithmic; checking
  it in wasm is cheap. Ligerito may wrap it later for size; correctness no
  longer depends on it.

## Network upgrades are not hardcoded

Epochs come from a `Schedule`: the upgrades `zcash_protocol` knows, or any
`(activation height, branch id)` list. zidecar refreshes its schedule from
zebrad's `getblockchaininfo` on every pass, so an upgrade a newer zebrad knows
(NU7, ...) is indexed without a zidecar release. The verifier checks upgrades
it knows against the compiled table and takes a newer one from the proof:
the branch id personalizes every history-tree hash and the PoW header commits
to the result, so a wrong id or boundary cannot verify, and the epoch must
still link down to the anchor. An unknown upgrade gets the newest node format
(V3) and the NU5 header binding; if it changes the node format, parsing fails
and the proof is rejected until the code learns the new format.

## Details that are easy to get wrong

- Sampling must agree bit for bit between a native server and a wasm client,
  so it is integer-only: `x = 1 - 2^(-k·u)` with a Q64 table for `2^(-2^-j)`,
  `δ = 2^-k ≤ tail / n`, and `m = ⌈λ · k · 0.694⌉` samples (an upper bound on
  FlyClient's `λ / log2(k / (k-1))` for an adversary below half the honest
  work). Defaults: λ = 40, tail = 16. Both are protocol parameters, sent in
  the request; the server clamps them.
- `zcash_history::Version::combine` asserts equal branch ids and adds work and
  counts unchecked; the verifier rejects such input before calling it.
- zebra's `getblock` prints `finalsaplingroot` and `blockcommitments`
  byte-reversed but `finalorchardroot` as is, and has no auth data root. The
  index takes hash/time/nBits from `getblockheader <hash> false`, Orchard and
  Ironwood roots from `z_gettreestate` frontiers (zebra's Ironwood tree is an
  Orchard note commitment tree), and rebuilds the ZIP-244 auth data root from
  the per-transaction `authdigest` (display order; `0xff…` for pre-v5).
- Transaction counts follow zebra: a transaction counts for a pool when it
  carries that pool's bundle (non-empty spends/outputs or actions).

## What FlyClient does not give us

- **Spent status.** The history tree has no nullifiers (ZIP-221 considered and
  left them out). NOMT nullifier proofs stay, and their roots are still not
  consensus-bound.
- **Difficulty adjustment between samples.** Sampled headers are checked
  against their own nBits; the per-block Digishield window is not re-derived.
  ZIP-221 itself calls FlyClient's guarantee under Zcash's fast-adjusting
  difficulty heuristic.
- **The heaviest chain.** A proof shows the server's chain has the claimed
  work; picking between servers means comparing `total_work` (cross-check).

## Not done yet

1. **Validate against a live zebrad** (`zidecar --zidecar-rpc --flyclient nu6.3`
   pointed at a node, read-only). The index has only run against unit
   fixtures. The first sync is the real test: the fail-closed check compares
   every block's header to our tree, so any byte-order or count mistake shows
   up as a refusal to serve, not as bad proofs.
2. **Omission checks.** The tip root's `orchard_tx`/`ironwood_tx` let a client
   compare against compact blocks; wire that into sync (whole epoch first,
   subtree ranges later).
3. **Proof size.** ~4.3 KB per opened leaf, mostly paths; a two-epoch proof
   (NU6.2 + part of NU6.3) is ~1.9 MB. Deduplicate shared path nodes, and let
   clients cache closed epochs (their proofs never change).
4. **Memory for the NU5 anchor.** The index keeps every epoch's tree in memory
   (~1.7M leaves). Fine for `nu6.3`; for `nu5`, store closed epochs' nodes on
   disk.
5. **zafu.** Expose `verify_flyclient` through `zcash-wasm` and call
   `GetFlyClientProof` from the extension (separate repo), with the same tip
   cross-check zcli does before trusting any root or count. zync-core's tonic
   `ZidecarClient` has no FlyClient call yet; if one is added, raise its 4 MB
   decode limit — multi-epoch proofs exceed it.
6. ~~**Ligerito.**~~ Done (2026-10): the Ligerito header trace and the NOMT
   proofs are removed from zcli, zidecar and zync-core; the Ligerito crates
   moved to their own repository.

## Prior art we looked at

- `ordian/zflyclient` (March 2026 hackathon): a `no_std` verifier for one
  block's inclusion under a tip (header parse, Equihash, `hashBlockCommitments`,
  V2 MMR path). No sampling, no PoW on sampled blocks, V2 only, one epoch, and
  no license, so nothing was copied. Its server half (Zaino PR #922) was
  closed unmerged; the lightwallet-protocol RPC (PR #21) is still open. Our
  message shapes are close enough to converge if that lands.
- `shielded-labs/zcash-light-client`: transparent-only SPV client whose Cairo
  "STARK proof" of Equihash only checks the solution length and that it is not
  all zeros, with a BLAKE2b block hash and a Digishield routine that does not
  match zcashd. Nothing reusable.

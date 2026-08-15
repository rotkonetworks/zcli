# Genesis-anchored header proof: FlyClient over the ZIP-221 MMR

Status: design for task #39 ("valid header/epoch proofs from a low/genesis start")
Scope: `bin/zidecar/src/header_chain.rs`, `epoch.rs`, `prover.rs`, `grpc_service/proofs.rs`
References: FlyClient (Bunz-Kiffer-Luu-Zamani, 2019); ZIP-221 (FlyClient-compatible
chain history); `zcash_history` crate. Extends `per-pool-proofs.md`.

## Problem

Today `header_chain.rs` builds a **full contiguous verification trace**: 32 fields
per header (block_hash, prev_hash, nBits, cumulative_difficulty, running
header/state commitments), and the ligerito proof proves EVERY header from a
configured `start_height` to tip - hash-chain linkage, PoW, difficulty
progression. Two consequences:

1. **Trusted anchor.** The proof bottoms out at a configured `start_height`, not a
   consensus constant. A client trusts the operator gave the real block there.
   `TrustlessStateProof.checkpoint` (the FROST anchor slot) is `None` - never
   constructed. So the state is trustless only DOWN TO that configured start.
2. **Genesis-anchoring is prohibitively expensive.** Anchoring at a universal
   constant means proving the whole header chain (millions of headers, each with
   an Equihash PoW). Proving Equihash in-circuit for every header does not scale;
   that is why the anchor sits at a configured start instead.

## Target

Replace the full contiguous trace with **FlyClient sampling over the ZIP-221
chain-history MMR**, anchored at **Heartwood** (a consensus constant), so the
header proof is both **cheap** and **trustless with no configured trust**.

### Why ZIP-221 is the right substrate (not a custom MMR)

- **Consensus-committed root.** The ZIP-221 MMR root is in every header's
  `hashBlockCommitments`. So the MMR is authenticated by the header PoW for free -
  the prover does NOT have to prove the MMR is complete/correct in-circuit. A
  custom zidecar MMR would need an in-circuit completeness argument (heavier,
  weaker).
- **Per-subtree total work.** ZIP-221 nodes commit `subtreeTotalWork` - exactly
  what FlyClient's difficulty-weighted sampling requires. ZIP-221 was designed for
  FlyClient (same lineage).
- **Canonical implementation exists.** The `zcash_history` crate builds/verifies
  the MMR; zidecar already holds every header (`header_chain.rs` fetches them from
  zebrad), so it can construct the MMR locally and self-verify each root against
  the `hashBlockCommitments` field. No new zebrad RPC required.

### Why Heartwood, not block 0

ZIP-221 activated at **Heartwood (~block 903k)**, not genesis. That is complete
for a shielded wallet:

- Heartwood is **below NU5/orchard (~1.69M) and ironwood (NU6.3)** - the MMR fully
  covers every shielded pool zafu spends. There are no orchard/ironwood notes
  below it. (Only early Sapling is pre-Heartwood; zafu is orchard-based.)
- The Heartwood activation block is a **hardcoded consensus constant** -
  universally agreed, not operator-chosen. Same trust quality as genesis.

So "genesis-anchored" for this wallet means **Heartwood-anchored via ZIP-221**,
and it is trustless and complete.

## The two-axis split (what goes in-circuit vs native)

FlyClient's whole point. Do NOT prove Equihash in-circuit for every header.

- **In the ligerito proof (succinct):** MMR inclusion of the sampled headers,
  cumulative-difficulty accounting, and binding the state roots
  (`tree_root`/`nullifier_root`) to the sampled chain.
- **Native (outside the circuit), on the O(log n) sampled headers only:** Equihash
  PoW verification. ~25 samples, not millions - cheap, and never in-circuit.

## Soundness-critical invariant

The sample positions MUST be derived by **Fiat-Shamir from (MMR root, tip
cumulative_difficulty)** - the same transcript both sides can recompute - and
NEVER chosen by the server. A server that picks its own samples can present a
lighter forged chain. This is the single line the whole construction rests on;
it holds whether the wrapper is ligerito or native FlyClient.

## Protocol sketch

**Prover (zidecar), per proof:**
1. Maintain the ZIP-221 MMR via `zcash_history` up to the anchor height (last
   completed epoch boundary >= Heartwood). Verify its root == the anchor header's
   `hashBlockCommitments` (consensus binding).
2. Derive sample set S = FiatShamir(mmr_root, tip_cumulative_difficulty),
   difficulty-weighted per FlyClient.
3. For each s in S: MMR inclusion path + the header.
4. ligerito-prove: every inclusion path is valid against mmr_root; the
   difficulty accounting from Heartwood to anchor is consistent; and the state
   roots at the anchor bind to this chain (`final_state_commitment`).
5. Fill `TrustlessStateProof.checkpoint` with the Heartwood-anchored,
   ZIP-221-bound checkpoint (replacing the `None` / unbuilt FROST slot).

**Verifier (zafu client):**
1. Recompute S = FiatShamir(mmr_root, tip_cumulative_difficulty); reject if the
   proof's samples differ.
2. Verify the ligerito proof (inclusions + difficulty + state binding).
3. **Native-check the PoW** of each sampled header (Equihash), and that the anchor
   header's `hashBlockCommitments` == mmr_root, and that the anchor descends from
   the hardcoded Heartwood constant.
4. Accept `tree_root`/`nullifier_root` at the anchor as trustless.

## What changes in zidecar

- `header_chain.rs`: alongside (or replacing) the 32-field contiguous trace, add
  the ZIP-221 MMR (via `zcash_history`) and per-header `hashBlockCommitments`
  verification. The contiguous trace can remain for the epoch-local segment;
  FlyClient carries the deep history.
- `epoch.rs`: anchor at the last completed epoch boundary >= Heartwood; the
  FlyClient sample set replaces "prove from configured start_height".
- `prover.rs`: the ligerito statement changes from "all headers contiguous" to
  "sampled MMR inclusions + difficulty + state binding". `ProofPublicOutputs`
  gains the mmr_root and the sample commitment.
- `grpc_service/proofs.rs`: populate `TrustlessStateProof.checkpoint` with the
  ZIP-221/Heartwood anchor; `get_state_roots(anchor)` at the boundary (already
  height-keyed).

## Relationship to NOMT (unchanged)

NOMT stays exactly as it is - the current-state nullifier/commitment accumulator
serving spend-time membership proofs. FlyClient authenticates the CHAIN; the
ligerito state binding ties NOMT's roots to that chain; NOMT is bound on top, not
modified. FlyClient does not go "into" NOMT - it goes into the header proof and
becomes the trust anchor NOMT's roots hang from.

## Ecosystem alignment

This is deliberately a "ride the standard, not our own trace" change - the header
work had gone cowboy and this pulls it back:

- **ZIP-221** (FlyClient-compatible chain history) is the consensus substrate, and
  the `zcash_history` crate is the canonical builder/verifier. We stop maintaining
  a bespoke 32-field header trace and bind to the consensus MMR root that every
  header already commits (`hashBlockCommitments`).
- **FlyClient** is a published protocol, not a home-grown sampling scheme.

Keep the genuinely novel part - the trustless light-client proof (ligerito header
proof + NOMT state binding, verified client-side; almost no wallet ships this).
But the durable path for it is NOT a private zidecar fork: **specify it as a ZIP**
(proof format + verifier), so other wallets/indexers can implement and review it.
Ride the substrate (ZIP-221, `zcash_history`); standardize the extension (the
trustless proof). Cowboy -> sheriff.

## Non-goals

- Not proving Equihash in-circuit (the whole point is native PoW on samples).
- Not covering pre-Heartwood history (no shielded notes there for this wallet).
- Not changing NOMT, the note-decryption kernels, or the wallet DB shape.

## Correctness / test gates

- MMR root at every synced height must equal the header's `hashBlockCommitments`
  (fail closed on mismatch - this is the consensus binding).
- Sample set must be reproducible from the public transcript (prover cannot
  influence it); a proof whose samples do not match the recomputed set is
  rejected.
- End-to-end: a client verifying only the proof + native PoW on samples must
  arrive at the same `tree_root`/`nullifier_root` a full contiguous verification
  would, anchored at Heartwood.

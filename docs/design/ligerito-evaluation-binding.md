# Binding header-proof outputs to the commitment: the missing ligerito opening

Status: design, needs cryptographic review before any implementation.
Written 2026-10-02.
Scope: `crates/ligerito` (`eval_proof.rs`, `prover.rs`, `verifier.rs`),
`crates/zync-core` (`prover.rs`, `verifier.rs`, `trace.rs`).
Relates to: `flyclient-header-proof.md` (which needs this primitive too),
`per-pool-proofs.md`.
References: Novakovic and Angeris, *Ligerito* (the evaluation protocol);
Evans and Angeris, *The Accidental Computer* (Jan 2025), §2.4 "matrix-vector
product" and §5; Evans, Mohnblatt and Angeris, *ZODA* (ePrint 2025/034).

## 1. Problem

The header proof proves that zidecar committed to a polynomial close to a
Reed-Solomon codeword. It does **not** prove anything about what the
polynomial contains. The repo already says so in three places:

- `crates/zync-core/src/lib.rs`, trust model, item 1: *"Public outputs
  (block hashes, state roots, commitments) are transcript-bound but NOT
  evaluation-proven — the ligerito proximity test does not constrain which
  values the polynomial contains. Soundness relies on the honest-prover
  assumption; cross-verification (item 4) detects a malicious prover."*
- `crates/zync-core/src/verifier.rs`, `verify_chain`: *"a malicious prover can
  claim arbitrary public outputs for any valid polynomial commitment. Sound
  composition requires evaluation opening proofs binding public outputs to
  specific polynomial positions."*
- `crates/ligerito/src/eval_proof.rs`, module doc: *"The eval sumcheck alone
  does NOT bind to the committed polynomial. A malicious prover could use a
  different polynomial for the sumcheck vs the Merkle commitment. Full
  soundness requires an evaluation opening that ties P(r) to the commitment
  (not yet implemented)."*

So every value a wallet trusts from the header proof (`tip_tree_root`,
`tip_nullifier_root`, `final_actions_commitment`, `tip_hash`, ...) is
currently trusted because zidecar is honest or because independent servers
agree. The ligerito proof adds anti-tampering in transit and nothing more.

## 2. What exists today

**Wired up.** `zync_core::prover::HeaderChainProof::prove` calls
`ligerito::prove_with_transcript` after absorbing the bincode
`ProofPublicOutputs` into the SHA-256 transcript.
`zync_core::verifier::verify_single` calls `verify_with_transcript`. No
evaluation claims are made.

**Dormant.** `ligerito::prove_with_evaluations` / `verify_with_evaluations`
exist, and nothing outside `crates/ligerito` calls them. They:

1. absorb the Merkle root of the committed polynomial `P`;
2. run a batched evaluation sumcheck for claims `P(z_k) = v_k`, i.e.
   `Σ_x P(x)·Q(x) = Σ_k α_k v_k` with `Q = Σ_k α_k eq(z_k, ·)`, reducing it to
   one claimed value `p_at_r = P(r)` at a random point `r`;
3. run the ordinary proximity protocol (`verify_core`) on the same transcript.

`verify_with_evaluations` returns `EvalVerifyResult { proximity_valid,
eval_challenges, p_at_r }` and **never compares `p_at_r` with anything
`verify_core` establishes**. The sumcheck is self-consistent for whatever
polynomial the prover had in mind, which need not be the committed one. As
it stands, the path adds no soundness over transcript binding. Wiring it into
zync-core unchanged would be a regression in honesty: it would look like
evaluation proofs and not be.

## 3. The missing primitive

> An **evaluation opening**: a proof that the committed polynomial `P`
> satisfies `P(r) = c` at a point `r` that the verifier fixes (here, the point
> the evaluation sumcheck ends at).

With it, steps 2 and 3 above compose: the sumcheck reduces many point claims
to one claim at `r`, and the opening ties that claim to the Merkle root.

Ligerito is a polynomial commitment scheme with an evaluation protocol. This
implementation runs the proximity variant: the initial partial-evaluation
point `partial_evals_0` is fresh Fiat-Shamir randomness
(`prover.rs::prove_core`), so the protocol establishes "the commitment is
close to a codeword, and here is a consistent partial evaluation at a random
point", with no external claim attached. **The Ligerito paper's evaluation
section is the authority for how to attach one; the proposal below must be
checked against it.**

### 3.1 Proposal (for review, not for implementation)

Two hooks are visible in the code:

- `partial_evals_0`: the first `initial_k` coordinates the prover folds with
  (`partial_eval_multilinear`, least-significant variable first, the same
  order `eval_sumcheck_prove` folds in).
- `glue_polynomials` / `glue_sums` with a fresh `beta`, which already merge a
  second sumcheck claim into the running one at each recursive step.

Sketch:

1. Run the first `initial_k` rounds of the evaluation sumcheck. Use its
   challenges `r_1..r_k` **as** `partial_evals_0` instead of drawing fresh
   ones. The residual claim is then about the partially evaluated polynomial
   `f = P(r_1..r_k, ·)`, which is exactly what `prove_core` commits to as
   `wtns_1`.
2. The residual claim `Σ_{x'} f(x')·Q'(x') = c'`, where `Q'` is `Q` folded with
   the same challenges, is a sumcheck over the same variables Ligerito's own
   sumcheck runs over. Glue it in with a fresh `beta`, as the recursion
   already does for its own claims.
3. At the end, the verifier needs `Q'` at the final point. `Q` is a sum of
   `eq` terms, so this is `O(#claims · n)` (`compute_eq_at_r` already does it).

The point of the sketch is that the binding needs **no new commitment and no
new code family**: it reuses the commitment, the partial evaluation and the
glue step the protocol already has. That is what *The Accidental Computer*
calls reusing the encoder's work: the vector `y_r = X̃·ḡ_r` that ZODA
publishes is this partial evaluation.

What the review must settle:

- Whether reusing sumcheck challenges as `partial_evals_0` keeps Ligerito's
  proximity soundness. The paper's bound assumes `partial_evals_0` is uniform
  and independent of the commitment. It is still uniform here (Fiat-Shamir,
  after the root is absorbed), but this needs checking, not asserting.
- Whether the glued claim needs its own degree bound or round structure, given
  that the existing sumcheck rounds use the linear `evaluate_quadratic` form.
- The soundness error of the combined protocol over `BinaryElem128`.

Effort: this is cryptographic design plus a proof, then a modest code change.
It should not be estimated as glue code.

## 4. What the opening unlocks

### 4.1 Point claims (Tier 1)

Once the opening exists, every public output that sits at a **fixed position**
in the trace becomes one or more `EvalClaim { index, value }`:

| Output | Trace position | Claims |
|---|---|---|
| `start_hash`, `start_prev_hash` | row 0, fields 1-16 | 16 |
| `tip_hash`, `tip_prev_hash` | row `N-1`, fields 1-16 | 16 |
| `start_height`, `end_height` | row 0 / row `N-1`, field 0 | 2 |
| `tip_tree_root`, `tip_nullifier_root`, `final_actions_commitment` | sentinel, fields 0-23 | 24 |

About 58 claims, batched into one sumcheck and one opening. Binding padding
as zeros (positions past the sentinel) is also worth one claim set, so a
prover cannot hide data after the sentinel.

**What this buys:** the prover can no longer claim outputs inconsistent with
its own commitment. Outputs from different proof segments (`verify_chain`)
now refer to committed data, so continuity checks between segments mean
something.

**What it does not buy:** the prover can still commit to a fabricated trace.
Nothing ties the committed rows to the real chain. **Cross-verification stays
load-bearing after Tier 1.**

### 4.2 Committed versus proven correct

Binding a value proves the trace *contains* it, not that it was *computed
correctly*:

| Value | Bound by Tier 1 openings | Correctness proven by |
|---|---|---|
| `tip_hash`, `start_hash`, prev hashes | yes | nothing yet (needs hash-chain argument, §4.3) |
| heights | yes | a public-vector check (§4.3) |
| sentinel roots (`tip_tree_root`, `tip_nullifier_root`, `final_actions_commitment`) | yes | nothing in the header proof (§5) |
| `cumulative_difficulty` | **no**: only the lower 32 bits are in field 18 | integer arithmetic, not linear over GF(2^32) |
| `final_commitment`, `final_state_commitment` | **no**: only the lower 4 bytes are in fields 19 and 30 | Blake2b chains, need a hash argument |

Outputs in the "no" rows cannot be bound by openings at all with the current
layout. Either move their full values into the trace (layout change, new
proof format) or stop exporting them as public outputs.

### 4.3 Constraints that are not point claims (Tier 1b)

- **Hash linkage**, `prev_hash_i == block_hash_{i-1}` for every row. This is a
  relation between positions 40 apart in the flat index, not a value at a
  position. `eval_proof.rs` only handles `EvalClaim { index, value }`. Proving
  it needs a zero-check over a shifted multilinear: either a layout where the
  shift is a row shift with a verifier-evaluable "next row" MLE (as in
  HyperPlonk and Binius), or a dedicated sumcheck. New protocol, not a batch
  of openings. N openings is not an option.
- **Heights**, field 0 of row `i` equals `start_height + i`. The verifier can
  evaluate the MLE of a public length-`N` vector in `O(N)`, so this is one
  extra claim against a verifier-computed value. Cheap once the opening
  exists.

Even with linkage proven, the `block_hash` cells are free values: a prover can
commit to an internally linked fake chain. Tying hashes to headers is the
FlyClient design's job (§6), not this document's.

## 5. Values no header proof can make trustless

`tip_nullifier_root` is the root of zidecar's NOMT tree. No consensus header
commits to it, so no proof over headers (contiguous, FlyClient or GKR) can
tie it to the chain. Its correctness needs either an argument over every
block's nullifiers (heavy: a proof that the NOMT updates were applied to the
real nullifier stream) or agreement between independent zidecar operators.
The same applies to `final_actions_commitment`, which is zidecar's Blake2b
chain over action roots.

`tip_tree_root` (the Orchard commitment tree) is different: consensus commits
to it, via ZIP-221 history nodes as far as we know. Check this against
ZIP-221 before relying on it. If so, the FlyClient design can bind it.

`flyclient-header-proof.md` says "Accept `tree_root`/`nullifier_root` at the
anchor as trustless". That holds for the tree root at best. The nullifier root
needs its own argument and should be listed as an open item there.

## 6. Relationship to the FlyClient design

`flyclient-header-proof.md` replaces the contiguous trace with FlyClient
sampling over the ZIP-221 MMR, with Equihash checked natively on the samples.
Its prover step 4, *"ligerito-prove: every inclusion path is valid against
mmr_root; the difficulty accounting ... is consistent; and the state roots at
the anchor bind to this chain"*, is a set of statements about what the
committed polynomial contains. **Every one of them needs the evaluation
opening from §3.** Without it, the FlyClient proof inherits the same
honest-prover assumption.

So the order is:

1. §3 evaluation opening (this document): reviewed, then implemented in
   `crates/ligerito`, with the dormant `*_with_evaluations` API replaced, not
   wired up as-is.
2. §4.1 point claims in zync-core. Small, mechanical, and the first place the
   opening is used. Proof format bumps; old proofs stay verifiable under the
   old (honest-prover) label during a transition.
3. FlyClient (`flyclient-header-proof.md`), built on the opening rather than on
   transcript binding.
4. §5 nullifier-root argument: a separate, open research item.

## 6a. Same gap elsewhere

`hitchho/jar@verifiable-execution` (a JAR/JAM fork branch, March 2026) has a
Lean 4 model of a Ligerito verifier, ported from a `commonware-commitment`
crate. It shows the same pattern:

- `Jar.Verifiable.verifyMemoryProof` runs only the Ligerito verifier. Its own
  comment says the grand-product constraint "is encoded in the polynomial
  structure, not as a separate check", but proximity does not check
  structure. `verifyGrandProduct` exists and is not called from it.
- `Jar.Commitment.WIProof.verifyProof` never looks at the circuit. Only the
  prover checks `isSatisfied`.

So constraint binding is the missing piece in at least one other Ligerito
port. Their `Commitment/DA.lean` (the Accidental Computer encoder and
sampler) and `Verifier.lean` are still useful as references and as a place
to state the §3 opening formally. Their `Threshold.lean` makes the point from
§4.2: in GF(2^k) a sum gives parity, so integer quantities need carry
circuits.

## 7. Non-goals

- Implementing the opening in this change. This document exists so the
  construction can be reviewed first.
- Proving SHA-256d or Equihash in-circuit. FlyClient already decided against
  it, for good reasons.
- Changing NOMT or the actions commitment.

## 8. Test gates for the eventual implementation

- A proof with a wrong claimed value at any bound position is rejected.
- A proof whose evaluation sumcheck was run over a polynomial other than the
  committed one is rejected. This is the attack the current code admits, and
  it needs an explicit adversarial test: build the sumcheck from `P'`, commit
  `P`, and expect rejection.
- Swapping a sentinel root after proving is rejected through the opening, not
  only through the transcript.
- The verifier derives the number of sumcheck rounds and the claim positions
  from config and `num_headers`, never from the proof (as
  `verify_with_evaluations` already does for `n`).

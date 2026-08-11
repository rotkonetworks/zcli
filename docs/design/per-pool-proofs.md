# Per-pool proofs

Status: design note. Written 2026-08-05, after NU6.3/Ironwood shipped and the
seams showed.

## Why

Zcash will keep adding shielded pools. Sapling, Orchard, now Ironwood; the next
one is a question of when. Today zidecar models shielded state as **one global
mutable structure with one root**, and every pool is folded into it. That
assumption is the direct cause of two user-visible failures we hit within hours
of Ironwood going live, and it will reproduce for each new pool.

### What broke, concretely

**1. Snapshot vs. live.** NOMT is a single tree. Proofs are generated against
`nomt.root()` *at request time*; the `at_height` a client sends is accepted and
ignored (`grpc_service/nomt.rs`). Meanwhile the ligerito header proof carries a
root snapshotted whenever the proof was last built. The indexer writes
continuously, so the two diverge constantly. Comparing them produced:

```
server integrity check failed: nullifier root mismatch
server integrity check failed: actions commitment mismatch:
  server tampered with block actions
```

Both were false alarms against a healthy server. We had to demote the check to
a log line, because the server cannot answer *"what was the root at height H"* —
so the comparison has no sound form. A check that cannot be sound is worse than
absent: it trains people to click past the one warning that should stop them.

**2. Head-of-line blocking.** One cursor walked the chain from the start
height. Ironwood exists only from block 3,428,143, so it sat behind ~1.6M blocks
of pre-activation history it had no interest in — roughly 20 hours to index the
~9k blocks that actually contained it. Ironwood is what wallets query *now*;
that ordering was exactly backwards. Giving it its own cursor made it current in
14 minutes.

That second fix is the shape of the answer, arrived at under pressure. This note
generalises it before the next pool forces the issue again.

## Ironwood is the only pool that matters now

NU6.3 has activated. Orchard is closed: no new orchard notes can be created,
and the only orchard operation left is migrating out of it. So this is not a
symmetric "support N pools equally" problem — it is **one live pool, plus
frozen history kept only long enough for users to leave it.**

That is a stronger simplification than it first looks. It means:

- the ~1.6M-block pre-activation backfill is **not on the critical path** for
  anything a user does today. It exists so holders of legacy orchard notes can
  see and migrate them. Running it at lowest priority — or paused, which is its
  current state — is correct, not a compromise.
- orchard proof coverage can be generated **once** and frozen. Its tree does not
  grow. Recomputing it continuously, which is what we do now, is pure waste.
- everything time-sensitive concerns exactly one pool. Ironwood gets the
  cursor, the freshness, the pinned roots, the priority.
- when orchard balances reach zero across the userbase, that whole index can be
  dropped rather than maintained forever.

The generalisation below still matters — there will be a pool after Ironwood,
and this same seam will reopen — but the near-term shape is simple: **one live
pool, one frozen archive.**

## The asymmetry worth exploiting

Pools are not alike, and treating them uniformly wastes the difference:

| pool | state | proof strategy |
|---|---|---|
| Sapling | closed | one proof, generated once, immutable forever |
| **Orchard** | **closed — NU6.3 has activated** | **one proof, generated once, frozen; droppable once balances hit zero** |
| **Ironwood** | **live** | **incremental, on demand, over a moving frontier** |
| pool N+1 | live on activation | same as Ironwood, no changes elsewhere |

Orchard's tree has stopped growing — that is not a future state, it is today.
Its history is finished, so its proof is a *build artifact*, not a running
computation: generate once, serve from cache, never recompute. Only Ironwood
needs incremental work. Today we pay live-pool costs for a dead pool's history
on every restart, which is why a rebuild took ~20 hours and had to be throttled
to stop it starving live traffic.

## Design

### 1. A pool is a first-class object

```rust
struct PoolIndex {
    pool: Pool,              // Sapling | Orchard | Ironwood | ...
    activation_height: u32,  // where this pool's history begins
    cursor: SyncCursor,      // independent progress marker
    nullifiers: NomtHandle,  // own tree
    commitments: NomtHandle, // own tree
    status: PoolStatus,      // Live | Closed { final_height }
}
```

Adding a pool becomes registering one of these. No changes to the sync loop,
the proof server, or the client's verification logic.

`SyncCursor` already exists (added for Ironwood) but is an enum of two known
variants — it should be keyed by pool instead.

### 2. Roots are pinned to heights

The load-bearing change. Every pool keeps `(height, root)` checkpoints, and
`GetNullifierProof`/`GetCommitmentProof` answer **against the requested
height**, not against whatever the tree happens to be now.

This is what makes the integrity check sound again. A client can then say "prove
this against the root at height H", compare it to the proof's root for H, and a
mismatch genuinely means the server contradicted itself — so it can fail closed
without false alarms.

NOMT is single-versioned, so this needs either periodic root checkpoints with
proofs served at checkpoint boundaries (cheap, coarse), or a versioned store
(expensive, exact). Checkpoints at a fixed interval are probably enough: clients
already round anchor heights for privacy.

### 3. Independent cursors, prioritised by relevance

Each pool syncs on its own cursor, concurrently. Priority follows what wallets
query: **Ironwood first, closed-pool backfill last or not at all.** Nobody is
waiting on 2019 Sapling blocks — or, now, on 2024 Orchard blocks — to send a
payment. The backfill being paused today costs nothing a user can perceive.

The shared NOMT commit lock already exists for this (added when the Ironwood
cursor landed alongside the backfill).

### 4. Per-pool horizons in the wire protocol

Already half-done: `GetNullifierProofsResponse` carries `synced_height` and
`ironwood_synced_height`. That pattern does not extend — it needs a map:

```proto
map<string, uint32> synced_heights = 5;  // pool name -> indexed height
```

The client already gates absence-proofs on the right pool's horizon; it just
needs to look the pool up rather than choose between two fields.

## What this fixes

- integrity checks become sound, so they can fail closed without false alarms
- a new pool costs one registration, not a sweep through the sync loop, proof
  server, client parser and UI
- closed-pool proofs are generated once instead of continuously
- live pools are never blocked behind history they do not need
- per-pool horizons stop being a special case bolted on for Ironwood

## What it does not fix

The ligerito header proof still has **no constraint system**: the roots it
"proves" are prover-chosen values absorbed into the prover's own transcript, so
nothing binds them to consensus, and block/action omission remains undetectable
from a single endpoint. Per-pool pinned roots are a *precondition* for fixing
that — you cannot bind a proof to a root the server cannot name — but they are
not the fix on their own. The concrete plan is in *Binding the header proof to
consensus* below.

Cross-endpoint verification (now wired, advisory) is the interim mitigation.

## Migration

Additive, and no client is forced to move:

1. per-pool cursors and `(height, root)` checkpoints server-side; existing
   endpoints keep answering as they do now
2. new height-pinned proof RPCs alongside the current ones
3. `synced_heights` map added; the two scalar fields stay until clients migrate
4. clients switch to pinned proofs and re-enable fail-closed integrity checks
5. retire the unpinned RPCs once no client uses them

Step 4 is the payoff: it restores the check we had to demote.

## Binding the header proof to consensus (ZIP-221 MMR + FlyClient)

This is the "design project of its own" from *What it does not fix*, made
concrete — and corrected after an adversarial review. The correction: **lead
with the ZIP-221 chain-history MMR** as the consensus anchor, and use the
ligerito header trace as the *data-availability layer* for verifying sampled
leaves, not as a second, weaker proof of chain structure.

### The consensus anchor: ZIP-221 already commits what we need

Every Zcash header commits to `hashBlockCommitments` — the ZIP-221 chain-history
MMR. Its `NodeData` (`zcash_history`) carries, per subtree: `subtree_total_work`,
`start/end_sapling_root`, `start/end_orchard_root`, **`start/end_ironwood_root`**,
and the difficulty targets. So the note-**commitment** roots for every pool we
care about (Ironwood included) *and* the cumulative work are **consensus-committed
data** — not values a server invents. That MMR, not our ligerito trace, is the
thing to bind to.

What is NOT in it, and never will be: a **nullifier-set accumulator**. Zcash
validates nullifiers against a set but commits no root for it (`header_chain.rs`
marks `nullifier_root` "reserved"; it comes from zidecar's own NOMT). So "is this
note unspent" can *never* be bound to consensus — it trusts the server to have
seen every nullifier. That is the hard floor (below), and it is exactly the check
voting leans on most.

### The pieces, in dependency order

**1. MMR membership — the actual consensus binding.** Prove the pinned
`(height, root)` is the note-commitment root an authenticated header at `height`
committed, as a leaf/peak inclusion in the `hashBlockCommitments` MMR. `NodeData`
already carries the pool roots, so this is a Merkle path against the MMR root of
an authenticated tip; `zcash_history` is the implementation. This is what stops
the roots being prover-chosen.

**2. FlyClient work sampling — makes each endpoint's chain verifiable and
quantifies its work.** The MMR gives structure + roots; FlyClient difficulty-
weighted sampling lets the client *natively* verify, on O(polylog) sampled
headers, `block_hash == BLAKE2b(header)` and PoW against `nBits`, and read a
**verifiable cumulative-work** figure. No PoW in-circuit. Ligerito's role is data
availability: `prove_with_evaluations` opens the sampled header leaves, bound to
the commitment, so the client has authentic bytes to check.

**3. Contiguity — mostly subsumed by (1).** MMR membership already places each
block in the chain, so a separate `prev_hash[N]==block_hash[N-1]` proof is
largely redundant. Sampled contiguity is also *not sound on its own*: a
contiguity break need not shed work, so difficulty sampling does not target it.
Keep contiguity only as a cheap sampled cross-check where the trace is used
without an MMR path; do **not** build the in-proof zerocheck if (1) is done.

### What the composition buys — and the sharp limits

- **(1)** makes the exported note-commitment roots *consensus-committed*.
- **(2)** makes each endpoint's chain *verifiably self-consistent* with a
  *verifiable cumulative-work* number.

Crucially, **(2) does NOT make a single endpoint's chain canonical.** FlyClient
proves "a chain with work W," not "the heaviest chain." A lone server can serve a
valid, self-consistent, *lower-work* fork with its own MMR, undetectable from
that endpoint alone. **Canonicity = take the max verifiable work across
independent endpoints (or a trusted reference tip).** So cross-endpoint
verification is not retired — it is *upgraded* from comparing opaque tips to
comparing *proven* work. The honest badge: **note-commitment state
consensus-verifiable; canonical tip requires a work reference (cross-endpoint);
nullifier completeness is trust-the-server.**

Hard limits, plainly:

- **Nullifier completeness ("is it unspent")**: never consensus-bindable — Zcash
  has no nullifier accumulator. NOMT non-membership binds a query to a *given*
  root (a server cannot forge non-membership against a bound root), but that the
  root reflects *all* nullifiers still trusts the server's sync. Permanent floor,
  and the check voting depends on most.
- **Canonicity is a work assumption**, not SNARK-soundness: honest-difficulty
  majority over the sampled window + an honest reference for the true tip work.
- **Fiat-Shamir grinding**: the sampler seed must fold in a *non-grindable*
  anchor — the authenticated tip's PoW / block hash — not just the prover-chosen
  commitment, or the prover grinds its trace to bias samples toward honest
  segments. Budget grinding bits into the security parameter.
- **Regtest tests none of this**: at trivial difficulty the FlyClient PoW
  argument is vacuous. Our v09 demos proved the plumbing, not the trust model.

### Work plan (dependency order)

0. **Prerequisite — an ironwood-aware, vector-validated ZIP-221 MMR crate.** The
   whole binding's soundness rests on hashing MMR nodes byte-for-byte the way
   consensus does. The ironwood-aware `zcash_history` (V3 `NodeData` with
   `start/end_ironwood_root`) is currently **fork-only** — not released, not in
   master's dep graph, and master retired the forks. So before any verifier:
   get a clean, *owned or upstreamed* ironwood ZIP-221 MMR crate (not a
   re-vendored fork), and **validate it against real mainnet `hashChainHistoryRoot`
   test vectors**. Also confirm zebrad exposes the chain-history MMR nodes needed
   to *build* inclusion proofs (history RPCs / `z_getsubtreesbyindex`), separate
   from the tree-state `commitments` it already returns. Do not write the
   verifier against a fork-only, unvalidated MMR.
1. **Precondition** (Design §2): per-pool `(height, root)` checkpoints so roots
   are nameable. Already migration step 1.
2. **ZIP-221 MMR binding** (the real fix): prove `(height, root)` membership in
   `hashBlockCommitments` via the step-0 MMR crate. Consensus-binds the note-
   commitment roots.
3. **FlyClient work sampling + verifier**: FS difficulty-weighted sampling
   (seeded with the authenticated tip PoW, not just the commitment); open sampled
   leaves via `prove_with_evaluations`; verify BLAKE2b/PoW natively; read
   verifiable cumulative work. No new proof system.
4. **Cross-endpoint = max verifiable work**: rewire the existing advisory check
   to compare the proven work from (3) and take the heaviest. The canonicity
   anchor.
5. **In-proof contiguity zerocheck**: skip unless (2) is not done; sampled
   contiguity is not sound alone.
6. **Badge + disclosure**: "partial" today → "note-commitment consensus-verified,
   canonical-via-work-reference, nullifier-completeness trusted" as (2)-(4) land.

Steps 2-4 are independent of the voting work and land incrementally.

### Protocol sketch for step 2 (pinned FlyClient proof)

New RPC alongside `GetHeaderProof`:

    GetPinnedHeaderProof(PinnedProofRequest{ height }) -> PinnedHeaderProof

`PinnedHeaderProof` carries:

- the pinned `(height, root)` being bound
- the ligerito commitment to the header-chain trace, and the tip's
  `cumulative_difficulty` (total work)
- a set of **sampled openings**: for each sampled header position `N`, the full
  32-field rows for `N` *and* `N-1` (the neighbor is needed for the contiguity
  check), proven via `prove_with_evaluations` (the existing eval-opening path)
- later (mechanism 3): the ZIP-221 `hashBlockCommitments` MMR membership for the
  pinned root

**Client verifier:**

1. Verify the ligerito opening proof — the returned rows are the committed ones
   (this is what `eval_proof.rs` already binds, via the RS/Merkle opening).
2. **Re-derive the sample positions locally** and check the server's samples
   match — see the soundness note below.
3. Per sampled `N`: check natively `block_hash[N] == BLAKE2b(header fields[N])`,
   PoW(`block_hash[N]`, `nBits[N]`), and contiguity `prev_hash[N] ==
   block_hash[N-1]`.
4. Check the pinned `root` is an MMR-membership leaf in the authenticated tip's
   `hashBlockCommitments` (the primary binding), and that the tip's verifiable
   cumulative work is the max across independent endpoints (canonicity — a single
   endpoint's self-consistent chain is not enough).

**Soundness notes — the two things not to get wrong.**
(a) The sampled positions MUST be derived by the *verifier* via Fiat-Shamir, not
chosen by the server; a server that picks its own samples cherry-picks the honest
headers of a mostly-forged chain. (b) The FS seed must fold in a *non-grindable*
anchor — the authenticated tip's PoW / block hash — not just the prover-chosen
`(commitment, tip work)`, or the prover grinds its trace to bias the samples.
Both are classic FlyClient requirements and the soundness-critical lines.

**What exists vs. what step 2 adds.** Exists: `prove_with_evaluations` (open at
chosen positions, bound to the commitment); the trace fields (`block_hash`,
`prev_hash`, `nBits`, `cumulative_difficulty`). Adds: the FS difficulty-weighted
sampler (shared prover/verifier), the neighbor-row opening for contiguity, and
the client-side BLAKE2b/PoW/equality checks. No new proof system.

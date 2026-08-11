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

## Binding the header proof to consensus (contiguity + ZIP-221 / FlyClient)

This is the "design project of its own" from *What it does not fix*, made
concrete. The header trace (`bin/zidecar/src/header_chain.rs`) already commits
to everything the binding needs — it is only missing the constraints and the
client-side checks that turn committed data into a *bound* claim. So the fix is
additive to the existing trace, not a rewrite.

### What the trace already carries (and why that matters)

`HeaderChainTrace` commits, per header (32 binary-field rows):

- `block_hash` (fields 1-8), `prev_hash` (fields 9-16) — the linkage
- `nBits` (17), `cumulative_difficulty` (18) — the work
- `sapling_root` / `orchard_root` / `nullifier_root` at epoch boundaries (20-29)

Ligerito commits this polynomial and can *open it at any position*. Today it
only proves an opening is consistent with the commitment — it does not enforce
any relation *between* committed fields, which is exactly why the roots are
prover-chosen. Because the data is already committed and openable, the fix does
not require rebuilding the trace: only (a) one in-proof relation and (b)
client-side checks on openings. Ligerito being a **polynomial commitment** is
the enabling property here, not a limitation — position openings are precisely
what FlyClient sampling needs.

### Three mechanisms — none needs a general SNARK or Equihash-in-circuit

**1. Contiguity.** Each header's `prev_hash` must equal the previous header's
`block_hash`: `prev_hash[N] (9-16) == block_hash[N-1] (1-8)`. There are two ways
to check it, and the cheap one is the right first step:

- *Sampled (no new crypto, do this first).* Ligerito today is a **pure PCS** —
  its sumcheck (`eval_proof.rs`) only proves openings `P(z)=v`, there is no
  relation/zerocheck harness. But the whole binding is FlyClient-probabilistic
  (mechanism 2) anyway, so fold contiguity into the *same sampled openings*:
  at each sampled position `N`, open `prev_hash[N]` and `block_hash[N-1]` and
  check equality natively. Reuses the existing opening machinery; probabilistic,
  which matches the model. A spliced/reordered chain fails the sample.
- *In-proof zerocheck (optional hardening, later).* For **deterministic**
  contiguity across all positions, add a zerocheck to ligerito: prove the
  virtual polynomial `prev_hash(x) - block_hash(shift(x))` is zero over the
  header hypercube (a standard eq-combined zero-check sumcheck). This is new
  crypto in the library, not a config flag. Ligerito being over binary fields
  makes any bit-level relation added here (e.g. later binding `block_hash` to
  BLAKE2b of the header fields) far friendlier than in a prime-field SNARK — but
  it is not needed for the probabilistic guarantee.

**2. Client-side FlyClient sampling — real headers + canonical (native).**
Use ligerito's position openings: the client asks the server to open the trace
at chosen rows. Do FlyClient's difficulty-weighted sampling over
`cumulative_difficulty` (field 18): sample O(polylog) header rows weighted by
work, open them, and *natively* verify for each sample that
`block_hash == BLAKE2b(header fields)` and that `block_hash` meets the `nBits`
PoW target (Equihash verified on the handful of sampled headers, on the client,
cheaply). This is the standard FlyClient argument — under an honest-difficulty
majority a forged or low-work chain is caught with overwhelming probability —
and it needs *no* PoW in-circuit. The trace comment already anticipated "full
hash data for client-side PoW verification"; this wires that data into an actual
sampling verifier instead of leaving it unused.

**3. ZIP-221 root binding — ties the pinned roots to what consensus committed.**
Zcash headers commit to `hashBlockCommitments` — the ZIP-221 chain-history MMR
(alongside the sapling/orchard roots). Bind the epoch-boundary roots (20-29) and
the per-pool `(height, root)` checkpoints (Design §2) to that MMR: the root the
wallet syncs against is proven to be the value an authenticated header at that
height committed, as an MMR-leaf membership against `hashBlockCommitments`. The
`zcash_history` crate is the MMR. This is what actually *binds them to
consensus* — the roots stop being prover-chosen and become leaves of a structure
miners committed under consensus rules.

### Why the pieces compose

- (1) makes the committed chain a real chain (contiguous).
- (2) makes it a real, probabilistically-canonical chain (headers hash
  correctly and carry PoW) — without proving PoW in-circuit.
- (3) makes the exported roots the ones consensus committed at those heights.
- The precondition is Design §2: the server must be able to *name* a
  `(height, root)` before any proof can bind to it.

Together the badge moves from **advisory** to **sound + consensus-bound
(probabilistically canonical)**.

### What it still does not buy (keep the badge honest)

- **Canonicity is probabilistic**, not SNARK-sound: it rests on FlyClient
  sampling + an honest-difficulty-majority assumption over the sampled range. A
  standard, accepted light-client model — not a proof of the single heaviest
  chain.
- **Omission / data availability**: the proof shows the roots are
  consensus-committed and the chain canonical; it does *not* show the server
  handed you *every* leaf under a root. NOMT non-membership + the pinned root
  bound this for the *specific* queries you make (a server cannot forge a
  non-membership against a bound root), but blanket "you saw all notes" still
  needs consensus-layer DA commitments. Unchanged from *What it does not fix*.

### Work plan (each step strictly tightens the badge)

1. **Precondition** (Design §2): per-pool `(height, root)` checkpoints so roots
   are nameable. Already migration step 1.
2. **FlyClient opening RPC + client verifier** (the load-bearing step, no new
   crypto): a height-pinned RPC returning difficulty-weighted sampled openings
   of the trace; a client verifier that, per sampled position, checks natively
   (a) `block_hash == BLAKE2b(header fields)`, (b) PoW meets `nBits`, and
   (c) **contiguity** `prev_hash[N] == block_hash[N-1]`. All three ride the
   existing ligerito position openings — (c) is the sampled contiguity above.
3. **In-proof contiguity zerocheck** (optional hardening): add the
   `prev_hash(x) - block_hash(shift(x))` zerocheck to ligerito for deterministic
   (all-positions) contiguity. New library crypto; do only if the probabilistic
   guarantee from step 2 is judged insufficient.
4. **ZIP-221 MMR binding**: prove `(height, root)` membership in the header's
   `hashBlockCommitments` MMR via `zcash_history`; bind the epoch roots (20-29)
   to the sampled headers' committed roots.
5. **Badge + disclosure**: "partial" today; "sound, canonical (probabilistic),
   DA-residual" as (2)-(4) land.

Steps 2-4 are independent of the voting work and land incrementally.

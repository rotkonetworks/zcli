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
not the fix. That remains a design project of its own.

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

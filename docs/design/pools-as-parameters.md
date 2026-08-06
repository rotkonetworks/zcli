# Pools are a parameter, not a branch

Status: design note. Written 2026-08-06, after NU6.3 shipped and the same
mistake surfaced four separate times in one day.

Companion to [`per-pool-proofs.md`](./per-pool-proofs.md), which made this
argument about sync horizons and proofs. This makes it about everything else:
the wire format, the scan API, and the client.

## The tell

Post-NU6.3 the wire looks like this:

```proto
repeated CompactAction actions = 3;           // orchard
bytes                  actions_root = 4;      // covers orchard only
repeated CompactAction ironwood_actions = 5;  // "Not covered by actions_root"
```

and the client mirrors it:

```ts
actions: CompactAction[];           // required, unqualified
ironwoodActions?: CompactAction[];  // optional, named
```

Orchard is mandatory and nameless; ironwood is optional and qualified. That
encodes "orchard is what a block contains, ironwood is an extra" — which was
true before NU6.3 and is now precisely inverted. Ironwood is the only pool that
can receive; orchard is frozen history nobody can add to.

The names are a symptom. The defect is that **the pool is a branch in every
consumer instead of an argument to one uniform operation.**

## What it cost, concretely

Four bugs in a single day, all the same shape:

1. **The scanner was ironwood-blind.** It constructed `OrchardDomain` for
   everything, with a comment asserting one domain decrypts both pools. True
   of the fork; false upstream, where the domain is split by note version and
   enforced. Silent — `try_note_decryption` returns `None`, not an error. It
   survived 288 unit tests, clean clippy, a verified wasm build and 4/4
   consensus fixtures, and was caught only by a real validator mining a
   transaction the wallet then could not see.
2. **The escrow's ironwood arm was inert.** `ironwood_actions_of` returned an
   empty slice behind a note claiming zecli did not expose the field. It did.
   An escrow that cannot see a deposit does not show a wrong balance; it fails
   to credit someone's money. Every ironwood test still passed, because they
   called the decrypt helper directly and never exercised the wiring.
3. **Two proto fields were swapped** in a hand-rolled decoder
   (`blocks_until_ready` / `last_epoch_proof_height`), so a healthy server read
   as permanently catching up. Second occurrence of that exact class; the first
   broke every ironwood send.
4. **Trial decryption ran twice per action.** The scan entry points already
   knew the pool and used it only as an output label, so the both-domain
   fallback — correct for an unknown action — ran on the hot path for every
   action in a 528k-block sync.

None of these were hard bugs. Each was a place where the pool was known and the
code either forgot to use it, used the wrong one, or used both.

## The shape, in service terms

Following *Your Server as a Function*: express the system boundary as one
asynchronous function, put cross-cutting concerns in filters, and compose.

**One service, pool as data:**

```rust
/// Scan any pool's compact actions. The pool is an argument, not a suffix.
type Scan = fn(PoolActions) -> Future<Vec<FoundNote>>;

struct PoolActions {
    pool: Pool,                    // Orchard | Ironwood | ...
    actions: Vec<CompactAction>,
}
```

Today this is two exported functions, `scan_actions_parallel` and
`scan_actions_ironwood_parallel`, with byte-identical bodies differing by a
string literal. That copy-paste is what a missing parameter looks like.

The note-encryption domain follows from the pool rather than being chosen
alongside it — `DomainChoice` (added for the double-decrypt fix) is the right
idea derived from the wrong source: it is computed from a `&str` label instead
of from a typed `Pool`.

**Filters, not conditionals.** cmx verification, change classification and
recipient attribution are identical across pools and currently sit as inline
branches inside the scan. Each is a filter wrapping the base service, stackable
and independently testable:

```
verify_cmx  >>>  classify_change  >>>  attribute_recipient  >>>  scan
```

**Futures for the pipeline.** The sync loop hand-rolls `await fetch; scan;
write;` in a `while`. It carries a comment promising "start fetching this batch
while the previous IDB write completes" — a prefetch that was never
implemented. Someone recognised the correct shape and had nowhere to express
it. With composition it is the ordinary thing: fetch(n+1) runs concurrently
with scan(n), and pipeline depth is a number, not a rewrite.

## Wire

The two-parallel-fields pattern does not extend, exactly as `per-pool-proofs.md`
concluded for `synced_heights`:

```proto
// one entry per pool present in the block
message PoolActions {
    string pool = 1;
    repeated CompactAction actions = 2;
    bytes actions_root = 3;   // per-pool, so no pool is privileged
}
repeated PoolActions pools = 6;
```

Note `actions_root` becomes per-pool. Today it covers orchard only, which is
why the ironwood field carries "Not covered by actions_root" — the integrity
story is orchard-scoped because the schema made orchard the default.

Field numbers 3/4/5 stay reserved and populated during migration; a client
reading `pools` and a client reading `actions` can coexist until the old fields
retire. Renaming is safe on the wire (numbers carry meaning, names do not) and
fails loudly at compile time in consumers, which is the good failure mode —
unlike the two silent field-number bugs above.

## What this buys

- adding pool N+1 is registering data, not editing the sync loop, the proto,
  the client, the worker and the UI
- "did we handle both pools here?" stops being a question a reviewer has to ask
  at every call site, because there is one call site
- the domain is derived from the pool, so it cannot disagree with it
- per-pool `actions_root` lets the integrity check cover the live pool instead
  of only the frozen one

## What it does not fix

The ligerito header proof still has no constraint system: the roots it "proves"
are prover-chosen values absorbed into the prover's own transcript. Per-pool
roots are a precondition for fixing that, not the fix.

## Migration

Additive, and no client is forced to move:

1. server emits `pools` alongside `actions`/`ironwood_actions`
2. `Pool` becomes a type in zcash-wasm; `DomainChoice` derives from it rather
   than from a string
3. the two scan exports collapse into one taking `PoolActions`
4. clients (zafu worker, zeratul escrow) switch to iterating `pools`
5. the scalar fields retire once no client reads them

Step 3 is where the four bugs above stop being possible to write.

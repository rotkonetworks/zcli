# Validator FROST custody with epoch-based resharing

Status: **superseded 2026-09-13** by
`penumbra/docs/design/validator-custody-bridge.md`. The target turned out to
be a pBTC/pZEC bridge held by the active validator set (6-of-11, chain-driven
reshare), not an operator treasury. The reshare protocol, hard rules, and
the frostito findings below still apply; sections 1, 4, and 8.1 do not.

Original status: draft for discussion. Written 2026-09-09. Target: a treasury held
by a rotating set of active Penumbra validators, first on a Zcash testnet
(3-of-5, small ZEC), then on bitcoin (7-of-11).

Scope of this document: the custody protocol, the resharing scheme, what
breaks in the current `frostito` reshare when used for this purpose, and the
concrete build plan on top of code we already have (`zcli`/`frost-spend`,
`frostito`, `narsild`, `frostsnap_core`).

---

## 1. Goal and non-goals

**Goal.** One long-lived group key (one bitcoin address, one Orchard FVK)
whose signing shares are held by whichever validators are currently active.
When a validator drops out, the remaining set can re-deal shares to a new set
without moving funds and without anyone learning the secret.

**Non-goals for v1.**

- Not a bridge or peg. No on-chain component decides when the key signs.
  Authorization is an off-chain policy among validator operators.
- Not stake-weighted. One validator, one share, one index. The stake-weighted
  OSST layer in `frostito`/`narsild` is out of scope.
- Not interoperable with other FROST wallets. Shares are only usable by our
  daemon until the draft `bip-frost-signing`/`bip-frost-dkg` settle.

**What resharing does and does not give.** Resharing keeps the group key and
therefore the address. It does *not* cryptographically revoke an evicted
member's old share. Shares from different epochs lie on different polynomials
and cannot be combined, so the security statement is per epoch: "fewer than
`t` members of any single past epoch collude". Because evicted members
accumulate over time, the treasury still needs the blunt tool: a fresh DKG and
a sweep to a new address on a slow schedule (quarterly) and immediately after
any suspected share compromise.

---

## 2. Parameters

| | Zcash testnet | Bitcoin |
|---|---|---|
| Curve / ciphersuite | Pallas, FROST(Pallas, BLAKE2b-512) via ZF `reddsa` | secp256k1, BIP340 via `schnorr_fun` (frostsnap) |
| n / t | 5 / 3 | 11 / 7 |
| Signing library | `frost-spend` (ZF `frost-core` 2.2) | `frostsnap_core` (`schnorr_fun` 0.13) |
| Reshare math | `frostito::reshare` (feature `pallas`) or ported | ported to `secp256kfun` types |
| Transport | ZF `frostd` relay + Noise_K sealing (exists in `zcli`) | same relay, or WireGuard mesh |

**Why 7-of-11 and not 8-of-11.** The 2/3+1 rule is a BFT consensus number:
it prevents two conflicting quorums. A single signing key has no fork problem,
so the only two questions are how many colluders can steal (7 vs 8) and how
many can be offline before funds freeze (4 vs 3). Among 11 independent
operators the extra liveness margin is worth more than the one extra colluder.

**The reshare slack problem.** A reshare needs exactly `t_old` dealers. With
7-of-11 and 4 validators offline, that is 7 dealers and zero tolerance for one
of them faulting mid-reshare. Section 5 handles this with an explicit abort
and retry, and section 4 delays eviction so we are rarely at the floor.

---

## 3. Actors and state

Every custodian runs one **signer daemon**. It holds:

- `epoch: u64` and the epoch **manifest** (section 5.2) it was derived from.
- Its secret share for the current epoch, and the previous epoch's share until
  the current epoch has been proven (section 5.5).
- The epoch's public key package: group key `Y`, the point polynomial `F_e`,
  and every member's verifying share `Y_j = F_e(j)`.
- Owned nonce state, written to disk before any partial signature is released
  (frostsnap's slot model, section 8).
- A long-term signer identity key (ed25519) used to authenticate to the relay
  and to countersign manifests.

Any custodian can act as **coordinator** for one session. The coordinator can
stall a session but cannot forge, so it needs no extra trust.

A **roster** is the list of validators who have opted in: validator identity
key, signer identity key, relay pubkey, and a small integer index `1..=n_max`
assigned once and never reused. Membership in an epoch is a subset of the
roster.

---

## 4. Membership function

The set for custody epoch `E` is computed deterministically from Penumbra
chain state at a fixed boundary height `H_E`, so every daemon derives the same
answer without talking to each other.

```
candidates(H) = roster members whose validator is in state Active at H
                and whose uptime window at H has missed_blocks < missed_blocks_maximum / 2
```

Penumbra's stake component already tracks per-validator uptime
(`signed_blocks_window_len`, `missed_blocks_maximum`) and moves validators
between `Active`, `Inactive`, `Jailed`, `Tombstoned`. Use that as the liveness
signal. Do not use `frostito::liveness`'s Ligerito block proofs; they solve a
different problem (proving a custodian runs a full node) and are not wired into
anything today.

**Hysteresis.** A member is evicted only after failing `candidates()` at two
consecutive boundaries, or immediately on `Jailed`/`Tombstoned`. A returning
validator is admitted only after passing at two consecutive boundaries. This
keeps us away from the `t_old` dealer floor during ordinary maintenance
windows.

**Cadence.** `E` is a monotonic counter: boundaries trigger reshares, they do
not number them (a retry at the same boundary is `E + 1`). A custody epoch is
`K` chain epochs (start with one week). A
reshare runs at a boundary only if the member set changed, or if `P` custody
epochs have passed since the last reshare (proactive rotation; start with
`P = 4`). Do not reshare every chain epoch.

**Set size.** Keep `n` fixed at the roster size where possible (11). If the
candidate set is smaller than `n`, reshare into the smaller set with the same
`t`; if it is smaller than `t + 1`, do not reshare, alert, and hold.

**Signer daemon liveness is separate from validator liveness.** A validator
can be Active on chain while its signer daemon is down. The daemon publishes a
signed heartbeat to the relay every chain epoch; the membership function also
requires a heartbeat within the last two chain epochs. Both signals are needed.

---

## 5. Reshare protocol

The math is standard proactive secret sharing (Desmedt–Jajodia), which is what
`frostito::reshare` implements: each old member `i` in a dealer set `S`
(`|S| = t_old`) re-shares its share `s_i` with a fresh random polynomial
`f_i` of degree `t_new − 1`, publishes Feldman commitments `C_i`, sends
`f_i(j)` to each new member `j`, and each `j` computes

```
s'_j = Σ_{i∈S} λ_i^S · f_i(j)         (new secret share)
F'   = Σ_{i∈S} λ_i^S · C_i            (new point polynomial, coefficient-wise)
Y_j  = F'(j)                          (new verifying shares)
Y    = F'(0)  == old Y                (invariant check)
```

`λ_i^S` are the Lagrange coefficients of `S` at zero. Everything below is
about **agreement and plumbing**, which is where the current code falls short.

### 5.1 Phases, with deadlines relative to the boundary height `H`

| Phase | Who | Deadline | Output |
|---|---|---|---|
| 0. Announce | every daemon | `H` | derives `(E, old set, new set, t)` locally |
| 1. Commit | every reachable old member | `H + D1` | `C_i` + signature, posted to the epoch room on the relay |
| 2. Manifest | coordinator, then every dealer in `S` | `H + D2` | signed manifest fixing `S` |
| 3. Distribute | each dealer in `S` | `H + D3` | sealed sub-share to each new member |
| 4. Aggregate | each new member | `H + D3` | `s'_j`, `F'`, verifies `Y` invariant and `g^{s'_j} == F'(j)` |
| 5. Canary | **every** new member | `H + D4` | signature under epoch `E` on a fixed test message, every member contributing a partial verified against `Y_j = F'(j)` |
| 6. Activate | every daemon | on canary | epoch `E` live; epoch `E−1` marked superseded |
| 7. Retire | every old member | `H + D5` | epoch `E−1` share and nonces deleted |

Suggested `D1..D5` for weekly epochs: 6h, 8h, 24h, 36h, 72h.

### 5.2 The manifest

The manifest is the single object that makes the reshare consistent:

```
Manifest {
  epoch:        E,
  group_key:    Y,
  old_members:  [(index, signer_pubkey)],     // epoch E−1 set
  dealers:      S,                            // exactly t_old indices, sorted
  new_members:  [(index, signer_pubkey)],     // epoch E set
  threshold:    t_new,
  commitments:  H(C_i for i in S, in order),
  boundary:     H, chain_id, block_hash(H),
}
```

Rules:

- `S` is chosen deterministically: the `t_old` lowest indices among old
  members whose commitment arrived by `D1` and verified. The coordinator only
  assembles; it has no choice to make.
- Every dealer in `S` countersigns the manifest with its signer key. A dealer
  signs **at most one manifest per epoch number**, and durably records the
  signed manifest hash before releasing its signature (same storage rule as
  nonce state, section 8.2: never snapshot-restored).
- That bound is weaker than it looks. Two valid manifests for one epoch need
  `2·t_old` dealer signatures from at most `n_old` dealers, so a coordinator
  can equivocate with `2t − n` double-signing dealers: 3 of 11 on bitcoin,
  and only **1** of 5 on the testnet. Equivocation costs liveness, not safety
  (no single polynomial ends up with `t` members who disagree about it, and
  the all-members canary below catches the split). To make it detection at
  the cost of one aborted epoch, aggregators exchange manifest hashes before
  phase 4 and refuse to aggregate on disagreement.
- A new member's aggregator accepts a sub-share only from a dealer named in a
  manifest carrying `t_old` valid dealer signatures, and only if the dealer's
  commitment hashes into `commitments`. Sub-shares from anyone else are
  dropped, even if they verify.
- The manifest, commitments, and dealer signatures are retained forever by
  every daemon. They are the audit trail for "who held what, when".

This is the same agreement the on-chain `warpito` path gets by picking the
first `t` dealers by index, but done off-chain and provable after the fact.

### 5.3 Sub-share confidentiality

`frostito::reshare` states that encryption is "not handled here". It is not
optional: each dealer polynomial has degree `t_new − 1` and is evaluated at
`n_new` points, so an observer of unencrypted sub-shares recovers every
dealer's share whenever `n_new > t_new`, and `t_old` of those is the key. This
is exactly the bug already recorded in `dkg-round2-confidentiality.md`.

Reuse the fix that already exists in `frost-spend::sealed` (per-recipient
X25519 sealed box, Noise prologue bound to the transcript). Bind the prologue
to the manifest hash so a sub-share sealed for epoch `E` cannot be replayed
into epoch `E+1`.

### 5.4 Abort and retry

- A dealer in `S` that signed the manifest but delivered no valid sub-share
  to some new member by `D3` aborts the epoch. The evidence is the signed
  manifest plus the missing or invalid sub-share. That dealer is treated as
  failed for the membership function (counts as one missed boundary).
- Retry once with a new manifest and a new `S` excluding the failed dealer.
  Because dealers sign at most one manifest per epoch number, the retry uses
  `E + 1` with the same intended member set. Epoch numbers are cheap;
  consistency is not.
- If fewer than `t_old` old members can commit, no reshare happens. The
  previous epoch stays live. Alert.

### 5.5 Two hard rules

1. **Never delete an epoch-`E−1` share until epoch `E` has produced a valid
   canary signature with every new member's partial verified.** The group-key
   invariant check in `finalize` passes for each member individually even
   when members landed on different polynomials. A `t`-of-`n` signature only
   proves `t` members agree; with 7-of-11, seven on one polynomial and four
   on another would pass and silently leave a 7-of-7 group. So the canary
   requires a partial signature from **every** new member, each verified by
   the coordinator against `Y_j = F'(j)` computed from the manifest's `S`. A
   member on the wrong polynomial fails that check and is identified by
   index. A botched reshare with old shares already gone is frozen funds.
2. **Every signing request names the epoch.** Signers refuse to sign with a
   share whose epoch is superseded, and refuse to sign for an epoch they have
   not activated. In frostsnap terms the epoch is the `AccessStructureId`.
   Nonce streams are opened fresh per epoch.

---

## 6. What breaks in the current `frostito` reshare for this purpose

Reviewed: `frostito/src/reshare.rs` at rev `14e38da` (identical to the copy in
`zk.poker/crates/frostito`), `warpito/src/accumulate.rs` (`accumulate_reshare`),
`narsild/src/dkg.rs` (branch `zcash-custody`), `jam-netadapter/frost-signer`
(`society.rs`, `mode.rs`) and `jam-netadapter/jam-service` (`zcash_*.rs`).

**F1. Aggregation is over whichever dealers reached this player.** *Fixed
2026-09-13 in zk.poker `frostito`: `Aggregator::new(player, &dealer_set)` and
`dkg::Aggregator` now take the agreed set, reject dealers outside it, and
refuse to finalize until all of it has arrived; `ReshareState::dealer_set()`
gives the deterministic choice.*
`Aggregator::aggregate` computes Lagrange coefficients over
`self.subshares` as collected. Two players who received different dealer
subsets end up on different degree-`t_new − 1` polynomials that share only the
constant term. `finalize` compares `Σ λ_i C_{i,0}` to `Y` per player, so it
passes for both. Signing then fails to aggregate and nothing identifies who is
on the wrong polynomial. The manifest (5.2) fixes this by making `S` an input,
not an observation. The `Aggregator` API needs a `dealer_set: &[u32]`
argument and must reject sub-shares outside it. `narsild`'s DKG has the same
shape: `close_round1` sets `actual_dealers` from what *this* node received.

**F2. No verifying shares.** *Fixed 2026-09-13: `finalize` returns the
reshared `SharePolynomial` with `verifying_share(j)` and `verify_share`.* Nothing computes `Y_j = F'(j)` or `F'` itself.
FROST needs the verifying shares to check partial signatures and to blame a
faulty signer. After the first reshare the group would have no identifiable
abort. `DealerCommitment::evaluate_at` has the primitive; the aggregator needs
to sum it over `S` with the same `λ_i^S`.

**F3. Sub-shares are plaintext by design.** See 5.3.

**F4. Epoch advances on commitments alone (`warpito`).** `accumulate_reshare`
flips `cust.epoch` once `t` commitments verify. No evidence that any new
member received or verified a sub-share, and no canary signature. The chain
can commit to an epoch whose share set nobody holds. For our off-chain design
this becomes rule 5.5(1).

**F5. Fixed-`n` on chain, variable-`n` in the crate.** `accumulate_reshare`
never updates `num_custodians`; `ReshareState` carries `new_player_count`;
`vault.md` takes `old_provider_count`/`new_provider_count`. Three different
answers. This document fixes `n` per epoch from the membership function and
records it in the manifest.

**F6. Threshold model is stated two ways.** `reshare.rs` assumes honest
majority among dealers; `warpito` enforces a ⅔ floor. For a single key the
relevant statement is section 1's per-epoch collusion bound; drop the ⅔ floor.

**F7. `liveness` module is unused and the wrong tool here.** It is not
referenced by `warpito`, and Penumbra's uptime tracking gives the signal we
actually want.

**F8. secp256k1 backend is not usable for signing.** `curve.rs` compresses
secp points to 32 bytes and decompresses assuming even `y`. That is lossy for
arbitrary points (commitment coefficients are not even-`y`). Use `frostito`
for Pallas reshare math only, and reimplement the reshare over `secp256kfun`
for bitcoin (section 8). It is roughly a hundred lines given
`SharedKey::point_polynomial`, `SecretShare`, and `homomorphic_poly_add`.

**F9. Unaudited, and the nested-FROST construction had a real binding gap.**
`SECURITY-nested-frost.md` records the v1 ROS issue. We do not use the nested
construction, but the crate as a whole has not had outside review. The plain
reshare math is textbook and small enough to review by hand; the manifest
protocol around it is the part that needs eyes.

**F10. Four divergent layers, none finished end to end.** The reshare
crypto lives in `frostito` (complete, tested). Three consumers disagree on the
coordination: `warpito` advances on a commitment quorum; `jam-netadapter`'s
`jam-service` runs the ceremony off-chain and only attests completion on
chain; `jam-netadapter/frost-signer` "society mode" has the right four-phase
state machine (commitments, distribution with share acks and complaints,
complete) but every trigger is a stub: `should_initiate_reshare` returns
`false` unconditionally, the submit calls are no-ops, and the example config
sets `reshare_interval = 0`. No consumer calls `frostito::reshare` outside the
crate's own tests. `warpito` also pins the pre-rename `zeratul/crates/osst`
copy, so a fix in `frostito` does not reach it. This document supersedes all
three coordination designs for the treasury use case; the jam-service shape
(off-chain ceremony, signed completion record) is the closest to section 5.

None of F1–F10 is a math error. They are missing agreement (F1, F4, F5),
missing plumbing (F2, F3), and mismatched assumptions (F6, F7, F8).

---

## 7. The audited alternative: ZF `frost-core` refresh + repair

`frost-core` 2.2 (pinned by `frost-spend`) ships two primitives:

- `keys::refresh::refresh_dkg_*`: every **remaining** member deals a
  zero-secret polynomial; shares are refreshed in place. `max_signers` may
  shrink (drop members), `min_signers` may not change. All remaining members
  must participate.
- `keys::repairable::repair_share_part1/2/3`: `t` helpers reconstruct the
  share for one identifier. Mathematically this works for any identifier on
  the polynomial, so it can add a member as well as recover one.

Drop-then-add is therefore possible with library code: refresh to shrink,
then repair to fill vacancies. The cost is liveness: refresh requires *every*
remaining member online in one ceremony, which is exactly the property the
`t_old`-dealer reshare avoids. With 11 operators across time zones that is a
real difference.

Recommendation: use the `t_old`-dealer reshare with the manifest protocol for
the epoch mechanism, and use `repairable` as the tool for the single common
case "one member lost its disk and needs its share back inside an epoch"
without triggering a reshare.

Two facts to confirm before relying on `repairable` for adding members:
whether `repair_share_part3` accepts an identifier that has no entry in the
existing `PublicKeyPackage`, and whether `frost-spend` can be moved from
`Identifier::derive(ed25519_vk)` to small integer identifiers. Lagrange math
in `frostito` assumes `u32` indices; ZF identifiers are field elements. The
daemon should assign integer identifiers at DKG time and keep the ed25519 key
as the authentication identity only.

---

## 8. Build plan

### 8.1 Testnet: 3-of-5 on Zcash regtest, then testnet, with ZEC

Reuse from `zcli`:

- `frost-spend::orchestrate::dkg_part1/2/3` with the v2 sealed round 2.
- `frostd` relay (`zidecar --frostd-listen`, or `deploy/frostd-relay.md`).
- Rendezvous room codes for the first ceremony only. Later epochs use a
  deterministic room id `H(chain_id ‖ group_key ‖ epoch)`.
- The 5-validator interleaved DKG harness in `bin/zcli/tests/bridge_e2e.rs`
  and the scripted ceremony driver in `bin/pokerbot/src/dkg.rs` as templates.
- `deploy/regtest/*` for an ephemeral zebrad chain.

New, in a `signerd` binary (or grow `narsild`):

1. **Persisted key packages.** `zcli` prints `key_package` hex and forgets
   it. The daemon stores per-epoch `KeyPackage`, `PublicKeyPackage`, manifest.
2. **Signing over the relay.** `zcli` only does DKG over `frostd`; signing is
   a stateless hex CLI. The daemon runs `sign-round1`/`round2`/`aggregate` as
   relay sessions with a coordinator, bound to the Orchard `sighash` and
   per-action `alpha` as `frost-spend` already does.
3. **Owned nonce state.** `zcli` hands nonces back as hex with no single-use
   enforcement. The daemon generates and consumes nonces internally, persists
   the consumed marker before releasing a signature share, and never exposes
   them.
4. **Membership function** against a Penumbra RPC (section 4), with the
   testnet using a stub that reads a JSON file so eviction can be simulated.
5. **Reshare** per section 5: commit, manifest, sealed distribute, aggregate
   with fixed `S`, canary, activate, retire. Rebuild `KeyPackage` and
   `PublicKeyPackage` from `s'_j`, `F'`, and `Y_j`.
6. **Policy hook.** Before signing, check destination allow-list, amount cap,
   and that the request names the live epoch.

Test matrix on regtest, all automated:

- 5 up: DKG, receive, spend.
- Evict 1 (4 members, t=3): reshare with `S` = 3 dealers, canary, spend.
- Re-admit (back to 5): reshare, canary, spend.
- Dealer faults after signing the manifest: abort, retry as `E+1`, spend.
- Two members receive from different dealer subsets **without** the manifest
  rule: confirm the all-members canary identifies them by index, then
  confirm the manifest rule prevents the split.
- Old-epoch signing request after activation: refused.
- Kill a daemon mid-round-3 and restart: no nonce reuse, no double aggregate.

Then the same on Zcash testnet with a small TAZ balance, run by five real
operators on five machines for at least four weekly epochs.

### 8.2 Bitcoin: 7-of-11 on `frostsnap_core`

- The signer daemon wraps `FrostSigner` from `frostsnap_core`; the
  coordinator role uses `FrostCoordinator`. Both are plain state machines
  with no USB assumption; `frostsnap_core/tests/env` runs them in-process.
- Transport: the bincode message enums from `frostsnap_comms`, not the serial
  framing, over the same relay or a WireGuard mesh.
- `KeyId` derives from the root point and is invariant across epochs.
  `AccessStructureId` derives from the point polynomial and changes each
  epoch. That is the right shape: one key, one access structure per epoch.
  BIP32-style app tweaks survive because they act on the invariant root.
- Reshare math over `secp256kfun`: dealers build a `Poly` with `a_0 = share`,
  commitments are `Point` polynomials, new share is a `SecretShare` paired
  against `SharedKey::from_poly(F')` via `pair_secret_share`, which performs
  the `g^{s'_j} == F'(j)` check for free.
- **Nonce rewind is the fatal footgun on servers.** Frostsnap's slot writes
  the consumed nonce index before releasing a share and refuses to sign below
  it. That survives crashes, not VM snapshots or ZFS rollbacks. Signer state
  lives on non-snapshotted storage; a lost signer is restored from its
  backup share through the restoration flow, never from a disk image.
- Fingerprint: `SharedKey::check_fingerprint` grinds leading zeros into the
  non-constant coefficients at DKG time. A reshared polynomial does not carry
  it, so share-backup matching in the restoration flow needs a per-epoch
  path (match on `KeyId` plus manifest) or the check skipped for reshared
  epochs.
- Interop: `frostsnap` shares are `schnorr_fun` only until the BIP drafts
  settle. Accepted for v1.

### 8.3 Order of work

1. Manifest-based reshare in `frostito` (fix F1, F2; add `dealer_set` input,
   verifying-share output, tests for the split-dealer-set case).
2. `signerd` for Pallas on regtest with the test matrix above.
3. Five-operator Zcash testnet run, four epochs.
4. Port reshare to `secp256kfun`; `signerd` backend for `frostsnap_core`.
5. Bitcoin signet run with 11 operators, then mainnet with a small balance.

---

## 9. Open questions

- **Membership source of truth.** Section 4 reads Penumbra chain state. Do we
  want the roster itself (the opt-in list and signer keys) on chain as a
  governance object, or is a signed JSON file in a repo enough for v1?
- **Canary cost on bitcoin.** A canary signature can be over a test message
  (frostsnap supports `SignTask::Test`), so it need not be an on-chain
  transaction. Confirm the same is acceptable for Zcash, where the sighash
  binding to `alpha` means a test message is not a spend.
- **Who may be coordinator.** Any member, or a rotating designated one per
  epoch? Rotating is simpler to reason about for equivocation evidence.
- **`repairable` for adding members.** Needs the two checks in section 7.
- **Sweep cadence.** Quarterly is a guess. It should be a function of how
  many distinct evicted members exist per past epoch.
- **Review.** The reshare math is textbook, but the manifest protocol and
  the sealing binding are ours. Who reviews it before mainnet bitcoin?
- **Penumbra epoch length.** `K` custody-epochs-per-reshare assumes weekly.
  Set from the mainnet `epoch_duration` once we pick the boundary rule.

# Draft issue — reshare in `zcli`: pin the version, and own the refresh

Status: draft for `rotkonetworks/zcli` (file with
`gh issue create -F docs/design/reshare-handoff-issue.md`).
Companion to `docs/design/validator-frost-custody.md` (the design) and
`frostito/CHANGELOG.md` 0.8.0 (the crate). Nothing here is implemented in
`zcli` yet: `frostito::reshare` is called from doc comments only
(`crates/frost-spend/src/{hierarchical.rs:21,sealed.rs:55}`), and
`ReshareGateFilter` is an architecture comment, not a type
(`hierarchical.rs:8`). That is the right time to close both gaps, before
`signerd` (§8.1 item 5 of the custody doc) wires the ceremony.

## Two things block a correct reshare

### 1. `bin/poker`'s pin predates the release that made dealers prove possession

The custody path (`crates/frost-spend`, `bin/zcli`) now depends on `frostito`
v0.8.0 (tag), where the proof requirement is in the types: `Cargo.toml:45`
pins `frostito = { git = "https://github.com/penumbrafi/frostito", tag = "v0.8.0" }`.
`bin/poker` still pins `osst 0.5.0` at the old rev `f4f1a1a` (2026-09-21) —
the last rev of the `osst` name, which upstream deleted at v0.6.0 two days
later; there is no newer `osst` to bump to:

```
bin/poker/Cargo.toml:35  osst = { git = "https://github.com/penumbrafi/frostito", rev = "f4f1a1aecd5193c8bbb4bd36cece7b6b6caa7f80", features = ["std","pallas","legacy-v1"] }
Cargo.lock:4715  name = "osst"  version = "0.5.0"
```

`frostito` 0.8.0 (2026-09-24, `c0dad6d`) made a reshare dealer **prove it can
open the constant term it publishes**:

> a dealer could copy the point out of the previous epoch's public polynomial
> and deal a polynomial through it, passing every Feldman check and the
> group-key check, since those are statements about commitments too.
> — `frostito/CHANGELOG.md` 0.8.0

The pinned rev has none of that:

```
$ git -C ../frostito show f4f1a1a:src/reshare.rs | grep -c prove_possession
0
```

So any ceremony driven from `bin/poker` today accepts a `DealerCommitment`
with no proof of knowledge and inherits the split/borrowed-commitment failure mode:
the epoch manifest's group-key check passes, and the group silently lands on
polynomials that never sign together (opaque abort, no identifiable culprit).

Fix, in the order it should land:

1. ~~Bump the workspace pin `osst`/`frostito` to 0.8.0~~ — landed for the
   custody path (workspace `frostito` at tag `v0.8.0`; `bin/poker` split onto
   its own `osst 0.5.0` entry). Still open: `bin/poker`'s `legacy-v1` (it
   exists to hold the pre-0.4 nested API; check whether the poker escrow still
   needs it before deleting), and the escrow-layer decision under "The pin
   decision" below.
2. `submit_commitment(commitment, proof)` — thread `Dealer::prove_possession`
   and `DealerCommitment::verify_possession` through whatever drives the
   ceremony, and put the epoch number the proof was minted for in the
   manifest, not in the transport.
3. Regression test with a *deliberate* copied commitment (deal through
   `g^{s_j}` taken from the previous epoch's polynomial) and assert
   `InvalidProofOfKnowledge`.

### 2. One frost-core version per group, and `zcli` currently links two

`frostito` is on `frost-core` 3.0. Penumbra's `decaf377-frost` is on 0.7, and
`frostito`'s README calls that split "the only thing in the way" for the UM
suite. `zcli` resolves both sides at once:

```
Cargo.lock:2385  name = "frost-core"  version = "2.2.0"   (via frost-tools rev 06c0dbd: frostd, frost-client)
Cargo.lock:2407  name = "frost-core"  version = "3.0.0"   (via frost-rerandomized = "=3.0.0", zakura-reddsa)
```

Refresh state is a `KeyPackage`/`PublicKeyPackage` pair, and its serialized
shape and verifying-share derivation are version-defined. A refresh where the
dealers and the signing path are on different frost-core versions does not
fail loudly — it produces a share set whose `Y_j` no longer match what the
signer validates, which surfaces as an unattributable partial-signature
failure at spend time.

The design doc is also stale here: §2 of `validator-frost-custody.md` says
"`frost-spend` (ZF `frost-core` 2.2)"; the resolved dependency is 3.0.0.

Gate to add: the ceremony — DKG, every reshare/refresh, and the canary —
must run entirely on one frost-core minor, and each round message must carry
the version and be refused on mismatch. Then fix the doc.

## The hazard this creates: a refresh is invisible to a second consumer

Reshare is **key-preserving**, so it does not retire old shares:

> because the reshare is key-preserving, rotation alone does not retire old
> shares — a stale quorum can still sign. `frostito::context` binds the epoch
> and a manifest hash into the signed bytes to close that, and its own docs
> say where it does not apply (protocol-defined signatures, where the message
> is a sighash somebody else chose).
> — `frostito/README.md`

That last clause is the problem, because the bridge path signs a sighash
somebody else chose: `bridge_sign_round2(..., sighash, alpha, ...)` →
`bridge_aggregate` (`hierarchical.rs:234-242`) is an Orchard `SpendAuth`
signature. There is no room in it for an epoch, so `frostito::context` cannot
cover it.

`ReshareGateFilter` ("blocks signing during rotation") is therefore the only
mechanism the design has, and it only holds inside one process that owns both
the share and the rotation — i.e. it assumes the group has exactly one
consumer. That assumption is not true today, and it is the one to write down
before `signerd` exists rather than after:

- `crates/frost-spend` + `bin/zcli`: the current nested API,
  `frostito = { features = ["pallas","std"] }` (v0.8.0).
- `bin/poker`: the deleted `osst` crate at its last rev (`f4f1a1a`), with
  `features = ["std","pallas","legacy-v1"]` — the nested FROST v1
  construction 0.6.0 removed, called from
  `bin/poker/src/main.rs:196` (`redpallas::nested_redpallas_sign`). Upstream
  deleted the name itself in 0.6.0 (`4ededc3` "drop OSST, rename to
  frostito"), together with `src/redpallas.rs`, `src/types.rs` and every wire
  domain tag (`osst/` -> `frostito/`), so the pinned rev and v0.8.0 do not
  interoperate at all and no `osst` release can follow. Different group, two
  dead-or-current crates: a `KeyPackage` or nested share from one cannot be
  consumed by the other, and a fix landed on the current API does not reach
  the poker escrow.

And cross-repo consumers with their own copies, per custody doc F10:
`warpito` pins `zeratul/crates/osst` — a vendored package still named `osst`
(v0.1.1, last touched 2026-08-06), so the deletion upstream never reached it
and a fix landed there does not flow to it;
`jam-netadapter/frost-signer` has the right four-phase state
machine with every trigger stubbed (`should_initiate_reshare` returns
`false`); `jam-service` attests completion on chain from an off-chain
ceremony.

What that produces, concretely: consumer A rotates position-1 to epoch `E`,
consumer B signs with the epoch `E−1` share it still holds, both aggregation
paths produce a signature that verifies under the unchanged bridge key, and
nothing on chain or in the signature names the epoch. The loss of the old
share's exclusivity is silent.

What to do — the rule is already written down, it just is not implemented:

1. **Every signing request names the epoch.** The signer refuses a share whose
   epoch is superseded and refuses to sign for an epoch it has not activated
   (custody doc §5.5(2)). The epoch is carried out-of-band — in the request,
   not in the sighash — because the sighash has no room for it.
2. **One owner per share.** Exactly one component owns the `KeyPackage` for a
   group and is the only thing that may reshare it; a second consumer gets a
   derived authority (a nested position), not a copy of the same share. In
   this repo that means `signerd` owns the bridge group, and `bin/poker`'s
   separate escrow group stays separate — but its `legacy-v1` pin must be
   resolved explicitly (migrate to the current nested API or park the path)
   rather than left at a generation upstream no longer maintains.
3. **Never delete epoch `E−1` until `E` canaries.** A partial signature from
   every new member, each verified against `Y_j = F'(j)` from the manifest's
   `S` (custody doc §5.5(1)) — this is the only thing that catches members
   landing on different polynomials.

## The pin decision

The custody path has moved off the `f4f1a1a` rev (landed): `Cargo.toml` pins
`frostito` at tag `v0.8.0`, and `crates/frost-spend` / `bin/zcli` are renamed
onto the crate's current name and API, so the proof-of-possession requirement
above sits in the type system rather than only in this document.

`bin/poker` stays on the old revision as its **own** dependency entry, on
purpose — and that is the deliberately papered-over part of this doc. It is
the last rev that still answers to the name `osst` (upstream deleted the crate
in 0.6.0, so a version bump has nowhere to go). Its
dispute path calls
`osst::redpallas::zcash::{setup_escrow, JuryNetwork, nested_redpallas_sign,
derive_address_bytes}` and enables `legacy-v1`, i.e. the escrow/jury layer and
the nested-v1 construction that upstream **deleted** in 0.6.0 (escrow moved
out as application logic; v1 was removed as known-insecure). zk.poker already
owns that layer — `crates/poker-escrow`, with `crates/poker-server/src/jury.rs`
over it and a vendored `crates/frostito` (package `frostito` 0.1.1) already
carrying the new name — while `zcli`'s `bin/poker` and
`.github/workflows/release.yml` still build and ship a second copy of it. The
follow-up is a decision, not a bump: have `bin/poker` consume `poker-escrow`
(git or path dep) and migrate to the current nested API, or stop shipping
`poker` from `zcli`.

## Acceptance criteria

- `cargo tree -i frost-core` in `zcli` shows a single version on the custody
  path (the frostd/relay side may keep its own, but not inside one group).
- A reshare round from a peer pinned to a different frostito/frost-core minor
  is refused with a named error, not a checksum mismatch or an opaque abort.
- A dealer that publishes a commitment it cannot open is rejected at
  `submit_commitment` (test: copied `g^{s_j}` from epoch `E−1`).
- A signing request naming epoch `E−1` after activation is refused, and the
  refusal is testable without a chain.
- `docs/design/validator-frost-custody.md` §2 states the frost-core version
  the code actually links.

## References

- `frostito` `c0dad6d` (0.8.0): `reshare::Dealer::prove_possession`,
  `ReshareState::submit_commitment` taking the proof, `REMOVED liveness`.
- `frostito/README.md`: key-preserving reshare; the epoch-binding limit of
  `frostito::context`; the frost-core 0.7/3.0 split against `decaf377-frost`.
- `zcli` `bin/poker/Cargo.toml:35` + `Cargo.lock:4715` (osst 0.5.0),
  `Cargo.toml:43` (`frostito` v0.8.0, custody path), `Cargo.lock:2385/:2407`
  (frost-core 2.2.0 and 3.0.0), `bin/poker/Cargo.toml:22,30` (legacy-v1).
- `zcli` `docs/design/validator-frost-custody.md` §2, §5.5, §6 (F1–F10), §7
  (ZF `frost-core` refresh/repairable as the alternative), §8.1 item 5.

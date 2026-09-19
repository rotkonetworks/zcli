# zcli

A Zcash wallet built to be driven by software. Every command speaks JSON, every
input comes from a flag or an environment variable, key derivation is
deterministic, and a long-running daemon (`zclid`) exposes the whole wallet over
gRPC so an agent never has to shell out at all.

Nothing is trusted. Chain data arrives with proofs — a ligerito commitment over
the header chain, NOMT merkle proofs for note commitments and nullifiers — and
is cross-checked against independent nodes before the wallet believes it.

```
cargo install zecli
zcli init sync
zcli view balance --json
```

## why agents

The usual light wallet assumes a person: a prompt to confirm, a QR to look at, a
progress bar, a seed phrase written on paper. zcli assumes a process.

- **`--json` everywhere** (or `ZCLI_JSON=1`) — machine-readable output, no
  prompts, no progress bars, no QR rendering.
- **No interactive key entry.** The wallet seed is an ed25519 SSH key
  (`-i`/`ZCLI_IDENTITY`) or a BIP-39 mnemonic (`ZCLI_MNEMONIC`) — the same key
  material an agent already has for SSH.
- **Deterministic derivation.** The same key gives the same wallet on any host,
  so an agent's wallet is reproducible from its credentials alone.
- **A spending key is optional.** Run watch-only (`-w` with an FVK) and let the
  agent build and prove transactions it cannot sign; a human or a hardware
  signer authorizes them out of band.
- **`--dry-run` on the money paths.** Build, select notes, compute the ZIP-317
  fee, and prove the transaction without broadcasting it. Proving is the
  expensive and failure-prone step, so this exercises the real path.
- **A daemon, not a cold start.** `zclid` keeps the wallet synced and answers
  queries instantly over a unix socket or an authenticated TCP port.

## zclid — the daemon agents talk to

`zcli` is a one-shot process: it opens the wallet, syncs what it must, does one
thing, exits. That is the wrong shape for an agent that asks about its balance
every few seconds. `zclid` keeps the wallet open and synced, polls the mempool,
and serves the wallet as a gRPC service.

```sh
zclid -i ~/.ssh/id_ed25519                       # unix socket only
zclid -i ~/.ssh/id_ed25519 --listen 127.0.0.1:9067   # + TCP for agents
```

`WalletDaemon` (`bin/zclid/proto/zclid.proto`):

| RPC | |
| --- | --- |
| `GetCustodyMode` | whether this daemon holds a spending key |
| `GetAddress` | receiving address (rotates diversifier) |
| `GetBalance` | shielded + transparent balance |
| `GetNotes` | unspent notes |
| `GetStatus` | sync height, chain tip, mempool counters, uptime |
| `GetPendingActivity` | unconfirmed incoming/outgoing |
| `GetHistory` | received + sent |
| `PrepareTransaction` | build + prove, return a PCZT for external signing |
| `SignAndSend` | build, prove, sign, broadcast (needs a spending key) |
| `SubmitSigned` | broadcast a PCZT signed elsewhere |
| `SendRawTransaction` | broadcast raw bytes |

Two properties matter for agent deployments:

- **Custody is a deployment choice, not a code change.** `--view-only` (with
  `--fvk`, or an FVK-only wallet) starts a daemon with no spending key. It can
  still answer every query and still `PrepareTransaction` — the agent gets a
  PCZT, and whoever holds the key signs it. `GetCustodyMode` lets the agent
  discover which mode it is in rather than assume.
- **The socket is the trust boundary.** Unix-socket requests skip auth (the
  filesystem already answered the question). The TCP listener is off unless you
  pass `--listen`, and when on it requires `authorization: bearer <token>`
  against a 256-bit token generated on first run at `~/.zcli/zclid.token`,
  compared in constant time.

Prepared transactions expire ten minutes after `PrepareTransaction`.

## keys

Priority order, highest first:

1. `--mnemonic` / `ZCLI_MNEMONIC`
2. `~/.config/zcli/mnemonic.age` (decrypted with the identity key)
3. `-i` / `ZCLI_IDENTITY` → `~/.config/zcli/id_zcli` → `~/.ssh/id_ed25519`

SSH-key wallets derive the orchard spending key from the ed25519 seed via
`BLAKE2b-512("ZcliWalletSeed" || ed25519_seed)`. `zcli init phrase` prints the
24-word recovery phrase behind one; `zcli init migrate` moves a legacy SSH-key
wallet onto the mnemonic-backed derivation, sweeping funds as it goes.

Environment: `ZCLI_IDENTITY`, `ZCLI_MNEMONIC`, `ZCLI_PASSPHRASE`, `ZCLI_FVK`,
`ZCLI_ENDPOINT`, `ZCLI_VERIFY_ENDPOINTS`, `ZCLI_JSON`, `ZCLI_WATCH`,
`ZCLI_CONFIRMATIONS`, `ZCLI_FORWARD`, `ZCLI_WEBHOOK_URL`, `ZCLI_WEBHOOK_SECRET`.
`zclid` additionally reads `ZCLI_VERIFY`.

## commands

```
zcli view        balance | address | notes | history | export        (alias: v)
zcli transaction send | shield | migrate                             (alias: tx)
zcli signer      export-notes | scan | verify                        (alias: s)
zcli multisig    host | join | dealer | dkg-part1..3 | sign-* | ...   (alias: ms)
zcli init        create | import-fvk | sync | phrase | migrate
zcli service     merchant | board | license-server | tree-info
```

Sending:

```sh
zcli tx send 0.1 u1... --memo "invoice 42" --dry-run --json
zcli tx shield --json
zcli tx migrate --dry-run        # NU6.3 turnstile, orchard → your own ironwood
```

`--dry-run` and `--fee` apply to ironwood sends (NU6.3 and later). On a
pre-NU6.3 chain both are refused with an error rather than ignored — silently
dropping `--dry-run` would broadcast a transaction you asked not to send.

`tx migrate` is the NU6.3 turnstile. Orchard outputs are consensus-disabled at
NU6.3 while orchard spends stay valid, so `tx send` cannot spend an orchard
note; `migrate` re-outputs the value to *your own* ironwood address. It moves
no value to anyone else, but it is one-way. Use `--dry-run` first.

## verification

`zcli signer verify` walks the whole chain of evidence and refuses to accept
server data that does not prove itself:

```
$ zcli signer verify
network:  mainnet
endpoint: https://zcash.rotko.net
tip:      3266078 (000000000075b2db)

1. trust anchor
   hardcoded orchard activation hash at height 1687104
   server returned: 0000000000d72315
   expected:        0000000000d72315
   PASS
2. cross-verification (1 independent node)
   https://zec.rocks - tip matches
   consensus: 1/1 agree (threshold: >2/3)
   PASS
3. header chain proof (ligerito)
   epoch proof: 1687104 -> 3265535 (1578432 headers, 452 KB)
   epoch proof anchored to activation hash: PASS
   epoch proof cryptographic verification:  PASS
   tip proof: 3265536 -> 3266078 (543 headers)
   chain continuity (tip chains to epoch proof): PASS
   total blocks proven: 1578974
4. cryptographically proven state roots
   (extracted from ligerito polynomial trace sentinel row)
   tree_root:          b375422028a896ed...
   nullifier_root:     512ab0f1f95c751e...
   actions_commitment: 18001392bc7a253b...
   proof freshness: 0 blocks behind tip

all checks passed
```

The layers:

1. **trust anchor** — the orchard activation block hash (height 1,687,104) is
   compiled into the binary. Everything else chains back to it.
2. **cross-verification** — block hashes checked against independent
   lightwalletd nodes (`--verify-endpoints` / `ZCLI_VERIFY_ENDPOINTS`,
   comma-separated; defaults to the zec.rocks and zec.stardust.rest regions),
   requiring >2/3 agreement.
3. **epoch proofs** — ligerito polynomial commitments prove the header chain
   from the anchor forward, 1.5M+ headers in one ~450 KB proof.
4. **commitment proofs** — NOMT merkle proves each received note commitment is
   in the tree.
5. **nullifier proofs** — NOMT merkle proves your nullifiers are *absent*, i.e.
   the notes are unspent.
6. **actions commitment** — a BLAKE2b chain over per-block action roots,
   checked against the value the proof asserts.

Trial decryption is local. The server learns which blocks you fetched, never
which notes are yours.

## backends

The default endpoint is a **zidecar** (`https://zcash.rotko.net`), which serves
compact blocks *and* the proof RPCs above. The cross-verification endpoints are
plain **lightwalletd** `CompactTxStreamer` — any lightwalletd-compatible server
(lightwalletd, zaino) works there.

The main data path still requires zidecar: compact blocks, tree state,
transactions, and broadcast go over `zidecar.v1`. Running zcli against a bare
lightwalletd or zaino as its *primary* endpoint is not supported yet — the four
proof RPCs have no equivalent there, and degrading them silently would defeat
the point of the verification chain.

## zidecar

The light server. Indexes the chain into NOMT and serves:

- compact blocks (orchard/ironwood actions only)
- epoch proofs — ligerito commitments over 1.5M+ block headers
- commitment proofs (NOMT merkle) for received notes
- nullifier proofs (NOMT merkle) for unspent verification
- cross-verification data against lightwalletd endpoints

## workspace

```
bin/
  zcli/            the CLI wallet (crate: zecli)
  zclid/           background wallet daemon — gRPC, the agent-facing surface
  zidecar/         light server — compact blocks + proofs
  relay/           dumb relay: rooms, participants, opaque bytes
  poker/           mental-poker table over the relay
  pokerbot/        automated player
  license-server/  ZEC payment detection → license issuance
  integration-v09/ end-to-end integration harness

crates/
  zync-core/       shared primitives — verification, scanning, proof types, gRPC proto
  zcash-wasm/      zafu — browser proving + wallet core (crate: zafu-wasm)
  zcash-voting/    shielded voting: ZKP delegation, vote commitments, Halo 2
  voting-wasm/     browser prover for the voting circuits
  pir-client/      private nullifier non-membership via PIR
  frost-spend/     FROST threshold spend authorization for orchard
  osst/            One-Step Schnorr Threshold Identification (pallas + ristretto255)
  zoda-vss/        verifiable secret sharing
  ring-vrf-wasm/   ring VRF for the browser
  maybe-rayon/     local fork: rayon shim compatible with halo2 on wasm32+atomics
  ligerito/        polynomial commitment scheme over binary extension fields
  ligerito-binary-fields/   binary field arithmetic (GF(2^128))
  ligerito-merkle/          merkle trees for ligerito commitments
  ligerito-reed-solomon/    reed-solomon erasure coding over binary fields

docs/design/       design notes (FROST custody, header proofs, per-pool proofs)
deploy/regtest/    ironwood end-to-end harness against a real zebrad
```

## ligerito

Polynomial commitment scheme over binary extension fields (GF(2^128)). Proves
properties of 1.5M+ block headers in a single proof using Reed-Solomon encoding
and Merkle-based verification.

## regtest: ironwood money paths against a real validator

The NU6.3 / Ironwood transaction builders are exercised locally by unit and
integration tests, but "we built a valid-looking transaction" and "a consensus
node accepted it" are different claims. `deploy/regtest/` closes that gap: it
runs a throwaway [zebrad](https://github.com/ZcashFoundation/zebra) Regtest
chain with NU6.3 live from block 1, and submits the real transactions to it.

```sh
# builds zebra on first run (~long), then mines, shields, withdraws
deploy/regtest/run-ironwood-e2e.sh

# skip the zebra build if you already have a zebrad with NU6.3 support
ZEBRAD=/path/to/zebrad deploy/regtest/run-ironwood-e2e.sh
```

What it does:

- `deploy/regtest/zebrad-regtest.toml` — Regtest with every upgrade, including
  `"NU6.3" = 1`, active from the first block. Regtest disables PoW, which is what
  makes `generatetoaddress` available. RPC on `127.0.0.1:28232`.
- `crates/zcash-wasm/tests/regtest_ironwood_e2e.rs` — mines 105 blocks to a
  transparent address it holds the key for, then:
  1. **t→z** spends the mature coinbase UTXO into one ironwood output
     (`build_shielding_transaction_ironwood_core`), and
  2. **z→t** spends the resulting ironwood note back out to a transparent
     address with ironwood change (`build_signed_ironwood_send_core`).

  Each transaction goes through `sendrawtransaction`, is mined, and is read back
  with `getblock <height> 2` to assert the ironwood bundle's action count, value
  balance, commitment-tree growth, and the value pool. The ZIP-317 conventional
  fee is recomputed from the *mined* transaction's own serialization (zebra's
  `zip317::conventional_actions`, which costs ironwood actions exactly like
  orchard ones) and compared against `zip317_shielding_fee` / the send fee.

The turnstile (orchard → ironwood migration) needs a *different* chain: this one
activates NU6.3 at height 1, and post-NU6.3 orchard outputs are consensus-
disabled, so there is no way to create the orchard note the migration must
spend. `deploy/regtest/zebrad-regtest-turnstile.toml` defers activation
(NU6.2 at 150, NU6.3 at 200) on its own ports so the note can be created early
and migrated later:

```sh
ZEBRAD=/path/to/zebrad deploy/regtest/run-turnstile-e2e.sh
```

Running either test by hand needs a node already listening and `--release` (it
builds a Halo 2 proving key and proves ironwood bundles). No `RUSTFLAGS` cfg is
needed any more — NU6.3 / Ironwood is ungated in the upstream `zcash_protocol` /
`orchard` releases, and setting `RUSTFLAGS` on the command line would in fact
*break* the wasm build by replacing `.cargo/config.toml`'s link-args:

```sh
cargo test --release -p zafu-wasm --test regtest_ironwood_e2e -- --ignored --nocapture
cargo test --release -p zafu-wasm --test regtest_turnstile_e2e -- --ignored --nocapture
```

The tests assert absolute commitment-tree sizes, so they want a fresh chain —
the scripts always start a new ephemeral node.

## air-gapped signing

`zcli signer export-notes` renders notes and merkle paths as an animated QR for
the [zigner](https://github.com/nickkuk/zigner) Android app; `zcli signer scan`
reads the signed result back from a webcam. Combined with a watch-only wallet
(`-w`), the spending key never touches the networked machine.

## donate

If you find this useful, send some shielded ZEC:

```
u153khs43zxz6hcnlwnut77knyqmursnutmungxjxd7khruunhj77ea6tmpzxct9wzlgen66jxwc93ea053j22afkktu7hrs9rmsz003h3
```

Include a memo and it shows up on the [donation board](https://zcli.rotko.net/board.html).

## acknowledgments

- [Bain Capital Crypto / ligerito.jl](https://github.com/BainCapitalCrypto/ligerito.jl) — the original polynomial commitment scheme we ported to Rust
- [thrumdev/nomt](https://github.com/thrumdev/nomt) — Nearly Optimal Merkle Tree, used for commitment and nullifier proofs
- [Penumbra Labs](https://github.com/penumbra-zone) — client-side sync model we build on

## license

MIT

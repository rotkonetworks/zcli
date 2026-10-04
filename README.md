# zcli

A Zcash wallet built to be driven by software. Every command speaks JSON, every
input comes from a flag or an environment variable, key derivation is
deterministic, and a long-running daemon (`zclid`) exposes the whole wallet over
gRPC so an agent never has to shell out at all.

Your notes stay yours. zcli scans every block itself, so the server never learns
which notes are yours. The chain is checked against a compiled anchor block,
cross-checked against independent nodes, and, where the server offers it,
against Zcash's own proof of work through FlyClient (ZIP-221).

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
- **A daemon, not a cold start.** `zclid` keeps the wallet at the chain tip and
  answers queries instantly over a unix socket or an authenticated TCP port.

## zclid — the daemon agents talk to

`zcli` is a one-shot process: it opens the wallet, syncs what it must, does one
thing, exits. That is the wrong shape for an agent that asks about its balance
every few seconds. `zclid` keeps the wallet synced, polls the mempool, and
serves the wallet as a gRPC service.

The wallet db is sled, which takes an exclusive lock on the directory: **one
process at a time**, daemon and CLI included. `zclid` does not hold it
permanently — it opens the wallet per sync and per request and drops it again —
so in steady state the lock is held for a couple of seconds every
`--sync-interval`. `Wallet::open` waits up to ~11s (200ms..2s backoff) for a
peer to release it, so the CLI and a running daemon coexist without lock
errors. A *catch-up* sync (wallet months behind, or a cold `--from`) holds the
lock for the whole run, minutes at a time: CLI commands fail then. Either wait
for the daemon to reach the tip, or stop it (`systemctl --user stop zclid`) and
run the catch-up from the CLI.

A failed sync is retried with a doubling delay (30s, 60s, … capped at ten
minutes) instead of on the fixed `--sync-interval`, so a server that keeps
failing is not hammered and the wallet lock is not held back to back.

Two checks keep a sync from storing a height it did not reach:

* a compact-block response that does not cover the requested range is treated
  as a *failed* fetch and retried, not as a smaller success;
* the scan refuses to store a sync point unless every height from the start to
  the tip arrived, in order, with no gaps. A server that skips a block would
  otherwise hide whatever it contains.

Height and both tree positions are written in one sled transaction, so a kill
in between cannot leave a height beside positions from another height.

```sh
zclid -i ~/.ssh/id_ed25519                       # unix socket only
zclid -i ~/.ssh/id_ed25519 --listen 127.0.0.1:9067   # + TCP for agents
```

`WalletDaemon` (`bin/zclid/proto/zclid.proto`):

| RPC | |
| --- | --- |
| `GetCustodyMode` | whether this daemon holds a spending key |
| `GetAddress` | unified orchard address + a transparent address for shielding |
| `GetBalance` | confirmed and pending-incoming zatoshis, note and pending-spend counts, sync height, chain tip |
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
zcli tx shield --source 1 --json   # shield the UTXOs of m/44'/133'/0'/0/1
zcli tx migrate --dry-run        # NU6.3 turnstile, orchard → your own ironwood
```

`tx shield` shields the transparent UTXOs of one BIP32 account address and sends
the value to this wallet's own ironwood address; `--source N` picks the address
(default 0). UTXOs whose script is not the selected address's P2PKH script are
refused rather than silently drained.

`--dry-run` and `--fee` apply to ironwood sends (NU6.3 and later). On a
pre-NU6.3 chain both are refused with an error rather than ignored — silently
dropping `--dry-run` would broadcast a transaction you asked not to send.

`tx migrate` is the NU6.3 turnstile. Orchard outputs are consensus-disabled at
NU6.3 while orchard spends stay valid, so `tx send` cannot spend an orchard
note; `migrate` re-outputs the value to *your own* ironwood address. It moves
no value to anyone else, but it is one-way. Use `--dry-run` first.

## verification

`zcli signer verify` checks the chain the server shows you:

1. **trust anchor** — the orchard activation block hash (height 1,687,104) is
   compiled into the binary, and the server must return that block.
2. **cross-verification** — the tip hash is checked against independent
   lightwalletd nodes (`--verify-endpoints` / `ZCLI_VERIFY_ENDPOINTS`,
   comma-separated; defaults to the zec.rocks and zec.stardust.rest regions),
   requiring >2/3 agreement.
3. **FlyClient** — when the server runs with `--flyclient`, a FlyClient proof
   over the ZIP-221 history tree: sampled headers with valid Equihash, MMR
   paths to the roots each committing header carries, epochs linked down to a
   compiled anchor (NU5 or NU6.3 activation). The FlyClient tip must be the
   cross-verified tip or be confirmed by the endpoints. See
   `docs/design/flyclient-header-proof.md` for what it does and does not prove.

Notes and spends are found by scanning on your machine: trial decryption for
notes, nullifier matching for spends. The server learns which blocks you
fetched, never which notes are yours.

## backends

The default endpoint is a **zidecar** (`https://zcash.rotko.net`), which serves
compact blocks and, when enabled, FlyClient proofs. The cross-verification endpoints are
plain **lightwalletd** `CompactTxStreamer`, so any lightwalletd-compatible
server works there — lightwalletd or zaino, self-hosted or public.
`LightwalletdClient::connect` probes the endpoint with a grpc-web request and
reads the response content-type, falling back to native gRPC framing when the
server answers `application/grpc`, so neither transport needs configuring.

The main data path still requires zidecar: compact blocks, tree state,
transactions, and broadcast go over `zidecar.v1`. Running zcli against a bare
lightwalletd or zaino as its *primary* endpoint is not supported yet.

## zidecar

The light server. lightwalletd-compatible, and with `--zidecar-rpc` also serves:

- compact blocks (orchard/ironwood actions only)
- whole-block transaction reads, for private memo fetches
- FlyClient proofs over the ZIP-221 history tree (`--flyclient nu6.3|nu5`)

## workspace

```
bin/
  zcli/            the CLI wallet (crate: zecli)
  zclid/           background wallet daemon — gRPC, the agent-facing surface
  zidecar/         light server — compact blocks + FlyClient proofs
  relay/           dumb relay: rooms, participants, opaque bytes
  poker/           heads-up poker CLI with frostito escrow via relay
  pokerbot/        headless heads-up bot driving poker-pvm over the E2EE relay
  license-server/  ZEC-paid pro license server for the zafu wallet
  integration-v09/ end-to-end integration harness (not published)

crates/
  zync-core/       shared primitives — FlyClient verification, scanning, gRPC proto
  zcash-wasm/      zafu — browser proving + wallet core (crate: zafu-wasm)
  zcash-voting/    shielded voting: ZKP delegation, vote commitments, Halo 2
  voting-wasm/     browser prover for the voting circuits
  pir-client/      private nullifier non-membership via PIR
  frost-spend/     FROST threshold spend authorization for orchard
  osst/            frostito: nested FROST with OSST identification, DKG, proactive resharing
  zoda-vss/        verifiable secret sharing via reed-solomon coding
  ring-vrf-wasm/   Bandersnatch Ring VRF prover for zafu pro membership proofs
  maybe-rayon/     local fork: rayon shim compatible with halo2 on wasm32+atomics

docs/design/       design notes (FROST custody, FlyClient, per-pool proofs)
deploy/regtest/    ironwood end-to-end harness against a real zebrad
```

## ligerito

The Ligerito polynomial commitment crates used to live here under `crates/`.
zcli no longer uses them; they moved to their own repository with their
history (2026-10).

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

- [zcash_history](https://crates.io/crates/zcash_history) and the [equihash](https://crates.io/crates/equihash) crate — the ZIP-221 history tree and proof of work behind FlyClient
- [Penumbra Labs](https://github.com/penumbra-zone) — client-side sync model we build on

## license

MIT

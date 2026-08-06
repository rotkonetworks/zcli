# zcash-lc

Zcash light client stack with cryptographic verification at every layer.
No trusted servers — header chain proofs, commitment proofs, nullifier proofs,
and cross-verification against independent nodes.

## workspace structure

```
bin/
  zcli/          CLI wallet — ssh ed25519 keys as wallet seed
  zidecar/       light server — indexes chain, serves compact blocks + proofs

crates/
  zync-core/     shared primitives — verification, scanning, proof types, gRPC proto
  ligerito/      polynomial commitment scheme over binary extension fields
  ligerito-binary-fields/   binary field arithmetic (GF(2^128))
  ligerito-merkle/          merkle trees for ligerito commitments
  ligerito-reed-solomon/    reed-solomon erasure coding over binary fields

proto/           canonical protobuf definitions (copied into crate dirs)
www/             zcli.rotko.net website
```

## zcli

Zcash CLI wallet that derives keys from SSH ed25519 keys or BIP-39 mnemonics.

- orchard shielded pool (no sapling legacy)
- trial decryption — server never learns which notes are yours
- air-gapped signing via [zigner](https://github.com/nickkuk/zigner) android app
- watch-only wallet (`-w`) with QR-based remote signing
- merchant payment acceptance with diversified addresses
- agent-friendly: `--json` output, env var config, deterministic key derivation

```
cargo install zecli
zcli sync
zcli balance
zcli send 0.1 u1...
```

## zidecar

Light server that indexes the zcash chain and serves:

- compact blocks (orchard actions only)
- epoch proofs — ligerito polynomial commitments over 1.5M+ block headers
- commitment proofs (NOMT merkle) for received notes
- nullifier proofs (NOMT merkle) for unspent verification
- cross-verification data against lightwalletd endpoints

## ligerito

Polynomial commitment scheme over binary extension fields (GF(2^128)).
Proves properties of 1.5M+ block headers in a single proof using
Reed-Solomon encoding and Merkle-based verification.

## verification layers

1. **epoch proofs** — ligerito proves the header chain from genesis
2. **commitment proofs** — NOMT merkle proves received note commitments exist in the tree
3. **nullifier proofs** — NOMT merkle proves wallet nullifiers are absent (unspent)
4. **actions commitment** — BLAKE2b chain over per-block action roots, verified against proven value
5. **cross-verification** — block hashes checked against independent lightwalletd nodes

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

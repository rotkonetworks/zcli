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

## donate

If you find this useful, send some shielded ZEC:

```
u153khs43zxz6hcnlwnut77knyqmursnutmungxjxd7khruunhj77ea6tmpzxct9wzlgen66jxwc93ea053j22afkktu7hrs9rmsz003h3
```

Include a memo and it shows up on the [donation board](https://zcli.rotko.net/board.html).

## acknowledgments

- [Guillermo Angeris](https://github.com/angeris) — whose work on polynomial commitments and proof systems directly inspired ligerito
- [Rob Habermeier](https://github.com/rphmeier) — for NOMT (New Ordered Merkle Tree), which we use for commitment and nullifier proofs
- [Penumbra Labs](https://github.com/penumbra-zone) — for pushing the boundary on what private proof-of-stake chains can do, and for open-sourcing the primitives that make it possible

## license

MIT

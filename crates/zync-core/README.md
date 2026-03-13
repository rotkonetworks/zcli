# zync-core

Trust-minimized Zcash light client primitives. Verification, scanning, proving.
Everything a light client needs to sync the Orchard shielded pool without trusting
a server.

## Trust model

zync minimizes trust in the server. Every claim is verified cryptographically:

```
hardcoded activation hash
        │
        ▼
  ┌─────────────┐     ligerito polynomial commitment
  │ header chain │────────────────────────────────────── proven NOMT roots
  │    proof     │     O(log n) verification,           (tree_root, nullifier_root,
  └─────────────┘     no headers transmitted             actions_commitment)
        │                                                    │
        ├────────────────────────┬────────────────────────────┤
        ▼                       ▼                            ▼
  ┌───────────┐          ┌────────────┐              ┌─────────────┐
  │ commitment│          │ nullifier  │              │   actions   │
  │   proofs  │          │   proofs   │              │ commitment  │
  └───────────┘          └────────────┘              │    chain    │
  NOMT sparse            NOMT sparse                └─────────────┘
  merkle proof:          merkle proof:               SHA256 merkle root
  note exists            spent/unspent               per block, Blake2b
  in global tree         status                      running chain

        │                       │                            │
        ▼                       ▼                            ▼
  received notes          balance is               server didn't omit,
  are real                 correct                 insert, or reorder
                                                   actions in any block
```

**What's verified:**

1. **Header chain.** Block headers encoded into a trace polynomial, proven with
   [ligerito](https://crates.io/crates/ligerito). The verifier checks the proof
   in O(log n) without seeing any headers. Chain continuity (prev_hash linkage),
   difficulty, and height progression are enforced by trace constraints.

2. **State proofs.** NOMT sparse merkle proofs for note commitments and nullifiers.
   Each proof's root is bound to the header-proven tree root. Commitment proofs
   verify received notes exist. Nullifier proofs verify spent/unspent status.

3. **Actions integrity.** Running Blake2b chain over per-block orchard action
   merkle roots. Checked against the header-proven value. Detects any tampering
   with the compact block action data the server sends during sync.

4. **Cross-verification.** BFT majority (>2/3) consensus against independent
   lightwalletd nodes. Tip and activation block hashes compared across providers.
   Prevents single-server eclipse attacks.

5. **Trial decryption.** After decrypting a note, the commitment is recomputed
   from the decrypted fields and compared to the server-provided cmx. A malicious
   server cannot forge ciphertexts that decrypt to notes with arbitrary values.

**What's NOT verified (scope boundaries):**

- Proof-of-work. Headers are committed, not validated for PoW. The header proof
  proves the server's chain is internally consistent and matches the activation
  anchor. It doesn't re-validate every block.
- Sapling pool. Only Orchard is supported.

## Modules

| Module | Purpose |
|--------|---------|
| `verifier` | Ligerito header chain proof verification (epoch + tip, parallel) |
| `nomt` | NOMT sparse merkle proof verification for commitments and nullifiers |
| `actions` | Per-block actions merkle root and running commitment chain |
| `scanner` | Orchard trial decryption with cmx verification (native + WASM parallel) |
| `sync` | Sync verification primitives: header proof validation, commitment/nullifier batch verification, cross-verify consensus, memo ciphertext extraction |
| `prover` | Ligerito proof generation from header chain traces |
| `trace` | Header chain trace encoding (headers → polynomial) |
| `client` | gRPC clients for zidecar and lightwalletd (feature-gated) |

## Usage

### Sync verification (light client)

```rust
use zync_core::{sync, Scanner};

// 1. verify header proof → extract proven NOMT roots
let proven = sync::verify_header_proof(&proof_bytes, tip, /*mainnet=*/true)?;

// 2. scan compact blocks
let scanner = Scanner::from_fvk(&fvk);
let notes = scanner.scan(&actions);

// 3. verify received notes exist (NOMT commitment proofs)
sync::verify_commitment_proofs(&proofs, &cmxs, &proven, &server_root)?;

// 4. verify nullifier status (NOMT nullifier proofs)
let spent = sync::verify_nullifier_proofs(&nf_proofs, &nfs, &proven, &nf_root)?;

// 5. verify block actions weren't tampered with
sync::verify_actions_commitment(&running, &proven.actions_commitment, true)?;
```

### Proof generation (server)

```rust
use zync_core::{trace, prover};

// encode headers into trace polynomial
let mut trace = trace::encode_trace(
    &headers, &state_roots,
    [0u8; 32], [0u8; 32],  // initial commitments
    tip_tree_root, tip_nullifier_root, final_actions_commitment,
)?;

// generate proof (auto-selects config based on trace size)
let proof = prover::HeaderChainProof::prove_auto(&mut trace)?;
let bytes = proof.serialize_full()?;
```

### Note scanning

```rust
use zync_core::{Scanner, ScanAction, Scope};

// from full viewing key (external scope, received notes)
let scanner = Scanner::from_fvk(&fvk);

// scan sequentially (WASM) or in parallel (native with rayon)
let found = scanner.scan(&actions);

// batch scanner tracks nullifiers across blocks
let mut batch = BatchScanner::from_fvk(&fvk);
for block in blocks {
    batch.scan_block(block.height, &block.actions);
}
println!("balance: {} zat", batch.unspent_balance());
```

### Cross-verification

```rust
use zync_core::sync::{hashes_match, CrossVerifyTally};

// compare block hashes (handles LE/BE byte order)
assert!(hashes_match(&zidecar_hash, &lightwalletd_hash));

// BFT tally
let tally = CrossVerifyTally { agree: 4, disagree: 1 };
assert!(tally.has_majority()); // 4/5 > 2/3
```

### Memo extraction

```rust
use zync_core::sync::extract_enc_ciphertext;

// extract 580-byte encrypted ciphertext from raw V5 transaction
if let Some(enc) = extract_enc_ciphertext(&raw_tx, &cmx, &epk) {
    // decrypt with orchard try_note_decryption using your orchard version
    // ...
}
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | yes | gRPC clients for zidecar and lightwalletd |
| `parallel` | yes | Rayon-based parallel note scanning |
| `wasm` | no | WASM bindings (wasm-bindgen, console_error_panic_hook) |
| `wasm-parallel` | no | WASM + parallel (requires SharedArrayBuffer) |

### WASM build

```sh
# single-threaded
cargo build --target wasm32-unknown-unknown \
  --no-default-features --features wasm

# multi-threaded (requires COOP/COEP headers for SharedArrayBuffer)
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
  cargo build --target wasm32-unknown-unknown \
  --no-default-features --features wasm-parallel \
  -Z build-std=panic_abort,std
```

## Cross-verification endpoints

Default mainnet endpoints from two independent operators, geographically distributed:

| Endpoint | Provider | Region |
|----------|----------|--------|
| `na.zec.rocks` | zec.rocks | North America |
| `eu.zec.rocks` | zec.rocks | Europe |
| `ap.zec.rocks` | zec.rocks | Asia Pacific |
| `us.zec.stardust.rest` | Chainsafe | US |
| `eu.zec.stardust.rest` | Chainsafe | Europe |
| `jp.zec.stardust.rest` | Chainsafe | Japan |

Available as `zync_core::client::CROSSVERIFY_MAINNET`.

## Wire formats

### Header proof

```
[epoch_full_size: u32 LE]
[epoch_full_proof]
[tip_full_proof]
```

Each full proof:
```
[public_outputs_len: u32 LE]
[public_outputs: bincode ProofPublicOutputs]
[log_size: u8]
[ligerito_proof: bincode FinalizedLigeritoProof]
```

### Trace layout

32 fields per header (BinaryElem32 = 4 bytes each):

| Fields | Content |
|--------|---------|
| 0 | height |
| 1-8 | block_hash (32 bytes) |
| 9-16 | prev_hash (32 bytes) |
| 17 | nBits |
| 18 | cumulative_difficulty |
| 19 | running commitment |
| 20-23 | sapling_root (epoch boundaries) |
| 24-27 | orchard_root (epoch boundaries) |
| 28-29 | nullifier_root (epoch boundaries) |
| 30 | state_commitment |
| 31 | reserved |

Sentinel row (24 fields after last header):

| Fields | Content |
|--------|---------|
| 0-7 | tip_tree_root |
| 8-15 | tip_nullifier_root |
| 16-23 | final_actions_commitment |

## License

MIT

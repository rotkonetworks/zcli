// frost-spend — FROST threshold spend authorization for Zcash Orchard
//
// shared crate used by both zcli (native) and zafu (wasm).
// wraps the ZF's FROST libraries + conradoplg's orchard fork.
//
// crypto provenance:
//   - reddsa (ZF): FROST(Pallas, BLAKE2b-512) ciphersuite
//   - frost-core 2.2.0 (ZF): DKG, signing rounds, aggregation
//   - frost-rerandomized 2.2.0 (ZF): rerandomized signatures
//   - ed25519-consensus 2 (Zebra): message authentication
//   - orchard (conradoplg/ZF fork): from_sk_ak for FVK derivation
//
// zero custom crypto. this crate is glue.

pub mod attestation;
pub mod hierarchical;
pub mod keys;
pub mod memo_codec;
pub mod message;
pub mod nested;
pub mod orchestrate;
pub mod relay_cipher;
pub mod sealed;
pub mod sign;
pub mod transport;

// re-export core types
pub use reddsa::frost::redpallas::{
    self as frost, keys as frost_keys, keys::dkg, round1, round2, Identifier, SigningPackage,
};
// frost-rerandomized 3.0: rerandomized aggregate + the Randomizer/
// RandomizedParams types now live in redpallas::rerandomized (reddsa's
// top-level `aggregate` is plain FROST). Per-share rerandomized signing uses
// `frost_rerandomized::sign` directly (see sign.rs / orchestrate.rs).
pub use reddsa::frost::redpallas::rerandomized::{aggregate, RandomizedParams, Randomizer};

pub use ed25519_consensus;

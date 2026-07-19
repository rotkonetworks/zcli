//! Persistent Ed25519 "session identity" — the SINGLE key that ties together the
//! three trust anchors of a paid table (byte-identical to the browser
//! `poker-server/web/src/identity.ts` anon session key):
//!
//!   (a) announced to the peer in the `seated` handshake as `sessionPub`,
//!   (b) pinned ON-CHAIN in the deposit memo `;id:<hex>` (only the depositor can set it),
//!   (c) used to sign the co-signed settlement the escrow verifies at `/settle`.
//!
//! All three MUST be the same key — that binding is what lets the escrow require a
//! settlement signature from exactly the party who funded the seat. The browser
//! uses WebCrypto `'Ed25519'` (RFC8032): raw 32-byte pubkey (64 hex), raw 64-byte
//! signature (128 hex). `ed25519-dalek` produces the identical bytes, so a sig made
//! here verifies in the escrow (`verify_settlement_sig`) and in the browser
//! (`verifyEd25519`), and vice-versa.
//!
//! Derivation:
//!   - selfplay: derived deterministically from the run `--seed` + seat, so a run is
//!     fully reproducible (same seed ⇒ same identity ⇒ same signatures).
//!   - play: loaded from a file path (raw 32-byte secret seed), generated + persisted
//!     on first use so a seat keeps a stable identity across reconnects.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;

/// One seat's persistent Ed25519 identity.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Build from a raw 32-byte secret seed. The pubkey is derived from it.
    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    /// Deterministic per-seat identity for reproducible selfplay runs. The 32-byte
    /// Ed25519 secret seed is stretched from the run seed + seat with a fixed domain
    /// separator so seat 0 and seat 1 get distinct-but-reproducible keys.
    pub fn for_selfplay(run_seed: u64, seat: u8) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"pokerbot/identity/v1");
        h.update(run_seed.to_le_bytes());
        h.update([seat]);
        let seed: [u8; 32] = h.finalize().into();
        Self::from_seed_bytes(seed)
    }

    /// Load an identity from `path` (raw 32-byte secret seed). If the file does not
    /// exist, generate a fresh random identity and persist its seed there (0600).
    /// Used by the `play` seat so it keeps a stable identity across reconnects.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read identity seed from {}", path.display()))?;
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("identity file {} must be exactly 32 bytes, got {}", path.display(), bytes.len()))?;
            Ok(Self::from_seed_bytes(seed))
        } else {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            std::fs::write(path, seed)
                .with_context(|| format!("write new identity seed to {}", path.display()))?;
            // best-effort tighten perms on unix (secret material).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(Self::from_seed_bytes(seed))
        }
    }

    /// Our public identity key as 64 lowercase hex chars — the `sessionPub` value
    /// announced in `seated`, pinned in the deposit memo, and verified at settlement.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Ed25519 sign `msg`, returning a 128-hex signature (RFC8032, WebCrypto-compatible).
    pub fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.signing.sign(msg).to_bytes())
    }
}

/// Verify a hex Ed25519 signature by `pubkey_hex` (64 hex) over `msg`. Returns false
/// on any decode / length / verify failure. Mirrors the escrow's
/// `verify_settlement_sig` exactly — same failure-closed semantics.
pub fn verify(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(pubkey_hex.trim()) else { return false };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else { return false };
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return false };
    vk.verify(msg, &Signature::from_bytes(&sig_arr)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_is_64_hex_and_sig_is_128_hex() {
        let id = Identity::for_selfplay(1, 0);
        let pk = id.pubkey_hex();
        assert_eq!(pk.len(), 64, "pubkey must be 64 hex chars (32 bytes)");
        assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
        let sig = id.sign(b"hello");
        assert_eq!(sig.len(), 128, "sig must be 128 hex chars (64 bytes)");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn selfplay_identity_is_deterministic_and_seat_distinct() {
        // same seed+seat ⇒ same key (reproducible runs).
        let a1 = Identity::for_selfplay(7, 0).pubkey_hex();
        let a2 = Identity::for_selfplay(7, 0).pubkey_hex();
        assert_eq!(a1, a2, "same seed+seat must reproduce the identity");
        // different seat ⇒ different key.
        let b = Identity::for_selfplay(7, 1).pubkey_hex();
        assert_ne!(a1, b, "seat 0 and seat 1 must differ");
        // different seed ⇒ different key.
        let c = Identity::for_selfplay(8, 0).pubkey_hex();
        assert_ne!(a1, c, "different seed must differ");
    }

    #[test]
    fn sign_verify_roundtrip_and_helper() {
        let id = Identity::for_selfplay(42, 1);
        let msg = b"zk.poker/settle/v1:ROOM:1:2:a:b:hash";
        let sig = id.sign(msg);
        assert!(verify(&id.pubkey_hex(), msg, &sig), "own sig must verify");
        // wrong message fails.
        assert!(!verify(&id.pubkey_hex(), b"tampered", &sig));
        // wrong pubkey fails.
        let other = Identity::for_selfplay(42, 0).pubkey_hex();
        assert!(!verify(&other, msg, &sig));
        // garbage sig / pubkey fail closed, never panic.
        assert!(!verify(&id.pubkey_hex(), msg, "not-hex"));
        assert!(!verify("zz", msg, &sig));
        assert!(!verify(&id.pubkey_hex(), msg, ""));
    }

    #[test]
    fn load_or_create_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("pokerbot-id-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seat.key");
        let _ = std::fs::remove_file(&path);
        let first = Identity::load_or_create(&path).unwrap().pubkey_hex();
        // second load reads the SAME persisted seed → same identity.
        let second = Identity::load_or_create(&path).unwrap().pubkey_hex();
        assert_eq!(first, second, "reloaded identity must match the persisted one");
        let _ = std::fs::remove_file(&path);
    }
}

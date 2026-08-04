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

/// Alias for `verify` under the name the transcript verifier ("the jury") calls.
/// Same failure-closed ed25519 check; kept as a distinct name so the verifier
/// reads against a stable interface regardless of the production `verify`.
pub fn verify_hex(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    verify(pubkey_hex, msg, sig_hex)
}

// ---------------------------------------------------------------------------
// action / delegation message helpers — the byte-exact strings the browser
// client signs (poker-server/web/src/identity.ts). The transcript verifier
// reconstructs these to check every per-action ed25519 signature and the
// zafu → session delegation chain.
// ---------------------------------------------------------------------------

/// canonical lowercase action name — the string that goes into the signed
/// action message and the transcript. Mirrors ACTION_MAP in the browser
/// engine-service.ts: { fold:0, check:1, call:2, bet:3, raise:4, allin:5 }.
pub fn action_name(action: poker_pvm::Action) -> &'static str {
    use poker_pvm::Action::*;
    match action {
        Fold => "fold",
        Check => "check",
        Call => "call",
        Bet => "bet",
        Raise => "raise",
        AllIn => "allin",
    }
}

/// parse a lowercase action name back to the engine action (inverse of
/// `action_name`). Used by the verifier to replay a transcript.
pub fn action_from_name(name: &str) -> Option<poker_pvm::Action> {
    use poker_pvm::Action::*;
    match name {
        "fold" => Some(Fold),
        "check" => Some(Check),
        "call" => Some(Call),
        "bet" => Some(Bet),
        "raise" => Some(Raise),
        "allin" => Some(AllIn),
        _ => None,
    }
}

/// the exact bytes signed for a game action:
/// `"{seat}|{action}|{amount}|{seq}"` — MUST byte-match the browser
/// `identity.ts::signAction`.
pub fn action_message(seat: u8, action: &str, amount: u64, seq: u32) -> Vec<u8> {
    format!("{}|{}|{}|{}", seat, action, amount, seq).into_bytes()
}

/// the exact bytes a zafu key signs to delegate to a per-room session key:
/// `"delegate:{sessionPubHex}:{room}"` — MUST byte-match the browser
/// `identity.ts` delegation (`delegate:{sessionPubKey}:{room}`).
pub fn delegation_message(session_pub_hex: &str, room: &str) -> Vec<u8> {
    format!("delegate:{}:{}", session_pub_hex, room).into_bytes()
}

// ---------------------------------------------------------------------------
// SessionIdentity — an EPHEMERAL per-room identity used only to PRODUCE signed
// transcripts (offline self-play + the verifier test-suite). It holds the
// secret key, so it lives only inside the reference client. Distinct from the
// production `Identity` above (that one is the on-chain-pinned session key
// loaded from a seed / file); this one models the browser's per-room ed25519
// session key plus an optional zafu long-lived key that delegates to it.
// ---------------------------------------------------------------------------

/// an ephemeral session identity (anon: session key IS the identity; zafu: a
/// long-lived zafu key delegates to the session key).
pub struct SessionIdentity {
    seat: u8,
    session: SigningKey,
    /// present only in zafu mode
    zafu: Option<SigningKey>,
    /// cached delegation signature (zafu over "delegate:{sessionPub}:{room}")
    delegation: Option<[u8; 64]>,
}

impl SessionIdentity {
    /// anon identity: session key only.
    pub fn anon(seat: u8) -> Self {
        Self {
            seat,
            session: SigningKey::generate(&mut OsRng),
            zafu: None,
            delegation: None,
        }
    }

    /// zafu identity: generate a fresh session key and delegate to it from a
    /// (freshly generated, for sim purposes) zafu key over the given room.
    pub fn zafu(seat: u8, room: &str) -> Self {
        let session = SigningKey::generate(&mut OsRng);
        let zafu = SigningKey::generate(&mut OsRng);
        let session_pub_hex = hex::encode(session.verifying_key().to_bytes());
        let sig = zafu.sign(&delegation_message(&session_pub_hex, room));
        Self {
            seat,
            session,
            zafu: Some(zafu),
            delegation: Some(sig.to_bytes()),
        }
    }

    pub fn seat(&self) -> u8 {
        self.seat
    }

    pub fn session_pub(&self) -> [u8; 32] {
        self.session.verifying_key().to_bytes()
    }

    pub fn session_pub_hex(&self) -> String {
        hex::encode(self.session_pub())
    }

    pub fn zafu_pub_hex(&self) -> Option<String> {
        self.zafu
            .as_ref()
            .map(|z| hex::encode(z.verifying_key().to_bytes()))
    }

    pub fn delegation_hex(&self) -> Option<String> {
        self.delegation.map(hex::encode)
    }

    /// the on-chain-pinned identity for this seat: the zafu pubkey in zafu
    /// mode, else the session pubkey (anon). this is the `;id:` value a real
    /// deposit memo would carry.
    pub fn pinned_id_hex(&self) -> String {
        self.zafu_pub_hex().unwrap_or_else(|| self.session_pub_hex())
    }

    /// sign a game action, returning the 64-byte signature as hex.
    pub fn sign_action(&self, action: &str, amount: u64, seq: u32) -> String {
        let msg = action_message(self.seat, action, amount, seq);
        hex::encode(self.session.sign(&msg).to_bytes())
    }
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
    fn action_name_roundtrips() {
        for a in [
            poker_pvm::Action::Fold,
            poker_pvm::Action::Check,
            poker_pvm::Action::Call,
            poker_pvm::Action::Bet,
            poker_pvm::Action::Raise,
            poker_pvm::Action::AllIn,
        ] {
            assert_eq!(action_from_name(action_name(a)), Some(a));
        }
        assert_eq!(action_from_name("bogus"), None);
    }

    #[test]
    fn session_identity_sign_and_verify_action() {
        let id = SessionIdentity::anon(0);
        let sig = id.sign_action("bet", 50, 1);
        let msg = action_message(0, "bet", 50, 1);
        assert!(verify_hex(&id.session_pub_hex(), &msg, &sig));
        // tampering the amount breaks the signature
        let bad = action_message(0, "bet", 51, 1);
        assert!(!verify_hex(&id.session_pub_hex(), &bad, &sig));
    }

    #[test]
    fn zafu_delegation_verifies() {
        let id = SessionIdentity::zafu(1, "room-7");
        let zpub = id.zafu_pub_hex().unwrap();
        let del = id.delegation_hex().unwrap();
        let msg = delegation_message(&id.session_pub_hex(), "room-7");
        assert!(verify_hex(&zpub, &msg, &del));
        // wrong room fails
        let msg2 = delegation_message(&id.session_pub_hex(), "room-8");
        assert!(!verify_hex(&zpub, &msg2, &del));
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

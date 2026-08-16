// sealed.rs — per-recipient encryption for DKG round-2 packages.
//
// WHY THIS EXISTS
//
// A DKG round-2 package carries one dealer's secret polynomial evaluated at
// one recipient. Until this module, those packages were signed but sent in
// the clear — and in a QR ceremony that means displayed on a screen.
//
// That is not a tidiness problem. With n participants and threshold t, each
// dealer's polynomial has degree t-1 and so is pinned down by t points. An
// observer of the round-2 traffic sees n-1 evaluations of every polynomial,
// which for any n > t — including 2-of-3 — interpolates them outright and
// hands over the group signing key. RFC 9591 requires round 2 to be
// confidential as well as authenticated; we had only the latter.
//
// WHY Noise_K
//
// This is the same pattern ZF's frost-client uses
// (Noise_K_25519_ChaChaPoly_BLAKE2s), so it is the Zcash ecosystem's
// transport rather than one of our own devising. That matters more than any
// property below: a reviewer can ask "did they use Noise_K correctly", which
// is answerable, instead of "is this bespoke construction sound", which is
// not.
//
// The K is what makes it usable here. Both parties' static keys are known in
// advance, so the handshake is a SINGLE message with no round trip. Round 1
// already broadcasts each participant's static key, authenticated, so round 2
// is one Noise message per recipient and the ceremony gains no extra QR
// scans. An interactive pattern like XX would have cost 1.5 round trips, and
// a round trip here means a human holding a phone up to another human.
//
// WHAT IT BINDS
//
//   recipient — it is the responder's static key; nobody else can read it
//   sender    — the `ss` mix puts the sender's static key in the key
//               schedule itself, not merely in a signature wrapped around it
//   ceremony  — passed as the Noise prologue, so both sides must agree on
//               the full participant set or the handshake produces different
//               keys and the message does not open
//
// Getting all three from the pattern is the point. The previous version of
// this file derived a key by hand and bolted sender and ceremony binding on
// through associated data, which worked but was mine to defend.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// The Noise pattern. Identical to ZF frost-client's, deliberately.
const NOISE_PATTERN: &str = "Noise_K_25519_ChaChaPoly_BLAKE2s";

/// Separation tag for deriving the X25519 key from the session's ed25519
/// seed. The two keys must not be the same key: one signs, one decrypts.
///
/// Note ZF made the opposite choice — one key, with XEdDSA to sign using an
/// X25519 key. Both are sound; theirs is more compact, this one needs no
/// special construction to justify. The wire format is unaffected either way.
const X25519_DERIVE_INFO: &[u8] = b"frost-dkg-x25519-v1";

/// Derive this session's X25519 secret from its ephemeral ed25519 seed.
///
/// Deriving rather than storing means every round recovers the key from the
/// `ephemeral_seed` already carried in the DKG secret state, so no round has
/// to thread new state through.
///
/// This is a KDF, not key reuse: the signing key is the seed, the decryption
/// key is HKDF(seed). They share an ancestor, not an exponent.
pub fn x25519_secret_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; 32];
    hk.expand(X25519_DERIVE_INFO, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// The X25519 public key a participant advertises in round 1.
pub fn x25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(x25519_secret_from_seed(seed));
    PublicKey::from(&sk).to_bytes()
}

/// A hash over the whole participant set — the ceremony's fingerprint,
/// used as the Noise prologue.
///
/// `entries` is every participant's (identifier, static key), including the
/// caller's own. Both sides build it: each knows its own pair and learns the
/// rest from round-1 broadcasts. Sorting makes it independent of the order
/// broadcasts happened to arrive in.
///
/// As a prologue this is what stops a message being replayed into a different
/// ceremony: disagree on the participant set and the handshake derives
/// different keys, so the message simply does not open.
///
/// Length prefixes rather than plain concatenation: without them ("ab","c")
/// and ("a","bc") hash identically, and a participant who can choose part of
/// the input could exploit that.
pub fn ceremony_transcript(entries: &[(String, [u8; 32])]) -> [u8; 32] {
    use sha2::Digest;

    let mut sorted: Vec<&(String, [u8; 32])> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    hasher.update(b"frost-dkg-ceremony-transcript-v1");
    hasher.update((sorted.len() as u64).to_le_bytes());
    for (id_hex, key) in sorted {
        hasher.update((id_hex.len() as u64).to_le_bytes());
        hasher.update(id_hex.as_bytes());
        hasher.update(key);
    }
    hasher.finalize().into()
}

/// Seal `plaintext` from us to `remote_public`, as a single Noise_K message.
pub fn seal(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    prologue: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut noise = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e| format!("noise pattern: {e}"))?,
    )
    .prologue(prologue)
    .local_private_key(local_private)
    .remote_public_key(remote_public)
    .build_initiator()
    .map_err(|e| format!("noise initiator: {e}"))?;

    // Noise_K is one message: ephemeral + encrypted payload + tag.
    let mut out = vec![0u8; plaintext.len() + 128];
    let n = noise
        .write_message(plaintext, &mut out)
        .map_err(|e| format!("noise write: {e}"))?;
    out.truncate(n);
    Ok(out)
}

/// Open a Noise_K message sent to us by `remote_public`.
pub fn open(
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    prologue: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let mut noise = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e| format!("noise pattern: {e}"))?,
    )
    .prologue(prologue)
    .local_private_key(local_private)
    .remote_public_key(remote_public)
    .build_responder()
    .map_err(|e| format!("noise responder: {e}"))?;

    let mut out = vec![0u8; message.len() + 128];
    let n = noise
        .read_message(message, &mut out)
        // Deliberately uninformative: which of wrong-sender, wrong-recipient,
        // wrong-ceremony or tampering caused it is not something to report
        // back differentially.
        .map_err(|_| "sealed package did not open".to_string())?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; 32] = [7u8; 32];
    const SEED_B: [u8; 32] = [9u8; 32];
    const SEED_C: [u8; 32] = [11u8; 32];

    fn transcript(tag: &str) -> [u8; 32] {
        ceremony_transcript(&[(tag.to_string(), x25519_public_from_seed(&SEED_A))])
    }

    /// The x25519-dalek public key we advertise must be the one snow expects
    /// for the same private bytes. If the two clamped differently, every
    /// handshake would fail — this pins that they agree.
    #[test]
    fn our_advertised_key_is_the_one_noise_uses() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let pk_a = x25519_public_from_seed(&SEED_A);
        let sk_b = x25519_secret_from_seed(&SEED_B);
        let pk_b = x25519_public_from_seed(&SEED_B);
        let p = transcript("c");

        let msg = seal(&sk_a, &pk_b, &p, b"hello").unwrap();
        assert_eq!(open(&sk_b, &pk_a, &p, &msg).unwrap(), b"hello");
    }

    /// The property the whole module exists for.
    #[test]
    fn the_wire_message_does_not_contain_the_plaintext() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let pk_b = x25519_public_from_seed(&SEED_B);
        let secret = b"this must not appear on a QR code";

        let msg = seal(&sk_a, &pk_b, &transcript("c"), secret).unwrap();
        assert!(msg.windows(secret.len()).all(|w| w != secret.as_slice()));
    }

    /// Recipient binding: it is the responder's static key.
    #[test]
    fn another_participant_cannot_open_it() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let pk_a = x25519_public_from_seed(&SEED_A);
        let pk_b = x25519_public_from_seed(&SEED_B);
        let sk_c = x25519_secret_from_seed(&SEED_C);
        let p = transcript("c");

        let msg = seal(&sk_a, &pk_b, &p, b"for b only").unwrap();
        assert!(open(&sk_c, &pk_a, &p, &msg).is_err());
    }

    /// Sender binding, and this is the upgrade over the previous hand-rolled
    /// version: `ss` puts the sender's static key in the key schedule, so a
    /// message cannot be reattributed even by someone who re-signs it.
    #[test]
    fn a_message_cannot_be_reattributed_to_another_sender() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let sk_b = x25519_secret_from_seed(&SEED_B);
        let pk_b = x25519_public_from_seed(&SEED_B);
        let pk_c = x25519_public_from_seed(&SEED_C);
        let p = transcript("c");

        let msg = seal(&sk_a, &pk_b, &p, b"from a").unwrap();
        // B tries to open it believing C sent it
        assert!(open(&sk_b, &pk_c, &p, &msg).is_err());
    }

    /// Ceremony binding, via the prologue.
    #[test]
    fn a_message_from_another_ceremony_does_not_open() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let pk_a = x25519_public_from_seed(&SEED_A);
        let sk_b = x25519_secret_from_seed(&SEED_B);
        let pk_b = x25519_public_from_seed(&SEED_B);

        let msg = seal(&sk_a, &pk_b, &transcript("ceremony-one"), b"share").unwrap();
        assert!(open(&sk_b, &pk_a, &transcript("ceremony-two"), &msg).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let pk_a = x25519_public_from_seed(&SEED_A);
        let sk_b = x25519_secret_from_seed(&SEED_B);
        let pk_b = x25519_public_from_seed(&SEED_B);
        let p = transcript("c");

        let mut msg = seal(&sk_a, &pk_b, &p, b"share").unwrap();
        let last = msg.len() - 1;
        msg[last] ^= 0x01;
        assert!(open(&sk_b, &pk_a, &p, &msg).is_err());
    }

    /// Noise_K mixes a fresh ephemeral, so two seals of the same plaintext
    /// must differ — otherwise the ceremony leaks which dealers sent equal
    /// packages.
    #[test]
    fn each_message_is_fresh() {
        let sk_a = x25519_secret_from_seed(&SEED_A);
        let pk_b = x25519_public_from_seed(&SEED_B);
        let p = transcript("c");

        let one = seal(&sk_a, &pk_b, &p, b"same").unwrap();
        let two = seal(&sk_a, &pk_b, &p, b"same").unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn the_x25519_key_is_not_the_ed25519_seed() {
        assert_ne!(x25519_secret_from_seed(&SEED_A), SEED_A);
    }

    /// The transcript must not depend on the order broadcasts arrived in.
    #[test]
    fn the_transcript_is_order_independent() {
        let a = ("aa".to_string(), [1u8; 32]);
        let b = ("bb".to_string(), [2u8; 32]);
        assert_eq!(
            ceremony_transcript(&[a.clone(), b.clone()]),
            ceremony_transcript(&[b, a])
        );
    }

    /// Length prefixing: these must not collide.
    #[test]
    fn the_transcript_is_not_ambiguous() {
        assert_ne!(
            ceremony_transcript(&[("ab".to_string(), [0u8; 32]), ("c".to_string(), [0u8; 32])]),
            ceremony_transcript(&[("a".to_string(), [0u8; 32]), ("bc".to_string(), [0u8; 32])])
        );
    }
}

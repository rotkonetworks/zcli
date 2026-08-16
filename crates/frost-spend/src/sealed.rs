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
// SHAPE
//
// Each recipient advertises an X25519 public key in its round-1 broadcast.
// The sender generates a FRESH ephemeral X25519 keypair per package, does
// ECDH against the recipient's key, and derives a one-use AEAD key from it.
//
// Fresh-per-package is what makes the rest simple. The derived key is used
// exactly once, so there is no nonce-reuse question to get wrong and no
// per-pair counter to carry across rounds; a zero nonce is correct here for
// the same reason it is in libsodium's sealed boxes and in age. It also
// means a sender's compromised long-term state cannot retroactively open
// packages it already sent.
//
// Authenticity is NOT this module's job — the sealed box travels inside the
// existing SignedMessage, which is what proves who sent it. What this module
// must prevent is a valid ciphertext being replayed into a different slot,
// so the recipient's identifier is bound into the AEAD associated data and a
// package addressed to one participant will not open for another.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Domain tag. Changing the wire format MUST change this, so that a package
/// from an older format fails to open rather than opening as something else.
const KDF_INFO: &[u8] = b"frost-dkg-round2-seal-v1";

/// Separation tag for deriving the X25519 key from the session's ed25519
/// seed. The two keys must not be the same key: one signs, one decrypts.
const X25519_DERIVE_INFO: &[u8] = b"frost-dkg-x25519-v1";

/// A package sealed to one recipient.
///
/// Hex rather than serde's default byte arrays for the same reason
/// SignedMessage does it: these ride in QR frames, where a 3.5x encoding
/// blowup is the difference between one frame and several.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedBox {
    /// Sender's ephemeral X25519 public key, fresh for this package.
    #[serde(with = "hex::serde")]
    pub epk: Vec<u8>,
    /// ChaCha20-Poly1305 ciphertext with tag appended.
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
}

/// Derive this session's X25519 secret from its ephemeral ed25519 seed.
///
/// Deriving rather than storing means every round can recover the key from
/// the `ephemeral_seed` already carried in the DKG secret state, so no round
/// has to thread new state through.
///
/// This is a KDF, not key reuse: the signing key is the seed, the decryption
/// key is HKDF(seed). They share an ancestor, not an exponent.
pub fn x25519_secret_from_seed(seed: &[u8; 32]) -> StaticSecret {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut out = [0u8; 32];
    hk.expand(X25519_DERIVE_INFO, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    StaticSecret::from(out)
}

/// The X25519 public key a participant advertises in round 1.
pub fn x25519_public_from_seed(seed: &[u8; 32]) -> PublicKey {
    PublicKey::from(&x25519_secret_from_seed(seed))
}

/// Derive the one-use AEAD key for a (ephemeral, recipient) pair.
///
/// Both public keys go into the salt so that a shared secret cannot be
/// repurposed under a different pairing.
fn derive_key(shared: &[u8; 32], epk: &PublicKey, rpk: &PublicKey) -> Key {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(epk.as_bytes());
    salt.extend_from_slice(rpk.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(KDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    *Key::from_slice(&key)
}

/// Seal `plaintext` to `recipient`, binding it to `aad`.
///
/// `aad` should identify who the package is for. A sealed box that is not
/// bound to its recipient can be lifted out of one participant's message and
/// dropped into another's, which the AEAD will happily accept.
pub fn seal(
    recipient: &PublicKey,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<SealedBox, String> {
    let esk = EphemeralSecret::random_from_rng(rng);
    let epk = PublicKey::from(&esk);
    let shared = esk.diffie_hellman(recipient);

    // Reject a degenerate shared secret. A contributory-behaviour check costs
    // nothing here and refuses the all-zero output that a small-order peer
    // key would produce.
    if !shared.was_contributory() {
        return Err("x25519: non-contributory shared secret".into());
    }

    let key = derive_key(shared.as_bytes(), &epk, recipient);
    let cipher = ChaCha20Poly1305::new(&key);
    // Zero nonce: the key is derived from a fresh ephemeral scalar and is
    // therefore used for exactly one message. See the module note.
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| "seal: aead encrypt failed".to_string())?;

    Ok(SealedBox {
        epk: epk.as_bytes().to_vec(),
        ct,
    })
}

/// Open a sealed box addressed to us. `aad` must match what the sender bound.
pub fn open(secret: &StaticSecret, aad: &[u8], sealed: &SealedBox) -> Result<Vec<u8>, String> {
    let epk_bytes: [u8; 32] = sealed
        .epk
        .as_slice()
        .try_into()
        .map_err(|_| "invalid x25519 ephemeral pubkey length")?;
    let epk = PublicKey::from(epk_bytes);
    let shared = secret.diffie_hellman(&epk);
    if !shared.was_contributory() {
        return Err("x25519: non-contributory shared secret".into());
    }

    let rpk = PublicKey::from(secret);
    let key = derive_key(shared.as_bytes(), &epk, &rpk);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        // Deliberately uninformative: whether it was the wrong recipient, a
        // tampered ciphertext or a mismatched aad is not something to report
        // back differentially.
        .map_err(|_| "sealed package did not open".to_string())
}

/// Associated data binding a round-2 package to its recipient.
pub fn round2_aad(recipient_id_hex: &str) -> Vec<u8> {
    let mut aad = Vec::from(KDF_INFO);
    aad.push(b'|');
    aad.extend_from_slice(recipient_id_hex.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn seeds() -> ([u8; 32], [u8; 32]) {
        ([7u8; 32], [9u8; 32])
    }

    #[test]
    fn round_trips_to_the_intended_recipient() {
        let (seed, _) = seeds();
        let sk = x25519_secret_from_seed(&seed);
        let pk = x25519_public_from_seed(&seed);
        let aad = round2_aad("aabb");

        let sealed = seal(&pk, &aad, b"secret share", &mut OsRng).unwrap();
        assert_eq!(open(&sk, &aad, &sealed).unwrap(), b"secret share");
    }

    /// The property the whole module exists for: an observer of the wire
    /// learns nothing, and the plaintext is not sitting in the bytes.
    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let (seed, _) = seeds();
        let pk = x25519_public_from_seed(&seed);
        let aad = round2_aad("aabb");
        let secret = b"this must not appear on a QR code";

        let sealed = seal(&pk, &aad, secret, &mut OsRng).unwrap();
        assert!(sealed
            .ct
            .windows(secret.len())
            .all(|w| w != secret.as_slice()));
    }

    #[test]
    fn another_participant_cannot_open_it() {
        let (a, b) = seeds();
        let pk_a = x25519_public_from_seed(&a);
        let sk_b = x25519_secret_from_seed(&b);
        let aad = round2_aad("aabb");

        let sealed = seal(&pk_a, &aad, b"for a only", &mut OsRng).unwrap();
        assert!(open(&sk_b, &aad, &sealed).is_err());
    }

    /// Replaying a valid package into a different recipient slot must fail —
    /// this is what binding the identifier into the aad buys.
    #[test]
    fn a_package_cannot_be_replayed_under_another_identifier() {
        let (seed, _) = seeds();
        let sk = x25519_secret_from_seed(&seed);
        let pk = x25519_public_from_seed(&seed);

        let sealed = seal(&pk, &round2_aad("aabb"), b"share", &mut OsRng).unwrap();
        assert!(open(&sk, &round2_aad("ccdd"), &sealed).is_err());
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let (seed, _) = seeds();
        let sk = x25519_secret_from_seed(&seed);
        let pk = x25519_public_from_seed(&seed);
        let aad = round2_aad("aabb");

        let mut sealed = seal(&pk, &aad, b"share", &mut OsRng).unwrap();
        sealed.ct[0] ^= 0x01;
        assert!(open(&sk, &aad, &sealed).is_err());
    }

    /// Two seals of the same plaintext to the same recipient must differ,
    /// or the ceremony leaks which dealers sent equal packages.
    #[test]
    fn each_seal_is_fresh() {
        let (seed, _) = seeds();
        let pk = x25519_public_from_seed(&seed);
        let aad = round2_aad("aabb");

        let one = seal(&pk, &aad, b"same", &mut OsRng).unwrap();
        let two = seal(&pk, &aad, b"same", &mut OsRng).unwrap();
        assert_ne!(one.epk, two.epk);
        assert_ne!(one.ct, two.ct);
    }

    /// The signing key and the decryption key must not be the same bytes.
    #[test]
    fn the_x25519_key_is_not_the_ed25519_seed() {
        let (seed, _) = seeds();
        assert_ne!(x25519_secret_from_seed(&seed).to_bytes(), seed);
    }
}

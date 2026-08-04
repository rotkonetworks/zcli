//! E2EE session crypto — byte-identical to the browser WebCrypto path in
//! `poker-server/web/src/transport.ts`.
//!
//! Handshake: each seat generates an ephemeral X25519 keypair and swaps public
//! keys in the clear (`_keyex`). The shared secret is X25519(my_sk, their_pk);
//! the AES key is `HKDF-SHA256(salt = 32 zero bytes, ikm = shared, info =
//! "poker-session")` truncated to 32 bytes. Payloads are AES-256-GCM with a
//! random 12-byte IV; the wire string is `base64(iv) + "." + base64(ct||tag)`.
//!
//! The browser derives the identical key because WebCrypto's `deriveBits`
//! returns the raw 32-byte DH output and its HKDF/AES-GCM use the same salt,
//! info and tag layout (aes-gcm appends the 16-byte tag to the ciphertext,
//! matching `crypto.subtle.encrypt`).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF `info` string — must match the browser exactly.
const HKDF_INFO: &[u8] = b"poker-session";

/// One seat's ephemeral X25519 identity plus the derived AES session key once
/// the peer's public key has arrived.
pub struct Session {
    secret: StaticSecret,
    public: PublicKey,
    /// AES-256-GCM cipher, `Some` once `derive` has run.
    cipher: Option<Aes256Gcm>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// Generate a fresh ephemeral keypair for this seat.
    pub fn new() -> Self {
        // StaticSecret (static_secrets feature) lets us hold the secret across
        // the async handshake; for a single ephemeral session that's fine.
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public, cipher: None }
    }

    /// Our public key, base64(standard, padded) — the `pk` field on the wire.
    pub fn public_b64(&self) -> String {
        B64.encode(self.public.to_bytes())
    }

    /// True once the shared AES key has been derived from the peer's pubkey.
    pub fn ready(&self) -> bool {
        self.cipher.is_some()
    }

    /// Derive the shared AES-256-GCM key from the peer's base64 X25519 pubkey.
    /// Idempotent: a second `_keyex` from the peer re-derives the same key.
    pub fn derive(&mut self, peer_pk_b64: &str) -> Result<()> {
        let raw = B64
            .decode(peer_pk_b64.trim())
            .context("peer pk is not valid base64")?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("peer pk must be 32 bytes, got {}", raw.len()))?;
        let peer_pub = PublicKey::from(arr);
        let shared = self.secret.diffie_hellman(&peer_pub);

        // HKDF-SHA256 with a 32-byte zero salt and info = "poker-session".
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared.as_bytes());
        let mut key32 = [0u8; 32];
        hk.expand(HKDF_INFO, &mut key32)
            .map_err(|_| anyhow!("hkdf expand failed"))?;

        let key = Key::<Aes256Gcm>::from_slice(&key32);
        self.cipher = Some(Aes256Gcm::new(key));
        Ok(())
    }

    /// Encrypt a plaintext game-message string into the `d.p` wire form
    /// `base64(iv).base64(ct||tag)`.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let cipher = self.cipher.as_ref().ok_or_else(|| anyhow!("session key not derived"))?;
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad: &[] })
            .map_err(|_| anyhow!("aes-gcm encrypt failed"))?;
        Ok(format!("{}.{}", B64.encode(iv), B64.encode(ct)))
    }

    /// Decrypt a `d.p` wire string back into the plaintext game-message string.
    pub fn decrypt(&self, wire: &str) -> Result<String> {
        let cipher = self.cipher.as_ref().ok_or_else(|| anyhow!("session key not derived"))?;
        let (iv_b64, ct_b64) = wire
            .split_once('.')
            .ok_or_else(|| anyhow!("bad envelope: no '.' separator"))?;
        let iv = B64.decode(iv_b64).context("iv base64")?;
        let ct = B64.decode(ct_b64).context("ct base64")?;
        if iv.len() != 12 {
            return Err(anyhow!("iv must be 12 bytes, got {}", iv.len()));
        }
        let nonce = Nonce::from_slice(&iv);
        let pt = cipher
            .decrypt(nonce, Payload { msg: &ct, aad: &[] })
            .map_err(|_| anyhow!("aes-gcm decrypt failed (auth tag mismatch?)"))?;
        String::from_utf8(pt).context("plaintext is not utf-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_agrees_and_roundtrips() {
        // Two seats derive the same key and can decrypt each other's frames.
        let mut a = Session::new();
        let mut b = Session::new();
        a.derive(&b.public_b64()).unwrap();
        b.derive(&a.public_b64()).unwrap();
        assert!(a.ready() && b.ready());

        let msg = r#"{"t":"action","d":{"action":"call","amount":0,"seq":1}}"#;
        let wire = a.encrypt(msg).unwrap();
        assert!(wire.contains('.'));
        assert_eq!(b.decrypt(&wire).unwrap(), msg);

        // symmetric the other way
        let wire2 = b.encrypt(msg).unwrap();
        assert_eq!(a.decrypt(&wire2).unwrap(), msg);
    }

    #[test]
    fn wrong_peer_fails_to_decrypt() {
        let mut a = Session::new();
        let mut b = Session::new();
        let c = Session::new();
        a.derive(&c.public_b64()).unwrap(); // a keyed to c, not b
        b.derive(&a.public_b64()).unwrap();
        let wire = b.encrypt("hello").unwrap();
        assert!(a.decrypt(&wire).is_err());
    }
}

//! Door codes, the magic wormhole way: a PAKE over a code's words.
//!
//! A code is `7-fern-dusk`. The number is a nameplate: the relay sees it and
//! uses it to pick a mailbox. The words never leave the device; both sides run
//! SPAKE2 (RustCrypto `spake2`, Ed25519 group, the construction magic wormhole
//! uses) over them, so the relay, which sees every message, gets no offline
//! test of a guess. Someone who guesses has to take part, and gets exactly one
//! guess per run, which a key-confirmation tag then tells the other side about.
//!
//! The door has a host (who made the code) and joiners. A joiner speaks first
//! (`Join`); the host answers each joiner with its own run (`Host`), its
//! message and a tag over it, so a wrong word is seen by the joiner at once.
//! More than two people means one run per joiner, never one run shared.
//!
//! The functions are stateless on purpose: a run is rebuilt from 32 bytes of
//! entropy the caller keeps (random per door, never a wallet seed), so a popup
//! can close between "start" and "finish" and nothing secret lives in the wasm
//! heap. The scalar is HKDF(entropy, session, side): no two runs share one.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;

const DOMAIN: &[u8] = b"zafu-door-v3";

/// Who speaks in a run: the joiner first, then the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Host,
    Join,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PakeError {
    /// the peer's message is not a SPAKE2 message of the other side
    BadMessage,
    /// entropy or a key of the wrong length
    BadInput,
}

impl std::fmt::Display for PakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PakeError::BadMessage => "not a door message",
            PakeError::BadInput => "a door key must be 32 bytes",
        })
    }
}

/// The words as both sides type them: case, spaces and dashes forgiven, the
/// number dropped (it is the nameplate, public anyway).
pub fn normalize(code: &str) -> String {
    code.to_lowercase()
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn hkdf32(ikm: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(DOMAIN), ikm)
        .expand_multi_info(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

fn ids(session: &[u8]) -> (Identity, Identity) {
    let id = |who: &[u8]| Identity::new(&[DOMAIN, b"/", who, b"/", session].concat());
    (id(b"host"), id(b"join"))
}

fn run(
    side: Side,
    code: &str,
    session: &[u8],
    entropy: &[u8],
) -> Result<(Spake2<Ed25519Group>, Vec<u8>), PakeError> {
    if entropy.len() != 32 {
        return Err(PakeError::BadInput);
    }
    let label: &[u8] = match side {
        Side::Host => b"host",
        Side::Join => b"join",
    };
    let rng = ChaCha20Rng::from_seed(hkdf32(entropy, &[b"scalar", label, session]));
    let pw = Password::new(normalize(code).as_bytes());
    let (host, join) = ids(session);
    Ok(match side {
        Side::Host => Spake2::<Ed25519Group>::start_a_with_rng(&pw, &host, &join, rng),
        Side::Join => Spake2::<Ed25519Group>::start_b_with_rng(&pw, &host, &join, rng),
    })
}

/// This side's message for one run (33 bytes).
pub fn message(
    side: Side,
    code: &str,
    session: &[u8],
    entropy: &[u8],
) -> Result<Vec<u8>, PakeError> {
    run(side, code, session, entropy).map(|(_, msg)| msg)
}

/// The run's 32-byte key, from this side's entropy and the peer's message. A
/// wrong word gives a key the other side does not have; [`check`] says so.
pub fn finish(
    side: Side,
    code: &str,
    session: &[u8],
    entropy: &[u8],
    peer: &[u8],
) -> Result<[u8; 32], PakeError> {
    let (state, _) = run(side, code, session, entropy)?;
    let k = state.finish(peer).map_err(|_| PakeError::BadMessage)?;
    // the transcript (both messages, both identities, the words) is already
    // in spake2's key; this only gives the door its own name for it
    Ok(hkdf32(&k, &[b"key"]))
}

fn key32(key: &[u8]) -> Result<&[u8], PakeError> {
    (key.len() == 32).then_some(key).ok_or(PakeError::BadInput)
}

/// Key confirmation: a tag over the message this side sent.
pub fn confirm(key: &[u8], own_msg: &[u8]) -> Result<[u8; 32], PakeError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&hkdf32(key32(key)?, &[b"confirm"]))
        .expect("HMAC takes any key length");
    mac.update(own_msg);
    Ok(mac.finalize().into_bytes().into())
}

/// The peer's tag over its message matches this key: same words, same run.
pub fn check(key: &[u8], peer_msg: &[u8], tag: &[u8]) -> bool {
    confirm(key, peer_msg).is_ok_and(|t| t.ct_eq(tag).into())
}

/// Two words both sides can compare, if they want to: 22 bits of the key.
pub fn verify_words(key: &[u8]) -> Result<String, PakeError> {
    let h = hkdf32(key32(key)?, &[b"verify"]);
    let words = bip39::Language::English.word_list();
    let a = ((h[0] as usize) << 3) | (h[1] as usize >> 5);
    let b = ((h[2] as usize) << 3) | (h[3] as usize >> 5);
    Ok(format!("{} {}", words[a], words[b]))
}

fn side_of(host: bool) -> Side {
    if host {
        Side::Host
    } else {
        Side::Join
    }
}

fn js(e: PakeError) -> JsError {
    JsError::new(&e.to_string())
}

/// `host`: this side made the code. Returns this side's 33-byte message.
#[wasm_bindgen]
pub fn door_pake_message(
    host: bool,
    code: &str,
    session: &[u8],
    entropy: &[u8],
) -> Result<Vec<u8>, JsError> {
    message(side_of(host), code, session, entropy).map_err(js)
}

/// The run's 32-byte key; throws when the peer's message is not one.
#[wasm_bindgen]
pub fn door_pake_finish(
    host: bool,
    code: &str,
    session: &[u8],
    entropy: &[u8],
    peer: &[u8],
) -> Result<Vec<u8>, JsError> {
    finish(side_of(host), code, session, entropy, peer)
        .map(|k| k.to_vec())
        .map_err(js)
}

#[wasm_bindgen]
pub fn door_pake_confirm(key: &[u8], own_msg: &[u8]) -> Result<Vec<u8>, JsError> {
    confirm(key, own_msg).map(|t| t.to_vec()).map_err(js)
}

#[wasm_bindgen]
pub fn door_pake_check(key: &[u8], peer_msg: &[u8], tag: &[u8]) -> bool {
    check(key, peer_msg, tag)
}

#[wasm_bindgen]
pub fn door_pake_verify_words(key: &[u8]) -> Result<String, JsError> {
    verify_words(key).map_err(js)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &[u8] = b"salt-0123456789abjoiner01";

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// one run: the joiner speaks, the host answers; both keys
    fn both(host_code: &str, join_code: &str, session: &[u8]) -> ([u8; 32], [u8; 32], Vec<u8>) {
        let y = message(Side::Join, join_code, session, &seed(2)).unwrap();
        let x = message(Side::Host, host_code, session, &seed(1)).unwrap();
        let kh = finish(Side::Host, host_code, session, &seed(1), &y).unwrap();
        let kj = finish(Side::Join, join_code, session, &seed(2), &x).unwrap();
        (kh, kj, x)
    }

    #[test]
    fn matching_codes_agree() {
        let (kh, kj, x) = both("7-fern-dusk", "fern dusk", SESSION);
        assert_eq!(kh, kj);
        assert!(check(&kj, &x, &confirm(&kh, &x).unwrap()));
        assert_eq!(verify_words(&kh).unwrap(), verify_words(&kj).unwrap());
        assert_eq!(verify_words(&kh).unwrap().split(' ').count(), 2);
    }

    #[test]
    fn normalization_forgives_how_a_code_is_typed() {
        assert_eq!(normalize("  7 - Fern   DUSK "), "fern-dusk");
        let (kh, kj, _) = both("7-fern-dusk", "  7 Fern-DUSK", SESSION);
        assert_eq!(kh, kj);
    }

    #[test]
    fn a_wrong_word_gives_another_key_and_the_tag_fails() {
        let (kh, kj, x) = both("7-fern-dusk", "7-fern-dawn", SESSION);
        assert_ne!(kh, kj);
        let tag = confirm(&kh, &x).unwrap();
        assert!(!check(&kj, &x, &tag), "a wrong word must be seen");
    }

    #[test]
    fn one_guess_per_run() {
        // a joiner holds one message (one guess); every other word fails against it
        let y = message(Side::Join, "fern-dawn", SESSION, &seed(2)).unwrap();
        let x = message(Side::Host, "fern-dusk", SESSION, &seed(1)).unwrap();
        let kh = finish(Side::Host, "fern-dusk", SESSION, &seed(1), &y).unwrap();
        let tag = confirm(&kh, &x).unwrap();
        for guess in ["fern-dawn", "fern-dust", "fern-duck", "dusk-fern"] {
            let kj = finish(Side::Join, guess, SESSION, &seed(2), &x).unwrap();
            assert!(!check(&kj, &x, &tag), "{guess}");
        }
    }

    #[test]
    fn the_key_is_bound_to_the_session() {
        let (k1, _, _) = both("fern-dusk", "fern-dusk", b"session-one");
        let (k2, _, _) = both("fern-dusk", "fern-dusk", b"session-two");
        assert_ne!(k1, k2);
        // messages made for one session do not finish another
        let y = message(Side::Join, "fern-dusk", b"session-one", &seed(2)).unwrap();
        let x = message(Side::Host, "fern-dusk", b"session-two", &seed(1)).unwrap();
        let kh = finish(Side::Host, "fern-dusk", b"session-two", &seed(1), &y).unwrap();
        let kj = finish(Side::Join, "fern-dusk", b"session-one", &seed(2), &x).unwrap();
        assert_ne!(kh, kj);
    }

    #[test]
    fn the_key_is_bound_to_the_transcript() {
        // the tag names the message it was made over: a tag moved to another
        // message, or a message swapped under it, fails
        let (kh, kj, x) = both("fern-dusk", "fern-dusk", SESSION);
        let tag = confirm(&kh, &x).unwrap();
        let other = message(Side::Host, "fern-dusk", SESSION, &seed(9)).unwrap();
        assert!(!check(&kj, &other, &tag));
        // and a host message swapped in transit yields a different key
        let kj2 = finish(Side::Join, "fern-dusk", SESSION, &seed(2), &other).unwrap();
        assert_ne!(kj, kj2);
    }

    #[test]
    fn a_run_is_rebuilt_from_its_seed() {
        let a = message(Side::Join, "fern-dusk", SESSION, &seed(2)).unwrap();
        let b = message(Side::Join, "fern-dusk", SESSION, &seed(2)).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 33);
        // a new session never reuses the scalar of another
        let c = message(Side::Join, "fern-dusk", b"another", &seed(2)).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn sides_cannot_be_swapped() {
        // a joiner's message fed to a joiner is refused, not mis-keyed
        let y = message(Side::Join, "fern-dusk", SESSION, &seed(2)).unwrap();
        assert_eq!(
            finish(Side::Join, "fern-dusk", SESSION, &seed(3), &y),
            Err(PakeError::BadMessage)
        );
        assert_eq!(
            finish(Side::Host, "fern-dusk", SESSION, &seed(1), &y[..20]),
            Err(PakeError::BadMessage)
        );
    }

    #[test]
    fn bad_lengths_are_refused() {
        assert_eq!(
            message(Side::Join, "a-b", SESSION, &[0; 31]),
            Err(PakeError::BadInput)
        );
        assert_eq!(confirm(&[0; 31], b"m"), Err(PakeError::BadInput));
        assert!(!check(&[0; 31], b"m", &[0; 32]));
    }
}

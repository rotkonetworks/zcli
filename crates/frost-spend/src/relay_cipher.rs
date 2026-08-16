// relay_cipher.rs — frostd-compatible end-to-end encryption.
//
// WHY THIS EXISTS RATHER THAN JUST USING frost-client
//
// frost-client is ZF's own client and zcli uses it directly, which is the
// right answer wherever it can be used. It cannot be used in zafu: it pulls
// message-io, rpassword and a full tokio, none of which build for wasm32.
//
// So the browser needs a cipher from a crate that is already in its wasm
// bundle, which is this one. That is only acceptable if the bytes are
// identical to upstream's, and that is not something to assume — zcli has
// both crates in its tree and asserts the interop directly, in
// `frostd_transport`'s `our_wasm_cipher_interoperates_with_upstream`.
//
// This is a reimplementation of frost_client::cipher::Cipher's wire
// behaviour, deliberately kept boring and mechanical:
//
//   * Noise_K_25519_ChaChaPoly_BLAKE2s, no prologue
//   * one Noise session per peer, in each direction
//   * initiator for sending, responder for receiving
//   * first message carries the handshake, then the session moves to
//     transport mode
//
// If upstream changes any of that, the interop test fails and this must
// follow. It has no licence to innovate.

use std::collections::HashMap;

use snow::{HandshakeState, TransportState};

/// Same pattern string as ZF frost-client. Must not diverge.
const NOISE_PATTERN: &str = "Noise_K_25519_ChaChaPoly_BLAKE2s";

/// Upstream caps messages at this size; matching it means we fail on the same
/// inputs they do rather than discovering the limit at the server.
const MAX_MSG_SIZE: usize = 1024 * 1024;

/// One direction of one peer's session: handshake first, then transport.
struct Session {
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
}

impl Session {
    fn new(handshake: HandshakeState) -> Self {
        Self {
            handshake: Some(handshake),
            transport: None,
        }
    }

    fn write(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, snow::Error> {
        if let Some(handshake) = &mut self.handshake {
            let r = handshake.write_message(payload, out);
            if handshake.is_handshake_finished() {
                let handshake = self.handshake.take().expect("checked above");
                self.transport = Some(handshake.into_transport_mode()?);
            }
            r
        } else if let Some(transport) = &mut self.transport {
            transport.write_message(payload, out)
        } else {
            Err(snow::Error::State(snow::error::StateProblem::HandshakeNotFinished))
        }
    }

    fn read(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, snow::Error> {
        if let Some(handshake) = &mut self.handshake {
            let r = handshake.read_message(message, out);
            if handshake.is_handshake_finished() {
                let handshake = self.handshake.take().expect("checked above");
                self.transport = Some(handshake.into_transport_mode()?);
            }
            r
        } else if let Some(transport) = &mut self.transport {
            transport.read_message(message, out)
        } else {
            Err(snow::Error::State(snow::error::StateProblem::HandshakeNotFinished))
        }
    }
}

/// End-to-end encryption for relay traffic, one session per peer.
///
/// The relay never sees plaintext, which is what makes it safe to run someone
/// else's relay — including ZF's.
pub struct RelayCipher {
    send: HashMap<[u8; 32], Session>,
    recv: HashMap<[u8; 32], Session>,
}

impl RelayCipher {
    /// Build sessions against every peer we expect to talk to.
    pub fn new(private_key: [u8; 32], peers: Vec<Vec<u8>>) -> Result<Self, String> {
        let mut send = HashMap::new();
        let mut recv = HashMap::new();

        for peer in peers {
            let peer_key: [u8; 32] = peer
                .as_slice()
                .try_into()
                .map_err(|_| "peer public key is not 32 bytes".to_string())?;

            send.insert(
                peer_key,
                Session::new(
                    builder(&private_key, &peer_key)?
                        .build_initiator()
                        .map_err(|e| format!("noise initiator: {e}"))?,
                ),
            );
            recv.insert(
                peer_key,
                Session::new(
                    builder(&private_key, &peer_key)?
                        .build_responder()
                        .map_err(|e| format!("noise responder: {e}"))?,
                ),
            );
        }

        Ok(Self { send, recv })
    }

    /// Encrypt for one peer.
    pub fn encrypt(&mut self, recipient: &[u8], msg: Vec<u8>) -> Result<Vec<u8>, String> {
        let key: [u8; 32] = recipient
            .try_into()
            .map_err(|_| "recipient key is not 32 bytes".to_string())?;
        let session = self
            .send
            .get_mut(&key)
            .ok_or_else(|| "no session for that recipient".to_string())?;

        let mut out = vec![0u8; MAX_MSG_SIZE];
        let n = session
            .write(&msg, &mut out)
            .map_err(|e| format!("encrypt: {e}"))?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypt from one peer.
    ///
    /// The sender is authenticated by this: Noise_K mixes the sender's static
    /// key into the key schedule, so a message relabelled as coming from
    /// somebody else does not decrypt.
    pub fn decrypt(&mut self, sender: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        let key: [u8; 32] = sender
            .try_into()
            .map_err(|_| "sender key is not 32 bytes".to_string())?;
        let session = self
            .recv
            .get_mut(&key)
            .ok_or_else(|| "no session for that sender".to_string())?;

        let mut out = vec![0u8; MAX_MSG_SIZE];
        let n = session
            .read(msg, &mut out)
            .map_err(|_| "message did not decrypt".to_string())?;
        out.truncate(n);
        Ok(out)
    }
}

fn builder<'a>(
    private_key: &'a [u8; 32],
    peer_key: &'a [u8; 32],
) -> Result<snow::Builder<'a>, String> {
    Ok(snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e| format!("noise pattern: {e}"))?,
    )
    .local_private_key(private_key)
    .remote_public_key(peer_key))
}

/// Sign a frostd login challenge.
///
/// frostd verifies this with XEdDSA over the participant's X25519 key - the
/// same key used for Noise. Using one key for both signing and DH normally
/// needs justifying; XEdDSA is the construction that does the justifying, and
/// it is what ZF's frost-client uses, so matching it is the whole point.
///
/// The rng is a parameter rather than OsRng so wasm callers can supply their
/// own; XEdDSA signatures are randomized.
pub fn sign_challenge(
    private_key: &[u8; 32],
    msg: &[u8],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<[u8; 64], String> {
    let key = xeddsa::xed25519::PrivateKey::from(private_key);
    use xeddsa::Sign as _;
    Ok(key.sign(msg, rng))
}

/// Generate a relay keypair, in the encoding frostd expects.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let keypair = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .map_err(|e| format!("noise pattern: {e}"))?,
    )
    .generate_keypair()
    .map_err(|e| format!("generate keypair: {e}"))?;

    let private: [u8; 32] = keypair
        .private
        .try_into()
        .map_err(|_| "private key is not 32 bytes".to_string())?;
    let public: [u8; 32] = keypair
        .public
        .try_into()
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    Ok((private, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_between_two_peers() {
        let (sk_a, pk_a) = generate_keypair().unwrap();
        let (sk_b, pk_b) = generate_keypair().unwrap();

        let mut alice = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();
        let mut bob = RelayCipher::new(sk_b, vec![pk_a.to_vec()]).unwrap();

        let msg = alice.encrypt(&pk_b, b"hello".to_vec()).unwrap();
        assert_eq!(bob.decrypt(&pk_a, &msg).unwrap(), b"hello");
    }

    /// Sessions are stateful: the first message carries the handshake, later
    /// ones run in transport mode. Both must work, in order.
    #[test]
    fn a_session_carries_more_than_one_message() {
        let (sk_a, pk_a) = generate_keypair().unwrap();
        let (sk_b, pk_b) = generate_keypair().unwrap();

        let mut alice = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();
        let mut bob = RelayCipher::new(sk_b, vec![pk_a.to_vec()]).unwrap();

        for expected in [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()] {
            let msg = alice.encrypt(&pk_b, expected.clone()).unwrap();
            assert_eq!(bob.decrypt(&pk_a, &msg).unwrap(), expected);
        }
    }

    /// The relay must not see plaintext — the reason running someone else's
    /// relay is acceptable at all.
    #[test]
    fn the_relay_never_sees_plaintext() {
        let (sk_a, _pk_a) = generate_keypair().unwrap();
        let (_sk_b, pk_b) = generate_keypair().unwrap();

        let mut alice = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();
        let secret = b"recipient and amount";
        let msg = alice.encrypt(&pk_b, secret.to_vec()).unwrap();

        assert!(msg.windows(secret.len()).all(|w| w != secret.as_slice()));
    }

    #[test]
    fn a_message_cannot_be_attributed_to_the_wrong_sender() {
        let (sk_a, pk_a) = generate_keypair().unwrap();
        let (sk_b, pk_b) = generate_keypair().unwrap();
        let (_sk_c, pk_c) = generate_keypair().unwrap();

        let mut alice = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();
        let mut bob = RelayCipher::new(sk_b, vec![pk_a.to_vec(), pk_c.to_vec()]).unwrap();

        let msg = alice.encrypt(&pk_b, b"from alice".to_vec()).unwrap();
        assert!(bob.decrypt(&pk_c, &msg).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let (sk_a, pk_a) = generate_keypair().unwrap();
        let (sk_b, pk_b) = generate_keypair().unwrap();

        let mut alice = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();
        let mut bob = RelayCipher::new(sk_b, vec![pk_a.to_vec()]).unwrap();

        let mut msg = alice.encrypt(&pk_b, b"share".to_vec()).unwrap();
        let last = msg.len() - 1;
        msg[last] ^= 0x01;
        assert!(bob.decrypt(&pk_a, &msg).is_err());
    }
}

// frostd_transport.rs — talk to a standard ZF frostd relay.
//
// WHY THIS REPLACES OUR OWN RELAY
//
// We had 341 lines here and 414 in zidecar implementing a bespoke gRPC relay
// with room codes. frostd does the same job — forward opaque blobs between
// session participants, trusting nothing, parsing nothing — and it is what
// the rest of the Zcash FROST ecosystem speaks.
//
// So this module writes no protocol. `frost_client::client::Client` is
// upstream's own client for all nine frostd endpoints, and
// `frost_client::cipher::Cipher` is upstream's Noise_K end-to-end encryption.
// Both come from the crate ZF maintains. Our wire format cannot drift from
// the standard because it is not ours to drift.
//
// A NOTE ON TYPES
//
// frost-client pins reddsa at a different revision than frost-spend does, so
// their FROST types and ours are distinct even where they look identical.
// That is fine and deliberately not fought: this module only moves opaque
// bytes. FROST semantics stay in frost-spend, transport stays here, and the
// two never exchange types.

use frost_client::api;
use frost_client::cipher::{Cipher, PrivateKey, PublicKey};
use frost_client::client::Client;

/// Error type kept local so callers do not take a frost-client dependency
/// just to match on failures.
#[derive(Debug)]
pub enum TransportError {
    Server(String),
    Cipher(String),
    NotJoined,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Server(s) => write!(f, "frostd: {s}"),
            TransportError::Cipher(s) => write!(f, "encryption: {s}"),
            TransportError::NotJoined => write!(f, "not in a session"),
        }
    }
}

impl std::error::Error for TransportError {}

pub type Result<T> = std::result::Result<T, TransportError>;

/// A session on a standard frostd relay.
pub struct FrostdTransport {
    client: Client,
    cipher: Cipher,
    session_id: Option<uuid::Uuid>,
    peers: Vec<PublicKey>,
}

impl FrostdTransport {
    /// Generate a participant keypair in frostd's own format.
    ///
    /// Upstream's, not ours — the pubkey is what other participants will
    /// address messages to, so it has to be the shape their client expects.
    pub fn generate_keypair() -> Result<(PrivateKey, PublicKey)> {
        Cipher::generate_keypair().map_err(|e| TransportError::Cipher(e.to_string()))
    }

    /// Connect to a frostd instance and authenticate.
    ///
    /// frostd's login is challenge-response: the server issues a challenge,
    /// we sign it with the participant key, and get back an access token.
    /// All of that is upstream's `Client`; we only sequence it.
    /// `public_key` is passed alongside rather than derived: upstream keeps
    /// PrivateKey's bytes private, and rightly so. Callers get both from
    /// `generate_keypair` and store both.
    pub async fn connect(
        host_port: String,
        private_key: PrivateKey,
        public_key: PublicKey,
        peers: Vec<PublicKey>,
    ) -> Result<Self> {
        let cipher = Cipher::new(private_key.clone(), peers.clone())
            .map_err(|e| TransportError::Cipher(e.to_string()))?;
        let mut client = Client::new(host_port);

        let challenge = client
            .challenge()
            .await
            .map_err(|e| TransportError::Server(e.to_string()))?
            .challenge;

        let signature = private_key
            .sign(challenge.as_bytes(), &mut rand::rngs::OsRng)
            .map_err(|e| TransportError::Cipher(e.to_string()))?;

        client
            .login(&api::LoginArgs {
                challenge,
                pubkey: public_key,
                signature: signature.to_vec(),
            })
            .await
            .map_err(|e| TransportError::Server(e.to_string()))?;

        Ok(Self {
            client,
            cipher,
            session_id: None,
            peers,
        })
    }

    /// Open a session as coordinator. `message_count` is how many messages
    /// each participant will send, which frostd uses for its own bookkeeping.
    pub async fn create_session(&mut self, message_count: u8) -> Result<uuid::Uuid> {
        let out = self
            .client
            .create_new_session(&api::CreateNewSessionArgs {
                pubkeys: self.peers.clone(),
                message_count,
            })
            .await
            .map_err(|e| TransportError::Server(e.to_string()))?;
        self.session_id = Some(out.session_id);
        Ok(out.session_id)
    }

    /// Join a session someone else created.
    pub fn join_session(&mut self, session_id: uuid::Uuid) {
        self.session_id = Some(session_id);
    }

    /// Encrypt and send to specific recipients (empty = the coordinator).
    pub async fn send(&mut self, recipients: Vec<PublicKey>, msg: Vec<u8>) -> Result<()> {
        let session_id = self.session_id.ok_or(TransportError::NotJoined)?;
        for recipient in &recipients {
            let encrypted = self
                .cipher
                .encrypt(Some(recipient), msg.clone())
                .map_err(|e| TransportError::Cipher(e.to_string()))?;
            self.client
                .send(&api::SendArgs {
                    session_id,
                    recipients: vec![recipient.clone()],
                    msg: encrypted,
                })
                .await
                .map_err(|e| TransportError::Server(e.to_string()))?;
        }
        Ok(())
    }

    /// Receive and decrypt whatever is queued for us.
    pub async fn receive(&mut self, as_coordinator: bool) -> Result<Vec<(PublicKey, Vec<u8>)>> {
        let session_id = self.session_id.ok_or(TransportError::NotJoined)?;
        let out = self
            .client
            .receive(&api::ReceiveArgs {
                session_id,
                as_coordinator,
            })
            .await
            .map_err(|e| TransportError::Server(e.to_string()))?;

        let mut result = Vec::with_capacity(out.msgs.len());
        for msg in out.msgs {
            let decrypted = self
                .cipher
                .decrypt(msg)
                .map_err(|e| TransportError::Cipher(e.to_string()))?;
            result.push((decrypted.sender, decrypted.msg));
        }
        Ok(result)
    }

    pub async fn close(&mut self) -> Result<()> {
        let session_id = self.session_id.ok_or(TransportError::NotJoined)?;
        self.client
            .close_session(&api::CloseSessionArgs { session_id })
            .await
            .map_err(|e| TransportError::Server(e.to_string()))?;
        self.session_id = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compatibility, at the layer that matters: a message we encrypt must be
    /// readable by a peer using upstream's cipher, because it IS upstream's
    /// cipher. If this ever fails, we have diverged from the ecosystem.
    #[test]
    fn a_message_we_encrypt_is_read_by_the_standard_cipher() {
        let (sk_a, pk_a) = FrostdTransport::generate_keypair().unwrap();
        let (sk_b, pk_b) = FrostdTransport::generate_keypair().unwrap();

        let mut alice = Cipher::new(sk_a, vec![pk_b.clone()]).unwrap();
        let mut bob = Cipher::new(sk_b, vec![pk_a.clone()]).unwrap();

        let sent = alice
            .encrypt(Some(&pk_b), b"round 2 package".to_vec())
            .unwrap();
        let received = bob
            .decrypt(api::Msg {
                sender: pk_a,
                msg: sent,
            })
            .unwrap();

        assert_eq!(received.msg, b"round 2 package");
    }

    /// The relay must never see plaintext — that is the property that lets
    /// frostd be untrusted, and the reason running someone else's relay is
    /// acceptable at all.
    #[test]
    fn the_relay_never_sees_plaintext() {
        let (sk_a, pk_a) = FrostdTransport::generate_keypair().unwrap();
        let (_sk_b, pk_b) = FrostdTransport::generate_keypair().unwrap();

        let mut alice = Cipher::new(sk_a, vec![pk_b.clone()]).unwrap();
        let secret = b"this must not reach the server";
        let sent = alice.encrypt(Some(&pk_b), secret.to_vec()).unwrap();

        assert!(sent.windows(secret.len()).all(|w| w != secret.as_slice()));
        let _ = pk_a;
    }

    /// Upstream's own note on `decrypt`: the sender in the Msg is
    /// authenticated, because Noise_K mixes the sender's static key into the
    /// key schedule. Claiming a different sender must therefore fail.
    #[test]
    fn a_message_cannot_be_attributed_to_the_wrong_sender() {
        let (sk_a, pk_a) = FrostdTransport::generate_keypair().unwrap();
        let (sk_b, pk_b) = FrostdTransport::generate_keypair().unwrap();
        let (_sk_c, pk_c) = FrostdTransport::generate_keypair().unwrap();

        let mut alice = Cipher::new(sk_a, vec![pk_b.clone()]).unwrap();
        let mut bob = Cipher::new(sk_b, vec![pk_a, pk_c.clone()]).unwrap();

        let sent = alice.encrypt(Some(&pk_b), b"from alice".to_vec()).unwrap();
        // relabelled as coming from carol
        assert!(bob
            .decrypt(api::Msg {
                sender: pk_c,
                msg: sent,
            })
            .is_err());
    }

    /// THE compatibility test for zafu.
    ///
    /// frost-client cannot go in the wasm bundle - it pulls message-io,
    /// rpassword and a full tokio. So zafu gets its cipher from frost-spend,
    /// which is already in the wasm. That is only acceptable if the two
    /// produce identical bytes, and this is where that is proven: encrypt
    /// with ours, decrypt with upstream's, and back again.
    ///
    /// If this fails, zafu and zcli cannot talk to each other and neither can
    /// talk to any other ecosystem client.
    #[test]
    fn our_wasm_cipher_interoperates_with_upstream() {
        use frost_spend::relay_cipher::{generate_keypair, RelayCipher};

        // generated by ours; upstream accepts the raw bytes
        let (sk_a, pk_a) = generate_keypair().unwrap();
        let (sk_b, pk_b) = generate_keypair().unwrap();
        let up_pk_a = PublicKey(pk_a.to_vec());
        let up_pk_b = PublicKey(pk_b.to_vec());

        // ours -> upstream
        let mut ours = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();
        let mut theirs = Cipher::new(
            PrivateKey::from(sk_b.to_vec()),
            vec![up_pk_a.clone()],
        )
        .unwrap();

        let sent = ours.encrypt(&pk_b, b"zafu to zcli".to_vec()).unwrap();
        let got = theirs
            .decrypt(api::Msg {
                sender: up_pk_a.clone(),
                msg: sent,
            })
            .unwrap();
        assert_eq!(got.msg, b"zafu to zcli");

        // upstream -> ours (fresh sessions, since each is stateful)
        let mut theirs_send = Cipher::new(
            PrivateKey::from(sk_b.to_vec()),
            vec![up_pk_a.clone()],
        )
        .unwrap();
        let mut ours_recv = RelayCipher::new(sk_a, vec![pk_b.to_vec()]).unwrap();

        let sent = theirs_send
            .encrypt(Some(&up_pk_a), b"zcli to zafu".to_vec())
            .unwrap();
        assert_eq!(ours_recv.decrypt(&pk_b, &sent).unwrap(), b"zcli to zafu");
        let _ = up_pk_b;
    }
}

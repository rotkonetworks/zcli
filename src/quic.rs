// QUIC transport for exchange API integration
//
// JAMNP-S auth model: self-signed ed25519 X.509 certs with base32-encoded
// alternative name. bidirectional channel — state pushes out (UP 0),
// deposit/withdrawal commands come back (CE 128/129).

use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

use crate::error::Error;
use crate::key::WalletSeed;
use crate::ops::merchant;
use crate::wallet::{Wallet, WithdrawalRequest};

const ALPN: &[u8] = b"zcli/0";
const MAX_MSG: usize = 4 * 1024 * 1024; // 4 MB

// stream kind bytes
const STREAM_UP_STATE: u8 = 0x00;
const STREAM_CE_DEPOSIT: u8 = 0x80;
const STREAM_CE_WITHDRAW: u8 = 0x81;

// -- base32 / alt name --

const BASE32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u64 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// JAMNP-S alternative name: "e" + base32(pubkey_le_u256, 52 chars)
pub fn derive_alt_name(pubkey: &[u8; 32]) -> String {
    let encoded = base32_encode(pubkey);
    // 32 bytes = 256 bits, ceil(256/5) = 52 base32 chars
    format!("e{}", &encoded[..52])
}

// -- cert generation --

/// generate self-signed X.509 cert from ed25519 keypair
pub fn generate_cert(
    seed: &[u8; 32],
    pubkey: &[u8; 32],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Error> {
    // ed25519 PKCS#8 v2 DER encoding:
    // SEQUENCE {
    //   INTEGER 1  (version v2)
    //   SEQUENCE { OID 1.3.101.112 }  (Ed25519)
    //   OCTET STRING { OCTET STRING { seed } }
    //   [1] { BIT STRING { pubkey } }
    // }
    let mut pkcs8 = Vec::with_capacity(16 + 32 + 12 + 32);
    // outer SEQUENCE header (we'll fix length after)
    pkcs8.push(0x30);
    pkcs8.push(0x00); // placeholder

    // version INTEGER 1
    pkcs8.extend_from_slice(&[0x02, 0x01, 0x01]);

    // algorithm SEQUENCE { OID 1.3.101.112 }
    pkcs8.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);

    // privateKey OCTET STRING { OCTET STRING { seed } }
    pkcs8.push(0x04); // outer OCTET STRING
    pkcs8.push(34);   // length = 2 + 32
    pkcs8.push(0x04); // inner OCTET STRING
    pkcs8.push(32);
    pkcs8.extend_from_slice(seed);

    // publicKey [1] { BIT STRING { pubkey } }
    pkcs8.push(0xa1); // context tag [1]
    pkcs8.push(35);   // length = 3 + 32
    pkcs8.push(0x03); // BIT STRING
    pkcs8.push(33);   // length = 1 + 32
    pkcs8.push(0x00); // no unused bits
    pkcs8.extend_from_slice(pubkey);

    // fix outer SEQUENCE length
    let inner_len = pkcs8.len() - 2;
    pkcs8[1] = inner_len as u8;

    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone()));
    let key_pair = rcgen::KeyPair::from_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519)
        .map_err(|e| Error::Other(format!("rcgen keypair: {}", e)))?;

    let alt_name = derive_alt_name(pubkey);
    let mut params = rcgen::CertificateParams::new(vec![alt_name])
        .map_err(|e| Error::Other(format!("rcgen params: {}", e)))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "zcli");

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Other(format!("rcgen self-sign: {}", e)))?;

    Ok((cert.into(), key_der))
}

/// extract ed25519 pubkey from a DER-encoded X.509 certificate
pub fn extract_pubkey_from_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    // find the ed25519 OID (1.3.101.112) = 06 03 2b 65 70
    // the public key BIT STRING follows the algorithm identifier
    let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let mut pos = 0;
    while pos + oid.len() < cert_der.len() {
        if cert_der[pos..pos + oid.len()] == oid {
            // skip past the OID and its enclosing SEQUENCE
            // look for BIT STRING (0x03) tag with 33 bytes (0x21)
            let search_start = pos + oid.len();
            for i in search_start..cert_der.len().saturating_sub(34) {
                if cert_der[i] == 0x03 && cert_der[i + 1] == 0x21 && cert_der[i + 2] == 0x00 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&cert_der[i + 3..i + 35]);
                    return Some(key);
                }
            }
        }
        pos += 1;
    }
    None
}

// -- custom cert verifiers --

/// client-side verifier: pins a specific ed25519 pubkey
#[derive(Debug)]
struct PinnedServerVerifier {
    expected: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pubkey = extract_pubkey_from_cert(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("no ed25519 pubkey in server cert".into())
        })?;
        if pubkey != self.expected {
            return Err(rustls::Error::General(format!(
                "server pubkey mismatch: got {}, expected {}",
                hex::encode(pubkey),
                hex::encode(self.expected),
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// server-side verifier: requires client cert, extracts pubkey
#[derive(Debug)]
pub struct ClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for ClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // just verify we can extract a valid ed25519 pubkey
        extract_pubkey_from_cert(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("no ed25519 pubkey in client cert".into())
        })?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

// -- TLS configs --

/// client config: presents our cert, verifies peer by pinned pubkey
pub fn client_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    peer_pubkey: &[u8; 32],
) -> Result<quinn::ClientConfig, Error> {
    let verifier = Arc::new(PinnedServerVerifier {
        expected: *peer_pubkey,
    });

    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| Error::Other(format!("rustls client config: {}", e)))?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic_config = QuicClientConfig::try_from(tls)
        .map_err(|e| Error::Other(format!("quinn client config: {}", e)))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_config));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(600)).unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// server config: presents our cert, requires client cert
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, Error> {
    let verifier = Arc::new(ClientCertVerifier);

    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| Error::Other(format!("rustls server config: {}", e)))?;

    tls.alpn_protocols = vec![ALPN.to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| Error::Other(format!("quinn server config: {}", e)))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(600)).unwrap(),
    ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

// -- message codec --

/// write a length-prefixed message to a QUIC send stream
pub async fn write_msg(send: &mut quinn::SendStream, data: &[u8]) -> Result<(), Error> {
    if data.len() > MAX_MSG {
        return Err(Error::Other(format!(
            "message too large: {} > {}",
            data.len(),
            MAX_MSG
        )));
    }
    let len = (data.len() as u32).to_le_bytes();
    send.write_all(&len)
        .await
        .map_err(|e| Error::Network(format!("write len: {}", e)))?;
    send.write_all(data)
        .await
        .map_err(|e| Error::Network(format!("write body: {}", e)))?;
    Ok(())
}

/// read a length-prefixed message from a QUIC recv stream
pub async fn read_msg(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Error> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Network(format!("read len: {}", e)))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MSG {
        return Err(Error::Other(format!(
            "message too large: {} > {}",
            len, MAX_MSG
        )));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| Error::Network(format!("read body: {}", e)))?;
    Ok(buf)
}

// -- client (zcli side) --

pub struct QuicLink {
    connection: quinn::Connection,
    state_send: Option<quinn::SendStream>,
}

impl QuicLink {
    /// connect to exchange API
    pub async fn connect(addr: &str, config: quinn::ClientConfig) -> Result<Self, Error> {
        let remote: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| Error::Other(format!("invalid address '{}': {}", addr, e)))?;

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| Error::Network(format!("bind udp: {}", e)))?;
        endpoint.set_default_client_config(config);

        let connection = endpoint
            .connect(remote, "zcli")
            .map_err(|e| Error::Network(format!("quic connect: {}", e)))?
            .await
            .map_err(|e| Error::Network(format!("quic handshake: {}", e)))?;

        Ok(Self {
            connection,
            state_send: None,
        })
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// push state update over UP 0 stream (opens on first call, reuses after)
    pub async fn push_state(&mut self, json: &str) -> Result<(), Error> {
        if self.state_send.is_none() {
            let mut send = self
                .connection
                .open_uni()
                .await
                .map_err(|e| Error::Network(format!("open UP 0: {}", e)))?;
            send.write_all(&[STREAM_UP_STATE])
                .await
                .map_err(|e| Error::Network(format!("write stream kind: {}", e)))?;
            self.state_send = Some(send);
        }
        let send = self.state_send.as_mut().unwrap();
        match write_msg(send, json.as_bytes()).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // drop broken stream so next push re-opens
                self.state_send = None;
                Err(e)
            }
        }
    }

    /// accept and handle incoming CE streams (deposit/withdrawal requests)
    pub async fn handle_incoming(
        connection: quinn::Connection,
        seed: WalletSeed,
        mainnet: bool,
    ) {
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("quic: accept_bi closed: {}", e);
                    return;
                }
            };
            let seed_bytes = *seed.as_bytes();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_ce_stream(&mut send, &mut recv, &seed_bytes, mainnet).await
                {
                    eprintln!("quic ce error: {}", e);
                }
            });
        }
    }
}

async fn handle_ce_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    seed_bytes: &[u8; 64],
    mainnet: bool,
) -> Result<(), Error> {
    // read stream kind byte
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind)
        .await
        .map_err(|e| Error::Network(format!("read stream kind: {}", e)))?;

    let req_data = read_msg(recv).await?;
    let req: serde_json::Value = serde_json::from_slice(&req_data)
        .map_err(|e| Error::Other(format!("invalid json: {}", e)))?;

    let resp = match kind[0] {
        STREAM_CE_DEPOSIT => handle_deposit(&req, seed_bytes, mainnet).await?,
        STREAM_CE_WITHDRAW => handle_withdraw(&req).await?,
        other => {
            return Err(Error::Other(format!("unknown stream kind: 0x{:02x}", other)));
        }
    };

    let resp_bytes = serde_json::to_vec(&resp)
        .map_err(|e| Error::Other(format!("serialize response: {}", e)))?;
    write_msg(send, &resp_bytes).await?;
    send.finish()
        .map_err(|e| Error::Network(format!("finish send: {}", e)))?;
    Ok(())
}

async fn handle_deposit(
    req: &serde_json::Value,
    seed_bytes: &[u8; 64],
    mainnet: bool,
) -> Result<serde_json::Value, Error> {
    let label = req["label"].as_str().unwrap_or("");
    let amount_zat = req["amount_zat"].as_u64().unwrap_or(0);
    let deposit = req["deposit"].as_bool().unwrap_or(true);
    let label_owned = if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    };

    // retry on wallet lock contention
    for attempt in 0..10u64 {
        let seed = WalletSeed::from_bytes(*seed_bytes);
        match merchant::create_request(
            &seed,
            amount_zat,
            label_owned.as_deref(),
            deposit,
            mainnet,
        ) {
            Ok(pr) => {
                return Ok(serde_json::json!({
                    "id": pr.id,
                    "address": pr.address,
                    "status": pr.status,
                }));
            }
            Err(Error::Wallet(msg)) if msg.contains("could not acquire lock") && attempt < 9 => {
                tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt + 1))).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::Wallet("wallet lock timeout".into()))
}

async fn handle_withdraw(req: &serde_json::Value) -> Result<serde_json::Value, Error> {
    let address = req["address"]
        .as_str()
        .ok_or_else(|| Error::Other("missing address".into()))?
        .to_string();
    let amount_zat = req["amount_zat"]
        .as_u64()
        .ok_or_else(|| Error::Other("missing amount_zat".into()))?;
    let label = req["label"].as_str().map(String::from);

    for attempt in 0..10u64 {
        match Wallet::open(&Wallet::default_path()) {
            Ok(wallet) => {
                let id = wallet.next_withdrawal_id()?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let wr = WithdrawalRequest {
                    id,
                    address: address.clone(),
                    amount_zat,
                    label: label.clone(),
                    created_at: now,
                    status: "pending".into(),
                    txid: None,
                    fee_zat: None,
                    error: None,
                };
                wallet.insert_withdrawal_request(&wr)?;

                return Ok(serde_json::json!({
                    "id": wr.id,
                    "status": wr.status,
                }));
            }
            Err(Error::Wallet(msg)) if msg.contains("could not acquire lock") && attempt < 9 => {
                tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt + 1))).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::Wallet("wallet lock timeout".into()))
}

/// parse hex-encoded ed25519 pubkey from CLI arg
pub fn parse_peer_key(hex_str: &str) -> Result<[u8; 32], Error> {
    let bytes =
        hex::decode(hex_str).map_err(|e| Error::Other(format!("invalid peer key hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(Error::Other(format!(
            "peer key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

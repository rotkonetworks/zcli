// exchange API example — QUIC server + HTTP REST API
//
// accepts zcli QUIC connection, receives UP 0 state pushes,
// serves HTTP endpoints for deposit/withdrawal management.
//
// usage:
//   cargo run --example exchange -- [--listen 0.0.0.0:4433] [--http 0.0.0.0:8080]
//       [--key exchange.key] [--peer-key <zcli_pubkey_hex>]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// reuse zcli's quic module for cert gen, codec, configs
use zecli::quic;

#[derive(Default)]
struct State {
    json: String,
    // connection for sending CE requests to zcli
    conn: Option<quinn::Connection>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let listen_addr: SocketAddr = arg_value(&args, "--listen")
        .unwrap_or("0.0.0.0:4433".into())
        .parse()?;
    let http_addr: SocketAddr = arg_value(&args, "--http")
        .unwrap_or("0.0.0.0:8080".into())
        .parse()?;
    let key_path = arg_value(&args, "--key").unwrap_or("exchange.key".into());
    let peer_key_hex = arg_value(&args, "--peer-key");

    // load or generate exchange ed25519 keypair
    let (seed, pubkey) = load_or_generate_key(&key_path)?;
    eprintln!("exchange pubkey: {}", hex::encode(pubkey));

    let (cert, key) = quic::generate_cert(&seed, &pubkey)?;
    let server_config = quic::server_config(cert, key)?;

    let state: Arc<Mutex<State>> = Arc::new(Mutex::new(State::default()));

    // QUIC server
    let quic_state = Arc::clone(&state);
    let peer_key_hex_clone = peer_key_hex.clone();
    tokio::spawn(async move {
        if let Err(e) = run_quic(listen_addr, server_config, quic_state, peer_key_hex_clone).await {
            eprintln!("quic server error: {}", e);
        }
    });

    eprintln!("http: listening on {}", http_addr);
    eprintln!("quic: listening on {}", listen_addr);

    // HTTP server
    let listener = TcpListener::bind(http_addr).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            let (method, path) = match parts.as_slice() {
                [m, p, ..] => (*m, *p),
                _ => return,
            };

            let response = handle_http(method, path, &state).await;
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

async fn handle_http(method: &str, path: &str, state: &Arc<Mutex<State>>) -> String {
    let (path_base, query) = match path.find('?') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path, ""),
    };

    let params = parse_query(query);

    match (method, path_base) {
        ("GET", "/state") => {
            let s = state.lock().await;
            let body = if s.json.is_empty() {
                r#"{"payments":[],"withdrawals":[]}"#.to_string()
            } else {
                s.json.clone()
            };
            http_json(200, &body)
        }

        ("GET", "/balance") => {
            let user = match params.get("user") {
                Some(u) => u.clone(),
                None => return http_json(400, r#"{"error":"missing user param"}"#),
            };
            let s = state.lock().await;
            let balance = compute_balance(&s.json, &user);
            http_json(
                200,
                &serde_json::json!({"user": user, "balance_zat": balance}).to_string(),
            )
        }

        ("POST", "/deposit") => {
            let user = match params.get("user") {
                Some(u) => u.clone(),
                None => return http_json(400, r#"{"error":"missing user param"}"#),
            };
            let conn = {
                let s = state.lock().await;
                s.conn.clone()
            };
            let conn = match conn {
                Some(c) => c,
                None => return http_json(503, r#"{"error":"no zcli connection"}"#),
            };

            let label = format!("user:{}", user);
            let req = serde_json::json!({
                "label": label,
                "amount_zat": 0,
                "deposit": true,
            });
            match send_ce(&conn, 0x80, &req).await {
                Ok(resp) => http_json(200, &resp.to_string()),
                Err(e) => http_json(500, &format!(r#"{{"error":"{}"}}"#, e)),
            }
        }

        ("POST", "/withdraw") => {
            let user = match params.get("user") {
                Some(u) => u.clone(),
                None => return http_json(400, r#"{"error":"missing user param"}"#),
            };
            let amount: u64 = match params.get("amount").and_then(|a| a.parse().ok()) {
                Some(a) => a,
                None => return http_json(400, r#"{"error":"missing/invalid amount param"}"#),
            };
            let address = match params.get("address") {
                Some(a) => a.clone(),
                None => return http_json(400, r#"{"error":"missing address param"}"#),
            };

            let conn = {
                let s = state.lock().await;
                s.conn.clone()
            };
            let conn = match conn {
                Some(c) => c,
                None => return http_json(503, r#"{"error":"no zcli connection"}"#),
            };

            let label = format!("user:{}", user);
            let req = serde_json::json!({
                "address": address,
                "amount_zat": amount,
                "label": label,
            });
            match send_ce(&conn, 0x81, &req).await {
                Ok(resp) => http_json(200, &resp.to_string()),
                Err(e) => http_json(500, &format!(r#"{{"error":"{}"}}"#, e)),
            }
        }

        ("GET", "/withdrawals") => {
            let user = match params.get("user") {
                Some(u) => u.clone(),
                None => return http_json(400, r#"{"error":"missing user param"}"#),
            };
            let s = state.lock().await;
            let filtered = filter_withdrawals(&s.json, &user);
            http_json(200, &filtered)
        }

        _ => http_json(404, r#"{"error":"not found"}"#),
    }
}

/// send a CE request (bidirectional stream) to zcli
async fn send_ce(
    conn: &quinn::Connection,
    kind: u8,
    req: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open_bi: {}", e))?;

    send.write_all(&[kind])
        .await
        .map_err(|e| format!("write kind: {}", e))?;

    let req_bytes = serde_json::to_vec(req).unwrap();
    quic::write_msg(&mut send, &req_bytes)
        .await
        .map_err(|e| format!("write msg: {}", e))?;
    send.finish().map_err(|e| format!("finish: {}", e))?;

    let resp_bytes = quic::read_msg(&mut recv)
        .await
        .map_err(|e| format!("read msg: {}", e))?;
    serde_json::from_slice(&resp_bytes).map_err(|e| format!("parse response: {}", e))
}

async fn run_quic(
    addr: SocketAddr,
    config: quinn::ServerConfig,
    state: Arc<Mutex<State>>,
    peer_key_hex: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = quinn::Endpoint::server(config, addr)?;

    loop {
        let incoming = match endpoint.accept().await {
            Some(i) => i,
            None => break,
        };
        let connection = incoming.await?;

        // optionally verify client pubkey
        if let Some(ref hex_str) = peer_key_hex {
            if let Ok(expected) = quic::parse_peer_key(hex_str) {
                if let Some(certs) = connection.peer_identity() {
                    if let Some(cert_chain) =
                        certs.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                    {
                        if let Some(cert) = cert_chain.first() {
                            if let Some(pk) = quic::extract_pubkey_from_cert(cert.as_ref()) {
                                if pk != expected {
                                    eprintln!(
                                        "quic: rejecting client with wrong pubkey: {}",
                                        hex::encode(pk)
                                    );
                                    connection.close(1u32.into(), b"pubkey mismatch");
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        eprintln!(
            "quic: client connected from {}",
            connection.remote_address()
        );

        // store connection for CE requests
        {
            let mut s = state.lock().await;
            s.conn = Some(connection.clone());
        }

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // accept unidirectional streams (UP 0 state pushes)
            loop {
                let mut recv = match connection.accept_uni().await {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!("quic: client disconnected");
                        let mut s = state.lock().await;
                        s.conn = None;
                        break;
                    }
                };

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    // read stream kind
                    let mut kind = [0u8; 1];
                    if recv.read_exact(&mut kind).await.is_err() {
                        return;
                    }
                    if kind[0] != 0x00 {
                        eprintln!("quic: unknown uni stream kind: 0x{:02x}", kind[0]);
                        return;
                    }

                    // read state push messages continuously
                    loop {
                        match quic::read_msg(&mut recv).await {
                            Ok(data) => {
                                if let Ok(json) = String::from_utf8(data) {
                                    let mut s = state.lock().await;
                                    s.json = json;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });
    }

    Ok(())
}

fn http_json(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        status,
        reason,
        body.len(),
        body
    )
}

fn compute_balance(state_json: &str, user: &str) -> i64 {
    let label = format!("user:{}", user);
    let v: serde_json::Value = match serde_json::from_str(state_json) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let mut balance: i64 = 0;

    // sum deposits
    if let Some(payments) = v["payments"].as_array() {
        for p in payments {
            if p["label"].as_str() == Some(&label) {
                balance += p["received_zat"].as_i64().unwrap_or(0);
            }
        }
    }

    // subtract completed withdrawals
    if let Some(withdrawals) = v["withdrawals"].as_array() {
        for w in withdrawals {
            if w["label"].as_str() == Some(&label) && w["status"].as_str() == Some("completed") {
                balance -= w["amount_zat"].as_i64().unwrap_or(0);
            }
        }
    }

    balance
}

fn filter_withdrawals(state_json: &str, user: &str) -> String {
    let label = format!("user:{}", user);
    let v: serde_json::Value = match serde_json::from_str(state_json) {
        Ok(v) => v,
        Err(_) => return "[]".into(),
    };

    let filtered: Vec<&serde_json::Value> = v["withdrawals"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|w| w["label"].as_str() == Some(&label))
                .collect()
        })
        .unwrap_or_default();

    serde_json::to_string(&filtered).unwrap_or_else(|_| "[]".into())
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn load_or_generate_key(path: &str) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    if std::path::Path::new(path).exists() {
        // load existing: file is 64 bytes (seed + pubkey)
        let data = std::fs::read(path)?;
        if data.len() != 64 {
            return Err(format!("key file must be 64 bytes, got {}", data.len()).into());
        }
        let mut seed = [0u8; 32];
        let mut pubkey = [0u8; 32];
        seed.copy_from_slice(&data[..32]);
        pubkey.copy_from_slice(&data[32..]);
        Ok((seed, pubkey))
    } else {
        // generate new keypair using ring
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| format!("keygen: {}", e))?;
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|e| format!("parse pkcs8: {}", e))?;

        // extract seed from pkcs8: the 32-byte private seed is at offset 16
        let pkcs8_bytes = pkcs8.as_ref();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&pkcs8_bytes[16..48]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(kp.public_key().as_ref());

        // save seed+pubkey
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&seed);
        out.extend_from_slice(&pubkey);
        std::fs::write(path, &out)?;
        eprintln!("generated new key: {}", path);
        Ok((seed, pubkey))
    }
}

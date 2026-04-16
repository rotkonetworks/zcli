//! license-server: ZEC-paid pro license oracle for zafu wallet.
//!
//! monitors ROTKO_LICENSE_ADDRESS for payments with `zid{bandersnatch_pubkey}` memos.
//! the Bandersnatch pubkey in the memo IS the ring member key - no separate
//! registration step. this eliminates the zpro-to-ring mapping that would
//! let the server correlate payment identity with ring membership.
//!
//! signs licenses with rotko's ed25519 key. serves ring keys for VRF proofs.
//!
//! endpoints:
//!   GET /license/{key}   - check/issue license for a Bandersnatch pubkey
//!   GET /ring-keys       - all active pro ring member pubkeys
//!
//! env:
//!   ZCLI_SIGNING_KEY     - 32-byte hex ed25519 seed (required for signing)
//!   ZEBRAD_RPC           - zebrad JSON-RPC endpoint (default: http://127.0.0.1:8232)

use axum::{
    extract::{Path, State},
    response::Json,
    routing::get,
    Router,
};
use clap::Parser;
use ed25519_consensus::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

// -- constants --

/// rotko's receiving address for license payments (unified address)
const LICENSE_ADDRESS: &str = "u153khs43zxz6hcnlwnut77knyqmursnutmungxjxd7khruunhj77ea6tmpzxct9wzlgen66jxwc93ea053j22afkktu7hrs9rmsz003h3";

/// 0.01 ZEC = 30 days
const ZAT_PER_30_DAYS: u64 = 1_000_000;

// -- types --

#[derive(Clone, Serialize, Deserialize)]
struct LicenseEntry {
    /// Bandersnatch ring VRF pubkey (hex) - this IS the license identity.
    /// goes in payment memo, used directly as ring member. no separate
    /// registration step, no zpro-to-ring mapping to leak.
    zid: String,
    plan: String,
    expires: u64,
    signature: String,
    valid: bool,
    total_paid_zat: u64,
    /// txids already counted (prevents double-counting on rescan)
    #[serde(default)]
    seen_txids: Vec<String>,
}

/// pending (0-conf) payment not yet credited
#[derive(Clone, Default)]
struct PendingInfo {
    amount_zat: u64,
    confirmations: u64,
}

#[derive(Clone)]
struct AppState {
    licenses: Arc<RwLock<HashMap<String, LicenseEntry>>>,
    ring_keys: Arc<RwLock<Vec<String>>>,
    /// 0-conf payments not yet credited (key = zid)
    pending: Arc<RwLock<HashMap<String, PendingInfo>>>,
    signing_key: Option<SigningKey>,
    zebrad_rpc: String,
    db: sled::Db,
    /// pubkeys that get pro for free (friends, testers, etc)
    friends: Arc<HashSet<String>>,
}

#[derive(Parser, Debug)]
#[command(name = "license-server")]
#[command(about = "ZEC-paid pro license oracle for zafu")]
struct Args {
    /// listen address
    #[arg(long, default_value = "0.0.0.0:3334")]
    listen: String,

    /// zebrad RPC endpoint
    #[arg(long, env = "ZEBRAD_RPC", default_value = "http://127.0.0.1:8232")]
    zebrad_rpc: String,

    /// ed25519 signing key seed (hex, 32 bytes)
    #[arg(long, env = "ZCLI_SIGNING_KEY", default_value = "")]
    signing_key: String,

    /// scan interval in seconds
    #[arg(long, default_value_t = 30)]
    scan_interval: u64,

    /// database path for license persistence
    #[arg(long, default_value = "./license.db")]
    db_path: String,

    /// path to friends file (one zpro pubkey per line, # comments)
    #[arg(long, default_value = "./friends.txt")]
    friends_file: String,
}

// -- main --

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "license_server=info".into()),
        )
        .init();

    let args = Args::parse();

    let signing_key = if !args.signing_key.is_empty() {
        let hex = args.signing_key.strip_prefix("0x").unwrap_or(&args.signing_key);
        let seed: [u8; 32] = hex::decode(hex)
            .expect("ZCLI_SIGNING_KEY must be valid hex")
            .try_into()
            .expect("ZCLI_SIGNING_KEY must be 32 bytes");
        Some(SigningKey::from(seed))
    } else {
        tracing::warn!("no ZCLI_SIGNING_KEY - licenses will be unsigned (dev mode)");
        None
    };

    // load friends file (one zpro pubkey per line, # comments, blank lines ok)
    let friends: HashSet<String> = std::fs::read_to_string(&args.friends_file)
        .unwrap_or_default()
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if !friends.is_empty() {
        info!("loaded {} friends from {}", friends.len(), args.friends_file);
    }

    let db = sled::open(&args.db_path).expect("failed to open license database");

    // load persisted licenses - ring = all valid paid keys (no separate registration)
    let mut licenses = HashMap::new();
    let mut ring_keys = Vec::new();
    for entry in db.iter().flatten() {
        if let Ok(lic) = bincode::deserialize::<LicenseEntry>(&entry.1) {
            if lic.valid {
                ring_keys.push(lic.zid.clone());
            }
            licenses.insert(lic.zid.clone(), lic);
        }
    }
    info!("loaded {} licenses, {} ring keys from {}", licenses.len(), ring_keys.len(), args.db_path);

    let state = AppState {
        licenses: Arc::new(RwLock::new(licenses)),
        ring_keys: Arc::new(RwLock::new(ring_keys)),
        signing_key,
        zebrad_rpc: args.zebrad_rpc.clone(),
        db,
        pending: Arc::new(RwLock::new(HashMap::new())),
        friends: Arc::new(friends),
    };

    // background scanner
    let scan_state = state.clone();
    let scan_interval = args.scan_interval;
    tokio::spawn(async move {
        loop {
            if let Err(e) = scan_payments(&scan_state).await {
                tracing::warn!("payment scan failed: {}", e);
            }
            tokio::time::sleep(std::time::Duration::from_secs(scan_interval)).await;
        }
    });

    let cors = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        .route("/license/:zid", get(get_license))
        .route("/ring-keys", get(get_ring_keys))
        .layer(cors)
        .with_state(state);

    info!("license-server listening on {}", args.listen);
    info!("zebrad: {}", args.zebrad_rpc);
    info!("license address: {}...{}", &LICENSE_ADDRESS[..20], &LICENSE_ADDRESS[LICENSE_ADDRESS.len()-8..]);

    let listener = tokio::net::TcpListener::bind(&args.listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// -- handlers --

async fn get_license(
    State(state): State<AppState>,
    Path(zid): Path<String>,
) -> Json<LicenseResp> {
    // on-demand scan: if we don't know this key yet, scan now instead
    // of making the user wait for the background loop
    {
        let licenses = state.licenses.read().await;
        let known = licenses.contains_key(&zid) || state.friends.contains(&zid);
        drop(licenses);
        if !known {
            let _ = scan_payments(&state).await;
        }
    }

    // friends get permanent pro
    // use JS-safe max (2^53 - 1) instead of u64::MAX to avoid JSON precision loss
    const PERMANENT_EXPIRES: u64 = 9_007_199_254_740_991;
    if state.friends.contains(&zid) {
        let mut sig = String::new();
        if let Some(ref sk) = state.signing_key {
            let payload = format!("zafu-license-v1\n{}\npro\n{}", zid, PERMANENT_EXPIRES);
            sig = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
        }
        return Json(LicenseResp {
            zid,
            plan: "pro".into(),
            expires: PERMANENT_EXPIRES,
            signature: sig,
            valid: true,
            pending_zat: 0,
            pending_confs: 0,
            required_confs: 0,
        });
    }

    let pending = state.pending.read().await;
    let pend = pending.get(&zid).cloned().unwrap_or_default();
    drop(pending);

    let licenses = state.licenses.read().await;
    if let Some(entry) = licenses.get(&zid) {
        Json(LicenseResp {
            zid: entry.zid.clone(),
            plan: entry.plan.clone(),
            expires: entry.expires,
            signature: entry.signature.clone(),
            valid: entry.valid,
            pending_zat: pend.amount_zat,
            pending_confs: pend.confirmations as u32,
            required_confs: 1,
        })
    } else {
        Json(LicenseResp {
            zid,
            plan: "free".into(),
            expires: 0,
            signature: String::new(),
            valid: false,
            pending_zat: pend.amount_zat,
            pending_confs: pend.confirmations as u32,
            required_confs: 1,
        })
    }
}

#[derive(Serialize)]
struct LicenseResp {
    zid: String,
    plan: String,
    expires: u64,
    signature: String,
    valid: bool,
    pending_zat: u64,
    pending_confs: u32,
    required_confs: u32,
}

async fn get_ring_keys(State(state): State<AppState>) -> Json<RingKeysResp> {
    let keys = state.ring_keys.read().await;
    Json(RingKeysResp { keys: keys.clone() })
}

#[derive(Serialize)]
struct RingKeysResp {
    keys: Vec<String>,
}

async fn rebuild_ring_keys(state: &AppState) {
    let licenses = state.licenses.read().await;
    // ring = all valid paid keys + friends. no separate registration,
    // no zpro-to-ring mapping. the payment identity IS the ring key.
    let mut keys: Vec<String> = licenses
        .values()
        .filter(|e| e.valid)
        .map(|e| e.zid.clone())
        .collect();
    // friends are ring members too
    for f in state.friends.iter() {
        if !keys.contains(f) {
            keys.push(f.clone());
        }
    }
    let mut ring = state.ring_keys.write().await;
    *ring = keys;
}

// -- payment scanner --

async fn scan_payments(state: &AppState) -> anyhow::Result<()> {
    info!("scanning for license payments...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // scan 0-conf (mempool) for instant pending feedback
    let unconfirmed = zebrad_call(
        &client,
        &state.zebrad_rpc,
        "z_listreceivedbyaddress",
        serde_json::json!([LICENSE_ADDRESS, 0]),
    )
    .await;

    let all_payments: Vec<ReceivedPayment> = match unconfirmed {
        Ok(val) => serde_json::from_value(val).unwrap_or_default(),
        Err(e) => {
            tracing::debug!("z_listreceivedbyaddress unavailable: {}", e);
            return Ok(());
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // separate into pending (0-conf) and confirmed (1+ conf)
    let mut new_pending: HashMap<String, PendingInfo> = HashMap::new();
    let mut licenses = state.licenses.write().await;
    let mut changed = false;

    for payment in &all_payments {
        let memo = decode_memo(&payment.memo);
        if !memo.starts_with("zid") {
            continue;
        }
        let zid = memo.trim_start_matches("zid").trim();
        if zid.is_empty() || zid.len() < 32 {
            continue;
        }

        let amount_zat = (payment.amount * 1e8) as u64;
        if amount_zat == 0 {
            continue;
        }

        if payment.confirmations < 1 {
            // 0-conf: track as pending for instant UI feedback
            let pend = new_pending.entry(zid.to_string()).or_default();
            pend.amount_zat += amount_zat;
            pend.confirmations = payment.confirmations;
            continue;
        }

        // 1+ conf: credit the license (skip already-seen txids)
        let entry = licenses.entry(zid.to_string()).or_insert_with(|| LicenseEntry {
            zid: zid.to_string(),
            plan: "free".into(),
            expires: 0,
            signature: String::new(),
            valid: false,
            total_paid_zat: 0,
            seen_txids: vec![],
        });

        if entry.seen_txids.contains(&payment.txid) {
            continue;
        }
        entry.seen_txids.push(payment.txid.clone());

        entry.total_paid_zat += amount_zat;
        let total_days = (entry.total_paid_zat as f64 / ZAT_PER_30_DAYS as f64 * 30.0) as u64;
        let expires = now + total_days * 86400;

        entry.plan = "pro".into();
        entry.expires = expires;
        entry.valid = expires > now;

        if let Some(ref sk) = state.signing_key {
            let payload = format!("zafu-license-v1\n{}\npro\n{}", zid, expires);
            let sig = sk.sign(payload.as_bytes());
            entry.signature = hex::encode(sig.to_bytes());
        }

        if let Ok(bytes) = bincode::serialize(entry) {
            let _ = state.db.insert(zid.as_bytes(), bytes);
        }

        changed = true;
        info!("license: {} = {} days ({} zat)", &zid[..12.min(zid.len())], total_days, entry.total_paid_zat);
    }

    drop(licenses);

    // update pending map
    let mut pending = state.pending.write().await;
    *pending = new_pending;
    drop(pending);

    if changed {
        let _ = state.db.flush_async().await;
        rebuild_ring_keys(state).await;
    }

    Ok(())
}

#[derive(Deserialize, Default)]
struct ReceivedPayment {
    #[serde(default)]
    #[allow(dead_code)]
    txid: String,
    #[serde(default)]
    amount: f64,
    #[serde(default)]
    memo: String,
    #[serde(default)]
    #[allow(dead_code)]
    confirmations: u64,
}

/// decode hex-encoded memo to UTF-8, stripping null padding
fn decode_memo(hex_memo: &str) -> String {
    let bytes = hex::decode(hex_memo).unwrap_or_default();
    // strip trailing zeros (zcash memos are 512 bytes, null-padded)
    let end = bytes.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// call zebrad JSON-RPC
async fn zebrad_call(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            anyhow::bail!("RPC error: {}", err);
        }
    }

    Ok(resp["result"].clone())
}

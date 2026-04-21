//! license-server: ZEC-paid pro license oracle for zafu wallet.
//!
//! Watches the license wallet (specified by FVK) for incoming Orchard notes
//! with `zid{bandersnatch_pubkey}` memos. The Bandersnatch pubkey in the memo
//! IS the ring member key — no separate registration step. This eliminates
//! the zpro-to-ring mapping that would let the server correlate payment
//! identity with ring membership.
//!
//! Sync architecture: connects to a zidecar gRPC endpoint, downloads compact
//! blocks, decrypts each Orchard action with the license FVK, fetches full
//! transactions for matched notes to extract memos. No zcashd needed —
//! pure light-client wallet.
//!
//! Signs licenses with rotko's ed25519 key. Serves ring keys for VRF proofs.
//!
//! endpoints:
//!   GET /license/{zid}   - check/issue license for a Bandersnatch pubkey
//!   GET /ring-keys       - all active pro ring member pubkeys
//!
//! env (see .env.example for the full list and how to obtain each value):
//!   ZCLI_SIGNING_KEY        - 32-byte hex ed25519 seed. its derived pubkey
//!                             MUST equal zafu's ROTKO_ZCASH_VERIFIER — that
//!                             constant is what verifies the licenses we sign.
//!   LICENSE_FVK             - 96-byte hex Orchard FullViewingKey for the
//!                             wallet that owns zafu's ROTKO_LICENSE_ADDRESS
//!                             (the address users send their ZEC payment to).
//!   ZIDECAR_URL             - zidecar gRPC endpoint. defaults to
//!                             https://zcash.rotko.net.
//!   LICENSE_LISTEN          - HTTP listen address. default 0.0.0.0:3334.
//!   LICENSE_DB_PATH         - sled DB path. default ./license.db.
//!   LICENSE_FRIENDS_FILE    - friends list path. default ./friends.txt.
//!   LICENSE_SCAN_INTERVAL   - rescan seconds. default 30.
//!   LICENSE_SYNC_FROM       - start-block height for first sync. optional.

mod scanner;

use axum::{
    extract::{Path, State},
    response::Json,
    routing::get,
    Router,
};
use clap::Parser;
use ed25519_consensus::SigningKey;
use orchard::keys::FullViewingKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use zecli::client::ZidecarClient;

// -- constants --

/// 0.01 ZEC = 30 days
const ZAT_PER_30_DAYS: u64 = 1_000_000;

/// JS-safe max (2^53 - 1) — used for permanent friend licenses
const PERMANENT_EXPIRES: u64 = 9_007_199_254_740_991;

/// sled key for tracking last scanned block height
const SYNC_HEIGHT_KEY: &[u8] = b"__sync_height__";

// -- types --

#[derive(Clone, Serialize, Deserialize)]
struct LicenseEntry {
    /// Bandersnatch ring VRF pubkey (hex) - this IS the license identity.
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

#[derive(Clone)]
struct AppState {
    licenses: Arc<RwLock<HashMap<String, LicenseEntry>>>,
    ring_keys: Arc<RwLock<Vec<String>>>,
    signing_key: Option<SigningKey>,
    db: sled::Db,
    /// pubkeys that get pro for free (friends, testers, etc)
    friends: Arc<HashSet<String>>,
}

#[derive(Parser, Debug)]
#[command(name = "license-server")]
#[command(about = "ZEC-paid pro license oracle for zafu")]
struct Args {
    /// listen address
    #[arg(long, env = "LICENSE_LISTEN", default_value = "0.0.0.0:3334")]
    listen: String,

    /// zidecar gRPC-Web endpoint (HTTP/2)
    #[arg(long, env = "ZIDECAR_URL", default_value = "https://zcash.rotko.net")]
    zidecar_url: String,

    /// orchard full viewing key for the license wallet (96 bytes hex)
    #[arg(long, env = "LICENSE_FVK")]
    fvk: String,

    /// ed25519 signing key seed (hex, 32 bytes)
    #[arg(long, env = "ZCLI_SIGNING_KEY", default_value = "")]
    signing_key: String,

    /// scan interval in seconds
    #[arg(long, env = "LICENSE_SCAN_INTERVAL", default_value_t = 30)]
    scan_interval: u64,

    /// database path for license persistence
    #[arg(long, env = "LICENSE_DB_PATH", default_value = "./license.db")]
    db_path: String,

    /// path to friends file (one zpro pubkey per line, # comments)
    #[arg(long, env = "LICENSE_FRIENDS_FILE", default_value = "./friends.txt")]
    friends_file: String,

    /// initial sync start block (skips earlier blocks). useful for testing
    /// or when the license wallet has a known birthday height. ignored after
    /// first sync (resumes from saved sync height).
    #[arg(long, env = "LICENSE_SYNC_FROM")]
    sync_from: Option<u32>,
}

// -- main --

#[tokio::main]
async fn main() {
    // load .env if present, then env vars take precedence over clap defaults.
    let _ = dotenvy::dotenv();

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

    let fvk = scanner::parse_fvk(&args.fvk).expect("invalid LICENSE_FVK");

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

    // seed initial sync height if --sync-from was provided and no sync state exists
    if let Some(from) = args.sync_from {
        if db.get(SYNC_HEIGHT_KEY).ok().flatten().is_none() {
            let _ = db.insert(SYNC_HEIGHT_KEY, &from.to_le_bytes());
            info!("initial sync will start from block {}", from);
        }
    }

    // load persisted licenses - ring = all valid paid keys (no separate registration)
    let mut licenses = HashMap::new();
    let mut ring_keys = Vec::new();
    for entry in db.iter().flatten() {
        // skip non-license keys (e.g. sync height)
        if entry.0.as_ref().starts_with(b"__") { continue; }
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
        db,
        friends: Arc::new(friends),
    };

    // background scanner
    let scan_state = state.clone();
    let scan_interval = args.scan_interval;
    let zidecar_url = args.zidecar_url.clone();
    tokio::spawn(async move {
        let client = match ZidecarClient::connect(&zidecar_url).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("failed to connect to zidecar: {e}");
                return;
            }
        };
        loop {
            if let Err(e) = sync_once(&scan_state, &client, &fvk).await {
                tracing::warn!("sync failed: {}", e);
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
    info!("zidecar: {}", args.zidecar_url);

    let listener = tokio::net::TcpListener::bind(&args.listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// -- sync --

async fn sync_once(
    state: &AppState,
    client: &ZidecarClient,
    fvk: &FullViewingKey,
) -> anyhow::Result<()> {
    let last_height = state.db.get(SYNC_HEIGHT_KEY)?
        .and_then(|v| {
            let b: [u8; 4] = v.as_ref().try_into().ok()?;
            Some(u32::from_le_bytes(b))
        })
        .unwrap_or(0);

    let (new_tip, memos) = scanner::scan(client, fvk, last_height).await?;
    if new_tip > last_height {
        info!("synced blocks {}..{} ({} memos found)", last_height + 1, new_tip, memos.len());
    }

    if memos.is_empty() && new_tip == last_height {
        return Ok(());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut licenses = state.licenses.write().await;
    let mut changed = false;

    for memo in &memos {
        if !memo.memo.starts_with("zid") { continue; }
        let zid = memo.memo.trim_start_matches("zid").trim().to_string();
        if zid.is_empty() || zid.len() < 32 { continue; }

        let txid_hex = hex::encode(&memo.txid);
        let entry = licenses.entry(zid.clone()).or_insert_with(|| LicenseEntry {
            zid: zid.clone(),
            plan: "free".into(),
            expires: 0,
            signature: String::new(),
            valid: false,
            total_paid_zat: 0,
            seen_txids: vec![],
        });

        if entry.seen_txids.contains(&txid_hex) { continue; }
        entry.seen_txids.push(txid_hex.clone());

        entry.total_paid_zat += memo.value_zat;
        let total_days = (entry.total_paid_zat as f64 / ZAT_PER_30_DAYS as f64 * 30.0) as u64;
        let expires = now + total_days * 86400;

        entry.plan = "pro".into();
        entry.expires = expires;
        entry.valid = expires > now;

        if let Some(ref sk) = state.signing_key {
            let payload = format!("zafu-license-v1\n{}\npro\n{}", zid, expires);
            entry.signature = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
        }

        if let Ok(bytes) = bincode::serialize(entry) {
            let _ = state.db.insert(zid.as_bytes(), bytes);
        }

        changed = true;
        info!(
            "license: {} = {} days ({} zat) at block {}",
            &zid[..12.min(zid.len())], total_days, entry.total_paid_zat, memo.block_height,
        );
    }

    drop(licenses);

    // persist sync height
    state.db.insert(SYNC_HEIGHT_KEY, &new_tip.to_le_bytes())?;

    if changed {
        let _ = state.db.flush_async().await;
        rebuild_ring_keys(state).await;
    }

    Ok(())
}

// -- handlers --

async fn get_license(
    State(state): State<AppState>,
    Path(zid): Path<String>,
) -> Json<LicenseResp> {
    // friends get permanent pro
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
        });
    }

    let licenses = state.licenses.read().await;
    if let Some(entry) = licenses.get(&zid) {
        Json(LicenseResp {
            zid: entry.zid.clone(),
            plan: entry.plan.clone(),
            expires: entry.expires,
            signature: entry.signature.clone(),
            valid: entry.valid,
        })
    } else {
        Json(LicenseResp {
            zid,
            plan: "free".into(),
            expires: 0,
            signature: String::new(),
            valid: false,
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
    let mut keys: Vec<String> = licenses
        .values()
        .filter(|e| e.valid)
        .map(|e| e.zid.clone())
        .collect();
    for f in state.friends.iter() {
        if !keys.contains(f) {
            keys.push(f.clone());
        }
    }
    let mut ring = state.ring_keys.write().await;
    *ring = keys;
}

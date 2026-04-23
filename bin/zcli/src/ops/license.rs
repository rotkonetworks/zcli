//! License server — processes ZEC payments for pro subscriptions.
//!
//! Architecture:
//! - Background sync loop detects "zid<pubkey>" memos in received notes
//! - Each payment processed ONCE (tracked by nullifier)
//! - Licenses stored in sled: key = zid_pubkey, value = SignedLicense JSON
//! - HTTP endpoint serves cached signed licenses
//! - Payment extends existing license: expires = max(current_expires, now) + new_days
//!
//! Confirmation policy:
//! - Payments under `instant_threshold_zat` are credited immediately (0 confs)
//! - Larger payments require `required_confs` confirmations
//! - Pending payments are tracked and reported to the client

use std::time::{SystemTime, UNIX_EPOCH};

use sled::Db;

use crate::error::Error;
use crate::wallet;

/// 0.01 ZEC = 1,000,000 zatoshi = 30 days
const RATE_ZAT_PER_30_DAYS: u64 = 1_000_000;

/// default: credit instantly for amounts under 0.1 ZEC (10M zat)
const DEFAULT_INSTANT_THRESHOLD_ZAT: u64 = 10_000_000;

/// default: 10 confirmations for larger payments
const DEFAULT_REQUIRED_CONFS: u32 = 10;

const LICENSES_TREE: &str = "licenses";
const PROCESSED_NULLIFIERS_TREE: &str = "processed_nullifiers";
const PENDING_TREE: &str = "pending_payments";

/// Configuration for the license server
#[derive(Clone)]
pub struct LicenseConfig {
    /// confirmations required for large payments
    pub required_confs: u32,
    /// payments below this are credited instantly (0 confs)
    pub instant_threshold_zat: u64,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            required_confs: DEFAULT_REQUIRED_CONFS,
            instant_threshold_zat: DEFAULT_INSTANT_THRESHOLD_ZAT,
        }
    }
}

/// A stored license in sled
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredLicense {
    pub zid: String,
    pub plan: String,
    pub expires: u64,
    pub signature: Vec<u8>,
    pub total_paid_zat: u64,
}

/// A pending (unconfirmed or under-confirmed) payment
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingPayment {
    pub zid: String,
    pub nullifier: [u8; 32],
    pub amount_zat: u64,
    pub block_height: u32,
    pub first_seen: u64,
}

/// Open (or create) the license database at the given path
pub fn open_license_db(dir: &str) -> Result<Db, Error> {
    let path = format!("{}/license-db", dir);
    sled::open(&path)
        .map_err(|e| Error::Other(format!("cannot open license db at {}: {}", path, e)))
}

/// Scan wallet notes for new "zid<pubkey>" payments, process them, store licenses.
/// Returns the number of new payments credited.
pub fn process_payments(
    license_db: &Db,
    signing_key: &ed25519_consensus::SigningKey,
    config: &LicenseConfig,
) -> Result<usize, Error> {
    let wallet = wallet::Wallet::open(&wallet::Wallet::default_path())?;
    let notes = wallet.all_received_notes()?;
    let sync_height = wallet.sync_height().unwrap_or(0);

    let licenses_tree = license_db
        .open_tree(LICENSES_TREE)
        .map_err(|e| Error::Other(format!("open licenses tree: {}", e)))?;
    let processed_tree = license_db
        .open_tree(PROCESSED_NULLIFIERS_TREE)
        .map_err(|e| Error::Other(format!("open processed tree: {}", e)))?;
    let pending_tree = license_db
        .open_tree(PENDING_TREE)
        .map_err(|e| Error::Other(format!("open pending tree: {}", e)))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut credited = 0;

    for note in &notes {
        // skip already-processed nullifiers
        if processed_tree
            .contains_key(note.nullifier)
            .map_err(|e| Error::Other(format!("check nullifier: {}", e)))?
        {
            continue;
        }

        // skip notes without "zid" memo
        let memo = match &note.memo {
            Some(m) if m.starts_with("zid") && m.len() > 3 => m,
            _ => continue,
        };

        let zid_pubkey = &memo[3..];
        if zid_pubkey.is_empty() || note.value == 0 {
            continue;
        }

        // check confirmation depth
        let confs = if note.block_height > 0 && sync_height >= note.block_height {
            sync_height - note.block_height
        } else {
            0
        };

        let needs_confs = if note.value < config.instant_threshold_zat {
            0 // instant credit for small amounts
        } else {
            config.required_confs
        };

        if confs < needs_confs {
            // not enough confirmations — track as pending
            let pending = PendingPayment {
                zid: zid_pubkey.to_string(),
                nullifier: note.nullifier,
                amount_zat: note.value,
                block_height: note.block_height,
                first_seen: now,
            };
            let json = serde_json::to_vec(&pending)
                .map_err(|e| Error::Other(format!("serialize pending: {}", e)))?;
            pending_tree
                .insert(note.nullifier, json)
                .map_err(|e| Error::Other(format!("store pending: {}", e)))?;

            eprintln!(
                "license: pending payment {} zat for zid {} ({}/{} confs)",
                note.value, zid_pubkey, confs, needs_confs
            );
            continue;
        }

        // enough confirmations — credit the license
        credit_payment(
            &licenses_tree,
            signing_key,
            zid_pubkey,
            note.value,
            now,
        )?;

        // mark nullifier as processed, remove from pending
        processed_tree
            .insert(note.nullifier, &[1u8])
            .map_err(|e| Error::Other(format!("mark processed: {}", e)))?;
        let _ = pending_tree.remove(note.nullifier);

        credited += 1;
        let days = (note.value as f64 / RATE_ZAT_PER_30_DAYS as f64 * 30.0) as u64;
        eprintln!(
            "license: credited {} zat for zid {} ({} days, {} confs)",
            note.value, zid_pubkey, days, confs
        );
    }

    if credited > 0 {
        license_db
            .flush()
            .map_err(|e| Error::Other(format!("flush license db: {}", e)))?;
    }

    Ok(credited)
}

/// Credit a payment to a ZID's license
fn credit_payment(
    licenses_tree: &sled::Tree,
    signing_key: &ed25519_consensus::SigningKey,
    zid_pubkey: &str,
    amount_zat: u64,
    now: u64,
) -> Result<(), Error> {
    let days = (amount_zat as f64 / RATE_ZAT_PER_30_DAYS as f64 * 30.0) as u64;
    if days == 0 {
        return Ok(());
    }

    let existing: Option<StoredLicense> = licenses_tree
        .get(zid_pubkey.as_bytes())
        .map_err(|e| Error::Other(format!("read license: {}", e)))?
        .and_then(|v| serde_json::from_slice(&v).ok());

    let (new_expires, total_paid) = match existing {
        Some(ref lic) => {
            let base = std::cmp::max(lic.expires, now);
            (base + days * 86400, lic.total_paid_zat + amount_zat)
        }
        None => (now + days * 86400, amount_zat),
    };

    let payload = format!("zafu-license-v1\n{}\npro\n{}", zid_pubkey, new_expires);
    let signature = signing_key.sign(payload.as_bytes());

    let license = StoredLicense {
        zid: zid_pubkey.to_string(),
        plan: "pro".into(),
        expires: new_expires,
        signature: signature.to_bytes().to_vec(),
        total_paid_zat: total_paid,
    };

    let json = serde_json::to_vec(&license)
        .map_err(|e| Error::Other(format!("serialize license: {}", e)))?;
    licenses_tree
        .insert(zid_pubkey.as_bytes(), json)
        .map_err(|e| Error::Other(format!("store license: {}", e)))?;

    Ok(())
}

/// Look up a license by ZID public key
pub fn get_license(license_db: &Db, zid_pubkey: &str) -> Result<Option<StoredLicense>, Error> {
    let licenses_tree = license_db
        .open_tree(LICENSES_TREE)
        .map_err(|e| Error::Other(format!("open licenses tree: {}", e)))?;

    match licenses_tree.get(zid_pubkey.as_bytes()) {
        Ok(Some(v)) => {
            let lic: StoredLicense = serde_json::from_slice(&v)
                .map_err(|e| Error::Other(format!("deserialize license: {}", e)))?;
            Ok(Some(lic))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(Error::Other(format!("read license: {}", e))),
    }
}

/// Get pending payment info for a ZID (if any)
pub fn get_pending(license_db: &Db, zid_pubkey: &str) -> Result<Option<PendingPayment>, Error> {
    let pending_tree = license_db
        .open_tree(PENDING_TREE)
        .map_err(|e| Error::Other(format!("open pending tree: {}", e)))?;

    // scan pending payments for this zid (linear scan — small table)
    for entry in pending_tree.iter() {
        let (_, value) = entry.map_err(|e| Error::Other(format!("iterate pending: {}", e)))?;
        if let Ok(p) = serde_json::from_slice::<PendingPayment>(&value) {
            if p.zid == zid_pubkey {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

/// Get current confirmations for a pending payment
pub fn pending_confs(sync_height: u32, block_height: u32) -> u32 {
    if block_height > 0 && sync_height >= block_height {
        sync_height - block_height
    } else {
        0
    }
}

/// Build the HTTP JSON response for a license lookup (includes pending info)
pub fn license_response_json(
    license_db: &Db,
    zid_pubkey: &str,
    license: Option<&StoredLicense>,
    config: &LicenseConfig,
) -> String {
    let pending = get_pending(license_db, zid_pubkey).ok().flatten();
    let sync_height = wallet::Wallet::open(&wallet::Wallet::default_path())
        .and_then(|w| w.sync_height())
        .unwrap_or(0);

    let (pending_zat, pending_c, required_c) = match &pending {
        Some(p) => {
            let confs = pending_confs(sync_height, p.block_height);
            let needed = if p.amount_zat < config.instant_threshold_zat {
                0
            } else {
                config.required_confs
            };
            (p.amount_zat, confs, needed)
        }
        None => (0, 0, 0),
    };

    match license {
        Some(lic) => serde_json::json!({
            "zid": lic.zid,
            "plan": lic.plan,
            "expires": lic.expires,
            "signature": hex::encode(&lic.signature),
            "valid": true,
            "pending_zat": pending_zat,
            "pending_confs": pending_c,
            "required_confs": required_c,
        })
        .to_string(),
        None => serde_json::json!({
            "zid": zid_pubkey,
            "plan": "free",
            "expires": 0,
            "signature": "",
            "valid": false,
            "pending_zat": pending_zat,
            "pending_confs": pending_c,
            "required_confs": required_c,
        })
        .to_string(),
    }
}

/// Parse signing key from hex (with optional 0x prefix)
pub fn parse_signing_key(key_hex: &str) -> Result<ed25519_consensus::SigningKey, Error> {
    let key_hex = key_hex.strip_prefix("0x").unwrap_or(key_hex);
    let seed: [u8; 32] = hex::decode(key_hex)
        .map_err(|e| Error::Other(format!("bad signing key hex: {}", e)))?
        .try_into()
        .map_err(|_| Error::Other("signing key must be 32 bytes".into()))?;
    Ok(ed25519_consensus::SigningKey::from(seed))
}

/// Shared license state for the HTTP server
pub struct LicenseState {
    pub db: Db,
    pub config: LicenseConfig,
}

impl LicenseState {
    /// Handle an HTTP request path, return (status_code, body)
    pub fn handle_request(&self, path: &str) -> (u16, String) {
        // GET /license/:zid
        if let Some(zid) = path.strip_prefix("/license/") {
            let zid = zid.trim_matches('/');
            if zid.is_empty() {
                return (400, r#"{"error":"missing zid"}"#.into());
            }
            match get_license(&self.db, zid) {
                Ok(lic) => (
                    200,
                    license_response_json(&self.db, zid, lic.as_ref(), &self.config),
                ),
                Err(e) => (500, format!(r#"{{"error":"{}"}}"#, e)),
            }
        } else if path == "/health" || path == "/" {
            (200, r#"{"status":"ok"}"#.into())
        } else {
            (404, r#"{"error":"not found"}"#.into())
        }
    }
}

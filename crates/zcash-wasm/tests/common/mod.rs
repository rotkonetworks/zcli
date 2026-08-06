//! Shared plumbing for the REAL-VALIDATOR regtest end-to-end tests
//! (`regtest_ironwood_e2e.rs`, `regtest_turnstile_e2e.rs`).
//!
//! Nothing here is test-specific policy: it is JSON-RPC transport, the ZIP-317
//! fee recomputation, key/address encoding, and the two-leaf merkle path helper.
//! The assertions live in the test files.
//!
//! This is `tests/common/mod.rs`, so cargo does NOT treat it as its own test
//! target; each test binary compiles its own copy via `mod common;` and only
//! uses part of it, hence the crate-level `dead_code` allowance.
#![allow(dead_code)]

use std::process::Command;
use std::sync::OnceLock;

use serde_json::{json, Value};

use incrementalmerkletree::{Hashable, Level};
use zcash_transparent::address::TransparentAddress;

/// Regtest coinbase maturity, same as mainnet.
pub const COINBASE_MATURITY: u32 = 100;

/// ZIP-317 marginal fee, in zatoshis per logical action.
pub const MARGINAL_FEE: u64 = 5_000;

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

/// Fallback RPC endpoint when neither `ZEBRAD_RPC` nor [`set_default_rpc`] has
/// been supplied - the port `deploy/regtest/zebrad-regtest.toml` listens on.
const BUILTIN_DEFAULT_RPC: &str = "http://127.0.0.1:28232";

static DEFAULT_RPC: OnceLock<String> = OnceLock::new();

/// Point the helpers at a different node when `ZEBRAD_RPC` is not set.
///
/// Each regtest harness owns its own port (the turnstile chain has a deferred
/// NU6.3 activation and must not share a node with the everything-at-height-1
/// chain), so a test that is not the default one calls this once at startup.
/// `ZEBRAD_RPC` still wins, so the runner scripts remain authoritative.
pub fn set_default_rpc(url: &str) {
    let _ = DEFAULT_RPC.set(url.to_string());
}

pub fn rpc_url() -> String {
    std::env::var("ZEBRAD_RPC").unwrap_or_else(|_| {
        DEFAULT_RPC
            .get()
            .cloned()
            .unwrap_or_else(|| BUILTIN_DEFAULT_RPC.to_string())
    })
}

/// One JSON-RPC call. Returns `Ok(result)` or `Err(the node's error object)` -
/// the error text is the whole point of these tests, so it is never swallowed.
///
/// This talks JSON-RPC over `curl` rather than pulling an HTTP client into this
/// crate's dependency graph; the crate ships to wasm and does not want one.
pub fn rpc(method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let out = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "120",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            &rpc_url(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(body.to_string().as_bytes())?;
            child.wait_with_output()
        })
        .expect("curl must be available to talk to zebrad");

    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !text.is_empty(),
        "empty response from {} - is zebrad running with the regtest config? \
         (see the module docs)",
        rpc_url()
    );
    let v: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("non-JSON response to {method}: {e}: {text}"));
    if let Some(err) = v.get("error") {
        if !err.is_null() {
            return Err(err.to_string());
        }
    }
    Ok(v["result"].clone())
}

pub fn rpc_ok(method: &str, params: Value) -> Value {
    rpc(method, params).unwrap_or_else(|e| panic!("{method} failed: {e}"))
}

pub fn tip_height() -> u32 {
    rpc_ok("getblockchaininfo", json!([]))["blocks"]
        .as_u64()
        .expect("blocks height") as u32
}

pub fn mine(n: u32, to: &str) {
    rpc_ok("generatetoaddress", json!([n, to]));
}

/// Size of a shielded note commitment tree as of `block`. Zebra omits
/// zero-sized trees from the `trees` object entirely, so absent means empty.
pub fn tree_size(block: &Value, pool: &str) -> u64 {
    block["trees"][pool]["size"].as_u64().unwrap_or(0)
}

/// Size of the ironwood note commitment tree as of `block`.
pub fn ironwood_tree_size(block: &Value) -> u64 {
    tree_size(block, "ironwood")
}

/// Size of the (legacy) orchard note commitment tree as of `block`.
pub fn orchard_tree_size(block: &Value) -> u64 {
    tree_size(block, "orchard")
}

/// Total value held in `pool` as of `block`, in zatoshis.
pub fn pool_zat(block: &Value, pool: &str) -> i64 {
    block["valuePools"]
        .as_array()
        .expect("valuePools")
        .iter()
        .find(|p| p["id"] == pool)
        .and_then(|p| p["chainValueZat"].as_i64())
        .unwrap_or_else(|| panic!("no {pool} value pool in the block's valuePools"))
}

/// Total value held in the ironwood pool as of `block`, in zatoshis.
pub fn ironwood_pool_zat(block: &Value) -> i64 {
    pool_zat(block, "ironwood")
}

/// Total value held in the legacy orchard pool as of `block`, in zatoshis.
pub fn orchard_pool_zat(block: &Value) -> i64 {
    pool_zat(block, "orchard")
}

/// The ZIP-317 conventional fee for a transaction, recomputed from the shape
/// the NODE reports rather than from our own builder's bookkeeping.
///
/// This mirrors zebra's `zip317::conventional_actions`
/// (zebra-chain/src/transaction/unmined/zip317.rs) byte for byte:
///
///   logical_actions = max(ceil(tx_in_total_size  / 150),
///                         ceil(tx_out_total_size /  34))
///                   + 2 * n_joinsplit
///                   + max(n_sapling_spends, n_sapling_outputs)
///                   + n_orchard_actions
///                   + n_ironwood_actions            <- ironwood costs like orchard
///   conventional_fee = 5_000 * max(2, logical_actions)
///
/// Note that the orchard and ironwood terms are ADDED, not maxed: a turnstile
/// migration with a 2-action orchard bundle and a 2-action ironwood bundle owes
/// `5_000 * 4 == 20_000`, which is what mainnet block 3,436,797 paid.
///
/// Recomputing it here from the mined JSON is the point of the exercise: if our
/// fee arithmetic and the validator's ever diverge, this is where it shows.
pub fn node_conventional_fee(tx: &Value) -> u64 {
    fn varint_len(n: usize) -> usize {
        match n {
            0..=252 => 1,
            253..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        }
    }
    fn script_len(script_hex: &str) -> usize {
        script_hex.len() / 2
    }

    let tx_in_total_size: usize = tx["vin"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|vin| {
            let script = script_len(vin["scriptSig"]["hex"].as_str().unwrap_or(""));
            // outpoint (32 + 4) + script (varint + bytes) + sequence (4)
            32 + 4 + varint_len(script) + script + 4
        })
        .sum();

    let tx_out_total_size: usize = tx["vout"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|vout| {
            let script = script_len(vout["scriptPubKey"]["hex"].as_str().unwrap_or(""));
            // value (8) + script (varint + bytes)
            8 + varint_len(script) + script
        })
        .sum();

    let count = |field: &str, sub: &str| -> usize {
        if sub.is_empty() {
            tx[field].as_array().map(|a| a.len()).unwrap_or(0)
        } else {
            tx[field][sub].as_array().map(|a| a.len()).unwrap_or(0)
        }
    };

    let logical_actions = tx_in_total_size
        .div_ceil(150)
        .max(tx_out_total_size.div_ceil(34))
        + 2 * count("vjoinsplit", "")
        + count("vShieldedSpend", "").max(count("vShieldedOutput", ""))
        + count("orchard", "actions")
        + count("ironwood", "actions");

    MARGINAL_FEE * (logical_actions as u64).max(2)
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

pub fn transparent_key(seed_byte: u8) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let secp = secp256k1::Secp256k1::signing_only();
    let sk = secp256k1::SecretKey::from_slice(&[seed_byte; 32]).expect("valid secret key");
    let pk = sk.public_key(&secp);
    (sk, pk)
}

/// Encode a P2PKH address for Regtest. Regtest shares testnet's `tm…` base58
/// prefix, which is what zebrad's `generatetoaddress` expects here.
pub fn encode_p2pkh(pk: &secp256k1::PublicKey) -> String {
    let addr = TransparentAddress::from_pubkey(pk);
    let TransparentAddress::PublicKeyHash(hash) = addr else {
        panic!("from_pubkey must produce a P2PKH address");
    };
    use zcash_address::ToAddress;
    zcash_address::ZcashAddress::from_transparent_p2pkh(
        zcash_protocol::consensus::NetworkType::Regtest,
        hash,
    )
    .to_string()
}

/// The canonical P2PKH `scriptPubKey` for `pk`, as the node prints it:
/// `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script_hex(pk: &secp256k1::PublicKey) -> String {
    let TransparentAddress::PublicKeyHash(hash) = TransparentAddress::from_pubkey(pk) else {
        panic!("from_pubkey must produce a P2PKH address");
    };
    format!("76a914{}88ac", hex::encode(hash))
}

/// The wallet's orchard-family keys, derived from a seed phrase exactly the way
/// the builders derive them internally. The same key material addresses both
/// the legacy orchard pool and the ironwood pool - the pools differ by note
/// version, not by key tree.
pub fn wallet_keys(
    seed_phrase: &str,
) -> (
    orchard::keys::FullViewingKey,
    orchard::keys::SpendAuthorizingKey,
) {
    let mnemonic = bip39::Mnemonic::parse(seed_phrase).expect("valid test mnemonic");
    let seed = mnemonic.to_seed("");
    // Regtest shares testnet's coin type (1).
    let sk = orchard::keys::SpendingKey::from_zip32_seed(&seed, 1, zip32::AccountId::ZERO).unwrap();
    (
        orchard::keys::FullViewingKey::from(&sk),
        orchard::keys::SpendAuthorizingKey::from(&sk),
    )
}

// ---------------------------------------------------------------------------
// merkle path against a real, two-leaf shielded tree
// ---------------------------------------------------------------------------

/// Build the merkle path for the note at `position` in a tree whose only leaves
/// are `cmxs` (in commitment order).
///
/// The regtest chains' coinbases pay a TRANSPARENT address, so a shielded tree
/// contains nothing but the two padded actions of the single transaction that
/// touched it - which makes the whole tree, and therefore the anchor, exactly
/// reproducible here. Both pools use `MerkleHashOrchard`, so this serves the
/// orchard and the ironwood tree alike.
pub fn two_leaf_merkle_path(
    cmxs: &[orchard::note::ExtractedNoteCommitment],
    position: u32,
) -> orchard::tree::MerklePath {
    assert_eq!(
        cmxs.len(),
        2,
        "this helper only covers a tree whose sole contents are one 2-action bundle"
    );
    let sibling_leaf = orchard::tree::MerkleHashOrchard::from_cmx(&cmxs[1 - position as usize]);

    let mut auth_path = [orchard::tree::MerkleHashOrchard::empty_leaf(); 32];
    auth_path[0] = sibling_leaf;
    for (level, node) in auth_path.iter_mut().enumerate().skip(1) {
        *node = orchard::tree::MerkleHashOrchard::empty_root(Level::from(level as u8));
    }
    orchard::tree::MerklePath::from_parts(position, auth_path)
}

// ---------------------------------------------------------------------------
// merkle path against the REAL chain, one pool at a time
// ---------------------------------------------------------------------------

/// Which shielded pool's commitments to read out of a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShieldedPool {
    Orchard,
    Ironwood,
}

impl ShieldedPool {
    pub fn name(self) -> &'static str {
        match self {
            ShieldedPool::Orchard => "orchard",
            ShieldedPool::Ironwood => "ironwood",
        }
    }
}

/// Raw bytes of a transaction as the NODE stored it.
fn raw_tx(txid: &str, tx_obj: &Value) -> Vec<u8> {
    let hex_str = match tx_obj["hex"].as_str() {
        Some(h) => h.to_string(),
        None => rpc_ok("getrawtransaction", json!([txid, 0]))
            .as_str()
            .unwrap_or_else(|| panic!("getrawtransaction {txid} returned no hex"))
            .to_string(),
    };
    hex::decode(&hex_str).unwrap_or_else(|e| panic!("bad tx hex for {txid}: {e}"))
}

/// Every commitment `pool` accumulated on this chain, in consensus order, from
/// block 1 through `to_height` inclusive.
///
/// Read back out of the node's own blocks and re-parsed from the raw
/// transactions, so it reflects what the validator committed rather than what
/// our builder thinks it built. This is the input a witness replay needs, and
/// keeping the two pools in separate functions of `pool` is the whole point:
/// feed the wrong list in and the resulting anchor is wrong.
pub fn pool_cmxs_through(
    to_height: u32,
    pool: ShieldedPool,
) -> Vec<orchard::note::ExtractedNoteCommitment> {
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    let mut cmxs = Vec::new();
    for height in 1..=to_height {
        let block = rpc_ok("getblock", json!([height.to_string(), 2]));
        for tx_obj in block["tx"].as_array().expect("block tx array") {
            let txid = tx_obj["txid"].as_str().expect("txid").to_string();
            let bytes = raw_tx(&txid, tx_obj);
            let tx = Transaction::read(&bytes[..], BranchId::Nu6_3)
                .unwrap_or_else(|e| panic!("cannot parse tx {txid} at height {height}: {e}"));
            match pool {
                ShieldedPool::Ironwood => {
                    if let Some(b) = tx.ironwood_bundle() {
                        cmxs.extend(b.actions().iter().map(|a| *a.cmx()));
                    }
                }
                ShieldedPool::Orchard => {
                    if let Some(b) = tx.orchard_bundle() {
                        cmxs.extend(b.actions().iter().map(|a| *a.cmx()));
                    }
                }
            }
        }
    }
    cmxs
}

/// Build the merkle path for the leaf at `position` by replaying `cmxs` into a
/// commitment tree with the SAME code the wallet uses (`zafu_wasm::witness`),
/// and return it together with the resulting anchor.
///
/// Unlike [`two_leaf_merkle_path`] this handles a tree of any size, which is
/// what makes it usable once more than one transaction has touched the pool.
pub fn replayed_merkle_path(
    cmxs: &[orchard::note::ExtractedNoteCommitment],
    position: u64,
) -> (orchard::tree::Anchor, orchard::tree::MerklePath) {
    let mut replay = zafu_wasm::witness::WitnessReplay::from_frontier_bytes(&[], &[position])
        .expect("empty frontier");
    for cmx in cmxs {
        replay
            .append_cmx_bytes(&cmx.to_bytes())
            .expect("append commitment");
    }
    let anchor = replay.anchor();
    let mut paths = replay
        .into_paths()
        .expect("witness for the requested position");
    (anchor, paths.remove(0))
}

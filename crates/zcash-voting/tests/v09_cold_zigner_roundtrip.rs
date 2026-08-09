//! REAL cold (zigner air-gapped) delegation round-trip against the local v09 chain.
//!
//! Proves the COLD voting-delegation path end to end: build a zafu voting
//! delegation as a redacted PCZT, sign it with zigner's REAL cold-signer code
//! (`pczt_signing::sign_redacted_pczt`, not a reimplementation), finalize it
//! locally (extract the spend-auth signature + real Halo2 ZKP #1), and get it
//! ACCEPTED by the live local v09 chain. If accepted, continue through cast-vote
//! and share reveal to FINALIZED/tally like the hot round-trip does.
//!
//! Everything past the delegation build/sign is copy-pasted verbatim from
//! `v09_roundtrip_real.rs` (the proven-accepted hot path) - only the delegation
//! build+sign step (Step 3) is swapped for the PCZT + zigner cold-signer seam.
//!
//! Run: cargo test -p zcash_voting --release --test v09_cold_zigner_roundtrip -- --ignored --nocapture

use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use blake2b_simd::Params as Blake2bParams;
use ff::{Field, PrimeField};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    keys::{Scope, SpendAuthorizingKey},
    note::{ExtractedNoteCommitment, NoteVersion, Rho},
    tree::MerkleHashOrchard,
    value::NoteValue,
    Note, NOTE_COMMITMENT_TREE_DEPTH,
};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use zcash_keys::keys::UnifiedSpendingKey;
use zip32::AccountId;

use voting_circuits::delegation::{ImtProofData, ImtProvider, SpacedLeafImtProvider};

use vote_commitment_tree::TreeClient;
use vote_commitment_tree::TreeSyncApi as _;
use vote_commitment_tree_client::http_sync_api::HttpTreeSyncApi;
use vote_commitment_tree_client::transport::{Transport, TransportError, TransportResponse};
use std::sync::Arc;

use zcash_voting::types::{DelegationProgressReporter, Network, NoteInfo, NoopProgressReporter, WitnessData};
use zcash_voting::wasm_delegation::InjectedImtProof;
use zcash_voting::wire::VotingRoundParams;
use zcash_voting::{BALLOT_DIVISOR, BUNDLE_NOTE_SLOTS};

/// See v09_roundtrip_real.rs for why this shim exists (the chain's REST shape
/// has no per-block `root` and no cursor). Reused verbatim.
struct FixedTreeSyncApi {
    inner: HttpTreeSyncApi,
    round_id_hex: String,
}

impl vote_commitment_tree::sync_api::TreeSyncApi for FixedTreeSyncApi {
    type Error = <HttpTreeSyncApi as vote_commitment_tree::sync_api::TreeSyncApi>::Error;

    fn get_tree_state(&self) -> Result<vote_commitment_tree::sync_api::TreeState, Self::Error> {
        self.inner.get_tree_state()
    }

    fn get_root_at_height(&self, height: u32) -> Result<Option<pasta_curves::Fp>, Self::Error> {
        self.inner.get_root_at_height(height)
    }

    fn get_block_commitments(
        &self,
        from_height: u32,
        to_height: u32,
    ) -> Result<vote_commitment_tree::sync_api::BlockCommitmentsPage, Self::Error> {
        #[derive(serde::Deserialize)]
        struct RawBlock {
            #[serde(default)]
            height: u64,
            #[serde(default)]
            start_index: u64,
            #[serde(default)]
            leaves: Vec<String>,
        }
        #[derive(serde::Deserialize)]
        struct RawResponse {
            #[serde(default)]
            blocks: Vec<RawBlock>,
        }

        // This chain caps a leaves query at a 1000-block span ("block range N
        // exceeds maximum 1000"). The sync driver re-invokes us on
        // `next_from_height`, so window each REST call to <=1000 blocks and
        // hand back the next cursor until we reach `to_height`.
        const MAX_SPAN: u32 = 900;
        let chunk_to = to_height.min(from_height + MAX_SPAN);
        let url = format!(
            "{}/shielded-vote/v1/commitment-tree/{}/leaves?from_height={}&to_height={}",
            CHAIN_REST_URL, self.round_id_hex, from_height, chunk_to
        );
        let resp = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap()
            .get(&url)
            .send()
            .unwrap_or_else(|e| panic!("GET {url} failed: {e}"));
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .unwrap_or_else(|e| panic!("reading body from {url} failed: {e}"));
        assert!(
            (200..300).contains(&status),
            "GET {url} returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
        let raw: RawResponse = serde_json::from_slice(&body)
            .unwrap_or_else(|e| panic!("parsing leaves response from {url} failed: {e}"));

        let mut blocks = Vec::with_capacity(raw.blocks.len());
        for b in raw.blocks {
            let height = b.height as u32;
            let leaves: Vec<vote_commitment_tree::MerkleHashVote> = b
                .leaves
                .iter()
                .map(|b64_str| {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64_str)
                        .expect("valid base64 leaf");
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    let fp = Option::from(pasta_curves::Fp::from_repr(arr)).expect("canonical Fp leaf");
                    vote_commitment_tree::MerkleHashVote::from_fp(fp)
                })
                .collect();
            let root = self
                .inner
                .get_root_at_height(height)?
                .unwrap_or_else(|| panic!("no root at height {height} (round {})", self.round_id_hex));
            blocks.push(vote_commitment_tree::sync_api::BlockCommitments {
                height,
                start_index: b.start_index,
                leaves,
                root,
            });
        }

        let next_from_height = if chunk_to < to_height { chunk_to + 1 } else { 0 };
        Ok(vote_commitment_tree::sync_api::BlockCommitmentsPage {
            blocks,
            next_from_height,
        })
    }
}

/// Blocking reqwest transport for the vote-commitment tree sync client.
struct ReqwestTransport {
    client: reqwest::blocking::Client,
}
impl ReqwestTransport {
    fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }
}
impl Transport for ReqwestTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| TransportError::Request(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .map_err(|e| TransportError::Request(e.to_string()))?
            .to_vec();
        Ok(TransportResponse { status, body })
    }
}

const CHAIN_REST_URL: &str = "http://127.0.0.1:1317";
const CHAIN_ID: &str = "svote-1";
const VOTE_MANAGER_KEY: &str = "vote-manager-1";
const CONTAINER: &str = "val1";
const VOTE_WINDOW_SECS: u64 = 180;

const PROPOSAL_ID: u32 = 1;
const CHOICE: u32 = 1; // Oppose
const NUM_OPTIONS: u32 = 2;
const PROPOSAL_AUTHORITY: u64 = 0xFFFF; // fresh bundle, no shares submitted yet

/// Mainnet NU6.3 (Ironwood) activation height, per zcash-voting's own test
/// `branch_id_for_height_follows_network_activation_heights` in src/lwd.rs.
const NU6_3_ACTIVATION_HEIGHT: u64 = 3_428_143;

/// Fixed 12-word BIP39 test mnemonic. zigner derives the spending key from
/// `mnemonic.to_seed("")`; the owner notes MUST be built against the same key.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

struct NoopDelegReporter;
impl DelegationProgressReporter for NoopDelegReporter {
    fn on_progress(&self, _p: zcash_voting::delegate::DelegationProgress) {}
}

fn log(msg: &str) {
    eprintln!("[v09-cold] {}", msg);
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn http_get(path: &str) -> Result<(u16, Value), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}{}", CHAIN_REST_URL, path);
    let resp = client.get(&url).send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let json = resp.json::<Value>().unwrap_or(Value::Null);
    Ok((status, json))
}

fn http_post(path: &str, body: &Value) -> Result<(u16, Value), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}{}", CHAIN_REST_URL, path);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let json = resp.json::<Value>().unwrap_or(Value::Null);
    Ok((status, json))
}

/// Poseidon round-id derivation (mirrors chain deriveRoundID over 8 Fp elements).
/// Copied verbatim from v09_roundtrip_real.rs.
fn derive_round_id(
    snapshot_height: u64,
    snapshot_blockhash: &[u8; 32],
    proposals_hash: &[u8; 32],
    vote_end_time: u64,
    nullifier_imt_root: &[u8; 32],
    nc_root: &[u8; 32],
) -> [u8; 32] {
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};

    let split = |bytes: &[u8; 32]| -> (pallas::Base, pallas::Base) {
        let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(bytes[16..32].try_into().unwrap());
        (pallas::Base::from_u128(lo), pallas::Base::from_u128(hi))
    };
    let (bh_lo, bh_hi) = split(snapshot_blockhash);
    let (ph_lo, ph_hi) = split(proposals_hash);
    let nf_root = pallas::Base::from_repr(*nullifier_imt_root).unwrap();
    let nc = pallas::Base::from_repr(*nc_root).unwrap();
    let inputs = [
        pallas::Base::from(snapshot_height),
        bh_lo,
        bh_hi,
        ph_lo,
        ph_hi,
        pallas::Base::from(vote_end_time),
        nf_root,
        nc,
    ];
    let hash = poseidon::Hash::<_, P128Pow5T3, ConstantLength<8>, 3, 2>::init().hash(inputs);
    hash.to_repr()
}

fn get_round(round_id_hex: &str) -> Option<Value> {
    let (status, json) = http_get(&format!("/shielded-vote/v1/round/{}", round_id_hex)).ok()?;
    if status != 200 {
        return None;
    }
    json.get("round").cloned().or(Some(json))
}

fn round_status(round_id_hex: &str) -> Option<i64> {
    get_round(round_id_hex)?.get("status").and_then(|s| s.as_i64())
}

fn round_ea_pk(round_id_hex: &str) -> Option<Vec<u8>> {
    let r = get_round(round_id_hex)?;
    let s = r.get("ea_pk")?.as_str()?;
    if s.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn tree_next_index(round_id_hex: &str) -> Option<u64> {
    let (status, json) =
        http_get(&format!("/shielded-vote/v1/commitment-tree/{}/latest", round_id_hex)).ok()?;
    if status != 200 {
        return None;
    }
    json.get("tree")?
        .get("next_index")
        .and_then(|v| v.as_u64())
}

fn tree_height(round_id_hex: &str) -> Option<u64> {
    let (status, json) =
        http_get(&format!("/shielded-vote/v1/commitment-tree/{}/latest", round_id_hex)).ok()?;
    if status != 200 {
        return None;
    }
    json.get("tree")?.get("height").and_then(|v| v.as_u64())
}

fn tally_has_proposal(round_id_hex: &str, proposal_id: u32) -> bool {
    let path = format!("/shielded-vote/v1/tally/{}/{}", round_id_hex, proposal_id);
    let (status, json) = match http_get(&path) {
        Ok(x) => x,
        Err(_) => return false,
    };
    if status != 200 {
        return false;
    }
    json.get("tally")
        .and_then(|t| t.as_object())
        .map(|m| !m.is_empty())
        .unwrap_or(false)
}

fn docker_exec(args: &[&str]) -> Result<String, String> {
    let mut full = vec!["exec", CONTAINER];
    full.extend_from_slice(args);
    let out = Command::new("docker")
        .args(&full)
        .output()
        .map_err(|e| format!("docker exec spawn: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "docker exec {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Create the voting round via a real Cosmos tx (svoted CLI inside the container).
/// Copied verbatim from v09_roundtrip_real.rs.
fn create_round_tx(
    session_json: &str,
    snapshot_height: u64,
    snapshot_blockhash: &[u8; 32],
    proposals_hash: &[u8; 32],
    vote_end_time: u64,
    nullifier_imt_root: &[u8; 32],
    nc_root: &[u8; 32],
) -> Result<String, String> {
    let host_path = format!(
        "{}/v09_cold_session.json",
        std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string())
    );
    std::fs::write(&host_path, session_json).map_err(|e| format!("write session json: {}", e))?;
    let cp = Command::new("docker")
        .args(["cp", &host_path, &format!("{}:/tmp/v09_cold_session.json", CONTAINER)])
        .output()
        .map_err(|e| format!("docker cp spawn: {}", e))?;
    if !cp.status.success() {
        return Err(format!(
            "docker cp failed: {}",
            String::from_utf8_lossy(&cp.stderr)
        ));
    }

    let stdout = docker_exec(&[
        "svoted",
        "tx",
        "vote",
        "create-voting-session",
        "/tmp/v09_cold_session.json",
        "--from",
        VOTE_MANAGER_KEY,
        "--keyring-backend",
        "test",
        "--chain-id",
        CHAIN_ID,
        "--gas",
        "auto",
        "--gas-adjustment",
        "1.5",
        "--fees",
        "6000usvote",
        "-y",
        "-o",
        "json",
    ])?;

    let v: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("parse tx json: {} (raw: {})", e, stdout))?;
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    let txhash = v
        .get("txhash")
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string();
    if code != 0 {
        return Err(format!(
            "create-voting-session tx rejected: code={} raw_log={:?}",
            code,
            v.get("raw_log")
        ));
    }
    let round_id = derive_round_id(
        snapshot_height,
        snapshot_blockhash,
        proposals_hash,
        vote_end_time,
        nullifier_imt_root,
        nc_root,
    );
    log(&format!("create tx accepted, txhash={}", txhash));
    Ok(hex::encode(round_id))
}

#[test]
#[ignore = "requires the local v09 chain running at 127.0.0.1:1317"]
fn v09_cold_zigner_roundtrip() {
    let mut rng = OsRng;

    // ---------------------------------------------------------------
    // Step 0: derive owner key from a BIP39 mnemonic (same seed zigner will
    // use). Hotkey stays a plain in-process ZIP-32 seed (unrelated to the
    // cold seam under test - only the OWNER's delegation key must be cold).
    // ---------------------------------------------------------------
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, TEST_MNEMONIC)
        .expect("parse test mnemonic");
    let seed = mnemonic.to_seed("");
    let account = AccountId::try_from(0u32).unwrap();
    let network = Network::Mainnet;
    let owner_usk = UnifiedSpendingKey::from_seed(&network, &seed, account).unwrap();
    let owner_ufvk = owner_usk.to_unified_full_viewing_key();
    let owner_ufvk_str = owner_ufvk.encode(&network);
    let owner_fvk = owner_ufvk.orchard().unwrap().clone();
    let fvk_bytes: [u8; 96] = owner_fvk.to_bytes();

    let seed_fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&seed)
        .expect("seed fingerprint")
        .to_bytes();

    log(&format!(
        "owner derived from bip39 mnemonic, ufvk={}",
        &owner_ufvk_str[..24.min(owner_ufvk_str.len())]
    ));

    // Hotkey (VAN note recipient). Unrelated to the cold seam - plain in-process
    // key, same as the hot test's step 0.
    let hotkey_seed = [0x43u8; 32];
    let hotkey_usk = UnifiedSpendingKey::from_seed(&network, &hotkey_seed, account).unwrap();
    let hotkey_fvk = hotkey_usk
        .to_unified_full_viewing_key()
        .orchard()
        .unwrap()
        .clone();
    let hotkey_addr = hotkey_fvk.address_at(0u32, Scope::External);
    let hotkey_raw_address = hotkey_addr.to_raw_address_bytes().to_vec();
    let address_index: u32 = 0;

    // ---------------------------------------------------------------
    // Step 1: build owner notes + NC tree + IMT (fills all 5 slots, so there
    // is zero padding and the dummy-IMT complexity is sidestepped).
    // ---------------------------------------------------------------
    let per_note_value = (BALLOT_DIVISOR / BUNDLE_NOTE_SLOTS as u64) + 1;
    let total_note_value = per_note_value * BUNDLE_NOTE_SLOTS as u64;
    let address = owner_fvk.address_at(0u32, Scope::External);

    let mut notes = Vec::new();
    for _ in 0..BUNDLE_NOTE_SLOTS {
        let (_, _, dummy_parent) = Note::dummy(&mut rng, None, NoteVersion::V3);
        let note = Note::new(
            address,
            NoteValue::from_raw(per_note_value),
            Rho::from_nf_old(dummy_parent.nullifier(&owner_fvk)),
            NoteVersion::V3,
            &mut rng,
        );
        notes.push(note);
    }
    log(&format!(
        "built {} notes, total_note_value={} ({} ballot(s))",
        notes.len(),
        total_note_value,
        total_note_value / BALLOT_DIVISOR
    ));

    let empty_leaf = MerkleHashOrchard::empty_leaf();
    let mut leaves = [empty_leaf; 8];
    for (i, note) in notes.iter().enumerate() {
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        leaves[i] = MerkleHashOrchard::from_cmx(&cmx);
    }
    let l1_0 = MerkleHashOrchard::combine(Level::from(0), &leaves[0], &leaves[1]);
    let l1_1 = MerkleHashOrchard::combine(Level::from(0), &leaves[2], &leaves[3]);
    let l1_2 = MerkleHashOrchard::combine(Level::from(0), &leaves[4], &leaves[5]);
    let l1_3 = MerkleHashOrchard::combine(Level::from(0), &leaves[6], &leaves[7]);
    let l2_0 = MerkleHashOrchard::combine(Level::from(1), &l1_0, &l1_1);
    let l2_1 = MerkleHashOrchard::combine(Level::from(1), &l1_2, &l1_3);
    let l3_0 = MerkleHashOrchard::combine(Level::from(2), &l2_0, &l2_1);
    let mut current = l3_0;
    for level in 3..NOTE_COMMITMENT_TREE_DEPTH {
        let sibling = MerkleHashOrchard::empty_root(Level::from(level as u8));
        current = MerkleHashOrchard::combine(Level::from(level as u8), &current, &sibling);
    }
    let nc_root_bytes: [u8; 32] = current.to_bytes();

    let l1 = [l1_0, l1_1, l1_2, l1_3];
    let l2 = [l2_0, l2_1];
    let imt = SpacedLeafImtProvider::new();
    let nf_imt_root_bytes: [u8; 32] = imt.root().to_repr();

    let mut merkle_witnesses = Vec::new();
    let mut imt_proofs: Vec<ImtProofData> = Vec::new();
    let mut full_notes: Vec<NoteInfo> = Vec::new();
    for (i, note) in notes.iter().enumerate() {
        let mut auth_path_hashes = [MerkleHashOrchard::empty_leaf(); NOTE_COMMITMENT_TREE_DEPTH];
        auth_path_hashes[0] = leaves[i ^ 1];
        auth_path_hashes[1] = l1[(i >> 1) ^ 1];
        auth_path_hashes[2] = l2[(i >> 2) ^ 1];
        for level in 3..NOTE_COMMITMENT_TREE_DEPTH {
            auth_path_hashes[level] = MerkleHashOrchard::empty_root(Level::from(level as u8));
        }
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        merkle_witnesses.push(WitnessData {
            note_commitment: MerkleHashOrchard::from_cmx(&cmx).to_bytes().to_vec(),
            position: i as u64,
            root: nc_root_bytes.to_vec(),
            auth_path: auth_path_hashes.iter().map(|h| h.to_bytes().to_vec()).collect(),
        });

        let nf_bytes = note.nullifier(&owner_fvk).to_bytes();
        let nf_base = pallas::Base::from_repr(nf_bytes).unwrap();
        imt_proofs.push(imt.non_membership_proof(nf_base).unwrap());

        full_notes.push(NoteInfo {
            commitment: cmx.to_bytes().to_vec(),
            nullifier: note.nullifier(&owner_fvk).to_bytes().to_vec(),
            value: per_note_value,
            position: i as u64,
            diversifier: note.recipient().diversifier().as_array().to_vec(),
            rho: note.rho().to_bytes().to_vec(),
            rseed: note.rseed().as_bytes().to_vec(),
            scope: 0,
            ufvk_str: owner_ufvk_str.clone(),
        });
    }

    // ---------------------------------------------------------------
    // Step 2: fix session fields + derive round_id. snapshot_height must be
    // >= NU6.3 activation so build_delegation_pczt's Ironwood-only check
    // passes.
    // ---------------------------------------------------------------
    let snapshot_height: u64 = NU6_3_ACTIVATION_HEIGHT;
    let snapshot_blockhash = [0xCCu8; 32];
    let proposals_hash = [0xDDu8; 32];
    let vote_end_time = now_secs() + VOTE_WINDOW_SECS;
    let round_id = derive_round_id(
        snapshot_height,
        &snapshot_blockhash,
        &proposals_hash,
        vote_end_time,
        &nf_imt_root_bytes,
        &nc_root_bytes,
    );
    let round_id_hex = hex::encode(round_id);
    log(&format!("derived round_id = {}", round_id_hex));

    let consensus_branch_id = zcash_voting::lwd::branch_id_for_height(network, snapshot_height)
        .expect("branch_id_for_height");
    log(&format!(
        "consensus_branch_id = 0x{:08X} at snapshot_height {}",
        consensus_branch_id, snapshot_height
    ));

    // ---------------------------------------------------------------
    // Step 3: create the round on-chain FIRST. build_delegation_pczt validates
    // params.ea_pk as a real 32-byte value (validate_round_params), so the
    // round (and its per-round ea_pk) must exist before the PCZT can be built.
    // ---------------------------------------------------------------
    let session_json = json!({
        "snapshot_height": snapshot_height,
        "snapshot_blockhash": hex::encode(snapshot_blockhash),
        "proposals_hash": hex::encode(proposals_hash),
        "vote_end_time": vote_end_time,
        "nullifier_imt_root": hex::encode(nf_imt_root_bytes),
        "nc_root": hex::encode(nc_root_bytes),
        "proposals": [
            {
                "id": 1,
                "title": "zafu v09 cold zigner round",
                "options": [
                    {"index": 0, "label": "Support"},
                    {"index": 1, "label": "Oppose"}
                ]
            }
        ]
    })
    .to_string();

    log("creating round via svoted tx create-voting-session...");
    let created_hex = create_round_tx(
        &session_json,
        snapshot_height,
        &snapshot_blockhash,
        &proposals_hash,
        vote_end_time,
        &nf_imt_root_bytes,
        &nc_root_bytes,
    )
    .expect("create round tx");
    assert_eq!(
        created_hex, round_id_hex,
        "on-chain derived round_id must match local derivation"
    );

    log("waiting for round to become ACTIVE...");
    let deadline = Instant::now() + Duration::from_secs(240);
    let mut active = false;
    while Instant::now() < deadline {
        if round_status(&round_id_hex) == Some(1) {
            active = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(active, "round never became ACTIVE");
    let ea_pk = round_ea_pk(&round_id_hex).expect("ACTIVE round must have ea_pk");
    assert_eq!(ea_pk.len(), 32, "ea_pk must be 32 bytes");
    log(&format!("round ACTIVE, ea_pk={}", hex::encode(&ea_pk)));

    // ---------------------------------------------------------------
    // Step 4: build the governance delegation PCZT (no chain anchor needed -
    // it's self-contained per wasm_delegation.rs docs) and redact it for the
    // cold signer.
    // ---------------------------------------------------------------
    let params = VotingRoundParams {
        vote_round_id: round_id_hex.clone(),
        snapshot_height,
        ea_pk: ea_pk.clone(),
        nc_root: nc_root_bytes.to_vec(),
        nullifier_imt_root: nf_imt_root_bytes.to_vec(),
    };

    log("building delegation PCZT (build_delegation_pczt)...");
    let artifact = zcash_voting::wasm_delegation::build_delegation_pczt(
        &full_notes,
        &params,
        network,
        &fvk_bytes,
        &hotkey_raw_address,
        consensus_branch_id,
        &seed_fingerprint,
        0,
        "zafu v09 cold zigner round",
    )
    .expect("build_delegation_pczt");
    log(&format!(
        "delegation PCZT built: redacted_pczt={}B, action_index={}, total_note_value={}, memo={:?}",
        artifact.redacted_pczt.len(),
        artifact.governance.action_index,
        artifact.total_note_value,
        artifact.display_memo,
    ));

    // ---------------------------------------------------------------
    // Step 5: sign with zigner's REAL cold-signer code. This is the
    // load-bearing step - the entry point under test.
    // ---------------------------------------------------------------
    log("calling pczt_signing::sign_redacted_pczt (REAL zigner cold-signer)...");
    let signed_pczt_bytes = pczt_signing::sign_redacted_pczt(
        &artifact.redacted_pczt,
        TEST_MNEMONIC,
        0,
        true, // mainnet
    )
    .unwrap_or_else(|e| panic!("pczt_signing::sign_redacted_pczt FAILED: {:?}", e));
    log(&format!(
        "zigner signed the PCZT: signed_pczt={}B",
        signed_pczt_bytes.len()
    ));

    // ---------------------------------------------------------------
    // Step 6: extract the spend-auth signature from the signed PCZT.
    // ---------------------------------------------------------------
    let spend_auth_sig = zcash_voting::delegate::spend_auth_signature(
        &signed_pczt_bytes,
        artifact.governance.action_index,
    )
    .expect("spend_auth_signature");
    log(&format!(
        "extracted spend_auth_sig ({} bytes)",
        spend_auth_sig.len()
    ));

    // Correctness check on the cold seam: zigner recomputes the sighash from
    // the PCZT contents itself (Signer::new(pczt).shielded_sighash()), so if
    // the redact/sign/extract round-trip is honest, re-extracting the sighash
    // from the SIGNED pczt must equal what build_delegation_pczt recorded.
    let sighash_from_signed = zcash_voting::delegate::pczt_sighash(&signed_pczt_bytes)
        .expect("pczt_sighash(signed)");
    assert_eq!(
        sighash_from_signed.as_slice(),
        artifact.governance.pczt_sighash.as_slice(),
        "sighash recomputed from zigner-signed PCZT must match the sighash \
         build_delegation_pczt recorded before signing"
    );
    log(&format!(
        "sighash cross-check OK: {}",
        hex::encode(sighash_from_signed)
    ));

    // ---------------------------------------------------------------
    // Step 7: build the real ZKP #1 delegation proof (prove_delegation).
    // 5 real notes fill all BUNDLE_NOTE_SLOTS, so padded_note_secrets/
    // dummy_imt_proofs are empty - no dummy-IMT complexity.
    // ---------------------------------------------------------------
    assert!(
        artifact.governance.padded_note_secrets.is_empty(),
        "expected zero padding with 5 real notes filling BUNDLE_NOTE_SLOTS"
    );
    let real_imt_proofs: Vec<InjectedImtProof> = imt_proofs
        .iter()
        .zip(full_notes.iter())
        .map(|(p, note)| InjectedImtProof {
            nullifier: note.nullifier.clone().try_into().unwrap(),
            root: p.root.to_repr(),
            nf_bounds: [
                p.nf_bounds[0].to_repr(),
                p.nf_bounds[1].to_repr(),
                p.nf_bounds[2].to_repr(),
            ],
            leaf_pos: p.leaf_pos,
            path: p.path.iter().map(|s| s.to_repr()).collect(),
        })
        .collect();

    log("building delegation proof (ZKP #1, real Halo2, 30-60s)...");
    let deleg_proof = zcash_voting::wasm_delegation::prove_delegation(
        &full_notes,
        &hotkey_raw_address,
        &artifact.governance.alpha,
        &artifact.governance.van_comm_rand,
        &round_id,
        &artifact.governance.padded_note_secrets,
        &artifact.governance.rseed_signed,
        &artifact.governance.rseed_output,
        &merkle_witnesses,
        &real_imt_proofs,
        &[], // dummy_imt_proofs: none, zero padding
        network,
    )
    .expect("prove_delegation");
    log(&format!(
        "delegation proof ready: proof={}B, van_comm={}, gov_nullifiers={}",
        deleg_proof.proof.len(),
        hex::encode(&deleg_proof.van_comm),
        deleg_proof.gov_nullifiers.len()
    ));

    // ---------------------------------------------------------------
    // Step 8: assemble + POST delegate-vote using the COLD-signed rk/sig and
    // the real ZKP #1 proof. Field names match the hot test's proven-accepted
    // JSON shape exactly.
    // ---------------------------------------------------------------
    let pre_next = tree_next_index(&round_id_hex).unwrap_or(0);
    let van_position = pre_next; // fresh round: 0

    let deleg_body = json!({
        "rk": b64(&artifact.governance.rk),
        "spend_auth_sig": b64(&spend_auth_sig),
        "sighash": b64(&artifact.governance.pczt_sighash),
        "signed_note_nullifier": b64(&deleg_proof.nf_signed),
        "cmx_new": b64(&deleg_proof.cmx_new),
        "van_cmx": b64(&deleg_proof.van_comm),
        "gov_nullifiers": deleg_proof.gov_nullifiers.iter().map(|g| b64(g)).collect::<Vec<_>>(),
        "proof": b64(&deleg_proof.proof),
        "vote_round_id": b64(&round_id),
    });
    log(&format!("POST delegate-vote (van_position={})...", van_position));
    let (st, js) = http_post("/shielded-vote/v1/delegate-vote", &deleg_body).expect("post delegate");
    log(&format!("=== COLD DELEGATE-VOTE RESPONSE: HTTP {} body={} ===", st, js));

    let code = js.get("code").and_then(|c| c.as_i64());
    let accepted = st == 200 && (code.is_none() || code == Some(0));
    if !accepted {
        panic!(
            "delegate-vote REJECTED by chain: HTTP {} body={} -- STOPPING per task instructions \
             (do not continue past a real rejection)",
            st, js
        );
    }
    log("cold delegate-vote ACCEPTED by chain (HTTP 200, code 0)");

    // Wait for van_cmx leaf to land.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut landed = false;
    while Instant::now() < deadline {
        if tree_next_index(&round_id_hex).map(|n| n >= pre_next + 1).unwrap_or(false) {
            landed = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(landed, "delegation van_cmx leaf never appeared in tree");
    let anchor_height = tree_height(&round_id_hex).expect("tree height") as u32;
    assert!(anchor_height > 0, "anchor_height must be > 0");
    log(&format!("delegation committed, anchor_height={}", anchor_height));

    // ---------------------------------------------------------------
    // Step 9: sync the vote-commitment tree + VAN witness (verbatim from hot test).
    // ---------------------------------------------------------------
    log(&format!("syncing vote-commitment tree, VAN witness @ pos {}...", van_position));
    let mut tree_client = TreeClient::empty();
    tree_client.mark_position(van_position);
    let sync_api = FixedTreeSyncApi {
        inner: HttpTreeSyncApi::new(
            CHAIN_REST_URL,
            round_id_hex.clone(),
            Arc::new(ReqwestTransport::new()) as Arc<dyn Transport>,
        ),
        round_id_hex: round_id_hex.clone(),
    };
    tree_client.sync(&sync_api).expect("TreeClient sync from chain");
    assert!(
        tree_client.size() >= van_position + 1,
        "synced tree must include VAN leaf (size={}, need>={})",
        tree_client.size(),
        van_position + 1
    );
    let witness = tree_client
        .witness(van_position, anchor_height)
        .expect("generate VAN witness");
    let auth_path: Vec<[u8; 32]> =
        witness.auth_path().iter().map(|h| h.to_bytes()).collect();
    assert_eq!(auth_path.len(), 24, "auth_path must have 24 siblings");

    let local_root = tree_client
        .root_at_height(anchor_height)
        .expect("local root at anchor height");
    let local_root_bytes = local_root.to_repr();
    if let Ok((200, tj)) = http_get(&format!(
        "/shielded-vote/v1/commitment-tree/{}/{}",
        round_id_hex, anchor_height
    )) {
        if let Some(on_chain_root_b64) =
            tj.get("tree").and_then(|t| t.get("root")).and_then(|r| r.as_str())
        {
            let on_chain = base64::engine::general_purpose::STANDARD
                .decode(on_chain_root_b64)
                .unwrap();
            assert_eq!(
                on_chain.as_slice(),
                &local_root_bytes[..],
                "local tree root must match on-chain root at anchor_height"
            );
            log("local VAN witness root matches on-chain root");
        }
    }

    // ---------------------------------------------------------------
    // Step 10: build vote commitment (real Halo2 ZKP #2 + ElGamal shares).
    // The cast/hotkey side is unrelated to the cold seam under test, so this
    // stays an in-process hotkey signer, exactly like the hot test.
    // ---------------------------------------------------------------
    log("building vote commitment (ZKP #2, real Halo2, 30-60s)...");
    let van_comm_rand_bytes = &artifact.governance.van_comm_rand;
    let bundle = zcash_voting::zkp2::build_vote_commitment(
        &hotkey_seed,
        network,
        address_index,
        total_note_value,
        van_comm_rand_bytes,
        &round_id,
        &ea_pk,
        PROPOSAL_ID,
        CHOICE,
        NUM_OPTIONS,
        &auth_path,
        van_position as u32,
        anchor_height,
        PROPOSAL_AUTHORITY,
        false,
        &NoopProgressReporter,
    )
    .expect("build_vote_commitment");
    assert_eq!(bundle.enc_shares.len(), 16, "must have 16 encrypted shares");
    assert_eq!(bundle.share_comms.len(), 16);
    assert_eq!(bundle.share_blinds.len(), 16);
    log(&format!(
        "vote commitment built: vc={}, shares_hash={}, proof={}B",
        hex::encode(&bundle.vote_commitment),
        hex::encode(&bundle.shares_hash),
        bundle.proof.len()
    ));

    // ---------------------------------------------------------------
    // Step 11: sign the cast sighash + POST cast-vote (verbatim from hot test).
    // ---------------------------------------------------------------
    const CAST_VOTE_SIGHASH_DOMAIN: &[u8] = b"SVOTE_CAST_VOTE_SIGHASH_V0";
    let mut canonical = Vec::new();
    canonical.extend_from_slice(CAST_VOTE_SIGHASH_DOMAIN);
    let mut buf32 = [0u8; 32];
    buf32[..32].copy_from_slice(&round_id);
    canonical.extend_from_slice(&buf32);
    canonical.extend_from_slice(&bundle.r_vpk_bytes);
    canonical.extend_from_slice(&bundle.van_nullifier);
    canonical.extend_from_slice(&bundle.vote_authority_note_new);
    canonical.extend_from_slice(&bundle.vote_commitment);
    let mut pid_buf = [0u8; 32];
    pid_buf[..4].copy_from_slice(&PROPOSAL_ID.to_le_bytes());
    canonical.extend_from_slice(&pid_buf);
    let mut ah_buf = [0u8; 32];
    ah_buf[..8].copy_from_slice(&(anchor_height as u64).to_le_bytes());
    canonical.extend_from_slice(&ah_buf);
    let sighash_full = Blake2bParams::new().hash_length(32).hash(&canonical);
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(sighash_full.as_bytes());

    let hot_ask = SpendAuthorizingKey::from(hotkey_usk.orchard());
    let alpha_v = pallas::Scalar::from_repr(
        <[u8; 32]>::try_from(bundle.alpha_v.as_slice()).unwrap(),
    )
    .unwrap();
    let rsk_v = hot_ask.randomize(&alpha_v);
    let vote_auth_sig = rsk_v.sign(&mut rng, &sighash);
    let vote_auth_sig_bytes: [u8; 64] = (&vote_auth_sig).into();

    let cast_body = json!({
        "van_nullifier": b64(&bundle.van_nullifier),
        "vote_authority_note_new": b64(&bundle.vote_authority_note_new),
        "vote_commitment": b64(&bundle.vote_commitment),
        "proposal_id": PROPOSAL_ID,
        "proof": b64(&bundle.proof),
        "vote_round_id": b64(&round_id),
        "vote_comm_tree_anchor_height": anchor_height,
        "r_vpk": b64(&bundle.r_vpk_bytes),
        "vote_auth_sig": b64(&vote_auth_sig_bytes),
    });
    log("POST cast-vote...");
    let (st, js) = http_post("/shielded-vote/v1/cast-vote", &cast_body).expect("post cast");
    log(&format!("=== CAST-VOTE RESPONSE: HTTP {} body={} ===", st, js));
    assert_eq!(st, 200, "cast-vote must return 200");

    let vc_position = van_position + 2;
    let cast_target = van_position + 3;
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut cast_landed = false;
    while Instant::now() < deadline {
        if tree_next_index(&round_id_hex).map(|n| n >= cast_target).unwrap_or(false) {
            cast_landed = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(cast_landed, "cast-vote leaves never appeared in tree");
    log(&format!("cast committed, vc_position={}", vc_position));

    // ---------------------------------------------------------------
    // Step 12: POST 16 encrypted shares (verbatim from hot test).
    // ---------------------------------------------------------------
    let helper_token = std::env::var("HELPER_API_TOKEN").ok();
    let share_comms_b64: Vec<String> = bundle.share_comms.iter().map(|c| b64(c)).collect();
    log("POST 16 shares to helper /shielded-vote/v1/shares...");
    for (i, share) in bundle.enc_shares.iter().enumerate() {
        let share_body = json!({
            "shares_hash": b64(&bundle.shares_hash),
            "proposal_id": PROPOSAL_ID,
            "vote_decision": CHOICE,
            "enc_share": {
                "c1": b64(&share.c1),
                "c2": b64(&share.c2),
                "share_index": i as u32,
            },
            "tree_position": vc_position,
            "vote_round_id": round_id_hex,
            "share_comms": share_comms_b64,
            "primary_blind": b64(&bundle.share_blinds[i]),
            "submit_at": 0,
        });
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let mut req = client
            .post(format!("{}/shielded-vote/v1/shares", CHAIN_REST_URL))
            .header("Content-Type", "application/json")
            .json(&share_body);
        if let Some(ref t) = helper_token {
            req = req.header("X-Helper-Token", t);
        }
        let resp = req.send().expect("post share");
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        if status != 200 {
            panic!("share {} rejected: HTTP {} body={}", i, status, body);
        }
        if i == 0 || i == 15 {
            log(&format!("=== SHARE {} RESPONSE: {} ===", i, body));
        }
    }

    log("waiting for helper to submit reveal-share (tally accumulator)...");
    let deadline = Instant::now() + Duration::from_secs(360);
    let mut has_tally = false;
    while Instant::now() < deadline {
        if tally_has_proposal(&round_id_hex, PROPOSAL_ID) {
            has_tally = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(4));
    }
    assert!(has_tally, "helper never submitted reveal-share to chain");
    log("tally accumulator present on chain");

    // ---------------------------------------------------------------
    // Step 13: wait for vote_end -> TALLYING -> FINALIZED.
    // ---------------------------------------------------------------
    let secs_left = vote_end_time.saturating_sub(now_secs());
    log(&format!(
        "waiting for vote_end ({}s left) then FINALIZED...",
        secs_left
    ));
    let deadline = Instant::now() + Duration::from_secs(secs_left + 600);
    let mut finalized = false;
    while Instant::now() < deadline {
        match round_status(&round_id_hex) {
            Some(3) => {
                finalized = true;
                break;
            }
            Some(s) => {
                if now_secs() % 30 == 0 {
                    log(&format!("round status={} (waiting for FINALIZED=3)", s));
                }
            }
            None => {}
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(finalized, "round never reached FINALIZED");
    log("round FINALIZED");

    // ---------------------------------------------------------------
    // Step 14: read the real tally-results.
    // ---------------------------------------------------------------
    let (st, tally_json) =
        http_get(&format!("/shielded-vote/v1/tally-results/{}", round_id_hex)).expect("tally-results");
    assert_eq!(st, 200, "tally-results must return 200");
    let pretty = serde_json::to_string_pretty(&tally_json).unwrap_or_default();
    log("=== FINAL TALLY RESULTS (COLD ZIGNER ROUND-TRIP) ===");
    eprintln!("{}", pretty);
    log(&format!("ROUND {} FINALIZED on v09 (cold delegation)", round_id_hex));

    let non_empty = tally_json
        .get("results")
        .and_then(|r| r.as_array())
        .map(|a| !a.is_empty())
        .or_else(|| {
            tally_json
                .get("tally_results")
                .and_then(|r| r.as_array())
                .map(|a| !a.is_empty())
        })
        .unwrap_or(false);
    assert!(non_empty, "tally-results must be non-empty: {}", pretty);
}

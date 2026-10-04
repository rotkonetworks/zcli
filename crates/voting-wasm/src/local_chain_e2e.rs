//! End-to-end run of the exported voting bindings against a local vote chain.
//!
//! Drives the same functions the wasm blob exports (`generate_voting_hotkey`,
//! `build_delegation_pczt`, `finalize_delegation`, `cast_vote_hot_wire`,
//! `build_vote_shares_from_recovery`), compiled natively, against a running
//! `svoted` (vote-sdk) and checks the chain finalizes a tally for the votes.
//!
//! The round has 37 proposals and the votes go to proposals 37 and 17 in one
//! delegation bundle: ids above 16 only verify under the 51-bit proposal
//! authority of voting-circuits 0.12, and the second vote only verifies when
//! it starts from the authority the first vote left behind.
//!
//! Ignored by default. Needs a chain started from vote-sdk's `scripts/init.sh`
//! (single validator, helper enabled, coordinator threshold 1):
//!
//! ```sh
//! VOTE_CHAIN_REST=http://127.0.0.1:21317 \
//! SVOTE_NODE=tcp://127.0.0.1:27657 SVOTE_HOME=/path/to/svhome SVOTED=/path/to/svoted \
//! cargo test -p voting-wasm --release -- --ignored --nocapture local_chain
//! ```
//!
//! The wallet is synthetic (`zcash_voting::selftest::synthetic_wallet`): the
//! round is created with that wallet's note-tree and nullifier-IMT roots, so
//! nothing here touches Zcash mainnet or a PIR server.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};

use vote_commitment_tree::{MerkleHashVote, TreeClient};
use vote_commitment_tree_client::http_sync_api::HttpTreeSyncApi;
use vote_commitment_tree_client::transport::{Transport, TransportError, TransportResponse};

use crate::voting::{build_vote_shares_from_recovery, cast_vote_hot_wire, generate_voting_hotkey};
use crate::voting_delegation::{build_delegation_pczt, finalize_delegation};

const PROPOSALS: u32 = 37;
const VOTES: [(u32, u32); 2] = [(37, 1), (17, 0)];
/// Long enough for both proofs plus the helper's randomized share delays.
const VOTE_WINDOW_SECS: u64 = 600;
/// A mainnet height in the NU6.3 era (the prod rounds' snapshot height).
const SNAPSHOT_HEIGHT: u64 = 3_459_350;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn rest() -> String {
    env_or("VOTE_CHAIN_REST", "http://127.0.0.1:21317")
}

fn log(msg: &str) {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    eprintln!("[e2e {t}] {msg}");
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

fn get(path: &str) -> Value {
    let url = format!("{}{}", rest(), path);
    let resp = http()
        .get(&url)
        .send()
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    resp.json().unwrap_or(Value::Null)
}

fn post(path: &str, body: &str) -> (u16, String) {
    let url = format!("{}{}", rest(), path);
    let resp = http()
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .unwrap_or_else(|e| panic!("POST {url}: {e}"));
    let status = resp.status().as_u16();
    (status, resp.text().unwrap_or_default())
}

/// POST a vote tx, retrying the transient CometBFT broadcast errors.
fn post_tx(path: &str, body: &str) -> Value {
    for attempt in 1..=10 {
        let (status, text) = post(path, body);
        let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status == 200 && parsed.get("code").and_then(Value::as_u64).unwrap_or(0) == 0 {
            return parsed;
        }
        log(&format!("{path} attempt {attempt}: HTTP {status} {text}"));
        assert!(status >= 500, "{path} rejected: HTTP {status} {text}");
        std::thread::sleep(Duration::from_secs(3));
    }
    panic!("{path} kept failing");
}

fn wait_until<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn b64_to_hex(s: &str) -> String {
    hex::encode(B64.decode(s).expect("base64"))
}

// --- round creation (MsgProposeCoordinatorAction{MsgCreateVotingSession}) ---

fn push_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn push_u64(out: &mut Vec<u8>, field: u32, v: u64) {
    if v != 0 {
        push_varint(out, (field as u64) << 3);
        push_varint(out, v);
    }
}

fn push_bytes(out: &mut Vec<u8>, field: u32, v: &[u8]) {
    if !v.is_empty() {
        push_varint(out, ((field as u64) << 3) | 2);
        push_varint(out, v.len() as u64);
        out.extend_from_slice(v);
    }
}

fn create_voting_session(creator: &str, nc_root: &[u8], imt_root: &[u8], vote_end: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_bytes(&mut out, 1, creator.as_bytes());
    push_u64(&mut out, 2, SNAPSHOT_HEIGHT);
    push_bytes(&mut out, 3, &[0xaa; 32]);
    // Unique per run so repeated runs create distinct rounds.
    let mut proposals_hash = [0u8; 32];
    proposals_hash[..8].copy_from_slice(&now().to_le_bytes());
    push_bytes(&mut out, 4, &proposals_hash);
    push_u64(&mut out, 5, vote_end);
    push_bytes(&mut out, 6, imt_root);
    push_bytes(&mut out, 7, nc_root);
    for id in 1..=PROPOSALS {
        let mut p = Vec::new();
        push_u64(&mut p, 1, id as u64);
        push_bytes(&mut p, 2, format!("Proposal {id}").as_bytes());
        for (index, label) in ["Support", "Oppose"].iter().enumerate() {
            let mut o = Vec::new();
            push_u64(&mut o, 1, index as u64);
            push_bytes(&mut o, 2, label.as_bytes());
            push_bytes(&mut p, 4, &o);
        }
        push_bytes(&mut out, 8, &p);
    }
    push_bytes(&mut out, 10, b"[TEST] zafu voting-circuits 0.12 e2e");
    out
}

fn svoted(args: &[&str]) -> String {
    let bin = env_or("SVOTED", "svoted");
    let out = Command::new(&bin).args(args).output().expect("run svoted");
    assert!(
        out.status.success(),
        "svoted {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn create_round(nc_root: &[u8], imt_root: &[u8]) -> String {
    let home = std::env::var("SVOTE_HOME").expect("SVOTE_HOME");
    let node = env_or("SVOTE_NODE", "tcp://127.0.0.1:27657");
    let key = env_or("SVOTE_VM_KEY", "vote-manager-1");
    let creator = svoted(&[
        "keys",
        "show",
        &key,
        "-a",
        "--keyring-backend",
        "test",
        "--home",
        &home,
    ])
    .trim()
    .to_string();
    let vote_end = now() + VOTE_WINDOW_SECS;
    let payload = create_voting_session(&creator, nc_root, imt_root, vote_end);
    let tx = json!({
        "body": {
            "messages": [{
                "@type": "/svote.v1.MsgProposeCoordinatorAction",
                "creator": creator,
                "payload": {"type_url": "/svote.v1.MsgCreateVotingSession", "value": B64.encode(&payload)},
            }],
            "memo": "", "timeout_height": "0",
            "extension_options": [], "non_critical_extension_options": []
        },
        "auth_info": {"signer_infos": [], "fee": {"amount": [], "gas_limit": "2000000", "payer": "", "granter": ""}},
        "signatures": []
    });
    let dir = std::env::temp_dir();
    let unsigned = dir.join(format!("zafu-e2e-unsigned-{}.json", now()));
    let signed = dir.join(format!("zafu-e2e-signed-{}.json", now()));
    std::fs::write(&unsigned, tx.to_string()).unwrap();
    svoted(&[
        "tx",
        "sign",
        unsigned.to_str().unwrap(),
        "--from",
        &key,
        "--keyring-backend",
        "test",
        "--chain-id",
        "svote-1",
        "--home",
        &home,
        "--node",
        &node,
        "--output-document",
        signed.to_str().unwrap(),
        "--yes",
    ]);
    let out = svoted(&[
        "tx",
        "broadcast",
        signed.to_str().unwrap(),
        "--node",
        &node,
        "--output",
        "json",
    ]);
    let _ = std::fs::remove_file(&unsigned);
    let _ = std::fs::remove_file(&signed);
    let res: Value = serde_json::from_str(&out).expect("broadcast json");
    assert_eq!(
        res["code"].as_u64().unwrap_or(0),
        0,
        "create round rejected: {out}"
    );
    let nc_b64 = B64.encode(nc_root);
    wait_until("the new round", 60, || {
        get("/shielded-vote/v1/rounds")["rounds"]
            .as_array()?
            .iter()
            .find(|r| r["nc_root"] == nc_b64)
            .map(|r| b64_to_hex(r["vote_round_id"].as_str().unwrap()))
    })
}

// --- vote commitment tree ---

struct ReqwestTransport;

impl Transport for ReqwestTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        let resp = http()
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

/// Every leaf of the round's tree so far, in position order.
fn tree_leaves(round_id: &str) -> Vec<String> {
    let latest = get(&format!(
        "/shielded-vote/v1/commitment-tree/{round_id}/latest"
    ));
    let height = latest["tree"]["height"].as_u64().unwrap_or(0);
    let mut leaves = Vec::new();
    let mut from = 1u64;
    while from <= height {
        let to = (from + 900).min(height);
        let page = get(&format!(
            "/shielded-vote/v1/commitment-tree/{round_id}/leaves?from_height={from}&to_height={to}"
        ));
        for block in page["blocks"].as_array().cloned().unwrap_or_default() {
            for leaf in block["leaves"].as_array().cloned().unwrap_or_default() {
                leaves.push(b64_to_hex(leaf.as_str().unwrap()));
            }
        }
        from = to + 1;
    }
    leaves
}

fn leaf_position(round_id: &str, leaf_hex: &str) -> Option<u64> {
    tree_leaves(round_id)
        .iter()
        .position(|l| l == leaf_hex)
        .map(|p| p as u64)
}

/// VAN witness JSON for `position`, anchored at the chain's latest tree height.
fn van_witness(round_id: &str, position: u64) -> String {
    let api = HttpTreeSyncApi::new(rest(), round_id, Arc::new(ReqwestTransport));
    let mut tree = TreeClient::empty();
    tree.mark_position(position);
    tree.sync(&api).expect("tree sync");
    let anchor = tree.last_synced_height().expect("synced height");
    let path = tree.witness(position, anchor).expect("VAN witness");
    let siblings: Vec<String> = path
        .auth_path()
        .iter()
        .map(|h: &MerkleHashVote| hex::encode(h.to_bytes()))
        .collect();
    json!({"auth_path_hex": siblings, "position": path.position(), "anchor_height": anchor})
        .to_string()
}

#[test]
#[ignore = "needs a local vote-sdk chain; see the module docs"]
fn local_chain_delegate_cast_tally() {
    // Synthetic wallet: two notes, so the bundle also carries padded notes
    // whose nullifiers need IMT proofs, as a real small wallet's would.
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&now().to_le_bytes());
    let wallet = zcash_voting::selftest::synthetic_wallet(seed, &[7_000_000, 7_000_000]).unwrap();

    log("creating a 37-proposal round");
    let round_id = create_round(&wallet.nc_root, &wallet.nullifier_imt_root);
    log(&format!("round {round_id}"));
    let round = wait_until("an ACTIVE round with ea_pk", 120, || {
        let r = get(&format!("/shielded-vote/v1/round/{round_id}"));
        let r = r.get("round").cloned().unwrap_or(r);
        (r["status"].as_u64() == Some(1) && r["ea_pk"].is_string()).then_some(r)
    });
    let ea_pk_hex = b64_to_hex(round["ea_pk"].as_str().unwrap());

    let hotkey: Value = serde_json::from_str(&generate_voting_hotkey("mainnet").unwrap()).unwrap();
    let hotkey_secret = hotkey["hotkey_secret_hex"].as_str().unwrap().to_string();

    let notes_json = json!(wallet
        .notes
        .iter()
        .map(|n| json!({
            "commitment_hex": hex::encode(&n.commitment),
            "nullifier_hex": hex::encode(&n.nullifier),
            "value": n.value,
            "position": n.position,
            "diversifier_hex": hex::encode(&n.diversifier),
            "rho_hex": hex::encode(&n.rho),
            "rseed_hex": hex::encode(&n.rseed),
            "scope": n.scope,
            "ufvk_str": n.ufvk_str,
        }))
        .collect::<Vec<_>>())
    .to_string();
    let round_params = json!({
        "vote_round_id": round_id,
        "snapshot_height": SNAPSHOT_HEIGHT,
        "ea_pk_hex": ea_pk_hex,
        "nc_root_hex": hex::encode(wallet.nc_root),
        "nullifier_imt_root_hex": hex::encode(wallet.nullifier_imt_root),
    })
    .to_string();
    let branch_id = zcash_voting::lwd::branch_id_for_height(
        zcash_voting::types::Network::Mainnet,
        SNAPSHOT_HEIGHT,
    )
    .unwrap();

    // Inputs for running the same calls through the wasm blob (node smoke).
    let fixture_dir = std::env::var("E2E_FIXTURE_DIR").ok();
    let dump = |name: &str, value: &Value| {
        if let Some(dir) = &fixture_dir {
            std::fs::write(format!("{dir}/{name}.json"), value.to_string()).unwrap();
        }
    };
    dump(
        "delegation-inputs",
        &json!({
            "fvk_hex": hex::encode(wallet.fvk_bytes),
            "seed_fingerprint_hex": hex::encode(wallet.seed_fingerprint),
            "account_index": wallet.account_index,
            "hotkey_pubkey_hex": hotkey["hotkey_pubkey_hex"],
            "notes_json": notes_json,
            "round_params_json": round_params,
            "consensus_branch_id": branch_id,
        }),
    );

    log("build_delegation_pczt");
    let built: Value = serde_json::from_str(
        &build_delegation_pczt(
            &hex::encode(wallet.fvk_bytes),
            &hex::encode(wallet.seed_fingerprint),
            wallet.account_index,
            hotkey["hotkey_pubkey_hex"].as_str().unwrap(),
            &notes_json,
            &round_params,
            branch_id,
            "zafu e2e",
            "mainnet",
            0,
        )
        .unwrap(),
    )
    .unwrap();
    let context_json = built["delegation_context_json"]
        .as_str()
        .unwrap()
        .to_string();
    let context: Value = serde_json::from_str(&context_json).unwrap();
    let mut delegation_state = built["delegation_state_json"].as_str().unwrap().to_string();
    let state: Value = serde_json::from_str(&delegation_state).unwrap();
    assert_eq!(
        state["proposal_authority"].as_u64(),
        Some(zcash_voting::MAX_PROPOSAL_AUTHORITY),
        "fresh bundle carries the 0.12 circuit's full authority"
    );

    // Hot signer: RedPallas under ask + alpha over the PCZT sighash.
    let sighash: [u8; 32] = hex::decode(built["pczt_sighash_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let alpha: [u8; 32] = hex::decode(context["alpha_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig =
        zcash_voting::selftest::sign_delegation_hot(&wallet.seed, 0, &alpha, &sighash).unwrap();

    // What the PIR server would return, for real and padded nullifiers.
    let nullifiers: Vec<String> = built["real_note_nullifiers_hex"]
        .as_array()
        .unwrap()
        .iter()
        .chain(built["dummy_note_nullifiers_hex"].as_array().unwrap())
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let imt_json = json!(nullifiers
        .iter()
        .map(|nf| {
            let nf: [u8; 32] = hex::decode(nf).unwrap().try_into().unwrap();
            let p = zcash_voting::selftest::synthetic_imt_proof(&nf).unwrap();
            json!({
                "nullifier_hex": hex::encode(p.nullifier),
                "root_hex": hex::encode(p.root),
                "nf_bounds_hex": p.nf_bounds.iter().map(hex::encode).collect::<Vec<_>>(),
                "leaf_pos": p.leaf_pos,
                "path_hex": p.path.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>())
    .to_string();
    let witnesses_json = json!(wallet
        .witnesses
        .iter()
        .map(|w| json!({
            "note_commitment_hex": hex::encode(&w.note_commitment),
            "position": w.position,
            "root_hex": hex::encode(&w.root),
            "auth_path_hex": w.auth_path.iter().map(hex::encode).collect::<Vec<_>>(),
        }))
        .collect::<Vec<_>>())
    .to_string();

    log("finalize_delegation (ZKP #1)");
    let t = Instant::now();
    let finalized: Value = serde_json::from_str(
        &finalize_delegation(
            &context_json,
            &witnesses_json,
            &imt_json,
            &hex::encode(sig),
            &hex::encode(sighash),
        )
        .unwrap(),
    )
    .unwrap();
    log(&format!("ZKP #1 in {:?}", t.elapsed()));
    let wire = finalized["delegation_submission_wire_json"]
        .as_str()
        .unwrap();
    let wire_v: Value = serde_json::from_str(wire).unwrap();
    assert!(
        wire_v.get("sighash").is_none(),
        "chain dropped the sighash field"
    );
    assert_eq!(
        B64.decode(wire_v["tx1_effects"].as_str().unwrap())
            .unwrap()
            .len(),
        821
    );

    // The chain must refuse each of these, or the acceptance below proves
    // nothing about its checks: a flipped proof byte (halo2 verifier), a
    // flipped TX1 byte (sighash rebuilt from tx1_effects no longer matches
    // the signature), and the pre-0.12 wire with `sighash` instead.
    let tamper = |field: &str| {
        let mut v = wire_v.clone();
        let mut bytes = B64.decode(v[field].as_str().unwrap()).unwrap();
        let i = bytes.len() / 2;
        bytes[i] ^= 1;
        v[field] = json!(B64.encode(bytes));
        v.to_string()
    };
    let mut old_format = wire_v.clone();
    old_format.as_object_mut().unwrap().remove("tx1_effects");
    old_format["sighash"] = json!(B64.encode(sighash));
    for (what, body) in [
        ("tampered proof", tamper("proof")),
        ("tampered tx1_effects", tamper("tx1_effects")),
        ("pre-0.12 sighash wire", old_format.to_string()),
    ] {
        let (status, text) = post("/shielded-vote/v1/delegate-vote", &body);
        let code = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["code"].as_u64())
            .unwrap_or(0);
        assert!(
            status != 200 || code != 0,
            "chain accepted a {what}: {text}"
        );
        log(&format!("chain refused the {what}: HTTP {status} {text}"));
    }

    log("POST /delegate-vote");
    post_tx("/shielded-vote/v1/delegate-vote", wire);
    let van_hex = context["van_hex"].as_str().unwrap().to_string();
    let mut van_position = wait_until("the VAN leaf", 90, || leaf_position(&round_id, &van_hex));
    log(&format!("VAN at {van_position}"));

    for (proposal_id, choice) in VOTES {
        log(&format!(
            "cast_vote_hot_wire proposal {proposal_id} choice {choice} (ZKP #2)"
        ));
        let vote_json = json!({
            "proposal_id": proposal_id, "choice": choice, "num_options": 2,
            "vc_tree_position": 0, "single_share": false,
        })
        .to_string();
        let cast_params = json!({"vote_round_id": round_id, "ea_pk_hex": ea_pk_hex}).to_string();
        let t = Instant::now();
        let cast: Value = serde_json::from_str(
            &cast_vote_hot_wire(
                &hotkey_secret,
                &cast_params,
                &delegation_state,
                &van_witness(&round_id, van_position),
                &vote_json,
                "mainnet",
                0,
            )
            .unwrap(),
        )
        .unwrap();
        log(&format!("ZKP #2 in {:?}", t.elapsed()));

        log("POST /cast-vote");
        post_tx("/shielded-vote/v1/cast-vote", &cast["wire"].to_string());
        let vc_hex = b64_to_hex(cast["wire"]["vote_commitment"].as_str().unwrap());
        let new_van_hex = b64_to_hex(cast["wire"]["vote_authority_note_new"].as_str().unwrap());
        let vc_position = wait_until("the vote commitment leaf", 90, || {
            leaf_position(&round_id, &vc_hex)
        });
        van_position = leaf_position(&round_id, &new_van_hex).expect("new VAN leaf");
        log(&format!("VC at {vc_position}, next VAN at {van_position}"));

        let shares: Vec<Value> = serde_json::from_str(
            &build_vote_shares_from_recovery(
                cast["commitment_bundle_json"].as_str().unwrap(),
                vc_position,
                0,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(shares.len(), 16);
        dump(
            &format!("shares-{proposal_id}"),
            &json!({
                "commitment_bundle_json": cast["commitment_bundle_json"],
                "vc_tree_position": vc_position,
                "shares": shares,
            }),
        );
        for share in &shares {
            assert_eq!(share["vote_round_id"].as_str(), Some(round_id.as_str()));
            assert!(share.get("all_enc_shares").is_none());
            let (status, text) = post("/shielded-vote/v1/shares", &share.to_string());
            assert!(
                (200..300).contains(&status),
                "share rejected: HTTP {status} {text}"
            );
        }
        log("16 shares accepted by the helper");

        delegation_state = cast["next_delegation_state_json"]
            .as_str()
            .unwrap()
            .to_string();
    }
    let state: Value = serde_json::from_str(&delegation_state).unwrap();
    assert_eq!(
        state["proposal_authority"].as_u64(),
        Some(zcash_voting::MAX_PROPOSAL_AUTHORITY & !(1 << 37) & !(1 << 17))
    );

    log("waiting for the tally");
    let wait = VOTE_WINDOW_SECS + 600;
    wait_until("FINALIZED", wait, || {
        let r = get(&format!("/shielded-vote/v1/round/{round_id}"));
        let r = r.get("round").cloned().unwrap_or(r);
        (r["status"].as_u64() == Some(3)).then_some(())
    });
    let tally = get(&format!("/shielded-vote/v1/tally-results/{round_id}"));
    log(&format!("tally {tally}"));
    let results = tally["results"].as_array().cloned().unwrap_or_default();
    for (proposal_id, choice) in VOTES {
        let hit = results.iter().find(|r| {
            r["proposal_id"].as_u64() == Some(proposal_id as u64)
                && r["vote_decision"].as_u64().unwrap_or(0) == choice as u64
        });
        let hit =
            hit.unwrap_or_else(|| panic!("no tally for proposal {proposal_id} choice {choice}"));
        assert_eq!(hit["total_value"].as_u64(), Some(1), "one ballot of weight");
    }
    log("tally has both votes");
}

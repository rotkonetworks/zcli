// frost.rs — WASM bindings for frost-spend orchestrate module
//
// exposes DKG, signing, and spend authorization to browser (zafu/zigner-web).
// all inputs/outputs are hex strings — transport-agnostic, JSON-serializable.

use wasm_bindgen::prelude::*;

// ── DKG ──

/// trusted dealer: generate key packages for all participants
#[wasm_bindgen]
pub fn frost_dealer_keygen(min_signers: u16, max_signers: u16) -> Result<String, JsError> {
    let result = frost_spend::orchestrate::dealer_keygen(min_signers, max_signers)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "packages": result.packages,
        "public_key_package": result.public_key_package_hex,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 1: generate ephemeral identity + signed commitment
#[wasm_bindgen]
pub fn frost_dkg_part1(max_signers: u16, min_signers: u16) -> Result<String, JsError> {
    let result = frost_spend::orchestrate::dkg_part1(max_signers, min_signers)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "broadcast": result.broadcast_hex,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 2: process signed round1 broadcasts, produce per-peer packages
#[wasm_bindgen]
pub fn frost_dkg_part2(secret_hex: &str, peer_broadcasts_json: &str) -> Result<String, JsError> {
    let broadcasts: Vec<String> = serde_json::from_str(peer_broadcasts_json)
        .map_err(|e| JsError::new(&format!("bad broadcasts JSON: {}", e)))?;
    let result = frost_spend::orchestrate::dkg_part2(secret_hex, &broadcasts)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "peer_packages": result.peer_packages,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 3: finalize — returns key package + public key package
#[wasm_bindgen]
pub fn frost_dkg_part3(
    secret_hex: &str,
    round1_broadcasts_json: &str,
    round2_packages_json: &str,
) -> Result<String, JsError> {
    let r1: Vec<String> = serde_json::from_str(round1_broadcasts_json)
        .map_err(|e| JsError::new(&format!("bad round1 JSON: {}", e)))?;
    let r2: Vec<String> = serde_json::from_str(round2_packages_json)
        .map_err(|e| JsError::new(&format!("bad round2 JSON: {}", e)))?;
    let result = frost_spend::orchestrate::dkg_part3(secret_hex, &r1, &r2)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "key_package": result.key_package_hex,
        "public_key_package": result.public_key_package_hex,
        "ephemeral_seed": result.ephemeral_seed_hex,
    })).map_err(|e| JsError::new(&e.to_string()))
}

// ── generic signing ──

/// signing round 1: generate nonces + signed commitments
#[wasm_bindgen]
pub fn frost_sign_round1(ephemeral_seed_hex: &str, key_package_hex: &str) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let (nonces, commitments) = frost_spend::orchestrate::sign_round1(&seed, key_package_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "nonces": nonces,
        "commitments": commitments,
    })).map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: generate signed randomizer
#[wasm_bindgen]
pub fn frost_generate_randomizer(
    ephemeral_seed_hex: &str,
    message_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let msg = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::generate_randomizer(&seed, &msg, &commitments)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// signing round 2: produce signed signature share
#[wasm_bindgen]
pub fn frost_sign_round2(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
    nonces_hex: &str,
    message_hex: &str,
    commitments_json: &str,
    randomizer_hex: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let msg = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::sign_round2(
        &seed, key_package_hex, nonces_hex, &msg, &commitments, randomizer_hex,
    ).map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: aggregate signed shares into final signature
#[wasm_bindgen]
pub fn frost_aggregate_shares(
    public_key_package_hex: &str,
    message_hex: &str,
    commitments_json: &str,
    shares_json: &str,
    randomizer_hex: &str,
) -> Result<String, JsError> {
    let msg = hex::decode(message_hex)
        .map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    let shares: Vec<String> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("bad shares JSON: {}", e)))?;
    frost_spend::orchestrate::aggregate_shares(
        public_key_package_hex, &msg, &commitments, &shares, randomizer_hex,
    ).map_err(|e| JsError::new(&e.to_string()))
}

// ── spend authorization (sighash + alpha bound) ──

/// derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded).
/// non-deterministic — internally generates a random nk/rivk. only safe when a
/// single party derives-and-broadcasts. interactive DKG should use
/// `frost_derive_address_from_sk` instead.
#[wasm_bindgen]
pub fn frost_derive_address_raw(
    public_key_package_hex: &str,
    diversifier_index: u32,
) -> Result<String, JsError> {
    let raw = frost_spend::orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(raw))
}

/// derive the multisig wallet's Orchard address (raw 43-byte address, hex-encoded)
/// from the group public key package and a caller-supplied `sk`. deterministic —
/// every participant computing this with the same inputs lands on byte-identical
/// output. pair with `frost_derive_ufvk(pkg, sk, mainnet)` so the stored address
/// and stored UFVK share a single source of truth for nk/rivk.
#[wasm_bindgen]
pub fn frost_derive_address_from_sk(
    public_key_package_hex: &str,
    sk_hex: &str,
    diversifier_index: u32,
) -> Result<String, JsError> {
    let sk_bytes = parse_32(sk_hex, "address sk")?;
    let raw = frost_spend::orchestrate::derive_address_from_sk(
        public_key_package_hex, sk_bytes, diversifier_index,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(hex::encode(raw))
}

/// host-only: sample a random 32-byte SpendingKey for nk/rivk derivation.
/// retries until the sampled bytes land in the Pallas scalar range.
/// returns hex-encoded 32-byte `sk` that the host broadcasts to peers in R1.
#[wasm_bindgen]
pub fn frost_sample_fvk_sk() -> String {
    use rand_core::{OsRng, RngCore};
    let mut rng = OsRng;
    // SpendingKey::from_bytes validates the scalar range; retry on the
    // vanishingly rare out-of-range case. we don't care which sk we land
    // on, only that all peers use the same one (which is why the host
    // broadcasts it rather than each peer generating their own).
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let maybe_sk: Option<orchard::keys::SpendingKey> =
            Option::from(orchard::keys::SpendingKey::from_bytes(bytes));
        if maybe_sk.is_some() {
            return hex::encode(bytes);
        }
    }
}

/// derive the Orchard-only UFVK string (`uview1…` / `uviewtest1…`) from a
/// caller-supplied 32-byte SpendingKey and a FROST public key package.
/// every participant, given the same `sk_hex` + `public_key_package_hex`,
/// lands on byte-identical output.
#[wasm_bindgen]
pub fn frost_derive_ufvk(
    public_key_package_hex: &str,
    sk_hex: &str,
    mainnet: bool,
) -> Result<String, JsError> {
    use zcash_address::unified::{Encoding, Fvk, Ufvk};
    use zcash_protocol::consensus::NetworkType;

    let sk_bytes = parse_32(sk_hex, "fvk sk")?;

    let pubkeys: frost_spend::frost_keys::PublicKeyPackage =
        frost_spend::orchestrate::from_hex(public_key_package_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let fvk = frost_spend::keys::derive_fvk_from_sk(sk_bytes, &pubkeys)
        .ok_or_else(|| JsError::new("failed to derive FVK from group key + sk"))?;

    // zcash_keys uses orchard-0.11 (registry) while frost-spend uses the ZF
    // orchard fork. both share the 96-byte FVK wire format, so we cross the
    // type boundary by going through bytes + zcash_address::unified::Ufvk
    // (byte-tagged items), bypassing zcash_keys::UnifiedFullViewingKey.
    let ufvk = Ufvk::try_from_items(vec![Fvk::Orchard(fvk.to_bytes())])
        .map_err(|e| JsError::new(&format!("build UFVK: {e}")))?;

    let network = if mainnet { NetworkType::Main } else { NetworkType::Test };
    Ok(ufvk.encode(&network))
}

/// sighash-bound round 2: produce FROST share for one Orchard action
#[wasm_bindgen]
pub fn frost_spend_sign_round2(
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::spend_sign_round2(
        key_package_hex, nonces_hex, &sighash, &alpha, &commitments,
    ).map_err(|e| JsError::new(&e.to_string()))
}

/// authenticated variant: wraps share in SignedMessage for relay transport
#[wasm_bindgen]
pub fn frost_spend_sign_round2_signed(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
    nonces_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::spend_sign_round2_signed(
        &seed, key_package_hex, nonces_hex, &sighash, &alpha, &commitments,
    ).map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: aggregate shares into Orchard SpendAuth signature (64 bytes hex)
#[wasm_bindgen]
pub fn frost_spend_aggregate(
    public_key_package_hex: &str,
    sighash_hex: &str,
    alpha_hex: &str,
    commitments_json: &str,
    shares_json: &str,
) -> Result<String, JsError> {
    let sighash = parse_32(sighash_hex, "sighash")?;
    let alpha = parse_32(alpha_hex, "alpha")?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    let shares: Vec<String> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("bad shares JSON: {}", e)))?;
    frost_spend::orchestrate::spend_aggregate(
        public_key_package_hex, &sighash, &alpha, &commitments, &shares,
    ).map_err(|e| JsError::new(&e.to_string()))
}

// ── Multisig verifier: parse outputs from unsigned tx using spender's UFVK ──

/// Parse the unsigned v5 transaction and recover what each Orchard action
/// is sending, using the FROST wallet's UFVK to OVK-decrypt outputs.
///
/// The spender (= each FROST joiner) owns the OVK that was used to encrypt
/// every action's output, so OVK decryption yields:
///   - external scope hits → real recipients of the spend
///   - internal scope hits → change back to our own multisig
///   - non-decryptable     → dummy padding action (zero value by construction)
///
/// Each joiner runs this on the unsigned tx bytes the host claims to have
/// built and compares the derived summary to the host's claimed
/// (recipient, amount, fee). A mismatch means the host lied.
///
/// `orchard_fvk_uview` is the ZIP-316 unified viewing key string
/// (`uview1…` / `uviewtest1…`) stored alongside the wallet.
///
/// Returns JSON:
/// {
///   "actions": [
///     { "index": u32,
///       "amount_zat": u64,
///       "recipient_raw_hex": "<43-byte hex>" | null,
///       "is_change": bool,
///       "decrypted": bool }
///   ],
///   "summary": {
///     "total_send_zat": u64,
///     "total_change_zat": u64,
///     "decrypted_count": u32,
///     "action_count": u32
///   }
/// }
#[wasm_bindgen]
pub fn frost_parse_tx_outputs(
    unsigned_tx_hex: &str,
    orchard_fvk_uview: &str,
) -> Result<String, JsError> {
    use std::io::Cursor;
    use orchard_legacy::keys::Scope;
    use orchard_legacy::note_encryption::OrchardDomain;
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_note_encryption::try_output_recovery_with_ovk;
    use zcash_primitives::consensus::BranchId;
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};

    let mut tx_bytes = hex::decode(unsigned_tx_hex)
        .map_err(|e| JsError::new(&format!("bad tx hex: {}", e)))?;

    // Capture the original branch id before any patching — sighash
    // personalization and header_digest both bake it in, so we MUST use
    // the real value (e.g. NU6.1 = 0x4dec_4df0) when reproducing sighash,
    // not the NU5 substitute we patch in to satisfy zcash_primitives.
    let original_branch_id: Option<u32> = if tx_bytes.len() >= 12 {
        Some(u32::from_le_bytes([tx_bytes[8], tx_bytes[9], tx_bytes[10], tx_bytes[11]]))
    } else {
        None
    };

    // zcash_primitives 0.21 ships zcash_protocol 0.4 whose BranchId enum
    // tops out at NU6 (0xc8e7_1055). Mainnet tx builds today use NU6.1
    // (0x4dec_4df0) and the parser rejects it with "Unknown consensus
    // branch ID". The orchard bundle layout is identical across
    // NU5/NU6/NU6.1, so we rewrite the branch-id field (bytes 8..12 of a
    // v5 tx header: version(4) + version_group_id(4) + branch_id(4)) to
    // NU5 just for parsing. We never re-serialize, so the original bytes
    // (including the real branch id committed to in sighash) are unaffected
    // outside this function.
    if tx_bytes.len() >= 12 {
        let branch = u32::from_le_bytes([tx_bytes[8], tx_bytes[9], tx_bytes[10], tx_bytes[11]]);
        if !matches!(branch, 0 | 0x5ba8_1b19 | 0x76b8_09bb | 0x2bb4_0e60
            | 0xf5b9_230b | 0xe9ff_75a6 | 0xc2d6_d0b4 | 0xc8e7_1055)
        {
            let nu5 = 0xc2d6_d0b4u32.to_le_bytes();
            tx_bytes[8..12].copy_from_slice(&nu5);
        }
    }

    let mut cursor = Cursor::new(&tx_bytes);
    let tx = Transaction::read(&mut cursor, BranchId::Nu5)
        .map_err(|e| JsError::new(&format!("parse v5 tx: {:?}", e)))?;

    // testnet uview prefix is `uviewtest1`, mainnet is `uview1`.
    let mainnet = !orchard_fvk_uview.starts_with("uviewtest");
    let ufvk = if mainnet {
        UnifiedFullViewingKey::decode(&MainNetwork, orchard_fvk_uview)
    } else {
        UnifiedFullViewingKey::decode(&TestNetwork, orchard_fvk_uview)
    }
    .map_err(|e| JsError::new(&format!("invalid UFVK: {}", e)))?;

    let orchard_fvk_keys = ufvk
        .orchard()
        .ok_or_else(|| JsError::new("UFVK has no orchard component"))?;

    // The zcash_keys orchard FVK comes from a different orchard version than
    // the one zcash_primitives uses for tx parsing. Cross through the 96-byte
    // wire format so OVK derivation, OrchardDomain, and the Action all share
    // a single orchard crate version (orchard_legacy = orchard 0.10).
    let fvk_bytes = orchard_fvk_keys.to_bytes();
    let fvk = orchard_legacy::keys::FullViewingKey::from_bytes(&fvk_bytes)
        .ok_or_else(|| JsError::new("invalid orchard FVK in UFVK"))?;

    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    let bundle = match tx.orchard_bundle() {
        Some(b) => b,
        None => {
            return Ok(serde_json::json!({
                "actions": [],
                "summary": {
                    "total_send_zat": 0u64,
                    "total_change_zat": 0u64,
                    "decrypted_count": 0u32,
                    "action_count": 0u32,
                },
            })
            .to_string());
        }
    };

    let actions: Vec<_> = bundle.actions().iter().collect();
    let mut actions_json = Vec::with_capacity(actions.len());
    let mut total_send: u64 = 0;
    let mut total_change: u64 = 0;
    let mut decrypted_count: u32 = 0;

    for (idx, action) in actions.iter().enumerate() {
        let domain = OrchardDomain::for_action(*action);
        let cv = action.cv_net();
        let out_ct = action.encrypted_note().out_ciphertext;

        // external: real recipient of a spend
        if let Some((note, addr, _memo)) =
            try_output_recovery_with_ovk(&domain, &ovk_external, *action, cv, &out_ct)
        {
            let amount = note.value().inner();
            total_send = total_send.saturating_add(amount);
            decrypted_count += 1;
            actions_json.push(serde_json::json!({
                "index": idx as u32,
                "amount_zat": amount,
                "recipient_raw_hex": hex::encode(addr.to_raw_address_bytes()),
                "is_change": false,
                "decrypted": true,
            }));
            continue;
        }

        // internal: change back to our own multisig
        if let Some((note, addr, _memo)) =
            try_output_recovery_with_ovk(&domain, &ovk_internal, *action, cv, &out_ct)
        {
            let amount = note.value().inner();
            total_change = total_change.saturating_add(amount);
            decrypted_count += 1;
            actions_json.push(serde_json::json!({
                "index": idx as u32,
                "amount_zat": amount,
                "recipient_raw_hex": hex::encode(addr.to_raw_address_bytes()),
                "is_change": true,
                "decrypted": true,
            }));
            continue;
        }

        // could not decrypt — dummy action, zero-value by construction
        actions_json.push(serde_json::json!({
            "index": idx as u32,
            "amount_zat": 0u64,
            "recipient_raw_hex": serde_json::Value::Null,
            "is_change": false,
            "decrypted": false,
        }));
    }

    // ── ZIP-244 sighash check ──
    // Recompute the message that the joiner is being asked to sign, from
    // the bundle they verified above. If the host published a real sighash
    // but a decoy unsignedTx (the "decoy bundle" attack the verifier closes), the
    // recomputed sighash will not match the host's claimed one — that's
    // the only way to detect a decoy that's internally consistent.
    //
    // We only support pure-orchard v5 txs here. If transparent or sapling
    // bundles are present, return None and the TS verdict layer treats it
    // as "unverified — sighash check unavailable for this shape".
    let pure_orchard = tx
        .transparent_bundle()
        .map_or(true, |t| t.vin.is_empty() && t.vout.is_empty())
        && tx.sapling_bundle().is_none();

    let computed_sighash_hex: Option<String> = if let (Some(branch_id), true) =
        (original_branch_id, pure_orchard)
    {
        // T.1 header_digest
        let mut header_data = Vec::with_capacity(20);
        header_data.extend_from_slice(&(5u32 | (1u32 << 31)).to_le_bytes());
        header_data.extend_from_slice(&0x26A7270Au32.to_le_bytes());
        header_data.extend_from_slice(&branch_id.to_le_bytes());
        header_data.extend_from_slice(&tx.lock_time().to_le_bytes());
        let expiry: u32 = u32::from(tx.expiry_height());
        header_data.extend_from_slice(&expiry.to_le_bytes());
        let header_digest = crate::blake2b_256_personal(b"ZTxIdHeadersHash", &header_data);

        // T.2 transparent_digest (empty — we asserted pure-orchard above)
        let transparent_digest = crate::blake2b_256_personal(b"ZTxIdTranspaHash", &[]);
        // T.3 sapling_digest (empty)
        let sapling_digest = crate::blake2b_256_personal(b"ZTxIdSaplingHash", &[]);
        // T.4 orchard_digest
        let orchard_digest = compute_orchard_digest_legacy(bundle);

        let mut personal = [0u8; 16];
        personal[..12].copy_from_slice(b"ZcashTxHash_");
        personal[12..16].copy_from_slice(&branch_id.to_le_bytes());

        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&header_digest);
        input.extend_from_slice(&transparent_digest);
        input.extend_from_slice(&sapling_digest);
        input.extend_from_slice(&orchard_digest);

        Some(hex::encode(crate::blake2b_256_personal(&personal, &input)))
    } else {
        None
    };

    Ok(serde_json::json!({
        "actions": actions_json,
        "summary": {
            "total_send_zat": total_send,
            "total_change_zat": total_change,
            "decrypted_count": decrypted_count,
            "action_count": actions.len() as u32,
        },
        "computed_sighash_hex": computed_sighash_hex,
    })
    .to_string())
}

/// ZIP-244 orchard tx body digest (T.4) for an orchard_legacy bundle.
/// Mirrors `compute_orchard_digest` in `lib.rs` byte-for-byte but uses
/// orchard 0.10 types so it can consume what `tx.orchard_bundle()` returns
/// from zcash_primitives 0.21.
fn compute_orchard_digest_legacy<A: orchard_legacy::bundle::Authorization>(
    bundle: &orchard_legacy::Bundle<A, zcash_primitives::transaction::components::Amount>,
) -> [u8; 32] {
    let mut compact_data = Vec::new();
    let mut memos_data = Vec::new();
    let mut noncompact_data = Vec::new();

    for action in bundle.actions().iter() {
        compact_data.extend_from_slice(&action.nullifier().to_bytes());
        compact_data.extend_from_slice(&action.cmx().to_bytes());
        let enc = &action.encrypted_note().enc_ciphertext;
        let epk = &action.encrypted_note().epk_bytes;
        compact_data.extend_from_slice(epk);
        compact_data.extend_from_slice(&enc[..52]);

        memos_data.extend_from_slice(&enc[52..564]);

        noncompact_data.extend_from_slice(&action.cv_net().to_bytes());
        noncompact_data.extend_from_slice(&<[u8; 32]>::from(action.rk()));
        noncompact_data.extend_from_slice(&enc[564..580]);
        noncompact_data.extend_from_slice(&action.encrypted_note().out_ciphertext);
    }

    let compact_digest = crate::blake2b_256_personal(b"ZTxIdOrcActCHash", &compact_data);
    let memos_digest = crate::blake2b_256_personal(b"ZTxIdOrcActMHash", &memos_data);
    let noncompact_digest = crate::blake2b_256_personal(b"ZTxIdOrcActNHash", &noncompact_data);

    let mut orchard_data = Vec::new();
    orchard_data.extend_from_slice(&compact_digest);
    orchard_data.extend_from_slice(&memos_digest);
    orchard_data.extend_from_slice(&noncompact_digest);
    orchard_data.push(bundle.flags().to_byte());
    orchard_data.extend_from_slice(&bundle.value_balance().to_i64_le_bytes());
    orchard_data.extend_from_slice(&bundle.anchor().to_bytes());

    crate::blake2b_256_personal(b"ZTxIdOrchardHash", &orchard_data)
}

// ── anchor attestation (domain-separated from spend auth) ──
//
// Signing uses the existing orchestrate::sign_round1/sign_round2/aggregate_shares
// with attestation_digest() as the message. No special signing API needed.
//
// The attestation data is 96 bytes: signature(64) || randomizer(32).

/// Compute the attestation digest for an anchor.
/// Returns hex-encoded 32-byte SHA-256 digest.
#[wasm_bindgen]
pub fn frost_attestation_digest(
    public_key_package_hex: &str,
    anchor_hex: &str,
    anchor_height: u32,
    mainnet: bool,
) -> Result<String, JsError> {
    let vk = frost_spend::attestation::extract_group_vk(public_key_package_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let anchor = parse_32(anchor_hex, "anchor")?;
    let digest = frost_spend::attestation::attestation_digest(&vk, &anchor, anchor_height, mainnet);
    Ok(hex::encode(digest))
}

/// Verify an attestation (96 bytes: sig || randomizer).
#[wasm_bindgen]
pub fn frost_attestation_verify(
    attestation_hex: &str,
    public_key_package_hex: &str,
    anchor_hex: &str,
    anchor_height: u32,
    mainnet: bool,
) -> Result<bool, JsError> {
    let anchor = parse_32(anchor_hex, "anchor")?;
    let attestation: [u8; 96] = hex::decode(attestation_hex)
        .map_err(|e| JsError::new(&format!("bad attestation hex: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("attestation must be 96 bytes (sig 64 + randomizer 32)"))?;

    frost_spend::attestation::verify_from_bytes(
        &attestation, public_key_package_hex, &anchor, anchor_height, mainnet,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

// ── helpers ──

fn parse_seed(hex_str: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("bad seed hex: {}", e)))?;
    bytes.try_into()
        .map_err(|_| JsError::new("seed must be 32 bytes"))
}

fn parse_32(hex_str: &str, name: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("bad {} hex: {}", name, e)))?;
    bytes.try_into()
        .map_err(|_| JsError::new(&format!("{} must be 32 bytes", name)))
}

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
    }))
    .map_err(|e| JsError::new(&e.to_string()))
}

/// DKG round 1: generate ephemeral identity + signed commitment
#[wasm_bindgen]
pub fn frost_dkg_part1(max_signers: u16, min_signers: u16) -> Result<String, JsError> {
    let result = frost_spend::orchestrate::dkg_part1(max_signers, min_signers)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "secret": result.secret_hex,
        "broadcast": result.broadcast_hex,
    }))
    .map_err(|e| JsError::new(&e.to_string()))
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
    }))
    .map_err(|e| JsError::new(&e.to_string()))
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
    }))
    .map_err(|e| JsError::new(&e.to_string()))
}

// ── generic signing ──

/// signing round 1: generate nonces + signed commitments
#[wasm_bindgen]
pub fn frost_sign_round1(
    ephemeral_seed_hex: &str,
    key_package_hex: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let (nonces, commitments) = frost_spend::orchestrate::sign_round1(&seed, key_package_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "nonces": nonces,
        "commitments": commitments,
    }))
    .map_err(|e| JsError::new(&e.to_string()))
}

/// coordinator: generate signed randomizer
#[wasm_bindgen]
pub fn frost_generate_randomizer(
    ephemeral_seed_hex: &str,
    message_hex: &str,
    commitments_json: &str,
) -> Result<String, JsError> {
    let seed = parse_seed(ephemeral_seed_hex)?;
    let msg =
        hex::decode(message_hex).map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
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
    let msg =
        hex::decode(message_hex).map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    frost_spend::orchestrate::sign_round2(
        &seed,
        key_package_hex,
        nonces_hex,
        &msg,
        &commitments,
        randomizer_hex,
    )
    .map_err(|e| JsError::new(&e.to_string()))
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
    let msg =
        hex::decode(message_hex).map_err(|e| JsError::new(&format!("bad message hex: {}", e)))?;
    let commitments: Vec<String> = serde_json::from_str(commitments_json)
        .map_err(|e| JsError::new(&format!("bad commitments JSON: {}", e)))?;
    let shares: Vec<String> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("bad shares JSON: {}", e)))?;
    frost_spend::orchestrate::aggregate_shares(
        public_key_package_hex,
        &msg,
        &commitments,
        &shares,
        randomizer_hex,
    )
    .map_err(|e| JsError::new(&e.to_string()))
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
    let raw =
        frost_spend::orchestrate::derive_address_raw(public_key_package_hex, diversifier_index)
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
        public_key_package_hex,
        sk_bytes,
        diversifier_index,
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

    let network = if mainnet {
        NetworkType::Main
    } else {
        NetworkType::Test
    };
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
        key_package_hex,
        nonces_hex,
        &sighash,
        &alpha,
        &commitments,
    )
    .map_err(|e| JsError::new(&e.to_string()))
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
        &seed,
        key_package_hex,
        nonces_hex,
        &sighash,
        &alpha,
        &commitments,
    )
    .map_err(|e| JsError::new(&e.to_string()))
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
        public_key_package_hex,
        &sighash,
        &alpha,
        &commitments,
        &shares,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

// ── Multisig verifier: parse outputs from unsigned tx using spender's UFVK ──

/// Recover the visible outputs of one orchard-shaped bundle with the OVKs,
/// appending one JSON entry per action.
///
/// Generic over the note-plaintext version because upstream orchard splits the
/// note-encryption domain by note version and enforces the plaintext lead
/// byte: `OrchardVersion` (V2, 0x02) for the orchard bundle, `IronwoodVersion`
/// (V3, 0x03) for the ironwood bundle. Unlike a bare compact action off the
/// wire, here the pool IS unambiguous — it is the bundle the action lives in —
/// so each bundle is decrypted with exactly its own domain rather than both.
///
/// `totals` is (total_send, total_change, decrypted_count).
fn recover_bundle_outputs<V, A>(
    bundle: &orchard::Bundle<A, zcash_protocol::value::ZatBalance>,
    pool: &str,
    ovk_external: &orchard::keys::OutgoingViewingKey,
    ovk_internal: &orchard::keys::OutgoingViewingKey,
    actions_json: &mut Vec<serde_json::Value>,
    totals: &mut (u64, u64, u32),
) where
    V: orchard::note_encryption::DomainVersion,
    A: orchard::bundle::Authorization,
{
    use zcash_note_encryption::try_output_recovery_with_ovk;

    for (idx, action) in bundle.actions().iter().enumerate() {
        let domain = orchard::note_encryption::NoteEncryptionDomain::<V>::for_action(action);
        let cv = action.cv_net();
        let out_ct = action.encrypted_note().out_ciphertext;

        // external: real recipient of a spend
        if let Some((note, addr, _memo)) =
            try_output_recovery_with_ovk(&domain, ovk_external, action, cv, &out_ct)
        {
            let amount = note.value().inner();
            totals.0 = totals.0.saturating_add(amount);
            totals.2 += 1;
            actions_json.push(serde_json::json!({
                "index": idx as u32,
                "pool": pool,
                "amount_zat": amount,
                "recipient_raw_hex": hex::encode(addr.to_raw_address_bytes()),
                "is_change": false,
                "decrypted": true,
            }));
            continue;
        }

        // internal: change back to our own multisig
        if let Some((note, addr, _memo)) =
            try_output_recovery_with_ovk(&domain, ovk_internal, action, cv, &out_ct)
        {
            let amount = note.value().inner();
            totals.1 = totals.1.saturating_add(amount);
            totals.2 += 1;
            actions_json.push(serde_json::json!({
                "index": idx as u32,
                "pool": pool,
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
            "pool": pool,
            "amount_zat": 0u64,
            "recipient_raw_hex": serde_json::Value::Null,
            "is_change": false,
            "decrypted": false,
        }));
    }
}

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
///       "pool": "orchard" | "ironwood",
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
    use orchard::keys::Scope;
    use std::io::Cursor;
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_primitives::transaction::{Transaction, TxVersion};
    // zcash_primitives 0.26 (librustzcash 5333c01b) moved consensus types
    // into zcash_protocol; BranchId is re-exported there.
    use zcash_protocol::consensus::{BranchId, MainNetwork, TestNetwork};

    let mut tx_bytes =
        hex::decode(unsigned_tx_hex).map_err(|e| JsError::new(&format!("bad tx hex: {}", e)))?;

    // Capture the original branch id before any patching — sighash
    // personalization and header_digest both bake it in, so we MUST use
    // the real value (e.g. NU6.1 = 0x4dec_4df0) when reproducing sighash,
    // not the NU5 substitute we patch in to satisfy zcash_primitives.
    let original_branch_id: Option<u32> = if tx_bytes.len() >= 12 {
        Some(u32::from_le_bytes([
            tx_bytes[8],
            tx_bytes[9],
            tx_bytes[10],
            tx_bytes[11],
        ]))
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
        if !matches!(
            branch,
            0 | 0x5ba8_1b19
                | 0x76b8_09bb
                | 0x2bb4_0e60
                | 0xf5b9_230b
                | 0xe9ff_75a6
                | 0xc2d6_d0b4
                | 0xc8e7_1055
        ) {
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
    // a single orchard crate (the registry 0.12 we depend on directly,
    // which librustzcash 5333c01b also resolves to).
    let fvk_bytes = orchard_fvk_keys.to_bytes();
    let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes)
        .ok_or_else(|| JsError::new("invalid orchard FVK in UFVK"))?;

    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    // Both orchard (V2) and ironwood (V3) bundles are inspected. The pool is
    // known here — it is which bundle the action sits in — so each is decrypted
    // with its own enforced note-version domain.
    let orchard_bundle = tx.orchard_bundle();
    let ironwood_bundle = tx.ironwood_bundle();

    let mut actions_json: Vec<serde_json::Value> = Vec::new();
    let mut totals: (u64, u64, u32) = (0, 0, 0);
    let mut action_count: u32 = 0;

    if let Some(b) = orchard_bundle {
        action_count += b.actions().len() as u32;
        recover_bundle_outputs::<orchard::note_encryption::OrchardVersion, _>(
            b,
            "orchard",
            &ovk_external,
            &ovk_internal,
            &mut actions_json,
            &mut totals,
        );
    }
    if let Some(b) = ironwood_bundle {
        action_count += b.actions().len() as u32;
        recover_bundle_outputs::<orchard::note_encryption::IronwoodVersion, _>(
            b,
            "ironwood",
            &ovk_external,
            &ovk_internal,
            &mut actions_json,
            &mut totals,
        );
    }

    // ── ZIP-244 sighash check ──
    // Recompute the message that the joiner is being asked to sign, from
    // the bundle they verified above. If the host published a real sighash
    // but a decoy unsignedTx (the "decoy bundle" attack the verifier closes), the
    // recomputed sighash will not match the host's claimed one — that's
    // the only way to detect a decoy that's internally consistent.
    //
    // We only support pure-orchard V5 txs here. Anything else returns None and
    // the TS verdict layer treats it as "unverified — sighash check
    // unavailable for this shape".
    //
    // The TX VERSION check is what makes the hardcoded V5 header below sound,
    // and it is not implied by the bundle checks. `Transaction::read` dispatches
    // on the version header, NOT on the `BranchId` we hand it, so a V6
    // transaction parses here perfectly well; a V6 tx that happens to carry an
    // orchard bundle and no ironwood bundle would otherwise satisfy every
    // bundle-shaped condition and be handed a V5 header digest (version
    // `5 | (1<<31)` and V5_VERSION_GROUP_ID `0x26A7270A`) that does not describe
    // it. Pinning `TxVersion::V5` closes that.
    //
    // The ironwood exclusion is load-bearing for the same reason on the body
    // side: `compute_orchard_digest_legacy` covers the orchard bundle only, so a
    // tx carrying an ironwood bundle would get a confidently-wrong digest. It is
    // now redundant with the version check (ironwood bundles only exist in V6)
    // but is kept as a belt-and-braces statement of what the digest covers.
    //
    // This fails safe either way: a wrong digest yields a mismatch verdict or a
    // signature the network rejects, never a false "verified" — that would need
    // the wrong digest to collide with the right one.
    let pure_orchard = tx.version() == TxVersion::V5
        && tx
            .transparent_bundle()
            .is_none_or(|t| t.vin.is_empty() && t.vout.is_empty())
        && tx.sapling_bundle().is_none()
        && ironwood_bundle.is_none();

    let computed_sighash_hex: Option<String> = if let (Some(branch_id), Some(bundle), true) =
        (original_branch_id, orchard_bundle, pure_orchard)
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
            "total_send_zat": totals.0,
            "total_change_zat": totals.1,
            "decrypted_count": totals.2,
            "action_count": action_count,
        },
        "computed_sighash_hex": computed_sighash_hex,
    })
    .to_string())
}

/// ZIP-244 orchard tx body digest (T.4). Mirrors `compute_orchard_digest`
/// in `lib.rs` byte-for-byte; consumes what `tx.orchard_bundle()` returns
/// from the librustzcash 5333c01b zcash_primitives.
fn compute_orchard_digest_legacy<A: orchard::bundle::Authorization>(
    bundle: &orchard::Bundle<A, zcash_protocol::value::ZatBalance>,
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
    orchard_data.push(
        bundle
            .flags()
            .to_byte(orchard::bundle::BundleVersion::orchard_v2())
            .expect("V5 legacy orchard bundle flags always fit the pre-NU6.3 format"),
    );
    orchard_data.extend_from_slice(&bundle.value_balance().to_i64_le_bytes());
    orchard_data.extend_from_slice(&bundle.anchor().to_bytes());

    crate::blake2b_256_personal(b"ZTxIdOrchardHash", &orchard_data)
}

/// Inspect a PCZT's orchard outputs + recompute its canonical ZIP-244 sighash,
/// for the FROST joiner's display↔sighash binding (gh #17). Returns the same
/// JSON shape as `frost_parse_tx_outputs`, but sources both the bundle and the
/// sighash from the PCZT itself via `Pczt::into_effects()` → `v5_signature_hash`.
/// So the value the joiner checks is the canonical message its signature will
/// commit to — never a host-supplied claim. The host publishes the (proven,
/// io-finalized, redacted) PCZT; `into_effects` needs neither proof nor sigs.
#[wasm_bindgen]
pub fn frost_inspect_pczt_outputs(
    pczt_hex: &str,
    orchard_fvk_uview: &str,
) -> Result<String, JsError> {
    use orchard::keys::Scope;
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};

    let bytes = hex::decode(pczt_hex).map_err(|e| JsError::new(&format!("bad pczt hex: {}", e)))?;
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;

    // Canonical sighash, taken from pczt's own Signer because it dispatches on
    // the transaction version. v5_signature_hash is WRONG for an ironwood (v6)
    // PCZT: it hands the joiner a v5 digest while the signature it is about to
    // produce commits to the v6 one, so the display<->sighash binding this
    // function exists to provide would not actually hold. This is the same
    // value build_ironwood_send_pczt returns and complete_ironwood_pczt
    // verifies against, so builder, joiner and completion agree by
    // construction rather than by three separate reimplementations.
    let shielded_sighash = pczt::roles::signer::Signer::new(pczt.clone())
        .map_err(|e| JsError::new(&format!("signer init: {:?}", e)))?
        .shielded_sighash();
    let computed_sighash_hex = hex::encode(shielded_sighash);

    // Effects supply the bundles for the output display. Same byte stream the
    // sighash above was derived from.
    let tx_data = pczt
        .into_effects()
        .map_err(|e| JsError::new(&format!("pczt into_effects: {:?}", e)))?;

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
    let fvk_bytes = orchard_fvk_keys.to_bytes();
    let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes)
        .ok_or_else(|| JsError::new("invalid orchard FVK in UFVK"))?;
    let ovk_external = fvk.to_ovk(Scope::External);
    let ovk_internal = fvk.to_ovk(Scope::Internal);

    // Inspect both pools. A turnstile / post-NU6.3 PCZT carries its outputs in
    // the ironwood bundle, whose V3 note plaintexts `OrchardDomain` refuses by
    // design; leaving it out would show a joiner an empty output list for a
    // transaction that in fact moves funds.
    let orchard_bundle = tx_data.orchard_bundle();
    let ironwood_bundle = tx_data.ironwood_bundle();

    let mut actions_json: Vec<serde_json::Value> = Vec::new();
    let mut totals: (u64, u64, u32) = (0, 0, 0);
    let mut action_count: u32 = 0;

    if let Some(b) = orchard_bundle {
        action_count += b.actions().len() as u32;
        recover_bundle_outputs::<orchard::note_encryption::OrchardVersion, _>(
            b,
            "orchard",
            &ovk_external,
            &ovk_internal,
            &mut actions_json,
            &mut totals,
        );
    }
    if let Some(b) = ironwood_bundle {
        action_count += b.actions().len() as u32;
        recover_bundle_outputs::<orchard::note_encryption::IronwoodVersion, _>(
            b,
            "ironwood",
            &ovk_external,
            &ovk_internal,
            &mut actions_json,
            &mut totals,
        );
    }

    Ok(serde_json::json!({
        "actions": actions_json,
        "summary": {
            "total_send_zat": totals.0,
            "total_change_zat": totals.1,
            "decrypted_count": totals.2,
            "action_count": action_count,
        },
        "computed_sighash_hex": computed_sighash_hex,
    })
    .to_string())
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
        &attestation,
        public_key_package_hex,
        &anchor,
        anchor_height,
        mainnet,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

// ── helpers ──

fn parse_seed(hex_str: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str).map_err(|e| JsError::new(&format!("bad seed hex: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| JsError::new("seed must be 32 bytes"))
}

fn parse_32(hex_str: &str, name: &str) -> Result<[u8; 32], JsError> {
    let bytes =
        hex::decode(hex_str).map_err(|e| JsError::new(&format!("bad {} hex: {}", name, e)))?;
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{} must be 32 bytes", name)))
}

// ── Ledger DMK describe (host-side, orchard V5) ──
//
// zafu's Ledger signer (device-signer-kit-zcash, DMK) needs the unsigned PCZT
// rendered as JSON so the device can present + sign it. Unlike the zigner cold
// path - which signs a REDACTED PCZT delivered over an untrusted QR channel and
// so must NOT see the note plaintext - a Ledger is a TRUSTED device holding the
// seed. It therefore gets the full, UN-redacted describe: spend note plaintext
// (recipient / value / rho / rseed), the spend-auth randomizer `alpha`, and the
// ZIP-32 derivation path it needs to re-derive the spend authorizing key and
// bind a signature.
//
// The emitted JSON is the exact contract consumed by
// `apps/extension/src/ledger/pczt-translate.ts` in the zafu repo
// (`LedgerPcztDescribe` / `LedgerPcztGlobalJson` / `LedgerPcztOrchardBundleJson`
// / `LedgerPcztOrchardActionJson`). Byte fields are lowercase hex; value fields
// are decimal strings (signed for `valueBalance`); an absent Option is `null`
// (global) or an empty string (per-action optional bytes/values).
//
// This walks the same `pczt::Pczt` that `frost_inspect_pczt_outputs` opens, but
// where that function displays decrypted OUTPUTS via `into_effects`, this reads
// the raw per-action spend + output fields. The spend-side secrets are not
// exposed on the pczt-crate `Spend` (they are `pub(crate)`), so we obtain the
// fully-getter'd orchard-crate representation (`orchard::pczt::Bundle`) through
// the read-only `Verifier` role, which parses the bundle and hands it to a
// closure - the same parsed form the low-level signer drives.
//
// CONTRACT NOTES (Rust -> pczt-translate.ts):
// - `coinType` is derived from the caller's `mainnet` flag (133 / 1). pczt
//   0.9.3's `common::Global` exposes no getter for `coin_type`; the TS side
//   only validates 133 or 1, so this is faithful.
// - `fallbackLockTime` is emitted as `null` (absent Option). `Global` exposes
//   no getter for `fallback_lock_time` either; `null` is the correct encoding
//   for a shielded-only send whose inputs impose no required locktime (the tx
//   nLockTime then falls back to 0). If a transparent leg with a required
//   locktime is ever added, this needs a real value and an upstream getter.
// - `txModifiable` is reconstructed from the four public flag predicates
//   (`inputs_modifiable` | `outputs_modifiable` << 1 | `has_sighash_single`
//   << 2 | `shielded_modifiable` << 7); bits 3-6 are always 0.
//
// IRONWOOD (NU6.3 / V6) - NOT IMPLEMENTED (scaffold below). Ledger's app-zcash
// PR #28 signs V6 shielded PCZTs, and device-signer-kit-zcash models
// `PcztIronwoodBundle`, but the TS mapper has no ironwood shape yet and fails
// closed on `txVersion != 5`. To add it: drop the V5 gate; describe
// `pczt.ironwood()` via `Verifier::with_ironwood` (identical getters), noting
// that the V6 `TransmittedNoteCiphertext` has different `enc_ciphertext` /
// `out_ciphertext` lengths than V5's [u8; 580] / [u8; 80]; then add a
// `LedgerPcztIronwoodBundleJson` shape here and the matching
// `PcztIronwoodBundle` mapping in pczt-translate.ts. See `ironwood_todo` below.
#[wasm_bindgen]
pub fn describe_pczt_for_ledger(pczt_hex: &str, mainnet: bool) -> Result<String, JsError> {
    use ff::PrimeField;
    use pczt::roles::verifier::{OrchardError, Verifier};

    let bytes = hex::decode(pczt_hex).map_err(|e| JsError::new(&format!("bad pczt hex: {}", e)))?;
    let pczt = pczt::Pczt::parse(&bytes)
        .map_err(|e| JsError::new(&format!("pczt parse failed: {:?}", e)))?;

    // V5 gate: this describe emits an orchard (V5) bundle, and the TS mapper
    // binds a signature over a V5 shape - refuse V6 rather than mis-describe it
    // as V5 (see the ironwood scaffold in the module comment above).
    let tx_version = *pczt.global().tx_version();
    if tx_version != 5 {
        return Err(JsError::new(&format!(
            "describe_pczt_for_ledger: only orchard V5 is supported (got tx_version {}); \
             ironwood/V6 describe is not implemented",
            tx_version
        )));
    }

    // ── global (read before `pczt` is moved into the Verifier) ──
    let g = pczt.global();
    let tx_modifiable: u8 = (g.inputs_modifiable() as u8)
        | ((g.outputs_modifiable() as u8) << 1)
        | ((g.has_sighash_single() as u8) << 2)
        | ((g.shielded_modifiable() as u8) << 7);
    let coin_type: u32 = if mainnet { 133 } else { 1 };
    let global_json = serde_json::json!({
        "txVersion": tx_version,
        "versionGroupId": *g.version_group_id(),
        "consensusBranchId": *g.consensus_branch_id(),
        "expiryHeight": *g.expiry_height(),
        "coinType": coin_type,
        "fallbackLockTime": serde_json::Value::Null,
        "txModifiable": tx_modifiable,
    });

    // ── orchard bundle-level fields (raw pczt bundle has public getters for
    //    these; the per-action secrets do not, hence the Verifier below) ──
    let ob = pczt.orchard();
    let flags: u8 = *ob.flags();
    let (value_magnitude, value_is_negative) = *ob.value_sum();
    let value_balance = if value_is_negative && value_magnitude != 0 {
        format!("-{}", value_magnitude)
    } else {
        format!("{}", value_magnitude)
    };
    let anchor_hex = match ob.anchor() {
        Some(a) => hex::encode(a),
        None => hex::encode([0u8; 32]),
    };

    // ── per-action fields via the read-only Verifier role ──
    let mut actions_json: Vec<serde_json::Value> = Vec::new();
    Verifier::new(pczt)
        .with_orchard(|bundle| {
            for action in bundle.actions() {
                let spend = action.spend();
                let output = action.output();
                let enc = output.encrypted_note();

                let signing_path = spend
                    .zip32_derivation()
                    .as_ref()
                    .map(|z| format_ledger_zip32_path(z.derivation_path()))
                    .unwrap_or_default();
                let seed_fingerprint = spend
                    .zip32_derivation()
                    .as_ref()
                    .map(|z| hex::encode(z.seed_fingerprint()))
                    .unwrap_or_default();
                let alpha = spend
                    .alpha()
                    .as_ref()
                    .map(|a| hex::encode(a.to_repr()))
                    .unwrap_or_default();

                actions_json.push(serde_json::json!({
                    "cvNet": hex::encode(action.cv_net().to_bytes()),
                    "nullifier": hex::encode(spend.nullifier().to_bytes()),
                    "rk": hex::encode(<[u8; 32]>::from(spend.rk())),
                    "spendRecipient": spend
                        .recipient()
                        .as_ref()
                        .map(|r| hex::encode(r.to_raw_address_bytes()))
                        .unwrap_or_default(),
                    "spendValue": spend
                        .value()
                        .as_ref()
                        .map(|v| v.inner().to_string())
                        .unwrap_or_default(),
                    "spendRho": spend
                        .rho()
                        .as_ref()
                        .map(|r| hex::encode(r.to_bytes()))
                        .unwrap_or_default(),
                    "spendRseed": spend
                        .rseed()
                        .as_ref()
                        .map(|r| hex::encode(r.as_bytes()))
                        .unwrap_or_default(),
                    "alpha": alpha,
                    "signingPath": signing_path,
                    "seedFingerprint": seed_fingerprint,
                    "cmx": hex::encode(output.cmx().to_bytes()),
                    "ephemeralKey": hex::encode(enc.epk_bytes),
                    "encCiphertext": hex::encode(enc.enc_ciphertext),
                    "outCiphertext": hex::encode(enc.out_ciphertext),
                    "recipient": output
                        .recipient()
                        .as_ref()
                        .map(|r| hex::encode(r.to_raw_address_bytes()))
                        .unwrap_or_default(),
                    "value": output
                        .value()
                        .as_ref()
                        .map(|v| v.inner().to_string())
                        .unwrap_or_default(),
                    "rseed": output
                        .rseed()
                        .as_ref()
                        .map(|r| hex::encode(r.as_bytes()))
                        .unwrap_or_default(),
                    "rcv": action
                        .rcv()
                        .as_ref()
                        .map(|r| hex::encode(r.to_bytes()))
                        .unwrap_or_default(),
                }));
            }
            Ok::<(), OrchardError<String>>(())
        })
        .map_err(|e| JsError::new(&format!("orchard bundle parse/verify failed: {:?}", e)))?;

    let result = serde_json::json!({
        "global": global_json,
        "orchardBundle": {
            "actions": actions_json,
            "flags": flags,
            "valueBalance": value_balance,
            "anchor": anchor_hex,
        },
    });
    Ok(result.to_string())
}

/// Format a ZIP-32 derivation path as the device-expected string, e.g.
/// `"32'/133'/0'"`. Hardened indices (high bit set) are rendered with a
/// trailing apostrophe against the un-hardened value; non-hardened indices are
/// rendered bare. `device-signer-kit-zcash`'s `signingPath` is a string, not an
/// array of components.
fn format_ledger_zip32_path(path: &[zip32::ChildIndex]) -> String {
    path.iter()
        .map(|c| {
            let raw = c.index();
            if raw >= 0x8000_0000 {
                format!("{}'", raw - 0x8000_0000)
            } else {
                raw.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

// IRONWOOD (V6) describe scaffold - see the module comment on
// `describe_pczt_for_ledger`. Intentionally not wired up: the TS mapper has no
// ironwood shape and fails closed on V6, so exposing a half-built ironwood
// describe would only invite a mis-signed V6 transaction. When Ledger's V6
// support is plumbed through zafu, replace this with a real
// `Verifier::with_ironwood` walk emitting a `LedgerPcztIronwoodBundleJson`.
#[allow(dead_code)]
fn ironwood_todo() {
    // TODO(ledger-v6): describe `pczt.ironwood()` for NU6.3 signing.
    // Needs, on this (Rust) side:
    //   - drop the `tx_version != 5` gate in `describe_pczt_for_ledger`;
    //   - walk `pczt.ironwood()` via `Verifier::with_ironwood` (same getters);
    //   - account for the V6 `TransmittedNoteCiphertext` length difference
    //     (enc/out ciphertext sizes differ from V5's [u8; 580] / [u8; 80]).
    // Needs, on the zafu (TS) side:
    //   - a `LedgerPcztIronwoodBundleJson` in pczt-translate.ts and the matching
    //     `PcztIronwoodBundle` mapping into device-signer-kit-zcash.
}

// ── frostd relay cipher ──
//
// End-to-end encryption for relay traffic, wire-compatible with ZF's
// frost-client. See frost_spend::relay_cipher for why this lives in
// frost-spend rather than being frost-client itself, and for the interop
// test that keeps the two honest.
//
// The relay never sees plaintext. That is what makes it acceptable to run
// someone else's relay — including ZF's — and it is what the zafu UI has
// been claiming for a while without it being true.
//
// Sessions are STATEFUL: the first message to a peer carries the Noise
// handshake, later ones run in transport mode. So a RelayCipher must live for
// the whole session and messages must be processed in order. A fresh cipher
// mid-session will not decrypt anything.

/// A relay session's ciphers, held across the whole session.
#[wasm_bindgen]
pub struct FrostRelayCipher {
    inner: frost_spend::relay_cipher::RelayCipher,
}

#[wasm_bindgen]
impl FrostRelayCipher {
    /// `peers_hex` is a JSON array of hex-encoded 32-byte public keys.
    #[wasm_bindgen(constructor)]
    pub fn new(private_key_hex: &str, peers_hex: &str) -> Result<FrostRelayCipher, JsError> {
        let sk_bytes = hex::decode(private_key_hex)
            .map_err(|e| JsError::new(&format!("private key hex: {e}")))?;
        let sk: [u8; 32] = sk_bytes
            .try_into()
            .map_err(|_| JsError::new("private key is not 32 bytes"))?;

        let peers: Vec<String> = serde_json::from_str(peers_hex)
            .map_err(|e| JsError::new(&format!("peers json: {e}")))?;
        let peers = peers
            .iter()
            .map(|p| hex::decode(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsError::new(&format!("peer key hex: {e}")))?;

        Ok(FrostRelayCipher {
            inner: frost_spend::relay_cipher::RelayCipher::new(sk, peers)
                .map_err(|e| JsError::new(&e))?,
        })
    }

    /// Encrypt for one peer. Returns hex.
    pub fn encrypt(&mut self, recipient_hex: &str, msg: &[u8]) -> Result<String, JsError> {
        let recipient = hex::decode(recipient_hex)
            .map_err(|e| JsError::new(&format!("recipient hex: {e}")))?;
        let out = self
            .inner
            .encrypt(&recipient, msg.to_vec())
            .map_err(|e| JsError::new(&e))?;
        Ok(hex::encode(out))
    }

    /// Decrypt from one peer. Authenticates the sender: Noise_K mixes the
    /// sender's static key into the key schedule, so a message relabelled as
    /// coming from somebody else does not decrypt.
    pub fn decrypt(&mut self, sender_hex: &str, msg_hex: &str) -> Result<Vec<u8>, JsError> {
        let sender =
            hex::decode(sender_hex).map_err(|e| JsError::new(&format!("sender hex: {e}")))?;
        let msg = hex::decode(msg_hex).map_err(|e| JsError::new(&format!("msg hex: {e}")))?;
        self.inner
            .decrypt(&sender, &msg)
            .map_err(|e| JsError::new(&e))
    }
}

/// Generate a relay keypair. Returns JSON `{ "private": hex, "public": hex }`.
///
/// The public key is what other participants address messages to, and what
/// frostd authenticates you by.
#[wasm_bindgen]
pub fn frost_relay_generate_keypair() -> Result<String, JsError> {
    let (private, public) =
        frost_spend::relay_cipher::generate_keypair().map_err(|e| JsError::new(&e))?;
    Ok(serde_json::json!({
        "private": hex::encode(private),
        "public": hex::encode(public),
    })
    .to_string())
}

/// Sign a frostd login challenge with a relay private key.
///
/// frostd authenticates by verifying XEdDSA over the participant's X25519
/// key - the same key Noise uses. This exists because without it the browser
/// can generate keys and encrypt, but cannot log in at all, which is how the
/// gap was found: by trying to wire the client up.
#[wasm_bindgen]
pub fn frost_relay_sign_challenge(
    private_key_hex: &str,
    challenge: &str,
) -> Result<String, JsError> {
    let sk_bytes =
        hex::decode(private_key_hex).map_err(|e| JsError::new(&format!("private key hex: {e}")))?;
    let sk: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| JsError::new("private key is not 32 bytes"))?;

    // frostd verifies over the challenge uuid's 16 RAW bytes (frost-client
    // signs `Uuid::as_bytes`), not the 36-char string. Sign raw when the
    // challenge parses as a uuid; fall back to the string bytes otherwise.
    let uuid_raw: Option<[u8; 16]> = {
        let hex_str: String = challenge.chars().filter(|c| *c != '-').collect();
        hex::decode(&hex_str).ok().and_then(|b| b.try_into().ok())
    };
    let msg: &[u8] = match &uuid_raw {
        Some(raw) => raw,
        None => challenge.as_bytes(),
    };
    let sig = frost_spend::relay_cipher::sign_challenge(&sk, msg, &mut rand_core::OsRng)
        .map_err(|e| JsError::new(&e))?;
    Ok(hex::encode(sig))
}

use indicatif::{ProgressBar, ProgressStyle};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note_encryption::OrchardDomain;
use zcash_note_encryption::{
    try_compact_note_decryption, EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE,
};

use crate::client::{LightwalletdClient, ZidecarClient};
use crate::error::Error;
use crate::key::WalletSeed;
use crate::wallet::{Wallet, WalletNote};

const BATCH_SIZE_MIN: u32 = 500;
const BATCH_SIZE_MAX: u32 = 5_000;
const BATCH_ACTIONS_TARGET: usize = 50_000; // aim for ~50k actions per batch

use zync_core::{
    ACTIVATION_HASH_MAINNET, ORCHARD_ACTIVATION_HEIGHT as ORCHARD_ACTIVATION_MAINNET,
    ORCHARD_ACTIVATION_HEIGHT_TESTNET as ORCHARD_ACTIVATION_TESTNET,
};

struct CompactShieldedOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    ciphertext: [u8; 52],
}

impl ShieldedOutput<OrchardDomain, COMPACT_NOTE_SIZE> for CompactShieldedOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.epk)
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx
    }
    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.ciphertext
    }
}

/// sync using a FullViewingKey directly (for watch-only wallets)
pub async fn sync_with_fvk(
    fvk: &FullViewingKey,
    endpoint: &str,
    verify_endpoints: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    sync_inner(
        fvk,
        endpoint,
        verify_endpoints,
        mainnet,
        json,
        from,
        from_position,
    )
    .await
}

pub async fn sync(
    seed: &WalletSeed,
    endpoint: &str,
    verify_endpoints: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    let coin_type = if mainnet { 133 } else { 1 };

    // derive viewing keys
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Wallet("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
    sync_inner(
        &fvk,
        endpoint,
        verify_endpoints,
        mainnet,
        json,
        from,
        from_position,
    )
    .await
}

async fn sync_inner(
    fvk: &FullViewingKey,
    endpoint: &str,
    verify_endpoints: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    let activation = if mainnet {
        ORCHARD_ACTIVATION_MAINNET
    } else {
        ORCHARD_ACTIVATION_TESTNET
    };

    let ivk_ext = fvk.to_ivk(Scope::External).prepare();
    let ivk_int = fvk.to_ivk(Scope::Internal).prepare();

    let client = ZidecarClient::connect(endpoint).await?;
    let wallet = Wallet::open(&Wallet::default_path())?;

    let start = if let Some(h) = from {
        // --from H means "tree state is known at H", so scan from H+1
        // (the tree state at H already includes block H's actions)
        (h + 1).max(activation)
    } else {
        // sync_height is the last fully processed block, so scan from +1
        let sh = wallet.sync_height()?;
        if sh > 0 {
            (sh + 1).max(activation)
        } else {
            activation
        }
    };
    let (tip, tip_hash) = client.get_tip().await?;

    // verify activation block hash against hardcoded anchor
    if mainnet {
        let blocks = client.get_compact_blocks(activation, activation).await?;
        if !blocks.is_empty()
            && !blocks[0].hash.is_empty()
            && blocks[0].hash != ACTIVATION_HASH_MAINNET
        {
            return Err(Error::Other(format!(
                "activation block hash mismatch: got {} expected {}",
                hex::encode(&blocks[0].hash),
                hex::encode(ACTIVATION_HASH_MAINNET),
            )));
        }
    }

    // cross-verify tip against independent lightwalletd node(s)
    let endpoints: Vec<&str> = verify_endpoints
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if !endpoints.is_empty() {
        cross_verify(&client, &endpoints, tip, &tip_hash, activation).await?;
    }

    // verify header chain proof (ligerito) — returns proven NOMT roots
    let proven_roots = verify_header_proof(&client, tip, mainnet).await?;

    eprintln!("tip={} start={}", tip, start);

    if start >= tip {
        if !json {
            eprintln!("wallet up to date at height {}", tip);
        }
        return Ok(0);
    }

    if !json {
        eprintln!(
            "scanning blocks from {} to {} ({} blocks)",
            start,
            tip,
            tip - start
        );
    }

    let total_blocks = tip - start;
    let pb = if !json && is_terminal::is_terminal(std::io::stderr()) {
        let pb = ProgressBar::new(total_blocks as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed}] {bar:50.cyan/blue} {pos:>7}/{len:7} {per_sec} ETA: {eta}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let mut found_total = 0u32;
    let mut current = start;
    let mut batch_size = BATCH_SIZE_MIN; // adaptive: grows for sparse blocks, shrinks for dense
                                         // global position counter - tracks every orchard action from activation
    let mut position_counter = if let Some(pos) = from_position {
        wallet.set_orchard_position(pos)?;
        pos
    } else {
        wallet.orchard_position()?
    };

    // collect new notes that need memo fetching
    type MemoEntry = ([u8; 32], Vec<u8>, [u8; 32], [u8; 32], [u8; 32]);
    let mut needs_memo: Vec<MemoEntry> = Vec::new();

    // collect received cmxs and positions for commitment proof verification
    let mut received_cmxs: Vec<[u8; 32]> = Vec::new();
    let mut received_positions: Vec<u64> = Vec::new();

    // collect notes in memory first; only persist after proof verification
    let mut pending_notes: Vec<WalletNote> = Vec::new();
    // collect nullifiers seen in actions to mark spent after verification
    let mut seen_nullifiers: Vec<[u8; 32]> = Vec::new();
    // running actions commitment chain for verifying block completeness
    // when resuming a partial sync, load the commitment saved at last sync height;
    // it must chain from activation to match the proven value.
    let saved_actions_commitment = wallet.actions_commitment()?;
    let actions_commitment_available = start <= activation || saved_actions_commitment != [0u8; 32];
    let mut running_actions_commitment = if start > activation {
        saved_actions_commitment
    } else {
        [0u8; 32]
    };

    while current <= tip {
        let end = (current + batch_size - 1).min(tip);
        let blocks = match retry_compact_blocks(&client, current, end).await {
            Ok(b) => b,
            Err(_) if batch_size > BATCH_SIZE_MIN => {
                // batch too large — halve and retry
                batch_size = (batch_size / 2).max(BATCH_SIZE_MIN);
                eprintln!("  reducing batch size to {}", batch_size);
                continue;
            }
            Err(e) => return Err(e),
        };

        let action_count: usize = blocks.iter().map(|b| b.actions.len()).sum();
        if action_count > 0 {
            eprintln!(
                "  batch {}..{}: {} blocks, {} orchard actions",
                current,
                end,
                blocks.len(),
                action_count
            );
        }

        // adaptive batch sizing: grow for sparse blocks, shrink for dense
        // cap growth to 2x per step to avoid overshooting
        if action_count == 0 {
            batch_size = (batch_size * 2).min(BATCH_SIZE_MAX);
        } else if action_count > BATCH_ACTIONS_TARGET {
            batch_size = (batch_size / 2).max(BATCH_SIZE_MIN);
        } else {
            batch_size = (batch_size * 2).clamp(BATCH_SIZE_MIN, BATCH_SIZE_MAX);
        }

        for block in &blocks {
            for action in &block.actions {
                if action.ciphertext.len() < 52 {
                    position_counter += 1;
                    continue;
                }

                let mut ct = [0u8; 52];
                ct.copy_from_slice(&action.ciphertext[..52]);

                let output = CompactShieldedOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    ciphertext: ct,
                };

                // try external then internal scope
                let result = try_decrypt(fvk, &ivk_ext, &ivk_int, &action.nullifier, &output);

                if let Some(decrypted) = result {
                    let wallet_note = WalletNote {
                        value: decrypted.value,
                        nullifier: decrypted.nullifier,
                        cmx: action.cmx,
                        block_height: block.height,
                        is_change: decrypted.is_change,
                        recipient: decrypted.recipient,
                        rho: decrypted.rho,
                        rseed: decrypted.rseed,
                        position: position_counter,
                        txid: action.txid.clone(),
                        memo: None,
                    };
                    pending_notes.push(wallet_note);
                    found_total += 1;
                    received_cmxs.push(action.cmx);
                    received_positions.push(position_counter);

                    if !action.txid.is_empty() && !decrypted.is_change {
                        needs_memo.push((
                            decrypted.nullifier,
                            action.txid.clone(),
                            action.cmx,
                            action.ephemeral_key,
                            action.nullifier,
                        ));
                    }
                }

                // collect nullifiers for marking spent after verification
                seen_nullifiers.push(action.nullifier);

                position_counter += 1;
            }

            // compute per-block actions_root and update running commitment chain
            let action_tuples: Vec<([u8; 32], [u8; 32], [u8; 32])> = block
                .actions
                .iter()
                .map(|a| (a.cmx, a.nullifier, a.ephemeral_key))
                .collect();
            let actions_root = zync_core::actions::compute_actions_root(&action_tuples);
            running_actions_commitment = zync_core::actions::update_actions_commitment(
                &running_actions_commitment,
                &actions_root,
                block.height,
            );
        }

        current = end + 1;

        if let Some(ref pb) = pb {
            pb.set_position((current - start) as u64);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // verify actions commitment chain against proven value
    running_actions_commitment = zync_core::sync::verify_actions_commitment(
        &running_actions_commitment,
        &proven_roots.actions_commitment,
        actions_commitment_available,
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    if !actions_commitment_available {
        eprintln!(
            "actions commitment: migrating from pre-0.5.1 wallet, saving proven {}...",
            hex::encode(&running_actions_commitment[..8]),
        );
    } else {
        eprintln!(
            "actions commitment verified: {}...",
            hex::encode(&running_actions_commitment[..8])
        );
    }

    // verify commitment proofs (NOMT) for received notes BEFORE storing
    if !received_cmxs.is_empty() {
        verify_commitments(
            &client,
            &received_cmxs,
            &received_positions,
            tip,
            &proven_roots,
        )
        .await?;
    }

    // now that proofs are verified, persist notes to wallet
    for note in &pending_notes {
        wallet.insert_note(note)?;
    }
    for nf in &seen_nullifiers {
        wallet.mark_spent(nf).ok();
    }
    wallet.set_sync_height(tip)?;
    wallet.set_orchard_position(position_counter)?;
    wallet.set_actions_commitment(&running_actions_commitment)?;

    // verify nullifier proofs (NOMT) for unspent notes
    verify_nullifiers(&client, &wallet, tip, &proven_roots).await?;

    // fetch memos for newly found notes
    if !needs_memo.is_empty() {
        eprintln!("fetching memos for {} notes...", needs_memo.len());
        for (nullifier, txid, cmx, epk, action_nf) in &needs_memo {
            match fetch_memo(&client, fvk, &ivk_ext, txid, cmx, epk, action_nf).await {
                Ok(Some(memo)) => {
                    // update note in wallet with memo
                    if let Ok(mut note) = wallet.get_note(nullifier) {
                        note.memo = Some(memo);
                        wallet.insert_note(&note).ok();
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("  memo fetch failed: {}", e),
            }
        }
    }

    // scan mempool for pending activity (full scan for privacy)
    let mempool_found = scan_mempool(&client, fvk, &ivk_ext, &ivk_int, &wallet, json).await;

    if !json {
        eprintln!(
            "synced to {} - {} new notes found (position {})",
            tip, found_total, position_counter
        );
        if mempool_found > 0 {
            eprintln!(
                "  {} pending mempool transaction(s) detected",
                mempool_found
            );
        }
    }

    Ok(found_total)
}

struct DecryptedNote {
    value: u64,
    nullifier: [u8; 32],
    is_change: bool,
    recipient: Vec<u8>,
    rho: [u8; 32],
    rseed: [u8; 32],
}

/// try trial decryption with both external and internal IVKs
/// extracts full note data needed for spending
fn try_decrypt(
    fvk: &FullViewingKey,
    ivk_ext: &PreparedIncomingViewingKey,
    ivk_int: &PreparedIncomingViewingKey,
    action_nf: &[u8; 32],
    output: &CompactShieldedOutput,
) -> Option<DecryptedNote> {
    let nf = orchard::note::Nullifier::from_bytes(action_nf);
    if nf.is_none().into() {
        return None;
    }
    let nf = nf.unwrap();

    let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&output.cmx);
    if cmx.is_none().into() {
        return None;
    }
    let cmx = cmx.unwrap();

    let compact = orchard::note_encryption::CompactAction::from_parts(
        nf,
        cmx,
        EphemeralKeyBytes(output.epk),
        output.ciphertext,
    );
    let domain = OrchardDomain::for_compact_action(&compact);

    // try external scope
    if let Some((note, _)) = try_compact_note_decryption(&domain, ivk_ext, output) {
        // Verify the note commitment matches what the server sent.
        // A malicious server could craft ciphertexts that decrypt to fake notes
        // with arbitrary values. Recomputing cmx from the decrypted note fields
        // and comparing against the server-provided cmx detects this.
        let recomputed = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if recomputed.to_bytes() != output.cmx {
            eprintln!("WARNING: cmx mismatch after decryption — server sent fake note, skipping");
            return None;
        }
        return Some(extract_note_data(fvk, &note, false));
    }

    // try internal scope (change/shielding)
    if let Some((note, _)) = try_compact_note_decryption(&domain, ivk_int, output) {
        let recomputed = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        if recomputed.to_bytes() != output.cmx {
            eprintln!("WARNING: cmx mismatch after decryption — server sent fake note, skipping");
            return None;
        }
        return Some(extract_note_data(fvk, &note, true));
    }

    None
}

use zync_core::sync::hashes_match;

/// cross-verify tip and activation block against independent lightwalletd nodes.
/// requires BFT majority (>2/3 of reachable nodes) to agree with zidecar.
/// hard-fails on hash mismatch, soft-fails only when no nodes reachable.
async fn cross_verify(
    zidecar: &ZidecarClient,
    endpoints: &[&str],
    tip: u32,
    tip_hash: &[u8],
    activation: u32,
) -> Result<(), Error> {
    eprintln!(
        "cross-verifying against {} lightwalletd node(s)...",
        endpoints.len()
    );

    // fetch activation block hash from zidecar once
    let zid_act = match zidecar.get_compact_blocks(activation, activation).await {
        Ok(blocks) if !blocks.is_empty() => blocks[0].hash.clone(),
        _ => vec![],
    };

    let mut tip_agree = 0u32;
    let mut tip_disagree = 0u32;
    let mut act_agree = 0u32;
    let mut act_disagree = 0u32;

    for &ep in endpoints {
        let lwd = match LightwalletdClient::connect(ep).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  {}: connect failed: {}", ep, e);
                continue;
            }
        };

        // check tip block hash
        match lwd.get_block(tip as u64).await {
            Ok((_, lwd_hash, _)) => {
                if hashes_match(tip_hash, &lwd_hash) {
                    tip_agree += 1;
                } else {
                    eprintln!(
                        "  {}: tip MISMATCH at {}: zidecar={} lwd={}",
                        ep,
                        tip,
                        hex::encode(tip_hash),
                        hex::encode(&lwd_hash)
                    );
                    tip_disagree += 1;
                }
            }
            Err(e) => {
                eprintln!("  {}: get_block({}): {}", ep, tip, e);
            }
        }

        // check activation block hash
        match lwd.get_block(activation as u64).await {
            Ok((_, lwd_hash, _)) => {
                if hashes_match(&zid_act, &lwd_hash) {
                    act_agree += 1;
                } else {
                    eprintln!(
                        "  {}: activation MISMATCH at {}: zidecar={} lwd={}",
                        ep,
                        activation,
                        hex::encode(&zid_act),
                        hex::encode(&lwd_hash)
                    );
                    act_disagree += 1;
                }
            }
            Err(e) => {
                eprintln!("  {}: get_block({}): {}", ep, activation, e);
            }
        }
    }

    let tip_total = tip_agree + tip_disagree;
    let act_total = act_agree + act_disagree;

    if tip_total == 0 && act_total == 0 {
        return Err(Error::Other(
            "cross-verification failed: no verify nodes responded".into(),
        ));
    }

    // BFT majority: need >2/3 of responding nodes to agree
    if tip_total > 0 {
        let threshold = (tip_total * 2).div_ceil(3);
        if tip_agree < threshold {
            return Err(Error::Other(format!(
                "tip hash rejected: {}/{} nodes disagree at height {}",
                tip_disagree, tip_total, tip,
            )));
        }
    }

    if act_total > 0 {
        let threshold = (act_total * 2).div_ceil(3);
        if act_agree < threshold {
            return Err(Error::Other(format!(
                "activation block rejected: {}/{} nodes disagree at height {}",
                act_disagree, act_total, activation,
            )));
        }
    }

    eprintln!(
        "cross-check ok: tip={} ({}/{}) activation={} ({}/{})",
        tip, tip_agree, tip_total, activation, act_agree, act_total,
    );
    Ok(())
}

use zync_core::sync::ProvenRoots;

async fn verify_header_proof(
    client: &ZidecarClient,
    tip: u32,
    mainnet: bool,
) -> Result<ProvenRoots, Error> {
    eprintln!("verifying header proof...");
    let (proof_bytes, proof_from, proof_to) = client
        .get_header_proof()
        .await
        .map_err(|e| Error::Other(format!("header proof fetch failed: {}", e)))?;
    eprintln!(
        "  proof: {} bytes, range {}..{}",
        proof_bytes.len(),
        proof_from,
        proof_to
    );

    let proven = zync_core::sync::verify_header_proof(&proof_bytes, tip, mainnet)
        .map_err(|e| Error::Other(e.to_string()))?;

    eprintln!(
        "header proof valid ({}..{}) continuous=true",
        proof_from, proof_to
    );
    eprintln!(
        "  proven tree_root={}.. nullifier_root={}...",
        hex::encode(&proven.tree_root[..8]),
        hex::encode(&proven.nullifier_root[..8]),
    );

    Ok(proven)
}

async fn verify_commitments(
    client: &ZidecarClient,
    cmxs: &[[u8; 32]],
    positions: &[u64],
    tip: u32,
    proven: &ProvenRoots,
) -> Result<(), Error> {
    eprintln!("verifying {} commitment proofs...", cmxs.len());
    let cmx_vecs: Vec<Vec<u8>> = cmxs.iter().map(|c| c.to_vec()).collect();
    let (proofs, root) = client
        .get_commitment_proofs(cmx_vecs, positions.to_vec(), tip)
        .await
        .map_err(|e| Error::Other(format!("commitment proof fetch failed: {}", e)))?;

    let proof_data: Vec<zync_core::sync::CommitmentProofData> = proofs
        .iter()
        .map(|p| zync_core::sync::CommitmentProofData {
            cmx: p.cmx,
            tree_root: p.tree_root,
            path_proof_raw: p.path_proof_raw.clone(),
            value_hash: p.value_hash,
        })
        .collect();

    zync_core::sync::verify_commitment_proofs(&proof_data, cmxs, proven, &root)
        .map_err(|e| Error::Other(e.to_string()))?;

    eprintln!(
        "all {} commitment proofs cryptographically valid",
        proofs.len()
    );
    Ok(())
}

async fn verify_nullifiers(
    client: &ZidecarClient,
    wallet: &Wallet,
    tip: u32,
    proven: &ProvenRoots,
) -> Result<(), Error> {
    let (_, unspent_notes) = wallet.shielded_balance()?;
    if unspent_notes.is_empty() {
        return Ok(());
    }
    eprintln!(
        "verifying nullifier proofs for {} unspent notes...",
        unspent_notes.len()
    );
    let nf_vecs: Vec<Vec<u8>> = unspent_notes.iter().map(|n| n.nullifier.to_vec()).collect();
    let requested_nfs: Vec<[u8; 32]> = unspent_notes.iter().map(|n| n.nullifier).collect();
    let (proofs, root) = client
        .get_nullifier_proofs(nf_vecs, tip)
        .await
        .map_err(|e| Error::Other(format!("nullifier proof fetch failed: {}", e)))?;

    let proof_data: Vec<zync_core::sync::NullifierProofData> = proofs
        .iter()
        .map(|p| zync_core::sync::NullifierProofData {
            nullifier: p.nullifier,
            nullifier_root: p.nullifier_root,
            is_spent: p.is_spent,
            path_proof_raw: p.path_proof_raw.clone(),
            value_hash: p.value_hash,
        })
        .collect();

    let spent =
        zync_core::sync::verify_nullifier_proofs(&proof_data, &requested_nfs, proven, &root)
            .map_err(|e| Error::Other(e.to_string()))?;

    for nf in &spent {
        eprintln!(
            "  nullifier {} proven spent, updating wallet",
            hex::encode(nf)
        );
        wallet.mark_spent(nf).ok();
    }

    eprintln!(
        "all {} nullifier proofs cryptographically valid",
        proofs.len()
    );
    Ok(())
}

/// retry compact block fetch with backoff (grpc-web streams are flaky)
async fn retry_compact_blocks(
    client: &ZidecarClient,
    start: u32,
    end: u32,
) -> Result<Vec<crate::client::CompactBlock>, Error> {
    let mut attempts = 0;
    loop {
        match client.get_compact_blocks(start, end).await {
            Ok(blocks) => return Ok(blocks),
            Err(e) => {
                attempts += 1;
                if attempts >= 3 {
                    return Err(e);
                }
                eprintln!("  retry {}/3 for {}..{}: {}", attempts, start, end, e);
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempts)).await;
            }
        }
    }
}

/// fetch full transaction and decrypt memo for a specific action
async fn fetch_memo(
    client: &ZidecarClient,
    _fvk: &FullViewingKey,
    ivk: &PreparedIncomingViewingKey,
    txid: &[u8],
    cmx: &[u8; 32],
    epk: &[u8; 32],
    action_nf: &[u8; 32],
) -> Result<Option<String>, Error> {
    use orchard::note_encryption::OrchardDomain;
    use zcash_note_encryption::{try_note_decryption, ENC_CIPHERTEXT_SIZE};

    let raw_tx = client.get_transaction(txid).await?;
    let Some(enc) = zync_core::sync::extract_enc_ciphertext(&raw_tx, cmx, epk) else {
        return Ok(None);
    };

    let nf = orchard::note::Nullifier::from_bytes(action_nf);
    if nf.is_none().into() {
        return Ok(None);
    }
    let nf = nf.unwrap();

    let cmx_parsed = orchard::note::ExtractedNoteCommitment::from_bytes(cmx);
    if cmx_parsed.is_none().into() {
        return Ok(None);
    }
    let cmx_parsed = cmx_parsed.unwrap();

    let mut compact_ct = [0u8; 52];
    compact_ct.copy_from_slice(&enc[..52]);
    let compact = orchard::note_encryption::CompactAction::from_parts(
        nf,
        cmx_parsed,
        EphemeralKeyBytes(*epk),
        compact_ct,
    );
    let domain = OrchardDomain::for_compact_action(&compact);

    struct FullOutput {
        epk: [u8; 32],
        cmx: [u8; 32],
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    }
    impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
        fn ephemeral_key(&self) -> EphemeralKeyBytes {
            EphemeralKeyBytes(self.epk)
        }
        fn cmstar_bytes(&self) -> [u8; 32] {
            self.cmx
        }
        fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
            &self.enc_ciphertext
        }
    }

    let output = FullOutput {
        epk: *epk,
        cmx: *cmx,
        enc_ciphertext: enc,
    };
    if let Some((_, _, memo)) = try_note_decryption(&domain, ivk, &output) {
        let end = memo
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        if end > 0 {
            return Ok(Some(String::from_utf8_lossy(&memo[..end]).to_string()));
        }
    }
    Ok(None)
}

/// scan full mempool for privacy — trial decrypt all actions + check nullifiers.
/// always scans everything so the server can't distinguish which tx triggered interest.
/// returns number of relevant transactions found (incoming or spend-pending).
async fn scan_mempool(
    client: &ZidecarClient,
    fvk: &FullViewingKey,
    ivk_ext: &PreparedIncomingViewingKey,
    ivk_int: &PreparedIncomingViewingKey,
    wallet: &Wallet,
    json: bool,
) -> u32 {
    let blocks = match client.get_mempool_stream().await {
        Ok(b) => b,
        Err(e) => {
            if !json {
                eprintln!("mempool scan skipped: {}", e);
            }
            return 0;
        }
    };

    let total_actions: usize = blocks.iter().map(|b| b.actions.len()).sum();
    if total_actions == 0 {
        return 0;
    }

    if !json {
        eprintln!(
            "scanning mempool: {} txs, {} orchard actions",
            blocks.len(),
            total_actions
        );
    }

    // collect wallet nullifiers for spend detection
    let wallet_nullifiers: Vec<[u8; 32]> = wallet
        .shielded_balance()
        .map(|(_, notes)| notes.iter().map(|n| n.nullifier).collect())
        .unwrap_or_default();

    let mut found = 0u32;

    for block in &blocks {
        let txid_hex = hex::encode(&block.hash);

        for action in &block.actions {
            // check if any wallet nullifier is being spent in mempool
            if wallet_nullifiers.contains(&action.nullifier) {
                if !json {
                    eprintln!(
                        "  PENDING SPEND: nullifier {}.. in mempool tx {}...",
                        hex::encode(&action.nullifier[..8]),
                        &txid_hex[..16],
                    );
                }
                found += 1;
            }

            // trial decrypt for incoming payments
            if action.ciphertext.len() >= 52 {
                let mut ct = [0u8; 52];
                ct.copy_from_slice(&action.ciphertext[..52]);
                let output = CompactShieldedOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    ciphertext: ct,
                };
                if let Some(decrypted) =
                    try_decrypt(fvk, ivk_ext, ivk_int, &action.nullifier, &output)
                {
                    let zec = decrypted.value as f64 / 1e8;
                    let kind = if decrypted.is_change {
                        "change"
                    } else {
                        "incoming"
                    };
                    if !json {
                        eprintln!(
                            "  PENDING {}: {:.8} ZEC in mempool tx {}...",
                            kind.to_uppercase(),
                            zec,
                            &txid_hex[..16],
                        );
                    }
                    found += 1;
                }
            }
        }
    }

    found
}

/// extract all fields from a decrypted note for wallet storage
fn extract_note_data(fvk: &FullViewingKey, note: &orchard::Note, is_change: bool) -> DecryptedNote {
    let note_nf = note.nullifier(fvk);
    DecryptedNote {
        value: note.value().inner(),
        nullifier: note_nf.to_bytes(),
        is_change,
        recipient: note.recipient().to_raw_address_bytes().to_vec(),
        rho: note.rho().to_bytes(),
        rseed: *note.rseed().as_bytes(),
    }
}

use indicatif::{ProgressBar, ProgressStyle};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note_encryption::OrchardDomain;
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, EphemeralKeyBytes, ShieldedOutput,
    COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};

use crate::client::{LightwalletdClient, ZidecarClient};
use crate::error::Error;
use crate::key::WalletSeed;
use crate::wallet::{Wallet, WalletNote};

const BATCH_SIZE: u32 = 500;

// orchard activation heights
const ORCHARD_ACTIVATION_MAINNET: u32 = 1_687_104;
const ORCHARD_ACTIVATION_TESTNET: u32 = 1_842_420;

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

struct FullShieldedOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for FullShieldedOutput {
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

pub async fn sync(
    seed: &WalletSeed,
    endpoint: &str,
    verify_endpoint: &str,
    mainnet: bool,
    json: bool,
    from: Option<u32>,
    from_position: Option<u64>,
) -> Result<u32, Error> {
    let coin_type = if mainnet { 133 } else { 1 };
    let activation = if mainnet {
        ORCHARD_ACTIVATION_MAINNET
    } else {
        ORCHARD_ACTIVATION_TESTNET
    };

    // derive viewing keys
    let sk = SpendingKey::from_zip32_seed(seed.as_bytes(), coin_type, zip32::AccountId::ZERO)
        .map_err(|_| Error::Wallet("failed to derive spending key".into()))?;
    let fvk = FullViewingKey::from(&sk);
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

    // cross-verify against independent lightwalletd
    if !verify_endpoint.is_empty() {
        eprintln!("cross-verifying with {}...", verify_endpoint);
        cross_verify(&client, verify_endpoint, tip, &tip_hash, activation).await;
    }

    // verify header chain proof before trusting any blocks
    verify_header_proof(&client).await?;

    // verify state proof (ligerito transition → verified roots)
    let (verified_tree_root, verified_nullifier_root) =
        verify_state_proof(&client, tip, mainnet).await?;

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

    while current <= tip {
        let end = (current + BATCH_SIZE - 1).min(tip);
        let blocks = retry_compact_blocks(&client, current, end).await?;

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
                let result = try_decrypt(&fvk, &ivk_ext, &ivk_int, &action.nullifier, &output);

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
                    wallet.insert_note(&wallet_note)?;
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

                // check if this action's nullifier spends one of our notes
                wallet.mark_spent(&action.nullifier).ok();

                position_counter += 1;
            }
        }

        current = end + 1;
        wallet.set_sync_height(end)?;
        wallet.set_orchard_position(position_counter)?;

        if let Some(ref pb) = pb {
            pb.set_position((current - start) as u64);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    // verify commitment proofs against verified tree root
    if !received_cmxs.is_empty() {
        if let Some(vroot) = verified_tree_root {
            verify_commitments(&client, &received_cmxs, &received_positions, tip, &vroot).await?;
        }
    }

    // verify nullifier proofs for unspent notes
    if let Some(vroot) = verified_nullifier_root {
        verify_nullifiers(&client, &wallet, tip, &vroot).await?;
    }

    // fetch memos for newly found notes
    if !needs_memo.is_empty() {
        eprintln!("fetching memos for {} notes...", needs_memo.len());
        for (nullifier, txid, cmx, epk, action_nf) in &needs_memo {
            match fetch_memo(&client, &fvk, &ivk_ext, txid, cmx, epk, action_nf).await {
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

    if !json {
        eprintln!(
            "synced to {} - {} new notes found (position {})",
            tip, found_total, position_counter
        );
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
        return Some(extract_note_data(fvk, &note, false));
    }

    // try internal scope (change/shielding)
    if let Some((note, _)) = try_compact_note_decryption(&domain, ivk_int, output) {
        return Some(extract_note_data(fvk, &note, true));
    }

    None
}

/// cross-verify tip and activation block against an independent lightwalletd.
/// hard-fails on hash mismatch (fork divergence), soft-fails on connectivity.
async fn cross_verify(
    zidecar: &ZidecarClient,
    verify_endpoint: &str,
    tip: u32,
    tip_hash: &[u8],
    activation: u32,
) {
    let lwd = match LightwalletdClient::connect(verify_endpoint).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: could not connect to verify endpoint: {}", e);
            return;
        }
    };

    let lwd_tip = match lwd.get_latest_block().await {
        Ok((h, _)) => h,
        Err(e) => {
            eprintln!("warning: lwd get_latest_block: {}", e);
            return;
        }
    };

    // compare block at zidecar tip height
    if let Ok((_, lwd_hash, _)) = lwd.get_block(tip as u64).await {
        if !tip_hash.is_empty() && !lwd_hash.is_empty() && tip_hash != lwd_hash {
            eprintln!(
                "FATAL: tip hash mismatch at height {}: zidecar={} lwd={}",
                tip,
                hex::encode(tip_hash),
                hex::encode(&lwd_hash)
            );
            std::process::exit(1);
        }
        eprintln!("tip cross-check ok (height {} lwd_tip={})", tip, lwd_tip);
    } else {
        eprintln!("warning: lwd could not fetch block at tip height {}", tip);
    }

    // compare activation block
    let lwd_act = match lwd.get_block(activation as u64).await {
        Ok((_, hash, _)) => hash,
        Err(e) => {
            eprintln!("warning: lwd get_block({}): {}", activation, e);
            return;
        }
    };
    let zid_act = match zidecar.get_compact_blocks(activation, activation).await {
        Ok(blocks) if !blocks.is_empty() => blocks[0].hash.clone(),
        _ => {
            eprintln!("warning: could not fetch activation block from zidecar");
            return;
        }
    };
    if !zid_act.is_empty() && !lwd_act.is_empty() && zid_act != lwd_act {
        eprintln!(
            "FATAL: activation block hash mismatch at {}: zidecar={} lwd={}",
            activation,
            hex::encode(&zid_act),
            hex::encode(&lwd_act)
        );
        std::process::exit(1);
    }
    eprintln!("activation block cross-check ok (height {})", activation);
}

async fn verify_header_proof(client: &ZidecarClient) -> Result<(), Error> {
    eprintln!("verifying header proof...");
    let (proof_bytes, proof_from, proof_to) = match client.get_header_proof().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: could not get header proof: {}", e);
            eprintln!("continuing without proof verification");
            return Ok(());
        }
    };
    let result = match zync_core::verifier::verify_proofs_full(&proof_bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warning: proof not ready: {}", e);
            eprintln!("continuing without verification");
            return Ok(());
        }
    };
    if !result.gigaproof_valid {
        return Err(Error::Other("gigaproof invalid".into()));
    }
    if !result.tip_valid {
        return Err(Error::Other("tip proof invalid".into()));
    }
    if !result.continuous {
        return Err(Error::Other("proof chain discontinuous".into()));
    }
    eprintln!(
        "proofs valid ({}..{}) continuous=true",
        proof_from, proof_to
    );
    Ok(())
}

async fn verify_state_proof(
    client: &ZidecarClient,
    tip: u32,
    mainnet: bool,
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>), Error> {
    eprintln!("verifying state proof...");
    let state_proof = match client.get_state_proof(tip).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: could not get state proof: {}", e);
            eprintln!("continuing without state root verification");
            return Ok((None, None));
        }
    };
    let registry = zync_core::trustless::SignerRegistry::new();
    let key = if mainnet {
        registry.mainnet_key()
    } else {
        registry.testnet_key()
    };
    let verified = state_proof
        .verify(key)
        .map_err(|e| Error::Other(format!("state proof invalid: {}", e)))?;
    eprintln!(
        "state proof valid (epoch {} height {})",
        verified.checkpoint_epoch, verified.height
    );
    Ok((Some(verified.tree_root), Some(verified.nullifier_root)))
}

async fn verify_commitments(
    client: &ZidecarClient,
    cmxs: &[[u8; 32]],
    positions: &[u64],
    tip: u32,
    expected_root: &[u8; 32],
) -> Result<(), Error> {
    eprintln!("verifying {} commitment proofs...", cmxs.len());
    let cmx_vecs: Vec<Vec<u8>> = cmxs.iter().map(|c| c.to_vec()).collect();
    let (proofs, response_root) = match client
        .get_commitment_proofs(cmx_vecs, positions.to_vec(), tip)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: could not get commitment proofs: {}", e);
            eprintln!("continuing without commitment verification");
            return Ok(());
        }
    };
    if response_root != *expected_root {
        return Err(Error::Other(
            "commitment proof tree root doesn't match verified state".into(),
        ));
    }
    for proof in &proofs {
        match proof.verify() {
            Ok(true) => {}
            Ok(false) => {
                return Err(Error::Other(format!(
                    "commitment proof invalid for cmx {}",
                    hex::encode(proof.cmx),
                )))
            }
            Err(e) => {
                return Err(Error::Other(format!(
                    "commitment proof verification error: {}",
                    e,
                )))
            }
        }
    }
    eprintln!("all commitment proofs valid");
    Ok(())
}

async fn verify_nullifiers(
    client: &ZidecarClient,
    wallet: &Wallet,
    tip: u32,
    expected_root: &[u8; 32],
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
    let (proofs, response_root) = match client.get_nullifier_proofs(nf_vecs, tip).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warning: could not get nullifier proofs: {}", e);
            eprintln!("continuing without nullifier verification");
            return Ok(());
        }
    };
    if response_root != *expected_root {
        return Err(Error::Other(
            "nullifier proof root doesn't match verified state".into(),
        ));
    }
    for proof in &proofs {
        match proof.verify() {
            Ok(true) => {
                if proof.is_spent {
                    eprintln!(
                        "  nullifier {} proven spent, updating wallet",
                        hex::encode(proof.nullifier)
                    );
                    wallet.mark_spent(&proof.nullifier).ok();
                }
            }
            Ok(false) => {
                return Err(Error::Other(format!(
                    "nullifier proof invalid for {}",
                    hex::encode(proof.nullifier),
                )))
            }
            Err(e) => {
                return Err(Error::Other(format!(
                    "nullifier proof verification error: {}",
                    e,
                )))
            }
        }
    }
    eprintln!("all nullifier proofs valid");
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
                if attempts >= 5 {
                    return Err(e);
                }
                eprintln!("  retry {}/5 for {}..{}: {}", attempts, start, end, e);
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
    let raw_tx = client.get_transaction(txid).await?;

    let enc_ciphertext = extract_enc_ciphertext(&raw_tx, cmx, epk)?;
    let Some(enc) = enc_ciphertext else {
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

    let output = FullShieldedOutput {
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
            let text = String::from_utf8_lossy(&memo[..end]).to_string();
            return Ok(Some(text));
        }
    }

    Ok(None)
}

/// extract the 580-byte enc_ciphertext for an action matching cmx+epk from raw tx bytes
///
/// V5 orchard action = cv(32) + nf(32) + rk(32) + cmx(32) + epk(32) + enc(580) + out(80) = 820 bytes
/// enc_ciphertext immediately follows epk within each action.
fn extract_enc_ciphertext(
    raw_tx: &[u8],
    cmx: &[u8; 32],
    epk: &[u8; 32],
) -> Result<Option<[u8; ENC_CIPHERTEXT_SIZE]>, Error> {
    for i in 0..raw_tx.len().saturating_sub(64 + ENC_CIPHERTEXT_SIZE) {
        if &raw_tx[i..i + 32] == cmx && &raw_tx[i + 32..i + 64] == epk {
            let start = i + 64;
            let end = start + ENC_CIPHERTEXT_SIZE;
            if end <= raw_tx.len() {
                let mut enc = [0u8; ENC_CIPHERTEXT_SIZE];
                enc.copy_from_slice(&raw_tx[start..end]);
                return Ok(Some(enc));
            }
        }
    }
    Ok(None)
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

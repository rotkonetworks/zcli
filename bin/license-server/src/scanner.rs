//! Compact-block sync + memo extraction for the license wallet.
//!
//! The license server is a single-FVK watch-only wallet. It pulls compact
//! blocks from zidecar, decrypts each Orchard action with the license FVK,
//! and for every received note fetches the full transaction to extract the
//! 512-byte memo. Memos starting with "zid" credit the corresponding
//! Bandersnatch ring pubkey for license issuance.
//!
//! No spending, no nullifier tracking, no commitment proof verification
//! (MVP — trust zidecar). Just: sync → decrypt → memo → credit.

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note_encryption::OrchardDomain;
use std::io::Cursor;
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, EphemeralKeyBytes, ShieldedOutput,
    COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};
use zecli::client::ZidecarClient;

/// Orchard activation height on Zcash mainnet (NU5).
const ORCHARD_ACTIVATION_MAINNET: u32 = 1_687_104;

/// Sync batch size (compact blocks per gRPC stream).
const BATCH_SIZE: u32 = 1_000;

/// A received note that the license server cares about.
pub struct ReceivedMemo {
    pub txid: Vec<u8>,
    pub block_height: u32,
    /// unix seconds of the block this memo landed in — authoritative source
    /// for license expiry so db wipes + rescans don't refresh the clock.
    pub block_time: u64,
    pub value_zat: u64,
    pub memo: String,
}

/// Parse an Orchard FullViewingKey from hex (96 bytes raw).
pub fn parse_fvk(hex_str: &str) -> anyhow::Result<FullViewingKey> {
    let stripped = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let bytes = hex::decode(stripped)
        .map_err(|e| anyhow::anyhow!("invalid FVK hex: {e}"))?;
    if bytes.len() != 96 {
        anyhow::bail!("FVK must be 96 bytes (got {})", bytes.len());
    }
    FullViewingKey::read(&mut Cursor::new(bytes))
        .map_err(|e| anyhow::anyhow!("invalid Orchard FVK: {e}"))
}

struct CompactOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    ct: [u8; 52],
}

impl ShieldedOutput<OrchardDomain, COMPACT_NOTE_SIZE> for CompactOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes { EphemeralKeyBytes(self.epk) }
    fn cmstar_bytes(&self) -> [u8; 32] { self.cmx }
    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] { &self.ct }
}

struct FullOutput {
    epk: [u8; 32],
    cmx: [u8; 32],
    enc: [u8; ENC_CIPHERTEXT_SIZE],
}

impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes { EphemeralKeyBytes(self.epk) }
    fn cmstar_bytes(&self) -> [u8; 32] { self.cmx }
    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] { &self.enc }
}

/// Sync from `last_height + 1` to the current tip and return all matched memos.
/// Returns (new_height, memos_found).
pub async fn scan(
    client: &ZidecarClient,
    fvk: &FullViewingKey,
    last_height: u32,
) -> anyhow::Result<(u32, Vec<ReceivedMemo>)> {
    let (tip, _) = client.get_tip().await
        .map_err(|e| anyhow::anyhow!("get_tip: {e}"))?;

    let start = last_height.saturating_add(1).max(ORCHARD_ACTIVATION_MAINNET);
    if start > tip {
        return Ok((tip, vec![]));
    }

    let ivk_ext: PreparedIncomingViewingKey =
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));

    let mut found = Vec::new();
    let mut current = start;

    while current <= tip {
        let end = (current + BATCH_SIZE - 1).min(tip);
        let blocks = client.get_compact_blocks(current, end).await
            .map_err(|e| anyhow::anyhow!("get_compact_blocks {current}..{end}: {e}"))?;

        for block in &blocks {
            for action in &block.actions {
                if action.ciphertext.len() < 52 { continue; }

                let mut ct = [0u8; 52];
                ct.copy_from_slice(&action.ciphertext[..52]);

                let nf = match orchard::note::Nullifier::from_bytes(&action.nullifier).into_option() {
                    Some(n) => n, None => continue,
                };
                let cmx_obj = match orchard::note::ExtractedNoteCommitment::from_bytes(&action.cmx).into_option() {
                    Some(c) => c, None => continue,
                };
                let compact = orchard::note_encryption::CompactAction::from_parts(
                    nf, cmx_obj, EphemeralKeyBytes(action.ephemeral_key), ct,
                );
                let domain = OrchardDomain::for_compact_action(&compact);

                let compact_output = CompactOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    ct,
                };

                // try compact decrypt first (fast, doesn't need full ciphertext)
                let Some((note, _addr)) =
                    try_compact_note_decryption(&domain, &ivk_ext, &compact_output)
                else { continue };

                // verify cmx (defense against malicious zidecar)
                let recomputed = orchard::note::ExtractedNoteCommitment::from(note.commitment());
                if recomputed.to_bytes() != action.cmx {
                    tracing::warn!("cmx mismatch — skipping potentially fake note");
                    continue;
                }

                // fetch full tx + extract this action's full ciphertext
                let raw_tx = client.get_transaction(&action.txid).await
                    .map_err(|e| anyhow::anyhow!("get_transaction: {e}"))?;
                let Some(enc) = zync_core::sync::extract_enc_ciphertext(
                    &raw_tx, &action.cmx, &action.ephemeral_key,
                ) else {
                    tracing::debug!("no matching action in raw tx");
                    continue;
                };

                // decrypt full ciphertext to get memo
                let full_output = FullOutput {
                    epk: action.ephemeral_key,
                    cmx: action.cmx,
                    enc,
                };
                let Some((_note2, _addr2, memo_bytes)) =
                    try_note_decryption(&domain, &ivk_ext, &full_output)
                else { continue };

                let memo = strip_null_padding(&memo_bytes);

                // fetch this block's on-chain timestamp — authoritative source
                // for license expiry. one extra RPC per credited memo, which
                // is rare in practice.
                let block_time = client.get_block_time(block.height).await
                    .map_err(|e| anyhow::anyhow!("get_block_time {}: {e}", block.height))?;

                found.push(ReceivedMemo {
                    txid: action.txid.clone(),
                    block_height: block.height,
                    block_time,
                    value_zat: note.value().inner(),
                    memo,
                });
            }
        }

        current = end + 1;
    }

    Ok((tip, found))
}

fn strip_null_padding(bytes: &[u8]) -> String {
    let end = bytes.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

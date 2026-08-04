//! compact block builder from full zcash blocks

use crate::error::{Result, ZidecarError};
use crate::zebrad::{BlockHeader, ZebradClient};
use tracing::debug;

/// Per-tx index inside the containing block. lightwalletd's CompactTx.index
/// is the canonical "position in block including coinbase + transparent-only
/// txs" — wallet SDKs use `index == 0` to identify coinbase. We thread this
/// through the per-pool item types so `to_lwd_block` can emit it correctly.
pub type BlockTxIndex = u32;

/// compact orchard action for trial decryption
#[derive(Debug, Clone)]
pub struct CompactAction {
    pub cmx: Vec<u8>,                 // 32 bytes
    pub ephemeral_key: Vec<u8>,       // 32 bytes
    pub ciphertext: Vec<u8>,          // 52 bytes (compact)
    pub nullifier: Vec<u8>,           // 32 bytes
    pub txid: Vec<u8>,                // 32 bytes - for memo retrieval
    pub block_tx_index: BlockTxIndex, // position of the containing tx in its block
}

/// compact sapling spend (nullifier only; rest is irrelevant for scanning)
#[derive(Debug, Clone)]
pub struct CompactSaplingSpendItem {
    pub txid: Vec<u8>,      // 32 bytes
    pub nullifier: Vec<u8>, // 32 bytes
    pub block_tx_index: BlockTxIndex,
}

/// compact sapling output for trial decryption
#[derive(Debug, Clone)]
pub struct CompactSaplingOutputItem {
    pub txid: Vec<u8>,          // 32 bytes
    pub cmu: Vec<u8>,           // 32 bytes
    pub ephemeral_key: Vec<u8>, // 32 bytes
    pub ciphertext: Vec<u8>,    // 52 bytes (ZIP-307 compact ciphertext prefix)
    pub block_tx_index: BlockTxIndex,
}

/// compact block with only scanning data
#[derive(Debug, Clone)]
pub struct CompactBlock {
    pub height: u32,
    pub hash: Vec<u8>,
    /// canonical 80+equihash-solution byte block header; empty for mempool synthetic blocks.
    pub header_bytes: Vec<u8>,
    pub actions: Vec<CompactAction>,
    pub sapling_spends: Vec<CompactSaplingSpendItem>,
    pub sapling_outputs: Vec<CompactSaplingOutputItem>,
    /// Ironwood actions (v6 transactions, NU6.3+). Same compact shape as
    /// Orchard — the pool reuses Orchard note encryption and addresses, so
    /// wallets trial-decrypt these with their existing Orchard keys.
    pub ironwood_actions: Vec<CompactAction>,
}

impl CompactBlock {
    /// build compact block from zebrad
    pub async fn from_zebrad(zebrad: &ZebradClient, height: u32) -> Result<Self> {
        let hash_str = zebrad.get_block_hash(height).await?;
        let block = zebrad.get_block(&hash_str, 1).await?;

        // pull raw block to extract the canonical header bytes; lwd clients hash
        // these to validate chain continuity.
        let header_bytes = match zebrad.get_block_raw(&hash_str).await {
            Ok(hex_str) => extract_header_bytes(&hex_str).unwrap_or_default(),
            Err(e) => {
                debug!("failed to fetch raw block at {}: {}", height, e);
                Vec::new()
            }
        };

        let mut actions = Vec::new();
        let mut sapling_spends = Vec::new();
        let mut sapling_outputs = Vec::new();
        let mut ironwood_actions = Vec::new();

        for (block_tx_index, txid) in block.tx.iter().enumerate() {
            match zebrad.get_raw_transaction(txid).await {
                Ok(tx) => {
                    let txid_bytes = hex_to_bytes(txid)?;
                    extract_tx_shielded(
                        &tx,
                        &txid_bytes,
                        block_tx_index as BlockTxIndex,
                        &mut actions,
                        &mut sapling_spends,
                        &mut sapling_outputs,
                        &mut ironwood_actions,
                    );
                }
                Err(e) => {
                    debug!("failed to fetch tx {}: {}", txid, e);
                }
            }
        }

        let hash = hex_to_bytes(&hash_str)?;

        Ok(Self {
            height,
            hash,
            header_bytes,
            actions,
            sapling_spends,
            sapling_outputs,
            ironwood_actions,
        })
    }

    /// build compact blocks for range
    pub async fn fetch_range(
        zebrad: &ZebradClient,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<Self>> {
        let mut blocks = Vec::new();

        for height in start_height..=end_height {
            let block = Self::from_zebrad(zebrad, height).await?;
            blocks.push(block);
        }

        Ok(blocks)
    }
}

impl CompactBlock {
    /// build compact blocks from mempool transactions
    /// returns one CompactBlock per mempool tx that has shielded data (height=0)
    pub async fn from_mempool(zebrad: &ZebradClient) -> Result<Vec<Self>> {
        let txids = zebrad.get_raw_mempool().await?;
        let mut blocks = Vec::new();

        for txid in &txids {
            match zebrad.get_raw_transaction(txid).await {
                Ok(tx) => {
                    let txid_bytes = hex_to_bytes(txid)?;
                    let mut actions = Vec::new();
                    let mut sapling_spends = Vec::new();
                    let mut sapling_outputs = Vec::new();
                    let mut ironwood_actions = Vec::new();
                    // mempool synthetic blocks: each tx is the only tx in its own
                    // CompactBlock, so block_tx_index is always 0.
                    extract_tx_shielded(
                        &tx,
                        &txid_bytes,
                        0,
                        &mut actions,
                        &mut sapling_spends,
                        &mut sapling_outputs,
                        &mut ironwood_actions,
                    );

                    if actions.is_empty()
                        && sapling_spends.is_empty()
                        && sapling_outputs.is_empty()
                        && ironwood_actions.is_empty()
                    {
                        continue;
                    }

                    blocks.push(Self {
                        height: 0, // unconfirmed
                        hash: txid_bytes,
                        header_bytes: Vec::new(),
                        actions,
                        sapling_spends,
                        sapling_outputs,
                        ironwood_actions,
                    });
                }
                Err(e) => {
                    debug!("mempool tx {} unavailable: {}", &txid[..16], e);
                }
            }
        }

        Ok(blocks)
    }
}

/// Extract orchard actions + sapling spends + sapling outputs from a single
/// RawTransaction into the caller-supplied vectors. All byte fields stored
/// here are in Zebra/display order; the conversion to lightwalletd wire
/// (protocol-order / little-endian) happens at `to_lwd_block` in lwd_service.
fn extract_tx_shielded(
    tx: &crate::zebrad::RawTransaction,
    txid_bytes: &[u8],
    block_tx_index: BlockTxIndex,
    actions: &mut Vec<CompactAction>,
    sapling_spends: &mut Vec<CompactSaplingSpendItem>,
    sapling_outputs: &mut Vec<CompactSaplingOutputItem>,
    ironwood_actions: &mut Vec<CompactAction>,
) {
    if let Some(orchard) = &tx.orchard {
        extract_pool_actions(orchard, txid_bytes, block_tx_index, actions);
    }

    if let Some(ironwood) = &tx.ironwood {
        extract_pool_actions(ironwood, txid_bytes, block_tx_index, ironwood_actions);
    }

    if let Some(spends) = &tx.sapling_spends {
        for s in spends {
            let Ok(nf) = hex_to_bytes(&s.nullifier) else {
                continue;
            };
            sapling_spends.push(CompactSaplingSpendItem {
                txid: txid_bytes.to_vec(),
                nullifier: nf,
                block_tx_index,
            });
        }
    }

    if let Some(outs) = &tx.sapling_outputs {
        for o in outs {
            let Ok(cmu) = hex_to_bytes(&o.cmu) else {
                continue;
            };
            let Ok(ek) = hex_to_bytes(&o.ephemeral_key) else {
                continue;
            };
            let Ok(ct_full) = hex_to_bytes(&o.enc_ciphertext) else {
                continue;
            };
            sapling_outputs.push(CompactSaplingOutputItem {
                txid: txid_bytes.to_vec(),
                cmu,
                ephemeral_key: ek,
                ciphertext: ct_full.into_iter().take(52).collect(),
                block_tx_index,
            });
        }
    }
}

/// Extract compact actions from an Orchard-shaped bundle (Orchard or Ironwood —
/// the Ironwood pool reuses the same action encoding).
fn extract_pool_actions(
    bundle: &crate::zebrad::OrchardData,
    txid_bytes: &[u8],
    block_tx_index: BlockTxIndex,
    out: &mut Vec<CompactAction>,
) {
    for action in &bundle.actions {
        let Ok(cmx) = hex_to_bytes(&action.cmx) else {
            continue;
        };
        let Ok(ek) = hex_to_bytes(&action.ephemeral_key) else {
            continue;
        };
        let Ok(ct_full) = hex_to_bytes(&action.enc_ciphertext) else {
            continue;
        };
        let Ok(nf) = hex_to_bytes(&action.nullifier) else {
            continue;
        };
        out.push(CompactAction {
            cmx,
            ephemeral_key: ek,
            ciphertext: ct_full.into_iter().take(52).collect(),
            nullifier: nf,
            txid: txid_bytes.to_vec(),
            block_tx_index,
        });
    }
}

/// Parse the canonical Zcash block header bytes out of the full block hex.
///
/// Layout: 140 fixed bytes (version + prevHash + merkleRoot + commitments +
/// time + bits + nonce) followed by a CompactSize-prefixed Equihash solution.
/// Returns the entire `version..end-of-solution` slice — i.e. exactly what
/// the SHA256d block hash is computed over.
fn extract_header_bytes(block_hex: &str) -> Result<Vec<u8>> {
    let bytes = hex_to_bytes(block_hex)?;
    let base = 140;
    if bytes.len() < base + 1 {
        return Err(ZidecarError::Serialization("block hex too short".into()));
    }
    let tag = bytes[base];
    let (solution_len, prefix_size) = match tag {
        0xff => {
            return Err(ZidecarError::Serialization(
                "block header solution length too large".into(),
            ))
        }
        0xfe => {
            if bytes.len() < base + 5 {
                return Err(ZidecarError::Serialization("block hex too short".into()));
            }
            let len = u32::from_le_bytes(bytes[base + 1..base + 5].try_into().unwrap()) as usize;
            (len, 5)
        }
        0xfd => {
            if bytes.len() < base + 3 {
                return Err(ZidecarError::Serialization("block hex too short".into()));
            }
            let len = u16::from_le_bytes(bytes[base + 1..base + 3].try_into().unwrap()) as usize;
            (len, 3)
        }
        n => (n as usize, 1),
    };
    let end = base + prefix_size + solution_len;
    if end > bytes.len() {
        return Err(ZidecarError::Serialization(
            "block hex shorter than declared header length".into(),
        ));
    }
    Ok(bytes[..end].to_vec())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|e| ZidecarError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zebrad::{OrchardAction, OrchardData, RawTransaction, SaplingOutput, SaplingSpend};

    #[test]
    fn test_hex_to_bytes() {
        let hex = "deadbeef";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    /// Solution length < 0xfd encodes as a single varint byte; total header is
    /// 140 fixed + 1 prefix + solution_len.
    #[test]
    fn test_extract_header_bytes_short_solution() {
        let mut bytes = vec![0u8; 140];
        bytes.push(0x05); // solution length = 5
        bytes.extend(vec![0xaa; 5]);
        bytes.extend(vec![0xff; 100]); // trailing tx data — must not appear in header

        let header = extract_header_bytes(&hex::encode(&bytes)).unwrap();
        assert_eq!(header.len(), 140 + 1 + 5);
        assert_eq!(&header[140..], &[0x05, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]);
    }

    /// Mainnet shape: equihash 200/9 → solution = 1344 bytes, prefix `0xfd 0x40 0x05`,
    /// total header = 1487 bytes.
    #[test]
    fn test_extract_header_bytes_fd_prefix_mainnet_size() {
        let mut bytes = vec![0u8; 140];
        bytes.extend(&[0xfd, 0x40, 0x05]); // 0xfd marker + le u16(1344)
        bytes.extend(vec![0xbb; 1344]);
        bytes.extend(vec![0xff; 100]);

        let header = extract_header_bytes(&hex::encode(&bytes)).unwrap();
        assert_eq!(header.len(), 1487);
    }

    /// 0xfe marker uses next 4 bytes as a little-endian u32 length.
    #[test]
    fn test_extract_header_bytes_fe_prefix() {
        let mut bytes = vec![0u8; 140];
        bytes.extend(&[0xfe, 0x10, 0x00, 0x00, 0x00]); // length = 16
        bytes.extend(vec![0xcc; 16]);

        let header = extract_header_bytes(&hex::encode(&bytes)).unwrap();
        assert_eq!(header.len(), 140 + 5 + 16);
    }

    /// Truncated input — declared length exceeds remaining bytes → error.
    #[test]
    fn test_extract_header_bytes_truncated_errors() {
        let mut bytes = vec![0u8; 140];
        bytes.push(0x64); // says 100-byte solution
        bytes.extend(vec![0xcc; 50]); // only 50 provided

        assert!(extract_header_bytes(&hex::encode(&bytes)).is_err());
    }

    /// Reaches into all four shielded pools in one tx and verifies every
    /// item lands in the right output vector with correct contents.
    #[test]
    fn test_extract_tx_shielded_mixed_pools() {
        let nf_orch = "01".repeat(32);
        let cmx = "02".repeat(32);
        let ek_orch = "03".repeat(32);
        let ct_orch = "04".repeat(580); // > 52 bytes; should be truncated
        let nf_sap = "05".repeat(32);
        let cmu = "06".repeat(32);
        let ek_sap = "07".repeat(32);
        let ct_sap = "08".repeat(580);
        let nf_iron = "09".repeat(32);
        let cmx_iron = "0a".repeat(32);
        let ek_iron = "0b".repeat(32);
        let ct_iron = "0c".repeat(580);
        let filler = "00".repeat(32);

        let tx = RawTransaction {
            txid: "abc".to_string(),
            version: 6,
            hex: String::new(),
            height: Some(100),
            sapling_spends: Some(vec![SaplingSpend {
                cv: filler.clone(),
                anchor: filler.clone(),
                nullifier: nf_sap.clone(),
                rk: filler.clone(),
                zkproof: filler.clone(),
                spend_auth_sig: filler.clone(),
            }]),
            sapling_outputs: Some(vec![SaplingOutput {
                cv: filler.clone(),
                cmu: cmu.clone(),
                ephemeral_key: ek_sap.clone(),
                enc_ciphertext: ct_sap.clone(),
                out_ciphertext: filler.clone(),
                zkproof: filler.clone(),
            }]),
            orchard: Some(OrchardData {
                actions: vec![OrchardAction {
                    cv: filler.clone(),
                    nullifier: nf_orch.clone(),
                    rk: filler.clone(),
                    cmx: cmx.clone(),
                    ephemeral_key: ek_orch.clone(),
                    enc_ciphertext: ct_orch.clone(),
                    out_ciphertext: filler.clone(),
                }],
            }),
            ironwood: Some(OrchardData {
                actions: vec![OrchardAction {
                    cv: filler.clone(),
                    nullifier: nf_iron.clone(),
                    rk: filler.clone(),
                    cmx: cmx_iron.clone(),
                    ephemeral_key: ek_iron.clone(),
                    enc_ciphertext: ct_iron.clone(),
                    out_ciphertext: filler.clone(),
                }],
            }),
        };

        let txid_bytes = vec![0xde; 32];
        let mut actions = Vec::new();
        let mut spends = Vec::new();
        let mut outputs = Vec::new();
        let mut iron = Vec::new();
        extract_tx_shielded(
            &tx,
            &txid_bytes,
            3,
            &mut actions,
            &mut spends,
            &mut outputs,
            &mut iron,
        );

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].nullifier, hex::decode(&nf_orch).unwrap());
        assert_eq!(actions[0].cmx, hex::decode(&cmx).unwrap());
        assert_eq!(actions[0].ephemeral_key, hex::decode(&ek_orch).unwrap());
        assert_eq!(actions[0].ciphertext.len(), 52);
        assert_eq!(actions[0].txid, txid_bytes);
        assert_eq!(actions[0].block_tx_index, 3);

        assert_eq!(spends.len(), 1);
        assert_eq!(spends[0].nullifier, hex::decode(&nf_sap).unwrap());
        assert_eq!(spends[0].txid, txid_bytes);
        assert_eq!(spends[0].block_tx_index, 3);

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].cmu, hex::decode(&cmu).unwrap());
        assert_eq!(outputs[0].ephemeral_key, hex::decode(&ek_sap).unwrap());
        assert_eq!(outputs[0].ciphertext.len(), 52);
        assert_eq!(outputs[0].txid, txid_bytes);
        assert_eq!(outputs[0].block_tx_index, 3);

        // ironwood actions land in their own vector, never in `actions`
        assert_eq!(iron.len(), 1);
        assert_eq!(iron[0].nullifier, hex::decode(&nf_iron).unwrap());
        assert_eq!(iron[0].cmx, hex::decode(&cmx_iron).unwrap());
        assert_eq!(iron[0].ephemeral_key, hex::decode(&ek_iron).unwrap());
        assert_eq!(iron[0].ciphertext.len(), 52);
        assert_eq!(iron[0].txid, txid_bytes);
        assert_eq!(iron[0].block_tx_index, 3);
    }

    /// A tx with no shielded data of any kind leaves all output vectors empty.
    #[test]
    fn test_extract_tx_shielded_transparent_only_is_noop() {
        let tx = RawTransaction {
            txid: "abc".to_string(),
            version: 5,
            hex: String::new(),
            height: None,
            sapling_spends: None,
            sapling_outputs: None,
            orchard: None,
            ironwood: None,
        };
        let mut a = Vec::new();
        let mut s = Vec::new();
        let mut o = Vec::new();
        let mut i = Vec::new();
        extract_tx_shielded(&tx, &[0xde; 32], 0, &mut a, &mut s, &mut o, &mut i);
        assert!(a.is_empty());
        assert!(s.is_empty());
        assert!(o.is_empty());
        assert!(i.is_empty());
    }
}

//! compact block builder from full zcash blocks

use crate::error::{Result, ZidecarError};
use crate::zebrad::{BlockHeader, ZebradClient};
use tracing::debug;

/// compact orchard action for trial decryption
#[derive(Debug, Clone)]
pub struct CompactAction {
    pub cmx: Vec<u8>,           // 32 bytes
    pub ephemeral_key: Vec<u8>, // 32 bytes
    pub ciphertext: Vec<u8>,    // 52 bytes (compact)
    pub nullifier: Vec<u8>,     // 32 bytes
    pub txid: Vec<u8>,          // 32 bytes - for memo retrieval
}

/// compact sapling spend (nullifier only; rest is irrelevant for scanning)
#[derive(Debug, Clone)]
pub struct CompactSaplingSpendItem {
    pub txid: Vec<u8>,      // 32 bytes
    pub nullifier: Vec<u8>, // 32 bytes
}

/// compact sapling output for trial decryption
#[derive(Debug, Clone)]
pub struct CompactSaplingOutputItem {
    pub txid: Vec<u8>,          // 32 bytes
    pub cmu: Vec<u8>,           // 32 bytes
    pub ephemeral_key: Vec<u8>, // 32 bytes
    pub ciphertext: Vec<u8>,    // 52 bytes (ZIP-307 compact ciphertext prefix)
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

        for txid in &block.tx {
            match zebrad.get_raw_transaction(txid).await {
                Ok(tx) => {
                    let txid_bytes = hex_to_bytes(txid)?;
                    extract_tx_shielded(
                        &tx,
                        &txid_bytes,
                        &mut actions,
                        &mut sapling_spends,
                        &mut sapling_outputs,
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
                    extract_tx_shielded(
                        &tx,
                        &txid_bytes,
                        &mut actions,
                        &mut sapling_spends,
                        &mut sapling_outputs,
                    );

                    if actions.is_empty()
                        && sapling_spends.is_empty()
                        && sapling_outputs.is_empty()
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
/// RawTransaction into the caller-supplied vectors.
fn extract_tx_shielded(
    tx: &crate::zebrad::RawTransaction,
    txid_bytes: &[u8],
    actions: &mut Vec<CompactAction>,
    sapling_spends: &mut Vec<CompactSaplingSpendItem>,
    sapling_outputs: &mut Vec<CompactSaplingOutputItem>,
) {
    if let Some(orchard) = &tx.orchard {
        for action in &orchard.actions {
            let Ok(cmx) = hex_to_bytes(&action.cmx) else { continue };
            let Ok(ek) = hex_to_bytes(&action.ephemeral_key) else { continue };
            let Ok(ct_full) = hex_to_bytes(&action.enc_ciphertext) else { continue };
            let Ok(nf) = hex_to_bytes(&action.nullifier) else { continue };
            actions.push(CompactAction {
                cmx,
                ephemeral_key: ek,
                ciphertext: ct_full.into_iter().take(52).collect(),
                nullifier: nf,
                txid: txid_bytes.to_vec(),
            });
        }
    }

    if let Some(spends) = &tx.sapling_spends {
        for s in spends {
            let Ok(nf) = hex_to_bytes(&s.nullifier) else { continue };
            sapling_spends.push(CompactSaplingSpendItem {
                txid: txid_bytes.to_vec(),
                nullifier: nf,
            });
        }
    }

    if let Some(outs) = &tx.sapling_outputs {
        for o in outs {
            let Ok(cmu) = hex_to_bytes(&o.cmu) else { continue };
            let Ok(ek) = hex_to_bytes(&o.ephemeral_key) else { continue };
            let Ok(ct_full) = hex_to_bytes(&o.enc_ciphertext) else { continue };
            sapling_outputs.push(CompactSaplingOutputItem {
                txid: txid_bytes.to_vec(),
                cmu,
                ephemeral_key: ek,
                ciphertext: ct_full.into_iter().take(52).collect(),
            });
        }
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

    #[test]
    fn test_hex_to_bytes() {
        let hex = "deadbeef";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}

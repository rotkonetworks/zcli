//! compact block builder from full zcash blocks

use crate::error::{Result, ZidecarError};
use crate::zebrad::{BlockHeader, ZebradClient};
use tracing::debug;

/// compact action for trial decryption
#[derive(Debug, Clone)]
pub struct CompactAction {
    pub cmx: Vec<u8>,           // 32 bytes
    pub ephemeral_key: Vec<u8>, // 32 bytes
    pub ciphertext: Vec<u8>,    // 52 bytes (compact)
    pub nullifier: Vec<u8>,     // 32 bytes
    pub txid: Vec<u8>,          // 32 bytes - for memo retrieval
}

/// compact block with only scanning data
#[derive(Debug, Clone)]
pub struct CompactBlock {
    pub height: u32,
    pub hash: Vec<u8>,
    pub actions: Vec<CompactAction>,
}

impl CompactBlock {
    /// build compact block from zebrad
    pub async fn from_zebrad(zebrad: &ZebradClient, height: u32) -> Result<Self> {
        let hash_str = zebrad.get_block_hash(height).await?;
        let block = zebrad.get_block(&hash_str, 1).await?;

        let mut actions = Vec::new();

        // fetch transactions and extract orchard actions
        for txid in &block.tx {
            match zebrad.get_raw_transaction(txid).await {
                Ok(tx) => {
                    if let Some(orchard) = tx.orchard {
                        let txid_bytes = hex_to_bytes(txid)?;
                        for action in orchard.actions {
                            actions.push(CompactAction {
                                cmx: hex_to_bytes(&action.cmx)?,
                                ephemeral_key: hex_to_bytes(&action.ephemeral_key)?,
                                // take first 52 bytes of encrypted ciphertext
                                ciphertext: hex_to_bytes(&action.enc_ciphertext)?
                                    .into_iter()
                                    .take(52)
                                    .collect(),
                                nullifier: hex_to_bytes(&action.nullifier)?,
                                txid: txid_bytes.clone(),
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to fetch tx {}: {}", txid, e);
                    // skip tx if unavailable
                }
            }
        }

        let hash = hex_to_bytes(&hash_str)?;

        Ok(Self {
            height,
            hash,
            actions,
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
    /// returns one CompactBlock per mempool tx that has orchard actions (height=0)
    pub async fn from_mempool(zebrad: &ZebradClient) -> Result<Vec<Self>> {
        let txids = zebrad.get_raw_mempool().await?;
        let mut blocks = Vec::new();

        for txid in &txids {
            match zebrad.get_raw_transaction(txid).await {
                Ok(tx) => {
                    if let Some(orchard) = tx.orchard {
                        if orchard.actions.is_empty() {
                            continue;
                        }
                        let txid_bytes = hex_to_bytes(txid)?;
                        let actions: Vec<CompactAction> = orchard
                            .actions
                            .into_iter()
                            .filter_map(|action| {
                                Some(CompactAction {
                                    cmx: hex_to_bytes(&action.cmx).ok()?,
                                    ephemeral_key: hex_to_bytes(&action.ephemeral_key).ok()?,
                                    ciphertext: hex_to_bytes(&action.enc_ciphertext)
                                        .ok()?
                                        .into_iter()
                                        .take(52)
                                        .collect(),
                                    nullifier: hex_to_bytes(&action.nullifier).ok()?,
                                    txid: txid_bytes.clone(),
                                })
                            })
                            .collect();

                        if !actions.is_empty() {
                            blocks.push(Self {
                                height: 0, // unconfirmed
                                hash: txid_bytes,
                                actions,
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("mempool tx {} unavailable: {}", &txid[..16], e);
                }
            }
        }

        Ok(blocks)
    }
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

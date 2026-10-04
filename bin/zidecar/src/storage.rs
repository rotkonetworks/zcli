//! zidecar's on-disk state: the FlyClient history-tree leaves and the auth
//! data roots that open each block's commitment (see history.rs), in sled.
//!
//! Deployments that predate this layout also have a `nomt/` directory and
//! other sled keys from the retired Ligerito/NOMT proof system; nothing reads
//! them any more and they can be deleted.

use crate::error::{Result, ZidecarError};
use tracing::info;

pub struct Storage {
    sled: sled::Db,
}

impl Storage {
    pub fn open(path: &str) -> Result<Self> {
        info!("opening storage at {}", path);
        let sled = sled::open(format!("{}/sled", path))
            .map_err(|e| ZidecarError::Storage(format!("sled: {}", e)))?;
        Ok(Self { sled })
    }

    /// Force pending writes to disk (graceful shutdown).
    pub fn flush(&self) -> Result<()> {
        self.sled
            .flush()
            .map_err(|e| ZidecarError::Storage(format!("flush sled: {}", e)))?;
        Ok(())
    }

    // FlyClient history tree. One leaf per block ('H' + height: serialized
    // ZIP-221 node) and the block's ZIP-244 auth data root ('D' + height),
    // which opens its hashBlockCommitments for clients.

    fn history_key(prefix: u8, height: u32) -> [u8; 5] {
        let mut key = [prefix, 0, 0, 0, 0];
        // big-endian so sled iterates leaves in height order
        key[1..].copy_from_slice(&height.to_be_bytes());
        key
    }

    pub fn store_history_leaf(&self, height: u32, node: &[u8], adr: &[u8; 32]) -> Result<()> {
        let map = |e: sled::Error| ZidecarError::Storage(format!("sled: {}", e));
        self.sled.insert(Self::history_key(b'H', height), node).map_err(map)?;
        self.sled.insert(Self::history_key(b'D', height), &adr[..]).map_err(map)?;
        Ok(())
    }

    pub fn get_history_leaf(&self, height: u32) -> Result<Option<Vec<u8>>> {
        self.sled
            .get(Self::history_key(b'H', height))
            .map(|v| v.map(|b| b.to_vec()))
            .map_err(|e| ZidecarError::Storage(format!("sled: {}", e)))
    }

    pub fn get_auth_data_root(&self, height: u32) -> Result<Option<[u8; 32]>> {
        match self.sled.get(Self::history_key(b'D', height)) {
            Ok(Some(b)) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Ok(Some(out))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(ZidecarError::Storage(format!("sled: {}", e))),
        }
    }

    /// Forget history leaves at and above `height` (a reorg).
    pub fn delete_history_from(&self, height: u32) -> Result<()> {
        let map = |e: sled::Error| ZidecarError::Storage(format!("sled: {}", e));
        for prefix in [b'H', b'D'] {
            let keys: Vec<_> = self
                .sled
                .range(Self::history_key(prefix, height)..=Self::history_key(prefix, u32::MAX))
                .keys()
                .collect::<std::result::Result<_, _>>()
                .map_err(map)?;
            for k in keys {
                self.sled.remove(k).map_err(map)?;
            }
        }
        Ok(())
    }
}

// storage error wrapper
impl From<String> for ZidecarError {
    fn from(s: String) -> Self {
        ZidecarError::Storage(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_leaves_round_trip_and_roll_back() {
        let dir = std::env::temp_dir().join(format!("zidecar-storage-{}", std::process::id()));
        let storage = Storage::open(dir.to_str().unwrap()).unwrap();
        for h in 100..110u32 {
            storage.store_history_leaf(h, &[h as u8; 7], &[h as u8; 32]).unwrap();
        }
        assert_eq!(storage.get_history_leaf(105).unwrap(), Some(vec![105u8; 7]));
        assert_eq!(storage.get_auth_data_root(109).unwrap(), Some([109u8; 32]));
        storage.delete_history_from(106).unwrap();
        assert_eq!(storage.get_history_leaf(105).unwrap(), Some(vec![105u8; 7]));
        assert_eq!(storage.get_history_leaf(106).unwrap(), None);
        assert_eq!(storage.get_auth_data_root(108).unwrap(), None);
        drop(storage);
        let _ = std::fs::remove_dir_all(dir);
    }
}

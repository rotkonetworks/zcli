// local wallet state backed by sled

use std::sync::OnceLock;

use orchard::note::{RandomSeed, Rho};
use orchard::value::NoteValue;
use sled::Db;

use crate::error::Error;

const SYNC_HEIGHT_KEY: &[u8] = b"sync_height";
const BIRTH_HEIGHT_KEY: &[u8] = b"birth_height";
const ORCHARD_POSITION_KEY: &[u8] = b"orchard_position";
const NEXT_REQUEST_ID_KEY: &[u8] = b"next_request_id";
const FORWARD_ADDRESS_KEY: &[u8] = b"forward_address";
const NOTES_TREE: &str = "notes";
const NULLIFIERS_TREE: &str = "nullifiers";
const SENT_TXS_TREE: &str = "sent_txs";
const PAYMENT_REQUESTS_TREE: &str = "payment_requests";
const WITHDRAWAL_REQUESTS_TREE: &str = "withdrawal_requests";
const NEXT_WITHDRAWAL_ID_KEY: &[u8] = b"next_withdrawal_id";
const ACTIONS_COMMITMENT_KEY: &[u8] = b"actions_commitment";
const FVK_KEY: &[u8] = b"full_viewing_key";

/// global watch mode flag — set once at startup, affects default_path()
static WATCH_MODE: OnceLock<bool> = OnceLock::new();

/// call once at startup to enable watch-only wallet path
pub fn set_watch_mode(enabled: bool) {
    WATCH_MODE.set(enabled).ok();
}

fn is_watch_mode() -> bool {
    WATCH_MODE.get().copied().unwrap_or(false)
}

/// a received note stored in the wallet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletNote {
    pub value: u64,
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub block_height: u32,
    pub is_change: bool,
    // spend data - required for orchard spend circuit
    // orchard address is 43 bytes (11-byte diversifier + 32-byte pk_d)
    pub recipient: Vec<u8>,
    pub rho: [u8; 32],
    pub rseed: [u8; 32],
    pub position: u64,
    #[serde(default)]
    pub txid: Vec<u8>,
    #[serde(default)]
    pub memo: Option<String>,
}

impl WalletNote {
    /// reconstruct an orchard::Note from stored bytes
    pub fn reconstruct_note(&self) -> Result<orchard::Note, Error> {
        if self.recipient.len() != 43 {
            return Err(Error::Wallet(format!(
                "recipient bytes wrong length: {} (expected 43)",
                self.recipient.len()
            )));
        }
        let mut addr_bytes = [0u8; 43];
        addr_bytes.copy_from_slice(&self.recipient);
        let recipient = Option::from(orchard::Address::from_raw_address_bytes(&addr_bytes))
            .ok_or_else(|| Error::Wallet("invalid recipient bytes".into()))?;
        let value = NoteValue::from_raw(self.value);
        let rho = Option::from(Rho::from_bytes(&self.rho))
            .ok_or_else(|| Error::Wallet("invalid rho bytes".into()))?;
        let rseed = Option::from(RandomSeed::from_bytes(self.rseed, &rho))
            .ok_or_else(|| Error::Wallet("invalid rseed bytes".into()))?;
        Option::from(orchard::Note::from_parts(recipient, value, rho, rseed))
            .ok_or_else(|| Error::Wallet("failed to reconstruct note".into()))
    }
}

/// a sent transaction stored in the wallet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SentTx {
    pub txid: String,
    pub amount: u64,
    pub fee: u64,
    pub recipient: String,
    pub tx_type: String, // "z→t", "z→z", "shield"
    pub block_height: u32,
    pub memo: Option<String>,
    pub timestamp: u64, // unix seconds when broadcast
}

/// a single deposit event on a payment request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Deposit {
    pub nullifier: Vec<u8>,
    pub amount_zat: u64,
    pub block_height: u32,
    pub forward_txid: Option<String>,
}

/// a merchant payment request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaymentRequest {
    pub id: u64,
    pub diversifier_index: u64,
    pub recipient: Vec<u8>, // 43-byte raw orchard address for matching
    pub address: String,    // u1... unified address for display
    pub amount_zat: u64,    // 0 = any amount
    pub label: Option<String>,
    pub created_at: u64,
    pub status: String, // pending / paid / forwarded / forward_failed
    /// true = deposit address (stays pending, accumulates deposits)
    /// false = invoice (one payment, then done)
    #[serde(default)]
    pub deposit: bool,
    /// all deposits received at this address (deposit mode)
    #[serde(default)]
    pub deposits: Vec<Deposit>,
    // legacy single-match fields (invoice mode)
    pub matched_nullifier: Option<Vec<u8>>,
    pub received_zat: Option<u64>,
    pub forward_txid: Option<String>,
}

/// a withdrawal request (exchange payout)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WithdrawalRequest {
    pub id: u64,
    pub address: String, // t1.../u1...
    pub amount_zat: u64,
    pub label: Option<String>,
    pub created_at: u64,
    pub status: String, // pending / completed / failed / insufficient
    pub txid: Option<String>,
    pub fee_zat: Option<u64>,
    pub error: Option<String>,
}

pub struct Wallet {
    db: Db,
}

impl Wallet {
    pub fn flush(&self) {
        self.db.flush().ok();
    }

    pub fn open(path: &str) -> Result<Self, Error> {
        let db = sled::open(path)
            .map_err(|e| Error::Wallet(format!("cannot open wallet db at {}: {}", path, e)))?;
        // migrate: remove stale keys from pre-0.5.3 when FVK was stored in main wallet
        // only clean up the main wallet (not the watch wallet)
        if !is_watch_mode() && !path.ends_with("/watch") {
            let _ = db.remove(b"wallet_mode");
            let _ = db.remove(b"full_viewing_key");
        }
        Ok(Self { db })
    }

    /// default wallet path based on mode:
    /// - normal: ~/.zcli/wallet
    /// - watch:  ~/.zcli/watch
    pub fn default_path() -> String {
        if is_watch_mode() {
            Self::watch_path()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            format!("{}/.zcli/wallet", home)
        }
    }

    /// watch-only wallet path: ~/.zcli/watch
    pub fn watch_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{}/.zcli/watch", home)
    }

    pub fn sync_height(&self) -> Result<u32, Error> {
        match self
            .db
            .get(SYNC_HEIGHT_KEY)
            .map_err(|e| Error::Wallet(format!("read sync height: {}", e)))?
        {
            Some(bytes) => {
                if bytes.len() == 4 {
                    Ok(u32::from_le_bytes(
                        bytes.as_ref().try_into().expect("len checked"),
                    ))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    }

    pub fn set_sync_height(&self, height: u32) -> Result<(), Error> {
        self.db
            .insert(SYNC_HEIGHT_KEY, &height.to_le_bytes())
            .map_err(|e| Error::Wallet(format!("write sync height: {}", e)))?;
        Ok(())
    }

    /// Get wallet birth height (0 if not set — means scan from activation)
    pub fn birth_height(&self) -> Result<u32, Error> {
        match self
            .db
            .get(BIRTH_HEIGHT_KEY)
            .map_err(|e| Error::Wallet(format!("read birth height: {}", e)))?
        {
            Some(bytes) if bytes.len() == 4 => {
                Ok(u32::from_le_bytes(bytes.as_ref().try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Set wallet birth height (called once, on first use)
    pub fn set_birth_height(&self, height: u32) -> Result<(), Error> {
        // Only set if not already set
        if self.birth_height()? == 0 {
            self.db
                .insert(BIRTH_HEIGHT_KEY, &height.to_le_bytes())
                .map_err(|e| Error::Wallet(format!("write birth height: {}", e)))?;
        }
        Ok(())
    }

    /// store a received note, keyed by nullifier
    pub fn insert_note(&self, note: &WalletNote) -> Result<(), Error> {
        let tree = self
            .db
            .open_tree(NOTES_TREE)
            .map_err(|e| Error::Wallet(format!("open notes tree: {}", e)))?;
        let value = serde_json::to_vec(note)
            .map_err(|e| Error::Wallet(format!("serialize note: {}", e)))?;
        tree.insert(note.nullifier, value)
            .map_err(|e| Error::Wallet(format!("insert note: {}", e)))?;
        Ok(())
    }

    /// get a note by nullifier
    pub fn get_note(&self, nullifier: &[u8; 32]) -> Result<WalletNote, Error> {
        let tree = self
            .db
            .open_tree(NOTES_TREE)
            .map_err(|e| Error::Wallet(format!("open notes tree: {}", e)))?;
        let value = tree
            .get(nullifier.as_ref())
            .map_err(|e| Error::Wallet(format!("get note: {}", e)))?
            .ok_or_else(|| Error::Wallet("note not found".into()))?;
        serde_json::from_slice(&value)
            .map_err(|e| Error::Wallet(format!("deserialize note: {}", e)))
    }

    /// mark a nullifier as spent
    pub fn mark_spent(&self, nullifier: &[u8; 32]) -> Result<(), Error> {
        let tree = self
            .db
            .open_tree(NULLIFIERS_TREE)
            .map_err(|e| Error::Wallet(format!("open nullifiers tree: {}", e)))?;
        tree.insert(nullifier.as_ref(), &[1u8])
            .map_err(|e| Error::Wallet(format!("mark spent: {}", e)))?;
        Ok(())
    }

    pub fn is_spent(&self, nullifier: &[u8; 32]) -> Result<bool, Error> {
        let tree = self
            .db
            .open_tree(NULLIFIERS_TREE)
            .map_err(|e| Error::Wallet(format!("open nullifiers tree: {}", e)))?;
        tree.contains_key(nullifier.as_ref())
            .map_err(|e| Error::Wallet(format!("check spent: {}", e)))
    }

    /// global orchard commitment position counter (increments for every action in every block)
    pub fn orchard_position(&self) -> Result<u64, Error> {
        match self
            .db
            .get(ORCHARD_POSITION_KEY)
            .map_err(|e| Error::Wallet(format!("read orchard position: {}", e)))?
        {
            Some(bytes) => {
                if bytes.len() == 8 {
                    Ok(u64::from_le_bytes(
                        bytes.as_ref().try_into().expect("len checked"),
                    ))
                } else {
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    }

    pub fn set_orchard_position(&self, pos: u64) -> Result<(), Error> {
        self.db
            .insert(ORCHARD_POSITION_KEY, &pos.to_le_bytes())
            .map_err(|e| Error::Wallet(format!("write orchard position: {}", e)))?;
        Ok(())
    }

    /// get all unspent notes and total shielded balance
    pub fn shielded_balance(&self) -> Result<(u64, Vec<WalletNote>), Error> {
        let notes_tree = self
            .db
            .open_tree(NOTES_TREE)
            .map_err(|e| Error::Wallet(format!("open notes tree: {}", e)))?;

        let mut balance = 0u64;
        let mut unspent = Vec::new();

        for entry in notes_tree.iter() {
            let (_, value) = entry.map_err(|e| Error::Wallet(format!("iterate notes: {}", e)))?;
            let note: WalletNote = serde_json::from_slice(&value)
                .map_err(|e| Error::Wallet(format!("deserialize note: {}", e)))?;
            if !self.is_spent(&note.nullifier)? {
                balance += note.value;
                unspent.push(note);
            }
        }

        Ok((balance, unspent))
    }

    /// store a sent transaction
    pub fn insert_sent_tx(&self, tx: &SentTx) -> Result<(), Error> {
        let tree = self
            .db
            .open_tree(SENT_TXS_TREE)
            .map_err(|e| Error::Wallet(format!("open sent_txs tree: {}", e)))?;
        let value = serde_json::to_vec(tx)
            .map_err(|e| Error::Wallet(format!("serialize sent tx: {}", e)))?;
        tree.insert(tx.txid.as_bytes(), value)
            .map_err(|e| Error::Wallet(format!("insert sent tx: {}", e)))?;
        Ok(())
    }

    /// all sent transactions, sorted by timestamp descending
    pub fn all_sent_txs(&self) -> Result<Vec<SentTx>, Error> {
        let tree = self
            .db
            .open_tree(SENT_TXS_TREE)
            .map_err(|e| Error::Wallet(format!("open sent_txs tree: {}", e)))?;

        let mut txs = Vec::new();
        for entry in tree.iter() {
            let (_, value) =
                entry.map_err(|e| Error::Wallet(format!("iterate sent_txs: {}", e)))?;
            let tx: SentTx = serde_json::from_slice(&value)
                .map_err(|e| Error::Wallet(format!("deserialize sent tx: {}", e)))?;
            txs.push(tx);
        }

        txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(txs)
    }

    /// all received notes (non-change), sorted by height descending
    pub fn all_received_notes(&self) -> Result<Vec<WalletNote>, Error> {
        let notes_tree = self
            .db
            .open_tree(NOTES_TREE)
            .map_err(|e| Error::Wallet(format!("open notes tree: {}", e)))?;

        let mut notes = Vec::new();
        for entry in notes_tree.iter() {
            let (_, value) = entry.map_err(|e| Error::Wallet(format!("iterate notes: {}", e)))?;
            let note: WalletNote = serde_json::from_slice(&value)
                .map_err(|e| Error::Wallet(format!("deserialize note: {}", e)))?;
            if !note.is_change {
                notes.push(note);
            }
        }

        notes.sort_by(|a, b| b.block_height.cmp(&a.block_height));
        Ok(notes)
    }

    // -- payment request methods --

    /// monotonic counter for payment request IDs (atomic via sled CAS)
    pub fn next_request_id(&self) -> Result<u64, Error> {
        loop {
            let old = self
                .db
                .get(NEXT_REQUEST_ID_KEY)
                .map_err(|e| Error::Wallet(format!("read next_request_id: {}", e)))?;

            let current = match &old {
                Some(bytes) if bytes.len() == 8 => {
                    u64::from_le_bytes(bytes.as_ref().try_into().expect("len checked"))
                }
                _ => 0,
            };

            let next = current + 1;
            let cas_result = self
                .db
                .compare_and_swap(
                    NEXT_REQUEST_ID_KEY,
                    old.as_deref(),
                    Some(&next.to_le_bytes()[..]),
                )
                .map_err(|e| Error::Wallet(format!("CAS next_request_id: {}", e)))?;

            if cas_result.is_ok() {
                return Ok(current);
            }
            // CAS failed = concurrent modification, retry
        }
    }

    pub fn insert_payment_request(&self, req: &PaymentRequest) -> Result<(), Error> {
        let tree = self
            .db
            .open_tree(PAYMENT_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open payment_requests tree: {}", e)))?;
        let value = serde_json::to_vec(req)
            .map_err(|e| Error::Wallet(format!("serialize payment request: {}", e)))?;
        tree.insert(req.id.to_be_bytes(), value)
            .map_err(|e| Error::Wallet(format!("insert payment request: {}", e)))?;
        Ok(())
    }

    pub fn get_payment_request(&self, id: u64) -> Result<PaymentRequest, Error> {
        let tree = self
            .db
            .open_tree(PAYMENT_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open payment_requests tree: {}", e)))?;
        let value = tree
            .get(id.to_be_bytes())
            .map_err(|e| Error::Wallet(format!("get payment request: {}", e)))?
            .ok_or_else(|| Error::Wallet(format!("payment request {} not found", id)))?;
        serde_json::from_slice(&value)
            .map_err(|e| Error::Wallet(format!("deserialize payment request: {}", e)))
    }

    pub fn update_payment_request(&self, req: &PaymentRequest) -> Result<(), Error> {
        self.insert_payment_request(req)
    }

    /// list payment requests with optional status filter
    pub fn list_payment_requests(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<PaymentRequest>, Error> {
        let tree = self
            .db
            .open_tree(PAYMENT_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open payment_requests tree: {}", e)))?;
        let mut reqs = Vec::new();
        for entry in tree.iter() {
            let (_, value) =
                entry.map_err(|e| Error::Wallet(format!("iterate payment_requests: {}", e)))?;
            let req: PaymentRequest = serde_json::from_slice(&value)
                .map_err(|e| Error::Wallet(format!("deserialize payment request: {}", e)))?;
            if let Some(filter) = status_filter {
                if req.status != filter {
                    continue;
                }
            }
            reqs.push(req);
        }
        Ok(reqs)
    }

    /// find a pending request whose recipient matches the given 43-byte address
    pub fn find_request_by_recipient(
        &self,
        recipient_bytes: &[u8],
    ) -> Result<Option<PaymentRequest>, Error> {
        let tree = self
            .db
            .open_tree(PAYMENT_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open payment_requests tree: {}", e)))?;
        for entry in tree.iter() {
            let (_, value) =
                entry.map_err(|e| Error::Wallet(format!("iterate payment_requests: {}", e)))?;
            let req: PaymentRequest = serde_json::from_slice(&value)
                .map_err(|e| Error::Wallet(format!("deserialize payment request: {}", e)))?;
            if req.status == "pending" && req.recipient == recipient_bytes {
                return Ok(Some(req));
            }
        }
        Ok(None)
    }

    pub fn set_forward_address(&self, addr: &str) -> Result<(), Error> {
        self.db
            .insert(FORWARD_ADDRESS_KEY, addr.as_bytes())
            .map_err(|e| Error::Wallet(format!("write forward address: {}", e)))?;
        Ok(())
    }

    pub fn get_forward_address(&self) -> Result<Option<String>, Error> {
        match self
            .db
            .get(FORWARD_ADDRESS_KEY)
            .map_err(|e| Error::Wallet(format!("read forward address: {}", e)))?
        {
            Some(bytes) => {
                let s = String::from_utf8(bytes.to_vec())
                    .map_err(|e| Error::Wallet(format!("forward address not utf8: {}", e)))?;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    // -- actions commitment --

    /// get the running actions commitment (for resuming sync)
    pub fn actions_commitment(&self) -> Result<[u8; 32], Error> {
        match self
            .db
            .get(ACTIONS_COMMITMENT_KEY)
            .map_err(|e| Error::Wallet(format!("read actions_commitment: {}", e)))?
        {
            Some(bytes) => {
                if bytes.len() == 32 {
                    let mut ac = [0u8; 32];
                    ac.copy_from_slice(&bytes);
                    Ok(ac)
                } else {
                    Ok([0u8; 32])
                }
            }
            None => Ok([0u8; 32]),
        }
    }

    pub fn set_actions_commitment(&self, commitment: &[u8; 32]) -> Result<(), Error> {
        self.db
            .insert(ACTIONS_COMMITMENT_KEY, commitment.as_ref())
            .map_err(|e| Error::Wallet(format!("write actions_commitment: {}", e)))?;
        Ok(())
    }

    // -- FVK / watch-only methods --

    /// store a 96-byte orchard full viewing key in the watch wallet
    pub fn store_fvk(&self, fvk_bytes: &[u8; 96]) -> Result<(), Error> {
        self.db
            .insert(FVK_KEY, fvk_bytes.as_ref())
            .map_err(|e| Error::Wallet(format!("write fvk: {}", e)))?;
        Ok(())
    }

    /// get stored FVK bytes (96 bytes), if any
    pub fn get_fvk_bytes(&self) -> Result<Option<[u8; 96]>, Error> {
        match self
            .db
            .get(FVK_KEY)
            .map_err(|e| Error::Wallet(format!("read fvk: {}", e)))?
        {
            Some(bytes) => {
                if bytes.len() == 96 {
                    let mut fvk = [0u8; 96];
                    fvk.copy_from_slice(&bytes);
                    Ok(Some(fvk))
                } else {
                    Err(Error::Wallet(format!(
                        "stored FVK wrong length: {} (expected 96)",
                        bytes.len()
                    )))
                }
            }
            None => Ok(None),
        }
    }

    /// check if watch wallet has an FVK stored
    pub fn has_fvk() -> bool {
        let watch = Self::open(&Self::watch_path());
        matches!(watch, Ok(w) if w.get_fvk_bytes().ok().flatten().is_some())
    }

    // -- withdrawal request methods --

    pub fn next_withdrawal_id(&self) -> Result<u64, Error> {
        loop {
            let old = self
                .db
                .get(NEXT_WITHDRAWAL_ID_KEY)
                .map_err(|e| Error::Wallet(format!("read next_withdrawal_id: {}", e)))?;

            let current = match &old {
                Some(bytes) if bytes.len() == 8 => {
                    u64::from_le_bytes(bytes.as_ref().try_into().expect("len checked"))
                }
                _ => 0,
            };

            let next = current + 1;
            let cas_result = self
                .db
                .compare_and_swap(
                    NEXT_WITHDRAWAL_ID_KEY,
                    old.as_deref(),
                    Some(&next.to_le_bytes()[..]),
                )
                .map_err(|e| Error::Wallet(format!("CAS next_withdrawal_id: {}", e)))?;

            if cas_result.is_ok() {
                return Ok(current);
            }
        }
    }

    pub fn insert_withdrawal_request(&self, req: &WithdrawalRequest) -> Result<(), Error> {
        let tree = self
            .db
            .open_tree(WITHDRAWAL_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open withdrawal_requests tree: {}", e)))?;
        let value = serde_json::to_vec(req)
            .map_err(|e| Error::Wallet(format!("serialize withdrawal request: {}", e)))?;
        tree.insert(req.id.to_be_bytes(), value)
            .map_err(|e| Error::Wallet(format!("insert withdrawal request: {}", e)))?;
        Ok(())
    }

    pub fn get_withdrawal_request(&self, id: u64) -> Result<WithdrawalRequest, Error> {
        let tree = self
            .db
            .open_tree(WITHDRAWAL_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open withdrawal_requests tree: {}", e)))?;
        let value = tree
            .get(id.to_be_bytes())
            .map_err(|e| Error::Wallet(format!("get withdrawal request: {}", e)))?
            .ok_or_else(|| Error::Wallet(format!("withdrawal request {} not found", id)))?;
        serde_json::from_slice(&value)
            .map_err(|e| Error::Wallet(format!("deserialize withdrawal request: {}", e)))
    }

    pub fn update_withdrawal_request(&self, req: &WithdrawalRequest) -> Result<(), Error> {
        self.insert_withdrawal_request(req)
    }

    pub fn list_withdrawal_requests(
        &self,
        status_filter: Option<&str>,
    ) -> Result<Vec<WithdrawalRequest>, Error> {
        let tree = self
            .db
            .open_tree(WITHDRAWAL_REQUESTS_TREE)
            .map_err(|e| Error::Wallet(format!("open withdrawal_requests tree: {}", e)))?;
        let mut reqs = Vec::new();
        for entry in tree.iter() {
            let (_, value) =
                entry.map_err(|e| Error::Wallet(format!("iterate withdrawal_requests: {}", e)))?;
            let req: WithdrawalRequest = serde_json::from_slice(&value)
                .map_err(|e| Error::Wallet(format!("deserialize withdrawal request: {}", e)))?;
            if let Some(filter) = status_filter {
                if req.status != filter {
                    continue;
                }
            }
            reqs.push(req);
        }
        Ok(reqs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_wallet() -> Wallet {
        let dir = tempfile::tempdir().unwrap();
        Wallet::open(dir.path().join("wallet").to_str().unwrap()).unwrap()
    }

    #[test]
    fn test_actions_commitment_default_zero() {
        let w = temp_wallet();
        assert_eq!(w.actions_commitment().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_actions_commitment_roundtrip() {
        let w = temp_wallet();
        let commitment = [0xab; 32];
        w.set_actions_commitment(&commitment).unwrap();
        assert_eq!(w.actions_commitment().unwrap(), commitment);
    }

    #[test]
    fn test_actions_commitment_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let path_str = path.to_str().unwrap();

        let commitment = [0xcd; 32];
        {
            let w = Wallet::open(path_str).unwrap();
            w.set_actions_commitment(&commitment).unwrap();
        }
        {
            let w = Wallet::open(path_str).unwrap();
            assert_eq!(w.actions_commitment().unwrap(), commitment);
        }
    }

    #[test]
    fn test_sync_height_and_position_roundtrip() {
        let w = temp_wallet();
        assert_eq!(w.sync_height().unwrap(), 0);
        assert_eq!(w.orchard_position().unwrap(), 0);

        w.set_sync_height(123456).unwrap();
        w.set_orchard_position(789).unwrap();

        assert_eq!(w.sync_height().unwrap(), 123456);
        assert_eq!(w.orchard_position().unwrap(), 789);
    }

    #[test]
    fn test_actions_commitment_chains_correctly() {
        let w = temp_wallet();

        // simulate syncing blocks 100..103 and saving commitment
        let mut ac = [0u8; 32];
        for height in 100..103 {
            let root = zync_core::actions::compute_actions_root(&[(
                [height as u8; 32],
                [0u8; 32],
                [0u8; 32],
            )]);
            ac = zync_core::actions::update_actions_commitment(&ac, &root, height);
        }
        w.set_actions_commitment(&ac).unwrap();
        w.set_sync_height(102).unwrap();

        // simulate resuming from 103 and continuing
        let mut resumed_ac = w.actions_commitment().unwrap();
        assert_eq!(resumed_ac, ac);
        for height in 103..106 {
            let root = zync_core::actions::compute_actions_root(&[(
                [height as u8; 32],
                [0u8; 32],
                [0u8; 32],
            )]);
            resumed_ac = zync_core::actions::update_actions_commitment(&resumed_ac, &root, height);
        }

        // compute the full chain from scratch for comparison
        let mut full_ac = [0u8; 32];
        for height in 100..106 {
            let root = zync_core::actions::compute_actions_root(&[(
                [height as u8; 32],
                [0u8; 32],
                [0u8; 32],
            )]);
            full_ac = zync_core::actions::update_actions_commitment(&full_ac, &root, height);
        }

        assert_eq!(resumed_ac, full_ac, "resumed chain must match full chain");
    }
}

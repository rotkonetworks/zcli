// local wallet state backed by sled

use std::sync::OnceLock;

use orchard::note::{RandomSeed, Rho};
use orchard::value::NoteValue;
use sled::Db;

use crate::error::Error;

const SYNC_HEIGHT_KEY: &[u8] = b"sync_height";
const BIRTH_HEIGHT_KEY: &[u8] = b"birth_height";
const ORCHARD_POSITION_KEY: &[u8] = b"orchard_position";
const IRONWOOD_POSITION_KEY: &[u8] = b"ironwood_position";
// orchard keeps the historical (unprefixed) key names so existing wallets keep
// their cached frontier across this change; ironwood gets its own pair.
const TREE_FRONTIER_KEY: &[u8] = b"tree_frontier";
const TREE_FRONTIER_HEIGHT_KEY: &[u8] = b"tree_frontier_height";
const IRONWOOD_TREE_FRONTIER_KEY: &[u8] = b"ironwood_tree_frontier";
const IRONWOOD_TREE_FRONTIER_HEIGHT_KEY: &[u8] = b"ironwood_tree_frontier_height";
const NEXT_REQUEST_ID_KEY: &[u8] = b"next_request_id";
const FORWARD_ADDRESS_KEY: &[u8] = b"forward_address";
const NOTES_TREE: &str = "notes";
const NULLIFIERS_TREE: &str = "nullifiers";
const SENT_TXS_TREE: &str = "sent_txs";
const PAYMENT_REQUESTS_TREE: &str = "payment_requests";
const WITHDRAWAL_REQUESTS_TREE: &str = "withdrawal_requests";
const NEXT_WITHDRAWAL_ID_KEY: &[u8] = b"next_withdrawal_id";
const FVK_KEY: &[u8] = b"full_viewing_key";

/// lock retry budget for `Wallet::open`: 200+400+...+2000ms ≈ 11s
const OPEN_LOCK_ATTEMPTS: u32 = 10;
const OPEN_LOCK_BACKOFF_MS: u64 = 200;

/// Sleep between lock retries without starving an async runtime.
///
/// `Wallet::open` is sync but is called from async handlers (zclid gRPC, the
/// mempool tick, quic). A bare `thread::sleep` there parks a tokio worker for
/// the whole retry budget; a handful of those during a long catch-up sync can
/// take every worker, stalling the very I/O the sync needs to finish and
/// release the lock. On a multi-thread runtime `block_in_place` hands this
/// worker's queued tasks to another thread first. (It panics on a
/// current-thread runtime, which therefore just sleeps.)
fn backoff_sleep(d: std::time::Duration) {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| std::thread::sleep(d))
        }
        _ => std::thread::sleep(d),
    }
}

/// global watch mode flag — set once at startup, affects default_path()
static WATCH_MODE: OnceLock<bool> = OnceLock::new();

/// call once at startup to enable watch-only wallet path
pub fn set_watch_mode(enabled: bool) {
    WATCH_MODE.set(enabled).ok();
}

fn is_watch_mode() -> bool {
    WATCH_MODE.get().copied().unwrap_or(false)
}

/// global testnet flag — set once at startup, moves all wallet state under
/// ~/.zcli/testnet so testnet notes never land in the mainnet wallet
static TESTNET: OnceLock<bool> = OnceLock::new();

pub fn set_testnet(enabled: bool) {
    TESTNET.set(enabled).ok();
}

/// ~/.zcli on mainnet, ~/.zcli/testnet on testnet
fn zcli_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    if TESTNET.get().copied().unwrap_or(false) {
        format!("{}/.zcli/testnet", home)
    } else {
        format!("{}/.zcli", home)
    }
}

/// Which shielded pool a note lives in.
///
/// Re-exported from `zafu_wasm`, which is where it now lives. It used to be
/// defined here — but this crate depends on zafu-wasm, not the other way
/// round, so the scanner down there could not see this type and dispatched on
/// a `&str` instead. One definition, on the correct side of the dependency
/// edge, is what lets the note-encryption domain be DERIVED from the pool
/// rather than chosen alongside it.
pub use zafu_wasm::Pool;

/// (frontier key, frontier height key) for a pool's cached tree frontier
fn frontier_keys(pool: Pool) -> (&'static [u8], &'static [u8]) {
    match pool {
        Pool::Orchard => (TREE_FRONTIER_KEY, TREE_FRONTIER_HEIGHT_KEY),
        Pool::Ironwood => (
            IRONWOOD_TREE_FRONTIER_KEY,
            IRONWOOD_TREE_FRONTIER_HEIGHT_KEY,
        ),
    }
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
    /// leaf position in the note's own pool's commitment tree
    pub position: u64,
    #[serde(default)]
    pub txid: Vec<u8>,
    #[serde(default)]
    pub memo: Option<String>,
    /// pool the note belongs to; defaults to orchard for notes stored
    /// before ironwood support existed
    #[serde(default)]
    pub pool: Pool,
}

impl WalletNote {
    /// reconstruct an orchard::Note from stored bytes
    ///
    /// # Note version
    ///
    /// `Note::from_parts` takes a [`orchard::note::NoteVersion`], and the
    /// version is part of what the note commits to: reconstruct a V3 note as V2
    /// and you get a DIFFERENT note, whose commitment and nullifier do not match
    /// the ones on chain. The spend then fails deep inside the builder, or —
    /// worse — produces a transaction the network rejects after minutes of
    /// proving.
    ///
    /// The version is not stored (notes predating ironwood have no such field),
    /// so it is derived from the pool: orchard notes are V2 (ZIP-212), ironwood
    /// notes are V3 (quantum-recoverable). That mapping is then VERIFIED rather
    /// than trusted — the reconstructed note's commitment must equal the `cmx`
    /// recorded at scan time. If it does not, the other version is tried before
    /// giving up, so a wrong assumption here surfaces as an explicit error
    /// instead of an invalid transaction.
    pub fn reconstruct_note(&self) -> Result<orchard::Note, Error> {
        use orchard::note::NoteVersion;

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

        let expected = match self.pool {
            Pool::Orchard => NoteVersion::V2,
            Pool::Ironwood => NoteVersion::V3,
        };
        // Expected version first, then the other one. Notes scanned before the
        // cmx check existed are still accepted on the expected version.
        let fallback = match expected {
            NoteVersion::V2 => NoteVersion::V3,
            NoteVersion::V3 => NoteVersion::V2,
        };

        for version in [expected, fallback] {
            let note: Option<orchard::Note> =
                Option::from(orchard::Note::from_parts(recipient, value, rho, rseed, version));
            let Some(note) = note else { continue };
            let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
            if cmx.to_bytes() == self.cmx {
                return Ok(note);
            }
        }

        Err(Error::Wallet(format!(
            "failed to reconstruct {} note: no note version reproduces the \
             commitment recorded at scan time. The stored note is inconsistent \
             with the chain; re-run `zcli init sync --full`.",
            self.pool.name()
        )))
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

    /// sled holds an exclusive lock on the db directory, so only one process can
    /// have the wallet open at a time. With `zclid` running as a daemon, a peer
    /// holds that lock for seconds at a time (every sync interval, plus the
    /// whole catch-up run), so wait for it instead of failing the command.
    /// ~11s of backoff covers a peer's sync window without hiding a real
    /// timeout — matches the retry that `quic.rs` used to do by hand.
    pub fn open(path: &str) -> Result<Self, Error> {
        let mut last: Option<Error> = None;
        for attempt in 0..OPEN_LOCK_ATTEMPTS {
            match Self::try_open(path) {
                Ok(wallet) => return Ok(wallet),
                Err(Error::Wallet(msg)) if msg.contains("could not acquire lock") => {
                    if attempt + 1 < OPEN_LOCK_ATTEMPTS {
                        backoff_sleep(std::time::Duration::from_millis(
                            OPEN_LOCK_BACKOFF_MS * (attempt as u64 + 1),
                        ));
                    }
                    last = Some(Error::Wallet(msg));
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| Error::Wallet("wallet lock timeout".into())))
    }

    /// single attempt — no lock retry. Callers that want to report a peer
    /// holding the wallet immediately (or measure it) use this.
    pub fn try_open(path: &str) -> Result<Self, Error> {
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
    /// (under ~/.zcli/testnet on testnet)
    pub fn default_path() -> String {
        if is_watch_mode() {
            Self::watch_path()
        } else {
            format!("{}/wallet", zcli_dir())
        }
    }

    /// watch-only wallet path: ~/.zcli/watch
    pub fn watch_path() -> String {
        format!("{}/watch", zcli_dir())
    }

    /// marker file recording which seed derivation an ssh-key wallet uses
    /// ("legacy-ssh" or "mnemonic-v1"); lives beside the wallet db, not in it,
    /// so it can be read before the db is opened
    pub fn derivation_marker_path() -> String {
        format!("{}/seed_derivation", zcli_dir())
    }

    /// wallet db path ignoring watch mode — the spending wallet's location
    pub fn spending_path() -> String {
        format!("{}/wallet", zcli_dir())
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
            .get(&nullifier[..])
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
        tree.insert(&nullifier[..], &[1u8])
            .map_err(|e| Error::Wallet(format!("mark spent: {}", e)))?;
        Ok(())
    }

    pub fn is_spent(&self, nullifier: &[u8; 32]) -> Result<bool, Error> {
        let tree = self
            .db
            .open_tree(NULLIFIERS_TREE)
            .map_err(|e| Error::Wallet(format!("open nullifiers tree: {}", e)))?;
        tree.contains_key(&nullifier[..])
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

    /// global ironwood commitment position counter (increments for every
    /// ironwood action in every block from NU6.3 activation)
    pub fn ironwood_position(&self) -> Result<u64, Error> {
        match self
            .db
            .get(IRONWOOD_POSITION_KEY)
            .map_err(|e| Error::Wallet(format!("read ironwood position: {}", e)))?
        {
            Some(bytes) if bytes.len() == 8 => Ok(u64::from_le_bytes(
                bytes.as_ref().try_into().expect("len checked"),
            )),
            _ => Ok(0),
        }
    }

    pub fn set_ironwood_position(&self, pos: u64) -> Result<(), Error> {
        self.db
            .insert(IRONWOOD_POSITION_KEY, &pos.to_le_bytes())
            .map_err(|e| Error::Wallet(format!("write ironwood position: {}", e)))?;
        Ok(())
    }

    /// cached commitment-tree frontier (hex-encoded) for fast witness building.
    ///
    /// Keyed by POOL: orchard and ironwood are separate trees with separate leaf
    /// numbering, and the two frontiers are byte-compatible, so handing the
    /// wrong one to the witness builder would be undetectable there. The pool is
    /// a required argument for exactly that reason.
    pub fn tree_frontier(&self, pool: Pool) -> Result<Option<(String, u32)>, Error> {
        let (frontier_key, height_key) = frontier_keys(pool);
        let frontier = self
            .db
            .get(frontier_key)
            .map_err(|e| Error::Wallet(format!("read tree frontier: {}", e)))?;
        let height = self
            .db
            .get(height_key)
            .map_err(|e| Error::Wallet(format!("read tree frontier height: {}", e)))?;
        match (frontier, height) {
            (Some(f), Some(h)) if h.len() == 4 => {
                let hex = String::from_utf8(f.to_vec())
                    .map_err(|e| Error::Wallet(format!("invalid frontier utf8: {}", e)))?;
                let height = u32::from_le_bytes(h.as_ref().try_into().expect("len checked"));
                Ok(Some((hex, height)))
            }
            _ => Ok(None),
        }
    }

    pub fn set_tree_frontier(&self, pool: Pool, hex: &str, height: u32) -> Result<(), Error> {
        let (frontier_key, height_key) = frontier_keys(pool);
        self.db
            .insert(frontier_key, hex.as_bytes())
            .map_err(|e| Error::Wallet(format!("write tree frontier: {}", e)))?;
        self.db
            .insert(height_key, &height.to_le_bytes())
            .map_err(|e| Error::Wallet(format!("write tree frontier height: {}", e)))?;
        self.db
            .flush()
            .map_err(|e| Error::Wallet(format!("flush frontier: {}", e)))?;
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

        txs.sort_by_key(|t| std::cmp::Reverse(t.timestamp));
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

        notes.sort_by_key(|n| std::cmp::Reverse(n.block_height));
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

    /// Persist the whole sync point — height and both tree positions — in ONE
    /// sled transaction. The positions are only meaningful as the count UP TO
    /// that height; written one by one, a process killed between the inserts
    /// would leave a height beside positions from another height.
    ///
    /// Notes and nullifiers stay outside this transaction deliberately: they
    /// are keyed by nullifier, so re-scanning a range re-inserts them
    /// unchanged. A torn write there costs a repeated scan, not state.
    pub fn commit_sync_point(
        &self,
        height: u32,
        orchard_position: u64,
        ironwood_position: u64,
    ) -> Result<(), Error> {
        self.db
            .transaction(|tx| -> sled::transaction::ConflictableTransactionResult<(), ()> {
                tx.insert(SYNC_HEIGHT_KEY, &height.to_le_bytes())?;
                tx.insert(ORCHARD_POSITION_KEY, &orchard_position.to_le_bytes())?;
                tx.insert(IRONWOOD_POSITION_KEY, &ironwood_position.to_le_bytes())?;
                Ok(())
            })
            .map_err(|e| Error::Wallet(format!("commit sync point: {:?}", e)))?;
        Ok(())
    }

    // -- FVK / watch-only methods --

    /// store a 96-byte orchard full viewing key in the watch wallet
    pub fn store_fvk(&self, fvk_bytes: &[u8; 96]) -> Result<(), Error> {
        self.db
            .insert(FVK_KEY, &fvk_bytes[..])
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

    // sled is single-process: a daemon (zclid) holds the wallet lock for
    // seconds at a time mid-sync. open() must wait for it, try_open() must not.
    #[test]
    fn test_open_waits_for_peer_lock_then_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let path = path.to_str().unwrap().to_string();

        let held = Wallet::open(&path).unwrap();
        let peer_path = path.clone();
        let peer = std::thread::spawn(move || Wallet::open(&peer_path));

        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(held);

        let opened = peer.join().unwrap();
        assert!(opened.is_ok(), "second open should wait: {:?}", opened.err());
    }

    #[test]
    fn test_try_open_fails_fast_while_peer_holds_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let path = path.to_str().unwrap().to_string();

        let _held = Wallet::open(&path).unwrap();
        match Wallet::try_open(&path) {
            Err(Error::Wallet(msg)) => assert!(
                msg.contains("could not acquire lock"),
                "expected a lock error, got: {}",
                msg
            ),
            other => panic!("expected lock failure, got {:?}", other.map(|_| "opened")),
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

}

#[cfg(test)]
mod sync_point_tests {
    use super::*;

    fn temp_wallet() -> Wallet {
        let dir = tempfile::tempdir().unwrap();
        Wallet::open(dir.path().join("wallet").to_str().unwrap()).unwrap()
    }

    #[test]
    fn commit_sync_point_writes_height_and_positions() {
        let w = temp_wallet();
        w.commit_sync_point(4_242, 17, 23).unwrap();

        assert_eq!(w.sync_height().unwrap(), 4_242);
        assert_eq!(w.orchard_position().unwrap(), 17);
        assert_eq!(w.ironwood_position().unwrap(), 23);
    }

    // Height and positions are ONE fact: a transaction that dies partway must
    // leave them untouched, not half-updated.
    #[test]
    fn aborted_sync_point_transaction_leaves_the_stored_point_untouched() {
        let w = temp_wallet();
        w.commit_sync_point(100, 7, 9).unwrap();

        let res: sled::transaction::TransactionResult<(), ()> = w.db.transaction(|tx| {
            tx.insert(SYNC_HEIGHT_KEY, &999u32.to_le_bytes())?;
            tx.insert(ORCHARD_POSITION_KEY, &1u64.to_le_bytes())?;
            Err(sled::transaction::ConflictableTransactionError::Abort(()))
        });
        assert!(res.is_err());

        assert_eq!(w.sync_height().unwrap(), 100);
        assert_eq!(w.orchard_position().unwrap(), 7);
        assert_eq!(w.ironwood_position().unwrap(), 9);
    }
}

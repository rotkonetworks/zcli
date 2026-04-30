//! grpc service — wallet queries, tx building, signing

use crate::proto::{self, wallet_daemon_server::WalletDaemon};
use crate::SharedState;
use orchard::keys::FullViewingKey;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// ZIP-317 fee constants (mirrored from zecli::ops::send)
const MARGINAL_FEE: u64 = 5_000;
const GRACE_ACTIONS: usize = 2;
const MIN_ORCHARD_ACTIONS: usize = 2;

pub struct WalletDaemonService {
    pub state: SharedState,
    pub wallet_path: String,
    pub endpoint: String,
    pub fvk: FullViewingKey,
    pub spending_key: Option<Arc<orchard::keys::SpendingKey>>,
    pub mainnet: bool,
}

impl WalletDaemonService {
    fn custody_mode(&self) -> proto::CustodyMode {
        if self.spending_key.is_some() {
            proto::CustodyMode::Custody
        } else {
            proto::CustodyMode::View
        }
    }
}

/// ZIP-317 fee for orchard-only spends (no transparent inputs)
fn compute_fee(n_spends: usize, n_z_outputs: usize, n_t_outputs: usize, has_change: bool) -> u64 {
    let n_orchard_outputs = n_z_outputs + if has_change { 1 } else { 0 };
    let n_orchard_actions = n_spends.max(n_orchard_outputs).max(MIN_ORCHARD_ACTIONS);
    let logical_actions = n_orchard_actions + n_t_outputs;
    MARGINAL_FEE * logical_actions.max(GRACE_ACTIONS) as u64
}

/// select notes covering target (largest-first, prefer recent positions)
#[allow(clippy::result_large_err)] // tonic::Status is the idiomatic error; worth the size
fn select_notes(
    notes: &[zecli::wallet::WalletNote],
    target: u64,
    pending_nfs: &[[u8; 32]],
) -> Result<Vec<zecli::wallet::WalletNote>, Status> {
    let mut candidates: Vec<_> = notes
        .iter()
        .filter(|n| !pending_nfs.contains(&n.nullifier))
        .cloned()
        .collect();
    candidates.sort_by(|a, b| b.value.cmp(&a.value).then(b.position.cmp(&a.position)));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for note in candidates {
        total += note.value;
        selected.push(note);
        if total >= target {
            return Ok(selected);
        }
    }

    Err(Status::failed_precondition(format!(
        "insufficient funds: have {} zat, need {} zat",
        total, target
    )))
}

/// validate a TransactionIntent at the gRPC boundary
#[allow(clippy::result_large_err)]
fn validate_intent(intent: &proto::TransactionIntent) -> Result<(), Status> {
    if intent.to_address.is_empty() {
        return Err(Status::invalid_argument("to_address is required"));
    }
    if intent.amount_zat == 0 {
        return Err(Status::invalid_argument("amount_zat must be > 0"));
    }
    if intent.memo.len() > 512 {
        return Err(Status::invalid_argument("memo exceeds 512 bytes"));
    }
    // validate address prefix
    let addr = &intent.to_address;
    if !addr.starts_with("u1")
        && !addr.starts_with("utest1")
        && !addr.starts_with("t1")
        && !addr.starts_with("tm")
    {
        return Err(Status::invalid_argument(format!(
            "unrecognized address format: {}",
            &addr[..addr.len().min(10)]
        )));
    }
    Ok(())
}

/// common path: open wallet, select notes, build witnesses, return everything
/// needed to construct a transaction
async fn prepare_spend(
    wallet_path: &str,
    endpoint: &str,
    fvk: &FullViewingKey,
    mainnet: bool,
    intent: &proto::TransactionIntent,
    pending_nfs: &[[u8; 32]],
) -> Result<PreparedSpend, Status> {
    let is_transparent =
        intent.to_address.starts_with("t1") || intent.to_address.starts_with("tm");
    let n_t_outputs = if is_transparent { 1 } else { 0 };
    let n_z_outputs = if is_transparent { 0 } else { 1 };

    // open wallet and select notes
    let (selected, cached_frontier, sync_height) = {
        let wallet = zecli::wallet::Wallet::open(wallet_path)
            .map_err(|e| Status::internal(e.to_string()))?;
        let (balance, notes) = wallet
            .shielded_balance()
            .map_err(|e| Status::internal(e.to_string()))?;

        let est_fee = compute_fee(1, n_z_outputs, n_t_outputs, true);
        let needed = intent.amount_zat + est_fee;
        if balance < needed {
            return Err(Status::failed_precondition(format!(
                "insufficient funds: have {} zat, need {} zat",
                balance, needed
            )));
        }

        let frontier = wallet.tree_frontier().ok().flatten();
        let sh = wallet.sync_height().unwrap_or(0);
        let sel = select_notes(&notes, needed, pending_nfs)?;
        (sel, frontier, sh)
    };

    // compute exact fee
    let total_in: u64 = selected.iter().map(|n| n.value).sum();
    let has_change =
        total_in > intent.amount_zat + compute_fee(selected.len(), n_z_outputs, n_t_outputs, true);
    let fee = compute_fee(selected.len(), n_z_outputs, n_t_outputs, has_change);
    if total_in < intent.amount_zat + fee {
        return Err(Status::failed_precondition(format!(
            "insufficient funds after fee: have {} zat, need {} zat",
            total_in,
            intent.amount_zat + fee
        )));
    }
    let change = total_in - intent.amount_zat - fee;

    // reconstruct orchard notes
    let orchard_notes: Vec<orchard::Note> = selected
        .iter()
        .map(|n| n.reconstruct_note())
        .collect::<Result<_, _>>()
        .map_err(|e| Status::internal(format!("note reconstruction: {}", e)))?;

    // build merkle witnesses (async - connects to zidecar)
    let client = zecli::client::ZidecarClient::connect(endpoint)
        .await
        .map_err(|e| Status::internal(format!("zidecar connect: {}", e)))?;
    let (tip, _) = client
        .get_tip()
        .await
        .map_err(|e| Status::internal(format!("get_tip: {}", e)))?;

    let (anchor, paths) = zecli::witness::build_witnesses(
        &client,
        &selected,
        tip,
        mainnet,
        true, // json=true suppresses stderr output
        cached_frontier,
        sync_height,
    )
    .await
    .map_err(|e| Status::internal(format!("witness build: {}", e)))?;

    // build spends
    let spends: Vec<(orchard::Note, orchard::tree::MerklePath)> =
        orchard_notes.into_iter().zip(paths).collect();

    // parse recipient for z-outputs
    let recipient_addr = if !is_transparent {
        Some(
            zecli::tx::parse_orchard_address(&intent.to_address, mainnet)
                .map_err(|e| Status::invalid_argument(format!("bad recipient: {}", e)))?,
        )
    } else {
        None
    };

    // build memo
    let mut memo_bytes = [0u8; 512];
    if !intent.memo.is_empty() {
        let bytes = intent.memo.as_bytes();
        let len = bytes.len().min(512);
        memo_bytes[..len].copy_from_slice(&bytes[..len]);
    }

    // build z/t output lists
    let z_outputs: Vec<(orchard::Address, u64, [u8; 512])> = if let Some(addr) = recipient_addr {
        vec![(addr, intent.amount_zat, memo_bytes)]
    } else {
        vec![]
    };
    let t_outputs: Vec<(String, u64)> = if is_transparent {
        vec![(intent.to_address.clone(), intent.amount_zat)]
    } else {
        vec![]
    };

    Ok(PreparedSpend {
        spends,
        z_outputs,
        t_outputs,
        change,
        _fee: fee,
        anchor,
        anchor_height: tip,
        fvk_bytes: fvk.to_bytes(),
    })
}

struct PreparedSpend {
    spends: Vec<(orchard::Note, orchard::tree::MerklePath)>,
    z_outputs: Vec<(orchard::Address, u64, [u8; 512])>,
    t_outputs: Vec<(String, u64)>,
    change: u64,
    _fee: u64,
    anchor: orchard::tree::Anchor,
    anchor_height: u32,
    fvk_bytes: [u8; 96],
}

#[tonic::async_trait]
impl WalletDaemon for WalletDaemonService {
    async fn get_custody_mode(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::CustodyModeResponse>, Status> {
        Ok(Response::new(proto::CustodyModeResponse {
            mode: self.custody_mode() as i32,
        }))
    }

    async fn get_address(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::AddressResponse>, Status> {
        let shielded = zecli::address::orchard_address_from_fvk(&self.fvk, self.mainnet)
            .map_err(|e| Status::internal(e.to_string()))?;

        // transparent address from FVK is not directly available -
        // would need the seed. return empty if view-only.
        let transparent = String::new();

        Ok(Response::new(proto::AddressResponse {
            shielded_address: shielded,
            transparent_address: transparent,
        }))
    }

    async fn get_balance(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::Balance>, Status> {
        let wallet = zecli::wallet::Wallet::open(&self.wallet_path)
            .map_err(|e| Status::internal(e.to_string()))?;
        let (balance, notes) = wallet
            .shielded_balance()
            .map_err(|e| Status::internal(e.to_string()))?;

        let state = self.state.read().await;
        let pending_incoming: u64 = state
            .pending_events
            .iter()
            .filter(|e| e.kind == proto::pending_event::Kind::Incoming as i32)
            .map(|e| e.value_zat)
            .sum();
        let num_pending_spends = state
            .pending_events
            .iter()
            .filter(|e| e.kind == proto::pending_event::Kind::Spend as i32)
            .count() as u32;

        Ok(Response::new(proto::Balance {
            confirmed_zat: balance,
            pending_incoming_zat: pending_incoming,
            num_notes: notes.len() as u32,
            num_pending_spends,
            synced_to: state.synced_to,
            chain_tip: state.chain_tip,
        }))
    }

    async fn get_notes(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::NoteList>, Status> {
        let wallet = zecli::wallet::Wallet::open(&self.wallet_path)
            .map_err(|e| Status::internal(e.to_string()))?;
        let (_, notes) = wallet
            .shielded_balance()
            .map_err(|e| Status::internal(e.to_string()))?;

        let state = self.state.read().await;
        let pending_nfs: Vec<[u8; 32]> = state
            .pending_events
            .iter()
            .filter(|e| e.kind == proto::pending_event::Kind::Spend as i32)
            .filter_map(|e| e.nullifier.as_slice().try_into().ok())
            .collect();

        let proto_notes = notes
            .into_iter()
            .map(|n| proto::WalletNote {
                value: n.value,
                nullifier: n.nullifier.to_vec(),
                cmx: n.cmx.to_vec(),
                height: n.block_height,
                is_change: n.is_change,
                spend_pending: pending_nfs.contains(&n.nullifier),
                position: n.position,
                txid: n.txid,
                memo: n.memo.unwrap_or_default(),
            })
            .collect();

        Ok(Response::new(proto::NoteList { notes: proto_notes }))
    }

    async fn get_status(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::DaemonStatus>, Status> {
        let state = self.state.read().await;
        Ok(Response::new(proto::DaemonStatus {
            synced_to: state.synced_to,
            chain_tip: state.chain_tip,
            syncing: state.syncing,
            mempool_txs_seen: state.mempool_txs_seen,
            mempool_actions_scanned: state.mempool_actions_scanned,
            started_at: state.started_at,
            endpoint: state.endpoint.clone(),
            custody_mode: self.custody_mode() as i32,
        }))
    }

    async fn get_pending_activity(
        &self,
        _req: Request<proto::Empty>,
    ) -> Result<Response<proto::PendingActivity>, Status> {
        let state = self.state.read().await;
        Ok(Response::new(proto::PendingActivity {
            events: state.pending_events.clone(),
        }))
    }

    async fn get_history(
        &self,
        _req: Request<proto::HistoryRequest>,
    ) -> Result<Response<proto::HistoryResponse>, Status> {
        // TODO: implement from wallet storage
        Ok(Response::new(proto::HistoryResponse { entries: vec![] }))
    }

    async fn prepare_transaction(
        &self,
        request: Request<proto::TransactionIntent>,
    ) -> Result<Response<proto::PreparedTransaction>, Status> {
        let intent = request.into_inner();
        validate_intent(&intent)?;

        // collect pending nullifiers to exclude from note selection
        let pending_nfs: Vec<[u8; 32]> = {
            let state = self.state.read().await;
            state
                .pending_events
                .iter()
                .filter(|e| e.kind == proto::pending_event::Kind::Spend as i32)
                .filter_map(|e| e.nullifier.as_slice().try_into().ok())
                .collect()
        };

        let prepared = prepare_spend(
            &self.wallet_path,
            &self.endpoint,
            &self.fvk,
            self.mainnet,
            &intent,
            &pending_nfs,
        )
        .await?;

        // build PCZT bundle + zigner sign request (heavy - halo2 proving)
        let fvk_bytes = prepared.fvk_bytes;
        let spends = prepared.spends;
        let z_outputs = prepared.z_outputs;
        let t_outputs = prepared.t_outputs;
        let change = prepared.change;
        let anchor = prepared.anchor;
        let anchor_height = prepared.anchor_height;
        let mainnet = self.mainnet;

        let (qr_data, pczt_state) = tokio::task::spawn_blocking(move || {
            zecli::pczt::build_pczt_and_qr(
                &fvk_bytes,
                &spends,
                &z_outputs,
                &t_outputs,
                change,
                anchor,
                anchor_height,
                mainnet,
            )
        })
        .await
        .map_err(|e| Status::internal(format!("proving task panic: {}", e)))?
        .map_err(|e| Status::internal(format!("pczt build: {}", e)))?;

        let sighash = pczt_state.sighash;
        let num_signatures = pczt_state.alphas.len() as u32;

        // generate random ID for this prepared transaction
        let mut tx_id = [0u8; 32];
        getrandom::getrandom(&mut tx_id)
            .map_err(|e| Status::internal(format!("rng: {}", e)))?;

        // store pczt_state in daemon state (GC stale entries first)
        {
            let mut state = self.state.write().await;
            state.gc_prepared_txs();
            state.prepared_txs.insert(
                tx_id,
                crate::PreparedTxEntry {
                    pczt_state,
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                },
            );
        }

        Ok(Response::new(proto::PreparedTransaction {
            sign_request: qr_data,
            sighash: sighash.to_vec(),
            num_signatures,
            pczt_state: tx_id.to_vec(),
        }))
    }

    async fn sign_and_send(
        &self,
        request: Request<proto::TransactionIntent>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        let sk = self.spending_key.as_ref().ok_or_else(|| {
            Status::failed_precondition("sign_and_send requires custody mode (no --view-only)")
        })?;

        let intent = request.into_inner();
        validate_intent(&intent)?;

        // collect pending nullifiers to exclude from note selection
        let pending_nfs: Vec<[u8; 32]> = {
            let state = self.state.read().await;
            state
                .pending_events
                .iter()
                .filter(|e| e.kind == proto::pending_event::Kind::Spend as i32)
                .filter_map(|e| e.nullifier.as_slice().try_into().ok())
                .collect()
        };

        let prepared = prepare_spend(
            &self.wallet_path,
            &self.endpoint,
            &self.fvk,
            self.mainnet,
            &intent,
            &pending_nfs,
        )
        .await?;

        // derive seed from spending key for build_orchard_spend_tx
        // the spending key is ZIP-32 derived, but build_orchard_spend_tx needs
        // the WalletSeed. since we hold the SpendingKey directly, we use the
        // PCZT flow instead: build unsigned, sign with sk, broadcast.
        let fvk_bytes = prepared.fvk_bytes;
        let spends = prepared.spends;
        let z_outputs = prepared.z_outputs;
        let t_outputs = prepared.t_outputs;
        let change = prepared.change;
        let anchor = prepared.anchor;
        let anchor_height = prepared.anchor_height;
        let mainnet = self.mainnet;
        let sk_clone = Arc::clone(sk);

        let tx_bytes = tokio::task::spawn_blocking(move || {
            // build PCZT (unsigned)
            let (_, pczt_state) = zecli::pczt::build_pczt_and_qr(
                &fvk_bytes,
                &spends,
                &z_outputs,
                &t_outputs,
                change,
                anchor,
                anchor_height,
                mainnet,
            )?;

            // sign each action that needs authorization using the spending key
            let ask = orchard::keys::SpendAuthorizingKey::from(&*sk_clone);
            let mut sigs = Vec::with_capacity(pczt_state.alphas.len());
            for alpha_repr in &pczt_state.alphas {
                let sig = sign_with_ask(&ask, &pczt_state.sighash, alpha_repr);
                sigs.push(sig);
            }

            // complete: apply signatures, extract bundle, serialize v5 tx
            zecli::pczt::complete_pczt_tx(pczt_state, &sigs)
        })
        .await
        .map_err(|e| Status::internal(format!("proving task panic: {}", e)))?
        .map_err(|e| Status::internal(format!("tx build: {}", e)))?;

        // broadcast
        let client = zecli::client::ZidecarClient::connect(&self.endpoint)
            .await
            .map_err(|e| Status::internal(format!("zidecar connect: {}", e)))?;
        let result = client
            .send_transaction(tx_bytes)
            .await
            .map_err(|e| Status::internal(format!("broadcast: {}", e)))?;

        Ok(Response::new(proto::SendResponse {
            txid: result.txid,
            error_code: result.error_code,
            error_message: result.error_message,
        }))
    }

    async fn submit_signed(
        &self,
        request: Request<proto::SignedTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        let signed = request.into_inner();

        // validate pczt_state ID
        let tx_id: [u8; 32] = signed
            .pczt_state
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("pczt_state must be 32 bytes"))?;

        // retrieve and remove the prepared transaction (one-shot use)
        let entry = {
            let mut state = self.state.write().await;
            state.gc_prepared_txs();
            state.prepared_txs.remove(&tx_id)
        };
        let entry = entry.ok_or_else(|| {
            Status::not_found("prepared transaction not found or expired (10 min TTL)")
        })?;

        let pczt_state = entry.pczt_state;
        let expected_sigs = pczt_state.alphas.len();

        // validate signature count
        if signed.signatures.len() != expected_sigs {
            return Err(Status::invalid_argument(format!(
                "expected {} signatures, got {}",
                expected_sigs,
                signed.signatures.len()
            )));
        }

        // validate and convert signatures to [u8; 64]
        let mut sigs = Vec::with_capacity(expected_sigs);
        for (i, sig_bytes) in signed.signatures.iter().enumerate() {
            let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                Status::invalid_argument(format!(
                    "signature {} must be 64 bytes, got {}",
                    i,
                    sig_bytes.len()
                ))
            })?;
            sigs.push(sig);
        }

        // complete transaction (apply sigs, extract bundle, serialize)
        let tx_bytes = tokio::task::spawn_blocking(move || {
            zecli::pczt::complete_pczt_tx(pczt_state, &sigs)
        })
        .await
        .map_err(|e| Status::internal(format!("complete task panic: {}", e)))?
        .map_err(|e| Status::internal(format!("tx complete: {}", e)))?;

        // broadcast
        let client = zecli::client::ZidecarClient::connect(&self.endpoint)
            .await
            .map_err(|e| Status::internal(format!("zidecar connect: {}", e)))?;
        let result = client
            .send_transaction(tx_bytes)
            .await
            .map_err(|e| Status::internal(format!("broadcast: {}", e)))?;

        Ok(Response::new(proto::SendResponse {
            txid: result.txid,
            error_code: result.error_code,
            error_message: result.error_message,
        }))
    }

    async fn send_raw_transaction(
        &self,
        request: Request<proto::RawTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        let data = request.into_inner().data;
        // connect per-request to avoid holding a long-lived connection
        // that may go stale - zidecar client is cheap to construct
        let client = zecli::client::ZidecarClient::connect(&self.endpoint)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let result = client
            .send_transaction(data)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::SendResponse {
            txid: result.txid,
            error_code: result.error_code,
            error_message: result.error_message,
        }))
    }
}

/// produce a RedPallas SpendAuth signature for one orchard action
///
/// this replicates what orchard::bundle::apply_signatures does internally:
/// the spending key's ask is randomized by alpha to get the per-action
/// signing key, then signs the sighash.
fn sign_with_ask(
    ask: &orchard::keys::SpendAuthorizingKey,
    sighash: &[u8; 32],
    alpha_repr: &[u8; 32],
) -> [u8; 64] {
    use ff::PrimeField;

    // reconstruct alpha scalar from repr
    let alpha = pasta_curves::pallas::Scalar::from_repr(*alpha_repr);
    // alpha was generated by the builder - repr is always valid
    let alpha = Option::from(alpha).expect("alpha repr from builder is always valid");

    // rsk = ask + alpha (randomized signing key)
    let rsk = ask.randomize(&alpha);

    // sign the sighash with the randomized key
    #[allow(clippy::needless_borrows_for_generic_args)]
    let sig = rsk.sign(&mut rand::rngs::OsRng, sighash);
    <[u8; 64]>::from(&sig)
}

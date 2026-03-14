//! grpc service — wallet queries, tx building, signing

use crate::proto::{self, wallet_daemon_server::WalletDaemon};
use crate::SharedState;
use orchard::keys::FullViewingKey;
use std::sync::Arc;
use tonic::{Request, Response, Status};

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

        // transparent address from FVK is not directly available —
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
        // TODO: select notes, build PCZT bundle, return sign request
        // this is the heavy path — uses FVK to build unsigned tx
        // works in both custody and view modes
        let _intent = request.into_inner();
        Err(Status::unimplemented(
            "PrepareTransaction not yet implemented — use zcli send for now",
        ))
    }

    async fn sign_and_send(
        &self,
        request: Request<proto::TransactionIntent>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        let _sk = self.spending_key.as_ref().ok_or_else(|| {
            Status::failed_precondition("sign_and_send requires custody mode (no --view-only)")
        })?;

        // TODO: prepare + sign + broadcast in one step
        // uses spending key from self.spending_key
        let _intent = request.into_inner();
        Err(Status::unimplemented(
            "SignAndSend not yet implemented — use zcli send for now",
        ))
    }

    async fn submit_signed(
        &self,
        request: Request<proto::SignedTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        // TODO: take pczt_state + signatures, complete tx, broadcast
        // works in both modes — external signer provides authorization
        let _signed = request.into_inner();
        Err(Status::unimplemented(
            "SubmitSigned not yet implemented — use zcli send for now",
        ))
    }

    async fn send_raw_transaction(
        &self,
        request: Request<proto::RawTransaction>,
    ) -> Result<Response<proto::SendResponse>, Status> {
        let data = request.into_inner().data;
        // connect per-request to avoid holding a long-lived connection
        // that may go stale — zidecar client is cheap to construct
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

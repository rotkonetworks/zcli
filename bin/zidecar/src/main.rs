#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing::{info, error, warn};
use tonic::transport::Server;

mod zebrad;
mod header_chain;
mod prover;
mod grpc_service;
mod storage;
mod compact;
mod error;
mod epoch;
mod constants;
mod witness;

use crate::{grpc_service::ZidecarService, epoch::EpochManager};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "zidecar")]
#[command(about = "ligerito-powered zcash light server", long_about = None)]
struct Args {
    /// zebrad RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8232")]
    zebrad_rpc: String,

    /// gRPC listen address
    #[arg(long, default_value = "0.0.0.0:50051")]
    listen: SocketAddr,

    /// RocksDB database path
    #[arg(long, default_value = "./zidecar.db")]
    db_path: String,

    /// Start height for header chain proofs
    #[arg(long, default_value_t = zync_core::ORCHARD_ACTIVATION_HEIGHT)]
    start_height: u32,

    /// Enable testnet mode
    #[arg(long)]
    testnet: bool,

}

#[tokio::main]
async fn main() -> Result<()> {
    // initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zidecar=info,tower_http=debug".into()),
        )
        .init();

    let args = Args::parse();

    info!("starting zidecar");
    info!("zebrad RPC: {}", args.zebrad_rpc);
    info!("gRPC listen: {}", args.listen);
    info!("database: {}", args.db_path);
    info!("start height: {}", args.start_height);
    info!("testnet: {}", args.testnet);

    // initialize storage
    let storage = storage::Storage::open(&args.db_path)?;
    info!("opened database");

    // initialize zebrad client
    let zebrad = zebrad::ZebradClient::new(&args.zebrad_rpc);

    // verify connection
    match zebrad.get_blockchain_info().await {
        Ok(info) => {
            info!("connected to zebrad");
            info!("  chain: {}", info.chain);
            info!("  blocks: {}", info.blocks);
            info!("  bestblockhash: {}", info.bestblockhash);
        }
        Err(e) => {
            error!("failed to connect to zebrad: {}", e);
            return Err(e.into());
        }
    }

    // initialize prover configs
    info!("initialized ligerito prover configs");
    info!("  tip proof: 2^{} config", zync_core::TIP_TRACE_LOG_SIZE);
    info!("  gigaproof: 2^{} config", zync_core::GIGAPROOF_TRACE_LOG_SIZE);

    // initialize epoch manager
    let storage_arc = Arc::new(storage);
    let epoch_manager = Arc::new(EpochManager::new(
        zebrad.clone(),
        storage_arc.clone(),
        zync_core::gigaproof_prover_config(),
        zync_core::tip_prover_config(),
        args.start_height,
    ));

    // check existing proof status
    let start_epoch = args.start_height / zync_core::EPOCH_SIZE;
    if let Ok(Some(cached_epoch)) = storage_arc.get_gigaproof_epoch() {
        let from_height = args.start_height;
        let to_height = cached_epoch * zync_core::EPOCH_SIZE + zync_core::EPOCH_SIZE - 1;
        let num_blocks = to_height - from_height + 1;
        info!("existing gigaproof: epochs {} -> {} ({} blocks, height {} -> {})",
              start_epoch, cached_epoch, num_blocks, from_height, to_height);
    } else {
        info!("no existing gigaproof found, will generate...");
    }

    // generate initial gigaproof synchronously before starting background tasks
    // this ensures we have a proof ready before accepting gRPC requests
    match epoch_manager.generate_gigaproof().await {
        Ok(_) => info!("gigaproof: ready"),
        Err(e) => warn!("gigaproof: generation failed: {}", e),
    }

    // start background tasks
    info!("starting background tasks...");

    // start background gigaproof generator (regenerates hourly when epochs complete)
    let epoch_manager_bg = epoch_manager.clone();
    tokio::spawn(async move {
        epoch_manager_bg.run_background_prover().await;
    });

    // start background state root tracker (for trustless proofs)
    let epoch_manager_state = epoch_manager.clone();
    tokio::spawn(async move {
        epoch_manager_state.run_background_state_tracker().await;
    });

    // start background tip proof generator (real-time proving)
    let epoch_manager_tip = epoch_manager.clone();
    tokio::spawn(async move {
        epoch_manager_tip.run_background_tip_prover().await;
    });

    // start background nullifier sync (indexes all shielded spends into nomt)
    let epoch_manager_nf = epoch_manager.clone();
    tokio::spawn(async move {
        epoch_manager_nf.run_background_nullifier_sync().await;
    });

    info!("  gigaproof generator: running (60s check)");
    info!("  state root tracker: running");
    info!("  tip proof generator: running (1s real-time)");
    info!("  nullifier sync: running (indexes shielded spends)");

    // create gRPC service
    let service = ZidecarService::new(
        zebrad,
        storage_arc,
        epoch_manager,
        args.start_height,
    );

    info!("starting gRPC server on {}", args.listen);
    info!("gRPC-web enabled for browser clients");

    // build gRPC service
    let grpc_service = zidecar::zidecar_server::ZidecarServer::new(service);

    // wrap with gRPC-web + CORS support for browser clients
    // tonic_web::enable() handles CORS and protocol translation
    let grpc_web_service = tonic_web::enable(grpc_service);

    Server::builder()
        .accept_http1(true) // required for gRPC-web
        .add_service(grpc_web_service)
        .serve(args.listen)
        .await?;

    Ok(())
}

// generated proto module
pub mod zidecar {
    tonic::include_proto!("zidecar.v1");
}

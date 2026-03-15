#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::{error, info, warn};

mod compact;
mod constants;
mod epoch;
mod error;
mod frost_relay;
mod grpc_service;
mod header_chain;
mod lwd_service;
mod middleware;
mod prover;
mod storage;
mod witness;
mod zebrad;

use crate::{epoch::EpochManager, grpc_service::ZidecarService, lwd_service::LwdService};
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

    /// Mempool cache TTL in seconds (0 = disabled, each request hits zebrad directly).
    /// Enable on public nodes serving many clients to reduce zebrad load.
    #[arg(long, default_value_t = 0)]
    mempool_cache_ttl: u64,

    /// Disable FROST dummy switch. The dummy switch forwards opaque signed
    /// blobs between room participants without reading them.
    #[arg(long)]
    no_frost_relay: bool,
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

    info!(
        "zidecar v{}-{}",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_HASH")
    );
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
    info!(
        "  epoch proof: 2^{} config",
        zync_core::EPOCH_PROOF_TRACE_LOG_SIZE
    );

    // initialize epoch manager
    let storage_arc = Arc::new(storage);
    let epoch_manager = Arc::new(EpochManager::new(
        zebrad.clone(),
        storage_arc.clone(),
        zync_core::epoch_proof_prover_config(),
        zync_core::tip_prover_config(),
        args.start_height,
    ));

    // check existing proof status
    let start_epoch = args.start_height / zync_core::EPOCH_SIZE;
    if let Ok(Some(cached_epoch)) = storage_arc.get_epoch_proof_epoch() {
        let from_height = args.start_height;
        let to_height = cached_epoch * zync_core::EPOCH_SIZE + zync_core::EPOCH_SIZE - 1;
        let num_blocks = to_height - from_height + 1;
        info!(
            "existing epoch proof: epochs {} -> {} ({} blocks, height {} -> {})",
            start_epoch, cached_epoch, num_blocks, from_height, to_height
        );
    } else {
        info!("no existing epoch proof found, will generate...");
    }

    // generate initial epoch proof synchronously before starting background tasks
    // this ensures we have a proof ready before accepting gRPC requests
    match epoch_manager.generate_epoch_proof().await {
        Ok(_) => info!("epoch proof: ready"),
        Err(e) => warn!("epoch proof: generation failed: {}", e),
    }

    // start background tasks
    info!("starting background tasks...");

    // start background epoch proof generator (regenerates hourly when epochs complete)
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

    info!("  epoch proof generator: running (60s check)");
    info!("  state root tracker: running");
    info!("  tip proof generator: running (1s real-time)");
    info!("  nullifier sync: running (indexes shielded spends)");

    // create gRPC services
    let lwd = LwdService::new(zebrad.clone(), storage_arc.clone(), args.testnet);
    let mempool_cache_ttl = std::time::Duration::from_secs(args.mempool_cache_ttl);
    if args.mempool_cache_ttl > 0 {
        info!("mempool cache: {}s TTL", args.mempool_cache_ttl);
    }
    let service = ZidecarService::new(
        zebrad,
        storage_arc,
        epoch_manager,
        args.start_height,
        mempool_cache_ttl,
    );

    info!("starting gRPC server on {}", args.listen);
    info!("gRPC-web enabled for browser clients");
    info!("lightwalletd CompactTxStreamer compatibility: enabled");

    let mut builder = Server::builder()
        .accept_http1(true)
        .layer(middleware::trace_layer());

    let router = builder
        .add_service(tonic_web::enable(
            lightwalletd::compact_tx_streamer_server::CompactTxStreamerServer::new(lwd),
        ))
        .add_service(tonic_web::enable(
            zidecar::zidecar_server::ZidecarServer::new(service),
        ));

    if args.no_frost_relay {
        info!("frost relay: disabled");
        router.serve(args.listen).await?;
    } else {
        let frost = frost_relay::FrostRelayService::new();
        info!("frost relay: enabled");
        router
            .add_service(tonic_web::enable(
                frost_relay_proto::frost_relay_server::FrostRelayServer::new(frost),
            ))
            .serve(args.listen)
            .await?;
    }

    Ok(())
}

// generated proto modules
pub mod zidecar {
    tonic::include_proto!("zidecar.v1");
}

pub mod lightwalletd {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

pub mod frost_relay_proto {
    tonic::include_proto!("frost_relay.v1");
}

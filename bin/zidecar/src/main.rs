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
mod orchard_tree;
mod prover;
mod ring_vrf;
mod storage;
mod witness;
mod zebrad;

use crate::{epoch::EpochManager, grpc_service::ZidecarService, lwd_service::LwdService};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "zidecar")]
#[command(
    about = "Zcash lightwalletd-compatible gRPC server, with optional ligerito proof and FROST surfaces.",
    long_about = None,
)]
struct Args {
    /// zebrad JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8232")]
    zebrad_rpc: String,

    /// gRPC listen address.
    #[arg(long, default_value = "0.0.0.0:50051")]
    listen: SocketAddr,

    /// Enable testnet mode (LightdInfo.chainName = "test", sapling activation
    /// = testnet activation height).
    #[arg(long)]
    testnet: bool,

    /// Mempool cache TTL in seconds (0 = disabled, each request hits zebrad
    /// directly). Enable on public nodes serving many clients to reduce
    /// upstream load.
    #[arg(long, default_value_t = 0)]
    mempool_cache_ttl: u64,

    /// OPT-IN: enable the rotko-specific ZidecarService (ligerito header-chain
    /// proofs, NOMT state-root tracking, FROST sign anchors). Also opens the
    /// RocksDB cache at `--db-path` and spawns the proof-generation background
    /// tasks. Off by default so the default `zidecar` binary is a drop-in
    /// lightwalletd replacement with no extra attack surface.
    #[arg(long)]
    zidecar_rpc: bool,

    /// OPT-IN: enable the FROST relay gRPC surface. Forwards opaque signed
    /// blobs between room participants without reading them.
    #[arg(long)]
    frost_relay: bool,

    /// OPT-IN: require `Authorization: Bearer <TOKEN>` on every gRPC request.
    /// When unset (default), the server accepts anonymous requests — the
    /// expected mode for a drop-in lightwalletd replacement serving Zashi or
    /// any other wallet SDK. Set this when exposing the optional zidecar
    /// or FROST surfaces alongside lwd.
    #[arg(long, env = "ZIDECAR_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// RocksDB cache path (only used when --zidecar-rpc is set).
    #[arg(long, default_value = "./zidecar.db")]
    db_path: String,

    /// Start height for header chain proofs (only used when --zidecar-rpc).
    #[arg(long, default_value_t = zync_core::ORCHARD_ACTIVATION_HEIGHT)]
    start_height: u32,
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
    info!("testnet: {}", args.testnet);
    info!(
        "surfaces: lightwalletd (always-on) | zidecar-rpc={} | frost-relay={} | auth={}",
        args.zidecar_rpc,
        args.frost_relay,
        if args.auth_token.is_some() {
            "bearer"
        } else {
            "none"
        },
    );

    let zebrad = zebrad::ZebradClient::new(&args.zebrad_rpc);
    match zebrad.get_blockchain_info().await {
        Ok(info) => {
            info!(
                "connected to zebrad: chain={} blocks={} tip={}",
                info.chain, info.blocks, info.bestblockhash
            );
        }
        Err(e) => {
            error!("failed to connect to zebrad: {}", e);
            return Err(e.into());
        }
    }

    // Build the base server stack with Tower hygiene that applies to every
    // surface (lwd + any opt-in extras): tracing, timeout, concurrency limit.
    let mut builder = Server::builder()
        .accept_http1(true)
        .layer(middleware::trace_layer())
        .layer(middleware::timeout_layer(
            middleware::DEFAULT_INBOUND_TIMEOUT,
        ))
        .layer(middleware::concurrency_limit_layer(
            middleware::DEFAULT_MAX_CONCURRENT_RPCS,
        ));

    // One shared interceptor across every surface. When --auth-token is unset
    // it passes through; when set it requires `authorization: Bearer <token>`
    // on every request to every service registered below. This is opt-in by
    // design: the default deployment is a wide-open lwd replacement.
    let auth = middleware::AuthInterceptor::new(args.auth_token.clone());

    // The lightwalletd CompactTxStreamer surface is always on — this is the
    // "drop-in lwd replacement for Zashi" guarantee. It needs no Storage and
    // no background work; just the Zebra RPC client.
    let lwd_server =
        lightwalletd::compact_tx_streamer_server::CompactTxStreamerServer::with_interceptor(
            LwdService::new(zebrad.clone(), args.testnet),
            auth.clone(),
        );
    let mut router = builder.add_service(tonic_web::enable(lwd_server));

    // Opt-in: the rotko ZidecarService surface (ligerito proofs, NOMT state
    // tracking, FROST sign anchors). Storage + EpochManager + the background
    // proof tasks are scoped to this branch so the default lwd-only deploy
    // doesn't open RocksDB or spawn provers.
    if args.zidecar_rpc {
        info!("zidecar-rpc surface: enabled");
        let storage = storage::Storage::open(&args.db_path)?;
        info!("opened database at {}", args.db_path);
        let storage_arc = Arc::new(storage);

        info!("initialized ligerito prover configs");
        info!("  tip proof: 2^{} config", zync_core::TIP_TRACE_LOG_SIZE);
        info!(
            "  epoch proof: 2^{} config",
            zync_core::EPOCH_PROOF_TRACE_LOG_SIZE
        );

        let epoch_manager = Arc::new(EpochManager::new(
            zebrad.clone(),
            storage_arc.clone(),
            zync_core::epoch_proof_prover_config(),
            zync_core::tip_prover_config(),
            args.start_height,
        ));

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

        match epoch_manager.generate_epoch_proof().await {
            Ok(_) => info!("epoch proof: ready"),
            Err(e) => warn!("epoch proof: generation failed: {}", e),
        }

        info!("starting background tasks...");
        let epoch_manager_bg = epoch_manager.clone();
        tokio::spawn(async move { epoch_manager_bg.run_background_prover().await });
        let epoch_manager_state = epoch_manager.clone();
        tokio::spawn(async move { epoch_manager_state.run_background_state_tracker().await });
        let epoch_manager_tip = epoch_manager.clone();
        tokio::spawn(async move { epoch_manager_tip.run_background_tip_prover().await });
        let epoch_manager_nf = epoch_manager.clone();
        tokio::spawn(async move { epoch_manager_nf.run_background_nullifier_sync().await });
        info!("  epoch proof generator + state tracker + tip prover + nullifier sync: running");

        let mempool_cache_ttl = std::time::Duration::from_secs(args.mempool_cache_ttl);
        if args.mempool_cache_ttl > 0 {
            info!("mempool cache: {}s TTL", args.mempool_cache_ttl);
        }
        let service = ZidecarService::new(
            zebrad.clone(),
            storage_arc,
            epoch_manager,
            args.start_height,
            mempool_cache_ttl,
        );
        let zidecar_server = zidecar::zidecar_server::ZidecarServer::with_interceptor(
            service,
            auth.clone(),
        );
        router = router.add_service(tonic_web::enable(zidecar_server));
    } else {
        info!("zidecar-rpc surface: disabled (use --zidecar-rpc to enable)");
    }

    // Opt-in: FROST relay (default off so the public lwd surface doesn't carry
    // the relay endpoint).
    if args.frost_relay {
        let frost = frost_relay::FrostRelayService::new();
        info!("frost relay: enabled");
        let frost_server = frost_relay_proto::frost_relay_server::FrostRelayServer::with_interceptor(
            frost,
            auth.clone(),
        );
        router = router.add_service(tonic_web::enable(frost_server));
    } else {
        info!("frost relay: disabled (use --frost-relay to enable)");
    }

    // Bind the listener synchronously so EADDRINUSE / permission errors
    // propagate from main() with a clean error instead of surfacing as a late
    // panic after the server task is spawned (Zaino pattern from
    // packages/zaino-serve/src/server/grpc.rs).
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind {}: {}", args.listen, e))?;
    info!("bound gRPC listener on {}", args.listen);
    info!("gRPC-web enabled for browser clients");
    info!("lightwalletd CompactTxStreamer compatibility: enabled");

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    router.serve_with_incoming(incoming).await?;

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

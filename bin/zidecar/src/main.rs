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
mod grpc_service;
mod header_chain;
mod lwd_service;
mod middleware;
mod orchard_tree;
mod prover;
mod rendezvous;
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


    /// OPT-IN: serve a standard ZF frostd relay on this address.
    ///
    /// This mounts upstream's own axum router unmodified - we implement none
    /// of the nine endpoints. frostd is designed to be untrusted: every
    /// message is end-to-end encrypted between participants, so running it
    /// grants no ability to read or forge anything.
    ///
    /// Served on its own listener rather than merged into the gRPC surface,
    /// so the lwd-compatible port stays exactly what it was.
    #[arg(long)]
    frostd_listen: Option<std::net::SocketAddr>,

    /// Serve frostd on a non-loopback address without TLS.
    ///
    /// Ceremony contents stay end-to-end encrypted either way; what leaks is
    /// the login token and the participant public keys. Only sensible if
    /// something else on the path is providing transport security.
    #[arg(long)]
    frostd_insecure: bool,

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
        "surfaces: lightwalletd (always-on) | zidecar-rpc={} | frostd={} | auth={}",
        args.zidecar_rpc,
        args.frostd_listen.is_some(),
        if args.auth_token.is_some() {
            "bearer"
        } else {
            "none"
        },
    );

    // Standard frostd relay, on its own listener. Upstream's router, upstream's
    // handlers - this spawns it and otherwise stays out of the way.
    //
    // Started BEFORE the zebrad connection deliberately: a FROST relay shuttles
    // opaque bytes between signers and has nothing to do with the chain node.
    // Signers coordinating a ceremony should not be blocked because the local
    // zebrad happens to be down.
    if let Some(addr) = args.frostd_listen {
        // We serve frostd without TLS. Every message on it is already
        // end-to-end encrypted, so a listener cannot read a ceremony - but
        // the bearer token and participant public keys do travel in clear,
        // and a stolen token lets someone drain a peer's queue and inject
        // rubbish into a session.
        //
        // So: loopback is fine unguarded, anything else needs saying out
        // loud. Refusing rather than warning, because a warning in a log is
        // not read by the person who typed the address.
        if !addr.ip().is_loopback() && !args.frostd_insecure {
            return Err(anyhow::anyhow!(
                "refusing to serve frostd on {addr} without TLS.\n\
                 Put it behind a reverse proxy that terminates TLS and point \
                 this at 127.0.0.1, or pass --frostd-insecure if you genuinely \
                 mean to expose plaintext HTTP (the login token and participant \
                 keys are visible to anyone on the path; ceremony contents are \
                 not, they are end-to-end encrypted)."
            ));
        }
        let state = frostd::AppState::new()
            .await
            .map_err(|e| anyhow::anyhow!("frostd state: {e}"))?;
        // Upstream's router, plus our /rendezvous/* discovery routes on the
        // same listener: a human room code that bootstraps the key exchange
        // and hands joiners the session uuid. See rendezvous.rs — it admits
        // nobody to anything; the nine frostd endpoints are untouched.
        let app = frostd::router(state).merge(rendezvous::router(rendezvous::RendezvousState::new()));
        let frostd_listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind frostd on {}: {}", addr, e))?;
        info!(
            "frostd relay: enabled on {} (no TLS - put it behind a reverse proxy)",
            addr
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(frostd_listener, app).await {
                tracing::error!("frostd server stopped: {e}");
            }
        });
    } else {
        info!("frostd relay: disabled (use --frostd-listen ADDR to enable)");
    }

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
    // Populated when the zidecar-rpc surface opens NOMT; the shutdown drain
    // below flushes + fsyncs it so a restart can't leave a torn bbn store.
    let mut drain_storage: Option<(Arc<storage::Storage>, String)> = None;

    let mut builder = Server::builder()
        .accept_http1(true)
        // must run before tonic-web decodes frames: rewrites empty-body
        // grpc-web requests (GetLightdInfo probes) into a valid empty frame
        .layer(tower::util::MapRequestLayer::new(
            middleware::empty_grpc_web_body_shim,
        ))
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
        // Hand the drain path a handle so SIGTERM can flush NOMT before exit.
        drain_storage = Some((storage_arc.clone(), args.db_path.clone()));

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
        // Shutdown signal for background loops (graceful-exit plumbing the
        // epoch tasks select on). Sender parked in a leaked guard: zidecar
        // currently runs tasks for the process lifetime; flip to a real
        // broadcast on SIGTERM when a drain path is needed.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        std::mem::forget(shutdown_tx);
        let epoch_manager_bg = epoch_manager.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { epoch_manager_bg.run_background_prover(rx).await });
        let epoch_manager_state = epoch_manager.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { epoch_manager_state.run_background_state_tracker(rx).await });
        let epoch_manager_tip = epoch_manager.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { epoch_manager_tip.run_background_tip_prover(rx).await });
        let epoch_manager_nf = epoch_manager.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { epoch_manager_nf.run_background_nullifier_sync(rx).await });
        // Ironwood indexes on its own cursor, concurrently with the full-chain
        // backfill: it spans only ~9k blocks from NU6.3 activation, so it is
        // servable in minutes instead of waiting out the backfill.
        let epoch_manager_iw = epoch_manager.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { epoch_manager_iw.run_background_ironwood_sync(rx).await });
        info!(
            "  epoch proof generator + state tracker + tip prover + nullifier sync \
             + ironwood sync: running"
        );

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
        let zidecar_server =
            zidecar::zidecar_server::ZidecarServer::with_interceptor(service, auth.clone());
        router = router.add_service(tonic_web::enable(zidecar_server));
    } else {
        info!("zidecar-rpc surface: disabled (use --zidecar-rpc to enable)");
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

    // Graceful shutdown. Without this, `systemctl restart` (SIGTERM) killed the
    // process mid-commit and NOMT v1.0.3's un-fsynced post-meta page writes were
    // lost, leaving a torn bbn store that fails to reopen ("failed to
    // reconstruct btree from bbn store file") — which cost us the whole
    // nullifier/commitment index three times. Storage::flush + fsync_nomt_files
    // existed for exactly this and had no caller.
    router
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await?;

    if let Some((storage, db_path)) = drain_storage {
        info!("draining NOMT before exit...");
        if let Err(e) = storage.flush() {
            warn!("NOMT flush failed on shutdown: {}", e);
        }
        if let Err(e) = storage::Storage::fsync_nomt_files(&db_path) {
            warn!("NOMT fsync failed on shutdown: {}", e);
        }
        info!("NOMT drained");
    }

    Ok(())
}

/// Resolve on SIGTERM (systemd stop/restart) or SIGINT (Ctrl-C).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!("cannot install SIGTERM handler: {}", e);
                return std::future::pending().await;
            }
        };
        tokio::select! {
            _ = term.recv() => info!("SIGTERM received, shutting down"),
            _ = tokio::signal::ctrl_c() => info!("SIGINT received, shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

// generated proto modules
pub mod zidecar {
    tonic::include_proto!("zidecar.v1");
}

pub mod lightwalletd {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}


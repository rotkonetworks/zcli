use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tracing::{error, info};

mod auth;
mod service;
mod syncer;

pub mod proto {
    tonic::include_proto!("zclid.v1");
}

#[derive(Parser, Debug)]
#[command(name = "zclid")]
#[command(about = "background wallet daemon for zcli")]
struct Args {
    /// zidecar endpoint
    #[arg(long, default_value = "https://zcash.rotko.net", env = "ZCLI_ENDPOINT")]
    endpoint: String,

    /// lightwalletd cross-verification endpoints (comma-separated)
    #[arg(long, default_value = "", env = "ZCLI_VERIFY")]
    verify_endpoints: String,

    /// unix socket for local zcli (fast, no auth)
    #[arg(long, default_value = "~/.zcli/zclid.sock")]
    socket: String,

    /// tcp listen address for remote access (zafu, agents)
    /// disabled by default — enable with e.g. --listen 127.0.0.1:9067
    #[arg(long)]
    listen: Option<String>,

    /// path to ed25519 SSH key for wallet derivation
    #[arg(short = 'i', long, default_value = "~/.ssh/id_ed25519")]
    identity: String,

    /// BIP-39 mnemonic (alternative to SSH key)
    #[arg(long, env = "ZCLI_MNEMONIC")]
    mnemonic: Option<String>,

    /// view-only mode — no spending key, builds unsigned txs for external signing
    #[arg(long)]
    view_only: bool,

    /// FVK hex (for view-only mode without SSH key)
    #[arg(long, env = "ZCLI_FVK")]
    fvk: Option<String>,

    /// use testnet
    #[arg(long)]
    testnet: bool,

    /// mempool poll interval in seconds
    #[arg(long, default_value_t = 10)]
    mempool_interval: u64,

    /// sync poll interval in seconds
    #[arg(long, default_value_t = 30)]
    sync_interval: u64,
}

pub struct DaemonState {
    pub synced_to: u32,
    pub chain_tip: u32,
    pub syncing: bool,
    pub mempool_txs_seen: u32,
    pub mempool_actions_scanned: u32,
    pub pending_events: Vec<proto::PendingEvent>,
    pub started_at: u64,
    pub endpoint: String,
}

impl DaemonState {
    fn new(endpoint: &str) -> Self {
        Self {
            synced_to: 0,
            chain_tip: 0,
            syncing: false,
            mempool_txs_seen: 0,
            mempool_actions_scanned: 0,
            pending_events: Vec::new(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            endpoint: endpoint.to_string(),
        }
    }
}

pub type SharedState = Arc<RwLock<DaemonState>>;

fn expand_tilde(p: &str) -> String {
    if let Some(stripped) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, stripped);
        }
    }
    p.to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zclid=info".into()),
        )
        .init();

    // disable core dumps — spending key should not be written to disk
    #[cfg(unix)]
    {
        use std::io::Error;
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &libc::rlimit { rlim_cur: 0, rlim_max: 0 }) };
        if ret != 0 {
            tracing::warn!("failed to disable core dumps: {}", Error::last_os_error());
        }
    }

    let args = Args::parse();
    let mainnet = !args.testnet;

    info!("zclid v{}", env!("CARGO_PKG_VERSION"));
    info!("endpoint: {}", args.endpoint);

    // derive keys — either full custody (spending key) or view-only (FVK only)
    let (fvk, spending_key) = if args.view_only {
        // view-only: FVK required — spending key never touches memory
        let fvk_hex = args.fvk.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--view-only requires --fvk <hex> (use `zcli export --fvk` to get it)")
        })?;
        let bytes = hex::decode(fvk_hex)
            .map_err(|e| anyhow::anyhow!("invalid FVK hex: {}", e))?;
        let fvk_arr: [u8; 96] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("FVK must be 96 bytes"))?;
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_arr)
            .ok_or_else(|| anyhow::anyhow!("invalid FVK"))?;
        info!("mode: view-only (FVK only, spending key never loaded)");
        (fvk, None)
    } else {
        // custody mode: retain spending key for signing
        let seed = if let Some(ref mnemonic) = args.mnemonic {
            zecli::key::load_mnemonic_seed(mnemonic)?
        } else {
            let key_path = expand_tilde(&args.identity);
            info!("identity: {}", key_path);
            zecli::key::load_ssh_seed(&key_path)?
        };
        let coin_type = if mainnet { 133 } else { 1 };
        let sk = orchard::keys::SpendingKey::from_zip32_seed(
            seed.as_bytes(), coin_type, zip32::AccountId::ZERO,
        ).map_err(|_| anyhow::anyhow!("failed to derive spending key"))?;
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        info!("mode: full custody (spending key held)");
        (fvk, Some(sk))
    };

    let state: SharedState = Arc::new(RwLock::new(DaemonState::new(&args.endpoint)));
    let wallet_path = zecli::wallet::Wallet::default_path();

    let svc_fvk = fvk.clone();
    let syncer = syncer::Syncer {
        fvk,
        endpoint: args.endpoint.clone(),
        verify_endpoints: args.verify_endpoints.clone(),
        mainnet,
        wallet_path: wallet_path.clone(),
        state: state.clone(),
        sync_interval: args.sync_interval,
        mempool_interval: args.mempool_interval,
    };
    tokio::spawn(async move {
        syncer.run().await;
    });

    let svc = service::WalletDaemonService {
        state: state.clone(),
        wallet_path: wallet_path.clone(),
        endpoint: args.endpoint.clone(),
        fvk: svc_fvk,
        spending_key: spending_key.map(|sk| Arc::new(sk)),
        mainnet,
    };

    let grpc_svc = proto::wallet_daemon_server::WalletDaemonServer::new(svc);

    // unix socket for local zcli
    let socket_path = expand_tilde(&args.socket);
    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        std::fs::create_dir_all(parent)?;
        // restrict parent directory so other users can't access socket
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    // remove stale socket — but only if it's actually a socket (prevent symlink attack)
    let sp = std::path::Path::new(&socket_path);
    if sp.exists() {
        let meta = std::fs::symlink_metadata(sp)?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("socket path {} is a symlink — refusing to proceed", socket_path);
        }
        std::fs::remove_file(sp)?;
    }
    let uds = tokio::net::UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);
    info!("local socket: {}", socket_path);

    // optional tcp for remote access (with bearer token auth)
    if let Some(ref addr_str) = args.listen {
        let addr: std::net::SocketAddr = addr_str.parse()?;

        let token_path = expand_tilde("~/.zcli/zclid.token");
        let token = auth::load_or_generate_token(&token_path)?;
        info!("remote tcp: {}", addr);
        info!("auth token: {}", token_path);

        let tcp_svc = grpc_svc.clone();
        let auth_layer = auth::AuthLayer::new(token);
        tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .layer(auth_layer)
                .add_service(tcp_svc)
                .serve(addr)
                .await
            {
                error!("tcp server failed: {}", e);
            }
        });
    }

    // serve on unix socket (main task)
    Server::builder()
        .add_service(grpc_svc)
        .serve_with_incoming(uds_stream)
        .await?;

    Ok(())
}

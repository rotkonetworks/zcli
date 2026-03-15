use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zcli", about = "zcash wallet CLI - ssh keys as wallet seed")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// path to ed25519 ssh private key
    #[arg(
        short = 'i',
        long = "identity",
        global = true,
        env = "ZCLI_IDENTITY",
        default_value = "~/.ssh/id_ed25519"
    )]
    pub identity: String,

    /// use bip39 mnemonic instead of ssh key
    #[arg(long, global = true, env = "ZCLI_MNEMONIC")]
    pub mnemonic: Option<String>,

    /// zidecar gRPC endpoint
    #[arg(
        long,
        global = true,
        env = "ZCLI_ENDPOINT",
        default_value = "https://zcash.rotko.net"
    )]
    pub endpoint: String,

    /// lightwalletd endpoints for cross-verification (comma-separated, empty to disable)
    #[arg(
        long,
        global = true,
        env = "ZCLI_VERIFY_ENDPOINTS",
        default_value = "https://na.zec.rocks,https://eu.zec.rocks,https://ap.zec.rocks,https://us.zec.stardust.rest,https://eu.zec.stardust.rest,https://jp.zec.stardust.rest"
    )]
    pub verify_endpoints: String,

    /// machine-readable json output, no prompts/progress/qr
    #[arg(long, global = true, env = "ZCLI_JSON")]
    pub json: bool,

    /// use mainnet (default)
    #[arg(long, global = true, default_value_t = true)]
    pub mainnet: bool,

    /// use testnet
    #[arg(long, global = true)]
    pub testnet: bool,

    /// use watch-only (FVK) wallet instead of SSH key wallet
    #[arg(short = 'w', long, global = true, env = "ZCLI_WATCH")]
    pub watch: bool,
}

impl Cli {
    pub fn is_mainnet(&self) -> bool {
        !self.testnet
    }

    fn expand_tilde(path: &str) -> String {
        if let Some(rest) = path.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                return format!("{}/{}", home.to_string_lossy(), rest);
            }
        }
        path.to_string()
    }

    /// resolve identity key path with priority:
    /// - i flag / ZCLI_IDENTITY → ~/.config/zcli/id_zcli → ~/.ssh/id_ed25519
    pub fn identity_path(&self) -> String {
        let explicit = Self::expand_tilde(&self.identity);

        // if user explicitly set - i or ZCLI_IDENTITY, use that
        if self.identity != "~/.ssh/id_ed25519" {
            return explicit;
        }

        // check ~/.config/zcli/id_zcli
        let config_key = Self::expand_tilde("~/.config/zcli/id_zcli");
        if std::path::Path::new(&config_key).exists() {
            return config_key;
        }

        explicit
    }

    /// resolve mnemonic with priority:
    /// --mnemonic / ZCLI_MNEMONIC → ~/.config/zcli/mnemonic.age (decrypted via identity key)
    pub fn mnemonic_source(&self) -> Option<MnemonicSource> {
        if let Some(ref m) = self.mnemonic {
            return Some(MnemonicSource::Plaintext(m.clone()));
        }

        let age_path = Self::expand_tilde("~/.config/zcli/mnemonic.age");
        if std::path::Path::new(&age_path).exists() {
            return Some(MnemonicSource::AgeFile(age_path));
        }

        None
    }
}

pub enum MnemonicSource {
    Plaintext(String),
    AgeFile(String),
}

#[derive(Subcommand)]
pub enum Command {
    /// show wallet addresses
    Address {
        /// show orchard (shielded) address
        #[arg(long)]
        orchard: bool,

        /// show transparent address
        #[arg(long)]
        transparent: bool,
    },

    /// show wallet balance
    Balance,

    /// shield transparent funds (t→z)
    Shield {
        /// fee override in zatoshis (auto-computed if omitted)
        #[arg(long)]
        fee: Option<u64>,
    },

    /// send zcash
    Send {
        /// amount in ZEC (e.g. 0.001)
        amount: String,

        /// recipient: t1.../u1...
        recipient: String,

        /// memo text (shielded only)
        #[arg(long)]
        memo: Option<String>,

        /// airgap mode: display QR for zigner signing, wait for response
        #[arg(long)]
        airgap: bool,
    },

    /// print receiving address
    Receive,

    /// scan chain for wallet notes
    Sync {
        /// start scanning from this block height
        #[arg(long)]
        from: Option<u32>,

        /// starting orchard position counter (use with --from to skip full scan)
        #[arg(long)]
        position: Option<u64>,
    },

    /// export wallet keys (requires confirmation)
    Export,

    /// list all received notes
    Notes,

    /// show transaction history (received + sent)
    History,

    /// run board: sync loop + HTTP API serving notes as JSON
    Board {
        /// HTTP port
        #[arg(long, default_value_t = 3333)]
        port: u16,

        /// sync interval in seconds
        #[arg(long, default_value_t = 300)]
        interval: u64,

        /// also write memos.json to this directory after each sync
        #[arg(long)]
        dir: Option<String>,
    },

    /// scan QR code from webcam
    Scan {
        /// camera device
        #[arg(long, default_value = "/dev/video0", env = "ZCLI_CAM")]
        device: String,

        /// timeout in seconds
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },

    /// import FVK from zigner QR (watch-only wallet)
    ImportFvk {
        /// hex-encoded FVK bytes (or scan from webcam if omitted)
        hex: Option<String>,
    },

    /// verify proofs: header chain, commitment proofs, nullifier proofs
    Verify,

    /// show orchard tree info at a height (for --position)
    TreeInfo {
        /// block height
        height: u32,
    },

    /// merchant payment acceptance + cold storage forwarding
    Merchant {
        #[command(subcommand)]
        action: MerchantAction,
    },

    /// FROST threshold multisig (t-of-n) using rerandomized RedPallas
    Multisig {
        #[command(subcommand)]
        action: MultisigAction,
    },
}

#[derive(Subcommand)]
pub enum MultisigAction {
    /// generate key shares using trusted dealer (simple, requires trust)
    Dealer {
        /// minimum signers required (threshold)
        #[arg(short = 't', long, default_value_t = 2)]
        min_signers: u16,

        /// total number of participants
        #[arg(short = 'n', long, default_value_t = 3)]
        max_signers: u16,
    },

    /// DKG round 1: generate commitment to broadcast
    DkgPart1 {
        /// your participant index (1-indexed)
        #[arg(short, long)]
        index: u16,

        /// total participants
        #[arg(short = 'n', long)]
        max_signers: u16,

        /// threshold (minimum signers)
        #[arg(short = 't', long)]
        min_signers: u16,
    },

    /// DKG round 2: process round1 packages from peers
    DkgPart2 {
        /// your round1 secret package (hex, from dkg-part1)
        secret: String,

        /// round1 packages from peers as index:hex pairs (comma-separated, e.g. "1:abc,2:def")
        #[arg(short, long, value_delimiter = ',')]
        packages: Vec<String>,
    },

    /// DKG round 3: finalize key generation
    DkgPart3 {
        /// your round2 secret package (hex, from dkg-part2)
        secret: String,

        /// round1 packages as index:hex pairs (comma-separated)
        #[arg(short = 'r', long, value_delimiter = ',')]
        round1_packages: Vec<String>,

        /// round2 packages as index:hex pairs (comma-separated)
        #[arg(short = 's', long, value_delimiter = ',')]
        round2_packages: Vec<String>,
    },

    /// signing round 1: generate nonces and commitments
    SignRound1 {
        /// your key package (hex, from dkg-part3 or dealer)
        key_package: String,
    },

    /// generate randomizer for a signing session (coordinator does this, shares with signers)
    Randomize {
        /// public key package (hex)
        public_key_package: String,

        /// message to sign (hex)
        message: String,

        /// all commitments as index:hex pairs (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
    },

    /// signing round 2: produce signature share
    SignRound2 {
        /// your key package (hex)
        key_package: String,

        /// your nonces from round1 (hex)
        nonces: String,

        /// message to sign (hex)
        message: String,

        /// randomizer from coordinator (hex)
        randomizer: String,

        /// all commitments as index:hex pairs (comma-separated, e.g. "1:abc,2:def")
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
    },

    /// aggregate signature shares into final signature (coordinator)
    Aggregate {
        /// public key package (hex)
        public_key_package: String,

        /// message that was signed (hex)
        message: String,

        /// randomizer used for signing (hex, from randomize step)
        randomizer: String,

        /// all commitments as index:hex pairs (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,

        /// signature shares as index:hex pairs (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        shares: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum MerchantAction {
    /// create a new payment request (unique diversified address)
    Create {
        /// amount in ZEC (e.g. 0.001), or "0" for any amount
        amount: String,

        /// label / memo for this request
        #[arg(long)]
        memo: Option<String>,

        /// permanent deposit address (exchange-style, accumulates deposits)
        #[arg(long)]
        deposit: bool,
    },

    /// list payment requests
    List {
        /// filter by status: pending, paid, forwarded, forward_failed
        #[arg(long)]
        status: Option<String>,
    },

    /// sync + match payments + optionally forward to cold storage
    Check {
        /// cold storage address (overrides env/db)
        #[arg(long, env = "ZCLI_FORWARD")]
        forward: Option<String>,

        /// minimum confirmation depth for matching payments
        #[arg(long, default_value_t = 10, env = "ZCLI_CONFIRMATIONS")]
        confirmations: u32,

        /// webhook URL to POST payment state
        #[arg(long, env = "ZCLI_WEBHOOK_URL")]
        webhook_url: Option<String>,

        /// HMAC-SHA256 secret for webhook signatures
        #[arg(long, env = "ZCLI_WEBHOOK_SECRET")]
        webhook_secret: Option<String>,
    },

    /// continuous sync + match + forward loop
    Watch {
        /// cold storage address (overrides env/db)
        #[arg(long, env = "ZCLI_FORWARD")]
        forward: Option<String>,

        /// minimum confirmation depth for matching payments
        #[arg(long, default_value_t = 10, env = "ZCLI_CONFIRMATIONS")]
        confirmations: u32,

        /// sync interval in seconds
        #[arg(long, default_value_t = 300)]
        interval: u64,

        /// write requests.json to this directory after each cycle (same-machine)
        #[arg(long)]
        dir: Option<String>,

        /// webhook URL to POST payment state (remote)
        #[arg(long, env = "ZCLI_WEBHOOK_URL")]
        webhook_url: Option<String>,

        /// HMAC-SHA256 secret for webhook signatures
        #[arg(long, env = "ZCLI_WEBHOOK_SECRET")]
        webhook_secret: Option<String>,

        /// exchange API QUIC address (e.g. "192.168.1.10:4433")
        #[arg(long, env = "ZCLI_QUIC")]
        quic: Option<String>,

        /// hex-encoded ed25519 pubkey of the exchange API (peer verification)
        #[arg(long, env = "ZCLI_PEER_KEY")]
        peer_key: Option<String>,
    },

    /// queue a withdrawal (payout from hot wallet)
    Withdraw {
        /// amount in ZEC (e.g. 0.5)
        amount: String,

        /// recipient address: t1.../u1...
        address: String,

        /// label / memo for this withdrawal
        #[arg(long)]
        memo: Option<String>,
    },

    /// list withdrawal requests
    WithdrawList {
        /// filter by status: pending, completed, failed, insufficient
        #[arg(long)]
        status: Option<String>,
    },

    /// set or show the default forward address
    SetForward {
        /// cold storage address to store (omit to show current)
        address: Option<String>,
    },
}

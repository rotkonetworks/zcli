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

    /// use mainnet (always true — testnet not supported yet)
    #[arg(long, global = true, default_value_t = true, hide = true)]
    pub mainnet: bool,

    /// use watch-only (FVK) wallet instead of SSH key wallet
    #[arg(short = 'w', long, global = true, env = "ZCLI_WATCH")]
    pub watch: bool,
}

impl Cli {
    pub fn is_mainnet(&self) -> bool {
        true
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
    /// View private chain state: balance, notes, addresses, history [aliases: v]
    #[command(alias = "v")]
    View {
        #[command(subcommand)]
        action: ViewAction,
    },

    /// Create and broadcast transactions [aliases: tx]
    #[command(alias = "tx")]
    Transaction {
        #[command(subcommand)]
        action: TxAction,
    },

    /// Air-gapped signer interaction: export notes, scan QR, verify proofs [aliases: s]
    #[command(alias = "s")]
    Signer {
        #[command(subcommand)]
        action: SignerAction,
    },

    /// FROST threshold multisig (t-of-n) [aliases: ms]
    #[command(alias = "ms")]
    Multisig {
        #[command(subcommand)]
        action: MultisigAction,
    },

    /// Initialize wallet: import FVK, sync chain
    Init {
        #[command(subcommand)]
        action: InitAction,
    },

    /// Background services and debug tools
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
pub enum ViewAction {
    /// show wallet balance
    Balance,

    /// show receiving address (default: shielded u1, rotates each call)
    Address {
        /// show transparent t-address instead of shielded
        #[arg(short = 't', long)]
        transparent: bool,

        /// print only the address string (no QR), for scripting/piping
        #[arg(short = 'e', long = "ephemeral")]
        ephemeral: bool,
    },

    /// list all received notes
    Notes,

    /// show transaction history (received + sent)
    History,

    /// export wallet keys (requires confirmation)
    Export,
}

#[derive(Subcommand)]
pub enum TxAction {
    /// send zcash
    Send {
        /// amount in ZEC (e.g. 0.001)
        amount: String,

        /// recipient: t1.../u1...
        recipient: String,

        /// memo text (shielded only)
        #[arg(long)]
        memo: Option<String>,

        /// airgap mode: display PCZT QR for zigner signing
        #[arg(long)]
        airgap: bool,
    },

    /// shield transparent funds (t→z)
    Shield {
        /// fee override in zatoshis (auto-computed if omitted)
        #[arg(long)]
        fee: Option<u64>,
    },
}

#[derive(Subcommand)]
pub enum SignerAction {
    /// export notes + merkle paths as animated QR for zigner
    ExportNotes {
        /// QR frame interval in milliseconds
        #[arg(long, default_value_t = 250)]
        interval: u64,

        /// max UR fragment length in bytes (controls QR density vs frame count)
        #[arg(long, default_value_t = 200)]
        fragment_size: usize,
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

    /// verify proofs: header chain, commitment proofs, nullifier proofs
    Verify,
}

#[derive(Subcommand)]
pub enum InitAction {
    /// import FVK from zigner QR (watch-only wallet)
    ImportFvk {
        /// hex-encoded FVK bytes (or scan from webcam if omitted)
        hex: Option<String>,
    },

    /// scan chain for wallet notes
    Sync {
        /// start scanning from this block height
        #[arg(long)]
        from: Option<u32>,

        /// starting orchard position counter (use with --from to skip full scan)
        #[arg(long)]
        position: Option<u64>,

        /// full rescan from orchard activation (for restoring old wallets)
        #[arg(long)]
        full: bool,
    },
}

#[derive(Subcommand)]
pub enum ServiceAction {
    /// merchant payment acceptance + cold storage forwarding
    Merchant {
        #[command(subcommand)]
        action: MerchantAction,
    },

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

    /// show orchard tree info at a height (for --position)
    TreeInfo {
        /// block height
        height: u32,
    },
}

#[derive(Subcommand)]
pub enum MultisigAction {
    /// generate key shares using trusted dealer (each share includes an ed25519 identity)
    Dealer {
        #[arg(short = 't', long, default_value_t = 2)]
        min_signers: u16,
        #[arg(short = 'n', long, default_value_t = 3)]
        max_signers: u16,
    },

    /// DKG round 1: generate ephemeral identity + signed commitment
    DkgPart1 {
        #[arg(short = 'n', long)]
        max_signers: u16,
        #[arg(short = 't', long)]
        min_signers: u16,
        /// display QR code for air-gapped zigner to scan
        #[arg(long)]
        qr: bool,
        /// label for the multisig wallet (used with --qr)
        #[arg(long, default_value = "")]
        label: String,
    },

    /// DKG round 2: process signed round1 broadcasts from peers
    DkgPart2 {
        /// your round1 secret state (hex, from dkg-part1)
        secret: String,
        /// signed round1 broadcasts from all other participants (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        packages: Vec<String>,
    },

    /// DKG round 3: finalize — produces key package + public key package
    DkgPart3 {
        /// your round2 secret state (hex, from dkg-part2)
        secret: String,
        /// signed round1 broadcasts from peers (hex, comma-separated)
        #[arg(short = 'r', long, value_delimiter = ',')]
        round1_packages: Vec<String>,
        /// signed round2 packages received from peers (hex, comma-separated)
        #[arg(short = 's', long, value_delimiter = ',')]
        round2_packages: Vec<String>,
    },

    /// signing round 1: generate ephemeral-signed nonces + commitments
    SignRound1 {
        /// your ephemeral seed (hex, from dealer bundle or dkg-part3)
        ephemeral_seed: String,
        /// your key package (hex)
        key_package: String,
    },

    /// coordinator: generate signed randomizer (broadcast to all signers)
    Randomize {
        /// coordinator's ephemeral seed (hex)
        ephemeral_seed: String,
        /// message to sign (hex)
        message: String,
        /// signed commitments from all signers (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
    },

    /// signing round 2: produce ephemeral-signed signature share
    SignRound2 {
        /// your ephemeral seed (hex)
        ephemeral_seed: String,
        /// your key package (hex)
        key_package: String,
        /// your nonces from round1 (hex, NOT the signed broadcast)
        nonces: String,
        /// message to sign (hex)
        message: String,
        /// signed randomizer from coordinator (hex)
        randomizer: String,
        /// signed commitments from all signers (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
    },

    /// coordinator: aggregate signed shares into final signature
    Aggregate {
        /// public key package (hex)
        public_key_package: String,
        /// message that was signed (hex)
        message: String,
        /// signed randomizer (hex, from randomize step)
        randomizer: String,
        /// signed commitments from all signers (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
        /// signed signature shares (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        shares: Vec<String>,
    },

    /// derive the multisig wallet's Orchard receiving address
    DeriveAddress {
        /// public key package (hex, from dealer or dkg-part3)
        public_key_package: String,
        /// diversifier index (default 0)
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },

    /// spend-authorize round 2: produce FROST share bound to sighash + alpha
    SpendSign {
        /// your key package (hex)
        key_package: String,
        /// your nonces from round1 (hex)
        nonces: String,
        /// transaction sighash (32 bytes hex)
        sighash: String,
        /// per-action alpha randomizer (32 bytes hex)
        alpha: String,
        /// signed commitments from all signers (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
    },

    /// coordinator: aggregate FROST shares into Orchard SpendAuth signature
    SpendAggregate {
        /// public key package (hex)
        public_key_package: String,
        /// transaction sighash (32 bytes hex)
        sighash: String,
        /// per-action alpha randomizer (32 bytes hex)
        alpha: String,
        /// signed commitments from all signers (hex, comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        commitments: Vec<String>,
        /// signature shares (hex, comma-separated)
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

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

    /// lightwalletd endpoint for cross-verification (empty to disable)
    #[arg(
        long,
        global = true,
        env = "ZCLI_VERIFY_ENDPOINT",
        default_value = "https://mainnet.lightwalletd.com"
    )]
    pub verify_endpoint: String,

    /// machine-readable json output, no prompts/progress/qr
    #[arg(long, visible_alias = "json", global = true, env = "ZCLI_SCRIPT")]
    pub script: bool,

    /// use mainnet (default)
    #[arg(long, global = true, default_value_t = true)]
    pub mainnet: bool,

    /// use testnet
    #[arg(long, global = true)]
    pub testnet: bool,
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

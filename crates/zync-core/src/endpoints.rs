//! Public lightwalletd endpoints for cross-verification.
//!
//! Geographically diverse nodes from independent operators.
//! Cross-verification requires >2/3 agreement (BFT majority) to detect
//! single-server eclipse attacks. Using nodes from different providers
//! and regions makes coordinated lying harder.

// zec.rocks (operated by Zcash community)
pub const LIGHTWALLETD_ZEC_ROCKS: &str = "https://zec.rocks";
pub const LIGHTWALLETD_ZEC_ROCKS_NA: &str = "https://na.zec.rocks";
pub const LIGHTWALLETD_ZEC_ROCKS_EU: &str = "https://eu.zec.rocks";
pub const LIGHTWALLETD_ZEC_ROCKS_AP: &str = "https://ap.zec.rocks";
pub const LIGHTWALLETD_ZEC_ROCKS_SA: &str = "https://sa.zec.rocks";

// stardust (operated by Chainsafe)
pub const LIGHTWALLETD_STARDUST_US: &str = "https://us.zec.stardust.rest";
pub const LIGHTWALLETD_STARDUST_EU: &str = "https://eu.zec.stardust.rest";
pub const LIGHTWALLETD_STARDUST_EU2: &str = "https://eu2.zec.stardust.rest";
pub const LIGHTWALLETD_STARDUST_JP: &str = "https://jp.zec.stardust.rest";

// testnet
pub const LIGHTWALLETD_TESTNET: &str = "https://testnet.zec.rocks";

/// Default cross-verification endpoints for mainnet.
///
/// One node per region from each provider for geographic and operator diversity.
/// All use port 443 with TLS.
pub const CROSSVERIFY_MAINNET: &[&str] = &[
    LIGHTWALLETD_ZEC_ROCKS_NA, // zec.rocks, North America
    LIGHTWALLETD_ZEC_ROCKS_EU, // zec.rocks, Europe
    LIGHTWALLETD_ZEC_ROCKS_AP, // zec.rocks, Asia Pacific
    LIGHTWALLETD_STARDUST_US,  // stardust, US
    LIGHTWALLETD_STARDUST_EU,  // stardust, Europe
    LIGHTWALLETD_STARDUST_JP,  // stardust, Japan
];

/// Default cross-verification endpoints for testnet.
pub const CROSSVERIFY_TESTNET: &[&str] = &[LIGHTWALLETD_TESTNET];

pub mod address;
pub mod error;
pub mod key;
pub mod pczt;
pub mod tx;

#[cfg(feature = "cli")]
#[cfg(target_os = "linux")]
pub mod cam;
#[cfg(feature = "cli")]
pub mod client;
#[cfg(feature = "cli")]
pub mod frost;
#[cfg(feature = "cli")]
pub mod frost_qr;
#[cfg(feature = "cli")]
pub mod frost_relay;

/// Standard ZF frostd relay transport. See the module note: this exists to
/// replace frost_relay, which is ours to maintain and speaks nobody else's
/// protocol.
pub mod frostd_transport;
#[cfg(feature = "cli")]
pub mod notes_export;
#[cfg(feature = "cli")]
pub mod ops;
#[cfg(feature = "cli")]
pub mod quic;
#[cfg(feature = "cli")]
pub mod wallet;
#[cfg(feature = "cli")]
pub mod witness;

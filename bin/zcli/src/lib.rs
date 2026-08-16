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

/// Run a FROST ceremony over a standard frostd relay.
pub mod frost_ceremony;
/// Standard ZF frostd relay transport, via ZF's own frost-client.
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

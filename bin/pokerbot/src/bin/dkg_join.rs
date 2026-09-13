//! dkg-join - run ONE frostd+rendezvous DKG joiner against an escrow's room, for
//! local end-to-end testing of the migrated non-uuid path. Usage:
//!   dkg-join <relay-http-url> <bip39-room-code> [test|main]
//! Prints the derived escrow UA on success (parties must all print the same one).

use std::time::Duration;

use pokerbot::dkg;
use zcash_protocol::consensus::NetworkType;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let relay = args.next().expect("usage: dkg-join <relay-url> <room-code> [network]");
    let code = args.next().expect("usage: dkg-join <relay-url> <room-code> [network]");
    let network = match args.next().as_deref() {
        Some("main") => NetworkType::Main,
        _ => NetworkType::Test,
    };

    match dkg::run_dkg_joiner_frostd(&relay, &code, network, Duration::from_secs(60)).await {
        Ok(out) => {
            eprintln!("DKG OK - net={:?}", out.network);
            // machine-readable: the group escrow UA all parties must agree on
            println!("UA {}", out.orchard_ua);
        }
        Err(e) => {
            eprintln!("DKG FAILED: {e}");
            std::process::exit(1);
        }
    }
}

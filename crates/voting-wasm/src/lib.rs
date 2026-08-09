//! Standalone WASM bindings for zafu shielded voting.
//!
//! Kept SEPARATE from `zafu-wasm` (the core wallet scanning/spend module) on
//! purpose: `zcash_voting` + `voting-circuits` pull their own orchard/pczt/
//! zcash_primitives graph, which must stay version-independent from the core
//! wallet module (co-versioning previously caused digest-pin and
//! sqlite/pool_migration conflicts). The extension lazy-loads this module
//! only when the vote-cast UI is opened; the core wallet never pays for it.
//!
//! Build with:
//! ```bash
//! ./build-wasm.sh
//! ```

/// HOT shielded-voting vote-casting bindings (casting slice only).
mod voting;
/// Shielded-voting delegation bindings (cold-signed PCZT + ZKP #1).
mod voting_delegation;
/// PIR bindings: fetch IMT non-membership proofs via a JS `fetch` callback.
mod voting_pir;

use wasm_bindgen::prelude::*;

/// Install a panic hook that forwards Rust panics to the JS console instead
/// of an opaque "unreachable executed" trap. Call once from JS after load.
#[wasm_bindgen]
pub fn voting_wasm_init_panic_hook() {
    console_error_panic_hook::set_once();
}

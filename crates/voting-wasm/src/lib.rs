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
#[cfg(target_arch = "wasm32")]
mod voting_pir;

use wasm_bindgen::prelude::*;

/// Rayon thread-pool bootstrap, exported as `initThreadPool` (wasm-bindgen-rayon's
/// own naming convention). JS must call this once, with the offscreen document's
/// `navigator.hardwareConcurrency`, before any proving function - mirrors
/// zafu-wasm's `crates/zcash-wasm/src/lib.rs` `pub use wasm_bindgen_rayon::init_thread_pool;`.
/// Only exists under `--features parallel`; the non-parallel build has no pool
/// to initialize and JS must skip the call.
#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

/// Install a panic hook that forwards Rust panics to the JS console instead
/// of an opaque "unreachable executed" trap. Call once from JS after load.
#[wasm_bindgen]
pub fn voting_wasm_init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Self-contained delegation-proof feasibility probe.
///
/// Builds synthetic wallet notes / Merkle witnesses / IMT non-membership
/// proofs entirely inside wasm (no host-supplied inputs) and runs a REAL
/// K=14 halo2 delegation proof via `zcash_voting::selftest`. Exists purely to
/// measure whether K=14 proving completes inside a wasm32 module and how
/// long it takes; the extension does not call this in production flows.
///
/// Returns JSON `{"ok":bool,"proof_len":N,"error":string|null}`. Timing is
/// deliberately left to the JS caller (`Date.now()` around the call) since
/// `std::time::Instant` panics on bare wasm32-unknown-unknown.
#[wasm_bindgen]
pub fn selftest_prove_delegation() -> String {
    match zcash_voting::selftest::run_selftest_delegation_proof() {
        Ok(result) => serde_json::json!({
            "ok": true,
            "proof_len": result.proof.len(),
            "error": null,
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "ok": false,
            "proof_len": 0,
            "error": e.to_string(),
        })
        .to_string(),
    }
}

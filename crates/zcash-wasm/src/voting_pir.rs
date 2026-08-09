//! PIR binding: fetch IMT non-membership proofs for delegation (Option A).
//!
//! The PIR *crypto* runs in wasm (vendored `pir-client` + valar-ypir); the
//! *network* stays in JS. The host supplies one generic async callback and this
//! module drives pir-client's audited tier-1→tier-2 orchestration over it — no
//! hyper/tonic/tokio in wasm. The output matches `finalize_delegation`'s
//! `imt_proofs_json` byte-for-byte.
//!
//! ## HTTP contract the JS `fetch` callback must service
//! Signature: `fetch(method: string, url: string, body?: Uint8Array) -> Promise<Uint8Array>`.
//! It MUST resolve with the raw response body on HTTP 2xx and REJECT (throw) on
//! any non-2xx / network error (status/headers are not surfaced to wasm; only
//! success-body vs failure matters). URLs are formed from `pir_base_url`:
//!   - `GET  {base}/tier0`         -> raw Tier0 bytes
//!   - `GET  {base}/params/tier1`  -> JSON YpirScenario
//!   - `GET  {base}/params/tier2`  -> JSON YpirScenario
//!   - `GET  {base}/root`          -> JSON RootInfo {nullifier_pool,dataset_version,pir_depth,root29(hex),num_ranges}
//!   - `POST {base}/tier1/query`   body = serialized YPIR query -> tier1 response bytes
//!   - `POST {base}/tier2/query`   body = serialized YPIR query -> tier2 response bytes
//! Per nullifier the client issues one tier1 POST then one tier2 POST (the tier2
//! index depends on the decoded tier1 row), all concurrently across nullifiers.

use std::sync::Arc;

use ff::PrimeField;
use js_sys::{Function, Promise, Uint8Array};
use pasta_curves::Fp;
use pir_client::{PirClient, Transport, TransportFuture, TransportResponse};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

/// Bridges pir-client's async `Transport` to a host-provided JS `fetch`.
///
/// wasm32 is single-threaded, so the `!Send` JS handle inside is sound (the
/// vendored `Transport` trait drops its `Send + Sync` bound on wasm).
struct JsFetchTransport {
    js_fetch: Function,
}

impl JsFetchTransport {
    fn call<'a>(
        &'a self,
        method: &'static str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> TransportFuture<'a> {
        let js_fetch = self.js_fetch.clone();
        let url = url.to_string();
        Box::pin(async move {
            let this = JsValue::NULL;
            let body_val: JsValue = match body {
                Some(b) => Uint8Array::from(b.as_slice()).into(),
                None => JsValue::UNDEFINED,
            };
            let ret = js_fetch
                .call3(
                    &this,
                    &JsValue::from_str(method),
                    &JsValue::from_str(&url),
                    &body_val,
                )
                .map_err(|e| anyhow::anyhow!("js fetch threw: {:?}", e))?;
            let promise: Promise = ret
                .dyn_into()
                .map_err(|_| anyhow::anyhow!("js_fetch must return a Promise"))?;
            let resolved = JsFuture::from(promise)
                .await
                .map_err(|e| anyhow::anyhow!("js fetch rejected: {:?}", e))?;
            let arr: Uint8Array = resolved
                .dyn_into()
                .map_err(|_| anyhow::anyhow!("js fetch must resolve to a Uint8Array"))?;
            Ok(TransportResponse {
                status: 200,
                headers: Vec::new(),
                body: arr.to_vec(),
            })
        })
    }
}

impl Transport for JsFetchTransport {
    fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a> {
        self.call("GET", url, None)
    }
    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> TransportFuture<'a> {
        self.call("POST", url, Some(body))
    }
}

fn fp_le_hex(fp: &Fp) -> String {
    hex::encode(fp.to_repr())
}

/// Fetch circuit-ready IMT non-membership proofs for a set of nullifiers.
///
/// `nullifiers_json` is a JSON array of 32-byte LE hex strings — the host passes
/// the UNION of the real-note nullifiers and the dummy-note nullifiers reported
/// by `build_delegation_pczt`. Resolves to a JSON `[ImtProofDto]` exactly as
/// `finalize_delegation` consumes it: `[{nullifier_hex, root_hex,
/// nf_bounds_hex[3], leaf_pos, path_hex[29]}]`.
#[wasm_bindgen]
pub async fn pir_fetch_imt_proofs(
    pir_base_url: String,
    nullifiers_json: String,
    js_fetch: Function,
) -> Result<String, JsError> {
    let nf_hexes: Vec<String> = serde_json::from_str(&nullifiers_json)
        .map_err(|e| JsError::new(&format!("nullifiers_json: {e}")))?;

    let mut nullifiers = Vec::with_capacity(nf_hexes.len());
    for h in &nf_hexes {
        let bytes = hex::decode(h.trim())
            .map_err(|e| JsError::new(&format!("invalid nullifier hex {h}: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsError::new(&format!("nullifier {h} must be 32 bytes")))?;
        let fp = Option::from(Fp::from_repr(arr))
            .ok_or_else(|| JsError::new(&format!("nullifier {h} is not a canonical field element")))?;
        nullifiers.push(fp);
    }

    let transport: Arc<dyn Transport> = Arc::new(JsFetchTransport { js_fetch });
    let client = PirClient::with_transport(&pir_base_url, transport)
        .await
        .map_err(|e| JsError::new(&format!("PIR connect failed: {e}")))?;

    let proofs = client
        .fetch_proofs(&nullifiers)
        .await
        .map_err(|e| JsError::new(&format!("PIR fetch failed: {e}")))?;

    if proofs.len() != nf_hexes.len() {
        return Err(JsError::new(&format!(
            "PIR returned {} proofs for {} nullifiers",
            proofs.len(),
            nf_hexes.len()
        )));
    }

    let dtos: Vec<serde_json::Value> = proofs
        .iter()
        .zip(nf_hexes.iter())
        .map(|(p, nf)| {
            serde_json::json!({
                "nullifier_hex": nf.trim().to_ascii_lowercase(),
                "root_hex": fp_le_hex(&p.root),
                "nf_bounds_hex": [
                    fp_le_hex(&p.nf_bounds[0]),
                    fp_le_hex(&p.nf_bounds[1]),
                    fp_le_hex(&p.nf_bounds[2]),
                ],
                "leaf_pos": p.leaf_pos,
                "path_hex": p.path.iter().map(fp_le_hex).collect::<Vec<_>>(),
            })
        })
        .collect();

    serde_json::to_string(&dtos).map_err(|e| JsError::new(&format!("serialize proofs: {e}")))
}

//! Ring VRF - anonymous "I belong" proof system for pro subscribers.
//!
//! Maintains a daily ring of Bandersnatch public keys for all active pro users.
//! Extension proves membership via Ring VRF without revealing identity.
//! Zidecar verifies proofs and grants priority sync under load.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{self as suite, *};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

type Suite = suite::BandersnatchSha512Ell2;

/// SRS bytes (BLS12-381 Powers of Tau, 2^11 elements)
const SRS_BYTES: &[u8] = include_bytes!("../../../crates/ring-vrf-wasm/data/bls12-381-srs-2-11-uncompressed-zcash.bin");

/// ring is always padded to a power of 2, minimum 64.
/// hides exact subscriber count. padding uses the arkworks padding point.
const MIN_RING_SIZE: usize = 64;

/// Cached ring state, regenerated daily.
pub struct RingState {
    /// all pro subscriber Bandersnatch pubkeys (32 bytes each, hex)
    pub ring_keys: Vec<Vec<u8>>,
    /// ring commitment (144 bytes)
    pub commitment: Vec<u8>,
    /// epoch string (YYYY-MM-DD)
    pub epoch: String,
    /// VRF context string (epoch + nonce)
    pub context: String,
    /// when this ring was built
    pub built_at: Instant,
}

/// Ring VRF manager - maintains ring state, verifies proofs.
pub struct RingVrfManager {
    state: Arc<RwLock<Option<RingState>>>,
    license_url: String,
}

impl RingVrfManager {
    pub fn new(license_url: String) -> Self {
        Self {
            state: Arc::new(RwLock::new(None)),
            license_url,
        }
    }

    /// Get current ring state (builds on first call, caches for the day).
    pub async fn get_ring(&self) -> Option<Arc<RingState>> {
        let today = chrono_today();

        // check if cached ring is still valid
        {
            let state = self.state.read().await;
            if let Some(ref s) = *state {
                if s.epoch == today {
                    // safe to clone Arc-like since we return borrowed data
                    // but we need to return owned - let's restructure
                }
            }
        }

        // rebuild if stale or missing
        let mut state = self.state.write().await;
        if let Some(ref s) = *state {
            if s.epoch == today {
                return Some(Arc::new(RingState {
                    ring_keys: s.ring_keys.clone(),
                    commitment: s.commitment.clone(),
                    epoch: s.epoch.clone(),
                    context: s.context.clone(),
                    built_at: s.built_at,
                }));
            }
        }

        match self.build_ring(&today).await {
            Ok(ring) => {
                let result = Arc::new(RingState {
                    ring_keys: ring.ring_keys.clone(),
                    commitment: ring.commitment.clone(),
                    epoch: ring.epoch.clone(),
                    context: ring.context.clone(),
                    built_at: ring.built_at,
                });
                *state = Some(ring);
                Some(result)
            }
            Err(e) => {
                tracing::warn!("failed to build pro ring: {}", e);
                None
            }
        }
    }

    /// Build ring from license-server data.
    async fn build_ring(&self, epoch: &str) -> anyhow::Result<RingState> {
        // fetch all active pro ring keys from license-server
        let url = format!("{}/ring-keys", self.license_url);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let ring_keys: Vec<Vec<u8>> = match client.get(&url).send().await {
            Ok(resp) => {
                #[derive(serde::Deserialize)]
                struct RingKeysResp {
                    keys: Vec<String>, // hex-encoded 32-byte pubkeys
                }
                let body: RingKeysResp = resp.json().await?;
                body.keys
                    .iter()
                    .filter_map(|h| hex::decode(h).ok())
                    .filter(|k| k.len() == 32)
                    .collect()
            }
            Err(e) => {
                tracing::warn!("license-server unreachable for ring keys: {}", e);
                vec![]
            }
        };

        // pad ring to hide exact subscriber count
        let padded_keys = pad_ring(ring_keys);

        // compute ring commitment over padded ring
        let commitment = if !padded_keys.is_empty() {
            compute_commitment(&padded_keys)?
        } else {
            vec![]
        };
        let ring_keys = padded_keys;

        // context is epoch-scoped. client adds per-request nonce for unlinkability.
        // server verifies against this base context (client appends nonce).
        let nonce = hex::encode(rand::random::<[u8; 8]>());
        let context = format!("zafu-pro-{}-{}", epoch, nonce);

        Ok(RingState {
            ring_keys,
            commitment,
            epoch: epoch.to_string(),
            context,
            built_at: Instant::now(),
        })
    }

    /// Verify a ring VRF proof from a gRPC request header.
    /// The client provides its own context (with per-request nonce) for unlinkability.
    /// We verify the proof is valid against the current ring commitment.
    /// Returns true if the proof is valid.
    pub async fn verify_proof(&self, proof_hex: &str, context: &str) -> bool {
        let state = self.state.read().await;
        let state = match state.as_ref() {
            Some(s) => s,
            _ => return false,
        };

        if state.ring_keys.is_empty() {
            return false;
        }

        // context must start with current epoch prefix (prevents replay from old epochs)
        if !context.starts_with(&format!("zafu-pro-{}", state.epoch)) {
            return false;
        }

        let proof_bytes = match hex::decode(proof_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        verify_ring_proof(
            state.ring_keys.len(),
            &state.commitment,
            context.as_bytes(),
            &proof_bytes,
        )
    }
}

/// Pad ring to next power of 2 (min 64) with arkworks padding points.
/// Hides exact subscriber count - an observer only knows the bucket.
fn pad_ring(mut keys: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if keys.is_empty() {
        return keys;
    }
    let target = MIN_RING_SIZE.max(keys.len().next_power_of_two());
    // serialize the padding point once
    let padding = {
        let mut buf = Vec::new();
        RingProofParams::padding_point()
            .serialize_compressed(&mut buf)
            .expect("padding point serialization");
        buf
    };
    while keys.len() < target {
        keys.push(padding.clone());
    }
    keys
}

/// Compute ring commitment from a list of Bandersnatch public keys.
fn compute_commitment(ring_keys: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    let pcs = PcsParams::deserialize_uncompressed_unchecked(&mut &SRS_BYTES[..])
        .map_err(|e| anyhow::anyhow!("SRS deserialize: {:?}", e))?;
    let params = RingProofParams::from_pcs_params(ring_keys.len(), pcs)
        .map_err(|e| anyhow::anyhow!("ring params: {:?}", e))?;

    let points: Vec<AffinePoint> = ring_keys
        .iter()
        .map(|key_bytes| {
            AffinePoint::deserialize_compressed(&key_bytes[..])
                .unwrap_or(RingProofParams::padding_point())
        })
        .collect();

    let verifier_key = params.verifier_key(&points);
    let commitment = verifier_key.commitment();

    let mut buf = Vec::new();
    commitment
        .serialize_compressed(&mut buf)
        .map_err(|e| anyhow::anyhow!("commitment serialize: {:?}", e))?;

    Ok(buf)
}

/// Verify a ring VRF proof.
fn verify_ring_proof(
    ring_size: usize,
    commitment_bytes: &[u8],
    context: &[u8],
    proof_bytes: &[u8],
) -> bool {
    use ark_vrf::ring::Verifier as _;

    if proof_bytes.len() < 33 || commitment_bytes.len() < 144 {
        return false;
    }

    let pcs = match PcsParams::deserialize_uncompressed_unchecked(&mut &SRS_BYTES[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let params = match RingProofParams::from_pcs_params(ring_size, pcs) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // deserialize commitment
    let commitment = match RingCommitment::deserialize_compressed(&mut &commitment_bytes[..]) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let verifier_key = params.verifier_key_from_commitment(commitment);
    let verifier = params.verifier(verifier_key);

    // parse VRF output (first 32 bytes)
    let output_point = match AffinePoint::deserialize_compressed(&mut &proof_bytes[..32]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let output = ark_vrf::Output::<Suite>::from_affine(output_point);

    // parse ring proof (remaining bytes)
    let proof = match RingProof::deserialize_compressed(&mut &proof_bytes[32..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // construct VRF input
    let input = match ark_vrf::Input::<Suite>::new(context) {
        Some(i) => i,
        None => return false,
    };

    // verify
    ark_vrf::Public::<Suite>::verify(input, output, &[], &proof, &verifier).is_ok()
}

/// Get today's date as YYYY-MM-DD.
fn chrono_today() -> String {
    // simple UTC date without chrono dependency
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    // approximate date calculation (good enough for epoch rotation)
    let y = (10000 * days as u64 + 14780) / 3652425;
    let doy = days as i64 - (365 * y as i64 + y as i64 / 4 - y as i64 / 100 + y as i64 / 400);
    let doy = if doy < 0 {
        let y = y - 1;
        days as i64 - (365 * y as i64 + y as i64 / 4 - y as i64 / 100 + y as i64 / 400)
    } else {
        doy
    };
    let mi = (100 * doy - 52) / 3060;
    let month = mi + 3 - 12 * (mi / 10);
    let year = y + (mi / 10) as u64;
    let day = doy - (mi * 306 + 5) / 10 + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

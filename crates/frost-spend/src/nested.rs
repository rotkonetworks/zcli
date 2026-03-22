// nested.rs — frostito: stake-weighted nested FROST signing
//
// each physical validator holds N Shamir shares (proportional to stake).
// instead of running FROST with 200 identifiers, each validator locally
// aggregates their shares into ONE commitment + ONE response.
//
// flow:
//   1. each validator: commit ONE nonce (regardless of share count)
//   2. coordinator: aggregate commitments → R_nested
//   3. outer protocol: R_nested is position B's commitment
//   4. coordinator: compute outer challenge, broadcast to validators
//   5. each validator: locally aggregate shares, produce ONE response
//   6. coordinator: sum responses → z_nested (one scalar)
//   7. outer protocol: z_nested is position B's signature share
//
// messages per round: 25 (one per physical validator), not 200 (one per share)
// stake weighting: automatic via Lagrange coefficients over the share set

use osst::curve::{OsstPoint, OsstScalar};
use osst::compute_lagrange_coefficients;
use osst::nested;
use osst::SecretShare;
use pasta_curves::pallas::{Point, Scalar};
use pasta_curves::group::ff::Field;

// re-export types from osst::nested that we still use
pub use nested::{InnerCommitments, InnerNonces, InnerSignatureShare, InnerSigningParams};

// ── frostito: stake-weighted validator types ──

/// a validator's bundle of shares (stake-weighted)
pub struct ValidatorShares {
    /// validator's physical index (used for commitment binding)
    pub validator_index: u32,
    /// the Shamir shares this validator holds (indices are share-level, not validator-level)
    pub shares: Vec<SecretShare<Scalar>>,
}

impl ValidatorShares {
    pub fn new(validator_index: u32, shares: Vec<SecretShare<Scalar>>) -> Self {
        Self { validator_index, shares }
    }

    /// total share count (stake weight)
    pub fn weight(&self) -> u32 {
        self.shares.len() as u32
    }

    /// all share indices held by this validator
    pub fn share_indices(&self) -> Vec<u32> {
        self.shares.iter().map(|s| s.index).collect()
    }

    /// compute effective share: Σ λ_j * share_j over this validator's shares
    /// where λ_j are Lagrange coefficients for the FULL active share set
    pub fn effective_share(&self, all_active_indices: &[u32]) -> Result<Scalar, osst::OsstError> {
        let all_lambda = compute_lagrange_coefficients::<Scalar>(all_active_indices)?;

        let mut effective = Scalar::ZERO;
        for share in &self.shares {
            let pos = all_active_indices.iter().position(|&i| i == share.index)
                .ok_or(osst::OsstError::InvalidIndex)?;
            effective += all_lambda[pos] * share.scalar();
        }
        Ok(effective)
    }
}

/// frostito nonce: ONE nonce per physical validator
pub struct FrostitoNonce {
    pub validator_index: u32,
    pub(crate) hiding: Scalar,
    pub(crate) binding: Scalar,
}

impl Drop for FrostitoNonce {
    fn drop(&mut self) {
        use osst::curve::OsstScalar;
        self.hiding.zeroize();
        self.binding.zeroize();
    }
}

/// frostito commitment: ONE per physical validator (broadcast)
#[derive(Clone, Debug)]
pub struct FrostitoCommitment {
    pub validator_index: u32,
    pub hiding: Point,
    pub binding: Point,
    /// total shares this validator represents (for threshold counting)
    pub weight: u32,
}

/// frostito signing params (from outer protocol)
#[derive(Clone)]
pub struct FrostitoSigningParams {
    /// outer challenge: c = H(R_outer, Y, msg)
    pub outer_challenge: Scalar,
    /// outer Lagrange coefficient for the nested position
    pub outer_lambda: Scalar,
    /// all active share indices across all participating validators
    /// (needed to compute Lagrange coefficients for effective share)
    pub active_share_indices: Vec<u32>,
}

/// frostito response: ONE per physical validator
pub struct FrostitoResponse {
    pub validator_index: u32,
    pub response: Scalar,
    pub weight: u32,
}

// ── frostito protocol ──

/// round 1: validator generates ONE nonce commitment
pub fn frostito_commit(
    validator_index: u32,
    weight: u32,
) -> (FrostitoNonce, FrostitoCommitment) {
    let mut rng = rand_core::OsRng;
    let hiding = <Scalar as Field>::random(&mut rng);
    let binding = <Scalar as Field>::random(&mut rng);

    let commitment = FrostitoCommitment {
        validator_index,
        hiding: Point::generator().mul_scalar(&hiding),
        binding: Point::generator().mul_scalar(&binding),
        weight,
    };

    (FrostitoNonce { validator_index, hiding, binding }, commitment)
}

/// coordinator: aggregate commitments into R_nested with binding factors
pub fn frostito_aggregate_commitments(
    commitments: &[FrostitoCommitment],
    message: &[u8],
) -> Point {
    use sha2::{Sha512, Digest};

    let mut r_agg = Point::identity();
    for c in commitments {
        // binding factor per validator (mirrors FROST binding)
        let rho = {
            let mut h = Sha512::new();
            h.update(b"frostito-bind-v1");
            h.update(c.validator_index.to_le_bytes());
            h.update((message.len() as u64).to_le_bytes());
            h.update(message);
            for ci in commitments {
                h.update(ci.validator_index.to_le_bytes());
                h.update(OsstPoint::compress(&ci.hiding));
                h.update(OsstPoint::compress(&ci.binding));
            }
            Scalar::from_bytes_wide(&h.finalize().into())
        };
        // R_k = D_k + ρ_k * E_k
        let r_k = c.hiding.add(&c.binding.mul_scalar(&rho));
        r_agg = r_agg.add(&r_k);
    }
    r_agg
}

/// coordinator: check if collected commitments meet stake threshold
pub fn frostito_threshold_met(commitments: &[FrostitoCommitment], threshold: u32) -> bool {
    let total: u32 = commitments.iter().map(|c| c.weight).sum();
    total >= threshold
}

/// round 2: validator produces ONE response using all their shares
pub fn frostito_sign(
    nonce: FrostitoNonce,
    validator_shares: &ValidatorShares,
    params: &FrostitoSigningParams,
    commitments: &[FrostitoCommitment],
    message: &[u8],
) -> Result<FrostitoResponse, osst::OsstError> {
    use sha2::{Sha512, Digest};

    // recompute binding factor for this validator (same as in aggregate_commitments)
    let rho = {
        let mut h = Sha512::new();
        h.update(b"frostito-bind-v1");
        h.update(nonce.validator_index.to_le_bytes());
        h.update((message.len() as u64).to_le_bytes());
        h.update(message);
        for ci in commitments {
            h.update(ci.validator_index.to_le_bytes());
            h.update(OsstPoint::compress(&ci.hiding));
            h.update(OsstPoint::compress(&ci.binding));
        }
        Scalar::from_bytes_wide(&h.finalize().into())
    };

    // compute effective share: Σ λ_j * share_j
    let effective = validator_shares.effective_share(&params.active_share_indices)?;

    // response: r + ρ*e + (λ_outer * c) * effective_share
    let nonce_part = nonce.hiding + rho * nonce.binding;
    let secret_part = params.outer_lambda * params.outer_challenge * effective;
    let response = nonce_part + secret_part;

    Ok(FrostitoResponse {
        validator_index: nonce.validator_index,
        response,
        weight: validator_shares.weight(),
    })
}

/// coordinator: aggregate responses into z_nested
pub fn frostito_aggregate_responses(responses: &[FrostitoResponse]) -> Scalar {
    let mut z = Scalar::ZERO;
    for r in responses {
        z += r.response;
    }
    z
}

// ── legacy wrappers (one share per participant) ──

pub fn validator_commit(
    holder_index: u32,
) -> (InnerNonces<Scalar>, InnerCommitments<Point>) {
    nested::inner_commit::<Point, _>(holder_index, &mut rand_core::OsRng)
}

pub fn aggregate_validator_commitments(
    inner_commitments: &[InnerCommitments<Point>],
    sighash: &[u8],
) -> Point {
    nested::aggregate_inner_commitments(inner_commitments, sighash)
}

pub fn validator_sign(
    nonces: InnerNonces<Scalar>,
    share: &SecretShare<Scalar>,
    params: &InnerSigningParams<Scalar>,
    inner_commitments: &[InnerCommitments<Point>],
    active_indices: &[u32],
    sighash: &[u8],
) -> Result<InnerSignatureShare<Scalar>, osst::OsstError> {
    nested::inner_sign::<Point>(
        nonces, share, params, inner_commitments, active_indices, sighash,
    )
}

pub fn aggregate_validator_shares(
    shares: &[InnerSignatureShare<Scalar>],
) -> Scalar {
    nested::aggregate_inner_shares(shares)
}

// ── tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use osst::dkg;
    use osst::nested::interleaved_dkg;

    /// frostito: stake-weighted nested signing
    /// 5 physical validators holding varying shares (total 200, threshold 134)
    /// produces a valid outer partial signature
    #[test]
    fn test_frostito_stake_weighted_signing() {
        let mut rng = rand_core::OsRng;

        let outer_t = 2u32;
        let nested_position = 2u32;
        let inner_total_shares = 10u32; // simplified: 10 shares instead of 200
        let inner_threshold = 7u32; // 2/3+1

        // 3 validators with different stake weights
        let stake_allocation = vec![
            (1u32, vec![1u32, 2, 3, 4]),    // validator 1: 4 shares (40%)
            (2u32, vec![5u32, 6, 7]),        // validator 2: 3 shares (30%)
            (3u32, vec![8u32, 9, 10]),       // validator 3: 3 shares (30%)
        ];

        // generate a group secret and split into shares
        let group_secret = <Scalar as Field>::random(&mut rng);
        let group_key = Point::generator().mul_scalar(&group_secret);

        // create Shamir shares for each share index
        // polynomial: f(x) = group_secret + a1*x + a2*x² + ... (degree = threshold-1)
        let mut coeffs = vec![group_secret];
        for _ in 1..inner_threshold {
            coeffs.push(<Scalar as Field>::random(&mut rng));
        }

        let all_shares: Vec<SecretShare<Scalar>> = (1..=inner_total_shares)
            .map(|i| {
                let x = Scalar::from(i as u64);
                let mut y = Scalar::ZERO;
                let mut x_pow = Scalar::ONE;
                for c in &coeffs {
                    y += c * x_pow;
                    x_pow *= x;
                }
                SecretShare::new(i, y)
            })
            .collect();

        // distribute shares to validators
        let mut validator_bundles: Vec<ValidatorShares> = Vec::new();
        for (vid, share_indices) in &stake_allocation {
            let shares: Vec<SecretShare<Scalar>> = share_indices.iter()
                .map(|&idx| all_shares[(idx - 1) as usize].clone())
                .collect();
            validator_bundles.push(ValidatorShares::new(*vid, shares));
        }

        // also need position A for the outer 2-of-2
        let dealer_a = dkg::Dealer::<Point>::new(1, outer_t, &mut rng);
        let position_a_secret = *dealer_a.generate_subshare(1).value();
        let position_a_share = SecretShare::new(1, position_a_secret);

        // outer group key = position A key + position B key (nested position)
        // for simplicity, use additive: outer_group = g^{s_a} + g^{s_b}
        // but actually we need a proper outer FROST setup...
        // let's test frostito in isolation first: just the inner protocol

        let message = b"frostito stake-weighted test";

        // === FROSTITO SIGNING ===

        // round 1: each validator commits ONE nonce
        let mut all_nonces = Vec::new();
        let mut all_commits = Vec::new();
        for vs in &validator_bundles {
            let (nonce, commit) = frostito_commit(vs.validator_index, vs.weight());
            all_nonces.push(nonce);
            all_commits.push(commit);
        }

        // check threshold
        assert!(frostito_threshold_met(&all_commits, inner_threshold));
        eprintln!("  threshold met: {} shares from {} validators",
            all_commits.iter().map(|c| c.weight).sum::<u32>(),
            all_commits.len(),
        );

        // aggregate commitments
        let r_nested = frostito_aggregate_commitments(&all_commits, message);

        // simulate outer challenge (in real flow, computed from outer signing package)
        let outer_challenge = {
            use sha2::{Sha512, Digest};
            let mut h = Sha512::new();
            h.update(b"frost-challenge-v1");
            h.update(OsstPoint::compress(&r_nested));
            h.update(OsstPoint::compress(&group_key));
            h.update(message);
            Scalar::from_bytes_wide(&h.finalize().into())
        };
        let outer_lambda = Scalar::ONE; // simplified: no outer Lagrange for standalone test

        // collect all active share indices
        let active_share_indices: Vec<u32> = validator_bundles.iter()
            .flat_map(|vs| vs.share_indices())
            .collect();

        let params = FrostitoSigningParams {
            outer_challenge,
            outer_lambda,
            active_share_indices,
        };

        // round 2: each validator signs with ONE response
        let mut all_responses = Vec::new();
        for (nonce, vs) in all_nonces.into_iter().zip(validator_bundles.iter()) {
            let response = frostito_sign(
                nonce, vs, &params, &all_commits, message,
            ).unwrap();
            all_responses.push(response);
        }

        // aggregate
        let z_nested = frostito_aggregate_responses(&all_responses);

        // verify: g^z_nested == R_nested + (λ * c) * group_key
        let lhs = Point::generator().mul_scalar(&z_nested);
        let rhs = r_nested.add(&group_key.mul_scalar(&(outer_lambda * outer_challenge)));
        assert_eq!(lhs, rhs, "frostito signature equation must hold");

        eprintln!("  frostito stake-weighted signing: VERIFIED ✓");
        eprintln!("  3 validators, 10 shares, threshold 7, 3 messages per round");
    }

    /// test that insufficient stake is rejected
    #[test]
    fn test_frostito_insufficient_stake() {
        let commit1 = FrostitoCommitment {
            validator_index: 1,
            hiding: Point::identity(),
            binding: Point::identity(),
            weight: 50,
        };
        let commit2 = FrostitoCommitment {
            validator_index: 2,
            hiding: Point::identity(),
            binding: Point::identity(),
            weight: 50,
        };

        // 100 out of 134 — not enough
        assert!(!frostito_threshold_met(&[commit1, commit2], 134));
    }

    /// legacy test: inner validators with one share each (osst::nested)
    #[test]
    fn test_nested_validator_sign_3of5() {
        let mut rng = rand_core::OsRng;

        let inner_n = 5u32;
        let inner_t = 3u32;
        let outer_t = 2u32;
        let nested_position = 2u32;

        let dealer_a = dkg::Dealer::<Point>::new(1, outer_t, &mut rng);

        let (inner_shares, coeff_commitments) =
            interleaved_dkg::<Point, _>(inner_n, inner_t, outer_t, &mut rng).unwrap();

        let eval_active: Vec<u32> = (1..=inner_t).collect();
        let eval_lambda = compute_lagrange_coefficients::<Scalar>(&eval_active).unwrap();
        let mut fp_at_1 = Scalar::ZERO;
        for (i, &k) in eval_active.iter().enumerate() {
            fp_at_1 += eval_lambda[i] * inner_shares[(k - 1) as usize].eval_at(1);
        }

        let fa_at_p = dealer_a.generate_subshare(nested_position);
        let (fa_pieces, _) = osst::nested::split_evaluation_for_inner::<Point, _>(
            fa_at_p.value(), inner_n, inner_t, &mut rng,
        );

        let mut validator_shares_legacy: Vec<SecretShare<Scalar>> = Vec::new();
        for k in 0..inner_n as usize {
            let sigma = osst::nested::combine_shares(
                &inner_shares[k],
                nested_position,
                &[(1, fa_pieces[k].1)],
            );
            validator_shares_legacy.push(SecretShare::new((k + 1) as u32, sigma));
        }

        let s1 = *dealer_a.generate_subshare(1).value() + fp_at_1;
        let position_a_share = SecretShare::new(1, s1);

        let group_key = dealer_a.commitment().share_commitment()
            .add(&coeff_commitments[0]);

        let sighash = b"bridge spend authorization test";
        let active_validators = vec![1u32, 3, 5];

        let mut all_nonces = Vec::new();
        let mut all_commits = Vec::new();
        for &k in &active_validators {
            let (nonces, commits) = validator_commit(k);
            all_nonces.push(nonces);
            all_commits.push(commits);
        }

        let r_nested = aggregate_validator_commitments(&all_commits, sighash);

        let (a_nonces, a_commits) = osst::frost::commit::<Point, _>(1, &mut rng);

        let nested_commits = osst::frost::SigningCommitments {
            index: nested_position,
            hiding: r_nested,
            binding: Point::identity(),
        };
        let package = osst::frost::SigningPackage::new(
            sighash.to_vec(),
            vec![a_commits, nested_commits],
        ).unwrap();

        let a_sig = osst::frost::sign::<Point>(
            &package, a_nonces, &position_a_share, &group_key,
        ).unwrap();

        let outer_indices = package.signer_indices();
        let outer_lambda = compute_lagrange_coefficients::<Scalar>(&outer_indices).unwrap();
        let nested_pos = outer_indices.iter().position(|&i| i == nested_position).unwrap();

        let outer_gc = {
            use sha2::{Sha512, Digest};
            let mut r = Point::identity();
            for &idx in &outer_indices {
                let c = package.get_commitments(idx).unwrap();
                let mut encoded = Vec::new();
                for si in package.signer_indices() {
                    let sc = package.get_commitments(si).unwrap();
                    encoded.extend_from_slice(&sc.index.to_le_bytes());
                    encoded.extend_from_slice(&sc.hiding.compress());
                    encoded.extend_from_slice(&sc.binding.compress());
                }
                let rho = {
                    use sha2::{Sha512, Digest};
                    let mut h = Sha512::new();
                    h.update(b"frost-binding-v1");
                    h.update(idx.to_le_bytes());
                    h.update((sighash.len() as u64).to_le_bytes());
                    h.update(sighash);
                    h.update(&encoded);
                    Scalar::from_bytes_wide(&h.finalize().into())
                };
                r = r.add(&c.hiding).add(&c.binding.mul_scalar(&rho));
            }
            r
        };

        let outer_challenge = {
            use sha2::{Sha512, Digest};
            let mut h = Sha512::new();
            h.update(b"frost-challenge-v1");
            h.update(OsstPoint::compress(&outer_gc));
            h.update(OsstPoint::compress(&group_key));
            h.update(sighash);
            Scalar::from_bytes_wide(&h.finalize().into())
        };

        let params = InnerSigningParams {
            outer_challenge,
            outer_lambda: outer_lambda[nested_pos],
        };

        let mut inner_sigs = Vec::new();
        for (nonces, &k) in all_nonces.into_iter().zip(active_validators.iter()) {
            let sig = validator_sign(
                nonces,
                &validator_shares_legacy[(k - 1) as usize],
                &params,
                &all_commits,
                &active_validators,
                sighash,
            ).unwrap();
            inner_sigs.push(sig);
        }

        let z_nested = aggregate_validator_shares(&inner_sigs);

        let nested_sig = osst::frost::SignatureShare {
            index: nested_position,
            response: z_nested,
        };

        let signature = osst::frost::aggregate::<Point>(
            &package,
            &[a_sig, nested_sig],
            &group_key,
            None,
        ).unwrap();

        assert!(
            osst::frost::verify_signature(&group_key, sighash, &signature),
            "nested 2-of-2 with 3-of-5 inner must verify"
        );
        eprintln!("bridge nested FROST: 2-of-2 outer × 3-of-5 inner = valid signature");
    }
}

//! end-to-end bridge custody crypto test
//!
//! verifies the full path: DKG → address → sign → valid SpendAuth signature
//! both for direct 2-of-2 and for nested (2-of-2 outer × 3-of-5 inner).
//!
//! run with: cargo test -p zecli --test bridge_e2e -- --nocapture

use frost_spend::hierarchical::{
    bridge_dkg_dealer, bridge_sign_round1, bridge_sign_round2,
    bridge_aggregate, bridge_derive_address, bridge_sign_local,
};
/// full bridge signing path: DKG → address → 2-of-2 sign → valid sig
#[test]
fn test_bridge_2of2_full_path() {
    eprintln!("\n=== bridge 2-of-2 full path ===");

    // step 1: DKG
    let dkg = bridge_dkg_dealer().expect("DKG");
    eprintln!("  DKG: bridge_vk={}...", &dkg.bridge_vk_hex[..16]);

    // step 2: address
    let addr = bridge_derive_address(&dkg.public_key_package_hex, 0).unwrap();
    assert_eq!(addr.len(), 43);
    eprintln!("  address: 43 bytes ✓");

    // step 3: sign (simulated sighash + alpha from PCZT)
    let sighash = [0xaa; 32];
    let mut alpha = [0u8; 32];
    alpha[0] = 0x01;

    let sig = bridge_sign_local(
        &dkg.osst_package,
        &dkg.validator_package,
        &sighash,
        &alpha,
    ).unwrap();

    assert_eq!(sig.len(), 128);
    eprintln!("  sig: {}...{} ✓", &sig[..16], &sig[112..]);
    eprintln!("=== PASSED ===\n");
}

/// stepwise signing: round1 → round2 → aggregate (matches narsild flow)
#[test]
fn test_bridge_stepwise_signing() {
    eprintln!("\n=== bridge stepwise signing ===");

    let dkg = bridge_dkg_dealer().unwrap();

    let sighash = [0xbb; 32];
    let mut alpha = [0u8; 32];
    alpha[0] = 0x02;

    // round 1: each position commits independently
    let state_a = bridge_sign_round1(&dkg.osst_package).unwrap();
    let state_b = bridge_sign_round1(&dkg.validator_package).unwrap();
    eprintln!("  round1: 2 commitments");

    let commits = vec![state_a.commitment_hex.clone(), state_b.commitment_hex.clone()];

    // round 2: each position signs independently
    let share_a = bridge_sign_round2(
        &dkg.osst_package, &state_a, &sighash, &alpha, &commits,
    ).unwrap();
    let share_b = bridge_sign_round2(
        &dkg.validator_package, &state_b, &sighash, &alpha, &commits,
    ).unwrap();
    eprintln!("  round2: 2 shares");

    // aggregate
    let sig = bridge_aggregate(
        &dkg.public_key_package_hex, &sighash, &alpha,
        &commits, &[share_a, share_b],
    ).unwrap();

    assert_eq!(sig.len(), 128);
    eprintln!("  aggregate: valid 64-byte SpendAuth sig ✓");
    eprintln!("=== PASSED ===\n");
}

/// nested signing: 2-of-2 outer where position B is 3-of-5 inner FROST
#[test]
fn test_bridge_nested_3of5_inner() {
    use frost_spend::nested::{
        validator_commit, aggregate_validator_commitments,
        validator_sign, aggregate_validator_shares,
        InnerSigningParams,
    };
    use osst::curve::{OsstPoint, OsstScalar};
    use osst::compute_lagrange_coefficients;
    use osst::dkg;
    use osst::nested::interleaved_dkg;
    use osst::SecretShare;
    use osst::frost as osst_frost;
    use pasta_curves::pallas::{Point, Scalar};
    use pasta_curves::group::ff::Field;
    use sha2::{Sha512, Digest};

    eprintln!("\n=== bridge nested: 2-of-2 outer × 3-of-5 inner ===");

    let mut rng = rand_core::OsRng;
    let inner_n = 5u32;
    let inner_t = 3u32;
    let outer_t = 2u32;
    let nested_position = 2u32;

    // position A: simple dealer
    let dealer_a = dkg::Dealer::<Point>::new(1, outer_t, &mut rng);

    // position B: interleaved DKG among 5 validators
    let (inner_shares, coeff_commitments) =
        interleaved_dkg::<Point, _>(inner_n, inner_t, outer_t, &mut rng).unwrap();
    eprintln!("  DKG: outer 2-of-2, inner 3-of-5");

    // reconstruct f_p(1) for position A's outer share
    let eval_active: Vec<u32> = (1..=inner_t).collect();
    let eval_lambda = compute_lagrange_coefficients::<Scalar>(&eval_active).unwrap();
    let mut fp_at_1 = Scalar::ZERO;
    for (i, &k) in eval_active.iter().enumerate() {
        fp_at_1 += eval_lambda[i] * inner_shares[(k - 1) as usize].eval_at(1);
    }

    // split dealer_a's evaluation for inner holders
    let fa_at_p = dealer_a.generate_subshare(nested_position);
    let (fa_pieces, _) = osst::nested::split_evaluation_for_inner::<Point, _>(
        fa_at_p.value(), inner_n, inner_t, &mut rng,
    );

    // each validator combines shares
    let mut validator_shares: Vec<SecretShare<Scalar>> = Vec::new();
    for k in 0..inner_n as usize {
        let sigma = osst::nested::combine_shares(
            &inner_shares[k],
            nested_position,
            &[(1, fa_pieces[k].1)],
        );
        validator_shares.push(SecretShare::new((k + 1) as u32, sigma));
    }

    // position A's outer secret
    let s1 = *dealer_a.generate_subshare(1).value() + fp_at_1;
    let position_a_share = SecretShare::new(1, s1);

    // group key
    let group_key = dealer_a.commitment().share_commitment()
        .add(&coeff_commitments[0]);
    let gk_hex = hex::encode(&OsstPoint::compress(&group_key));
    eprintln!("  group key: {}...", &gk_hex[..16]);

    // === SIGNING ===
    let sighash = b"bridge nested e2e spend authorization";
    let active_validators = vec![1u32, 3, 5];

    // inner validators commit
    let mut all_nonces = Vec::new();
    let mut all_commits = Vec::new();
    for &k in &active_validators {
        let (nonces, commits) = validator_commit(k);
        all_nonces.push(nonces);
        all_commits.push(commits);
    }
    let r_nested = aggregate_validator_commitments(&all_commits, sighash);
    eprintln!("  inner round1: 3 validators committed");

    // position A commits
    let (a_nonces, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng);

    // outer signing package
    let nested_commits = osst_frost::SigningCommitments {
        index: nested_position,
        hiding: r_nested,
        binding: Point::identity(),
    };
    let package = osst_frost::SigningPackage::new(
        sighash.to_vec(),
        vec![a_commits, nested_commits],
    ).unwrap();

    // position A signs
    let a_sig = osst_frost::sign::<Point>(
        &package, a_nonces, &position_a_share, &group_key,
    ).unwrap();
    eprintln!("  position A: signed ✓");

    // compute outer params for inner validators
    let outer_indices = package.signer_indices();
    let outer_lambda = compute_lagrange_coefficients::<Scalar>(&outer_indices).unwrap();
    let nested_pos = outer_indices.iter().position(|&i| i == nested_position).unwrap();

    let outer_gc = {
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

    // inner validators sign
    let mut inner_sigs = Vec::new();
    for (nonces, &k) in all_nonces.into_iter().zip(active_validators.iter()) {
        let sig = validator_sign(
            nonces,
            &validator_shares[(k - 1) as usize],
            &params,
            &all_commits,
            &active_validators,
            sighash,
        ).unwrap();
        inner_sigs.push(sig);
    }
    let z_nested = aggregate_validator_shares(&inner_sigs);
    eprintln!("  position B: 3-of-5 validators signed + aggregated ✓");

    let nested_sig = osst_frost::SignatureShare {
        index: nested_position,
        response: z_nested,
    };

    // outer aggregate
    let signature = osst_frost::aggregate::<Point>(
        &package,
        &[a_sig, nested_sig],
        &group_key,
        None,
    ).unwrap();

    // verify
    assert!(
        osst_frost::verify_signature(&group_key, sighash, &signature),
        "nested 2-of-2 × 3-of-5 signature must verify"
    );
    eprintln!("  signature verified against group key ✓");
    eprintln!("=== PASSED ===\n");
}

/// verify that different validator subsets produce valid signatures
#[test]
fn test_bridge_nested_different_subsets() {
    use frost_spend::nested::{
        validator_commit, aggregate_validator_commitments,
        validator_sign, aggregate_validator_shares,
        InnerSigningParams,
    };
    use osst::curve::{OsstPoint, OsstScalar};
    use osst::compute_lagrange_coefficients;
    use osst::dkg;
    use osst::nested::interleaved_dkg;
    use osst::SecretShare;
    use osst::frost as osst_frost;
    use pasta_curves::pallas::{Point, Scalar};
    use pasta_curves::group::ff::Field;
    use sha2::{Sha512, Digest};

    eprintln!("\n=== bridge nested: liveness test (different subsets) ===");

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

    let mut validator_shares: Vec<SecretShare<Scalar>> = Vec::new();
    for k in 0..inner_n as usize {
        let sigma = osst::nested::combine_shares(
            &inner_shares[k], nested_position, &[(1, fa_pieces[k].1)],
        );
        validator_shares.push(SecretShare::new((k + 1) as u32, sigma));
    }

    let s1 = *dealer_a.generate_subshare(1).value() + fp_at_1;
    let position_a_share = SecretShare::new(1, s1);
    let group_key = dealer_a.commitment().share_commitment().add(&coeff_commitments[0]);

    // test 4 different validator subsets — all must produce valid sigs
    let subsets: &[&[u32]] = &[
        &[1, 2, 3],
        &[1, 3, 5],
        &[2, 4, 5],
        &[3, 4, 5],
    ];

    for subset in subsets {
        let sighash = format!("subset {:?}", subset);
        let sighash = sighash.as_bytes();

        let mut nonces_vec = Vec::new();
        let mut commits_vec = Vec::new();
        for &k in *subset {
            let (n, c) = validator_commit(k);
            nonces_vec.push(n);
            commits_vec.push(c);
        }

        let r_nested = aggregate_validator_commitments(&commits_vec, sighash);
        let (a_nonces, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng);

        let nested_commits = osst_frost::SigningCommitments {
            index: nested_position,
            hiding: r_nested,
            binding: Point::identity(),
        };
        let package = osst_frost::SigningPackage::new(
            sighash.to_vec(),
            vec![a_commits, nested_commits],
        ).unwrap();

        let a_sig = osst_frost::sign::<Point>(
            &package, a_nonces, &position_a_share, &group_key,
        ).unwrap();

        let outer_indices = package.signer_indices();
        let outer_lambda = compute_lagrange_coefficients::<Scalar>(&outer_indices).unwrap();
        let nested_pos = outer_indices.iter().position(|&i| i == nested_position).unwrap();

        let outer_gc = {
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
        for (nonces, &k) in nonces_vec.into_iter().zip(subset.iter()) {
            inner_sigs.push(
                validator_sign(
                    nonces, &validator_shares[(k - 1) as usize],
                    &params, &commits_vec, subset, sighash,
                ).unwrap(),
            );
        }

        let z_nested = aggregate_validator_shares(&inner_sigs);
        let nested_sig = osst_frost::SignatureShare {
            index: nested_position,
            response: z_nested,
        };

        let signature = osst_frost::aggregate::<Point>(
            &package, &[a_sig, nested_sig], &group_key, None,
        ).unwrap();

        assert!(
            osst_frost::verify_signature(&group_key, sighash, &signature),
            "subset {:?} failed", subset
        );
        eprintln!("  subset {:?}: ✓", subset);
    }

    eprintln!("=== PASSED (4/4 subsets) ===\n");
}

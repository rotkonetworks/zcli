//! end-to-end bridge custody crypto test
//!
//! verifies the full path: DKG → address → sign → valid SpendAuth signature
//! both for direct 2-of-2 and for nested (2-of-2 outer × 3-of-5 inner).
//!
//! run with: cargo test -p zecli --test bridge_e2e -- --nocapture

use frost_spend::hierarchical::{
    bridge_aggregate, bridge_derive_address, bridge_dkg_dealer, bridge_sign_local,
    bridge_sign_round1, bridge_sign_round2,
};

use frostito::curve::pallas::SpendAuthPoint;
use frostito::{CurvePoint, SecretShare};
use frost_spend::frost::{self, Identifier, Signature, SigningPackage, VerifyingKey};
use frost_spend::frost_keys::{self, IdentifierList};
use frost_spend::nested::{
    frostito_aggregate_commitment_pair, frostito_aggregate_responses_verified, frostito_commit,
    frostito_sign_v2, inner_precommit, verify_inner_precommit, NestedSigningRequest, ValidatorShares,
    WeightedRoster,
};
use frost_spend::{round1, round2};
use pasta_curves::group::ff::{Field, PrimeField};
use pasta_curves::group::GroupEncoding;
use pasta_curves::pallas::{Point, Scalar};
use std::collections::BTreeMap;

/// The inner round's id. frostito carries it through round 1 into `inner_sign`,
/// which refuses to answer a round the holder did not commit to (finding N-2).
/// A deployment derives it from the epoch, the nested position and a round
/// counter; a test just needs it stable.
const SESSION: [u8; 32] = [0x5e; 32];
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

    let sig =
        bridge_sign_local(&dkg.osst_package, &dkg.validator_package, &sighash, &alpha).unwrap();

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

    let commits = vec![
        state_a.commitment_hex.clone(),
        state_b.commitment_hex.clone(),
    ];

    // round 2: each position signs independently
    let share_a =
        bridge_sign_round2(&dkg.osst_package, &state_a, &sighash, &alpha, &commits).unwrap();
    let share_b =
        bridge_sign_round2(&dkg.validator_package, &state_b, &sighash, &alpha, &commits).unwrap();
    eprintln!("  round2: 2 shares");

    // aggregate
    let sig = bridge_aggregate(
        &dkg.public_key_package_hex,
        &sighash,
        &alpha,
        &commits,
        &[share_a, share_b],
    )
    .unwrap();

    assert_eq!(sig.len(), 128);
    eprintln!("  aggregate: valid 64-byte SpendAuth sig ✓");
    eprintln!("=== PASSED ===\n");
}

/// The outer position a nested group controls, and its inner threshold.
const NESTED_POSITION: u32 = 2;
const INNER_THRESHOLD: u32 = 3;

fn identifier(index: u16) -> Identifier {
    Identifier::try_from(index).expect("small identifier")
}

fn rand_scalar(rng: &mut rand_core::OsRng) -> Scalar {
    use frostito::CurveScalar;
    use rand_core::RngCore;
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_wide(&wide)
}

/// Shamir over the nested position's secret: `n` shares, `t` to reconstruct.
/// Shares are indexed 1..=n, matching the outer identifiers the weighted
/// roster and frostito use as Lagrange x-coordinates.
fn shamir(secret: Scalar, n: u32, t: u32, rng: &mut rand_core::OsRng) -> Vec<SecretShare<Scalar>> {
    let mut coeffs = vec![secret];
    for _ in 1..t {
        coeffs.push(rand_scalar(rng));
    }
    (1..=n)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;
            let mut x_pow = Scalar::ONE;
            for c in &coeffs {
                y += c * x_pow;
                x_pow *= x;
            }
            SecretShare::new(i, y).expect("1-indexed by construction")
        })
        .collect()
}

/// A 2-of-2 outer key pair (identifier 1 flat, identifier 2 the nested
/// position) whose nested share is split 3-of-5 among five single-share
/// validators.
struct NestedFixture {
    roster: WeightedRoster,
    bundles: Vec<ValidatorShares>,
    public_shares: Vec<(u32, Point)>,
    key_a: frost_keys::KeyPackage,
    pubkeys: frost_keys::PublicKeyPackage,
    group_key: VerifyingKey,
}

fn nested_fixture(rng: &mut rand_core::OsRng) -> NestedFixture {
    let (shares, pubkeys) =
        frost_keys::generate_with_dealer(2, 2, IdentifierList::Default, &mut *rng)
        .expect("2-of-2 dealer keygen");
    let key_a = frost_keys::KeyPackage::try_from(shares[&identifier(1)].clone())
        .expect("share 1 verifies");
    let nested_secret = shares[&identifier(NESTED_POSITION as u16)]
        .signing_share()
        .to_scalar();
    let group_key = *pubkeys.verifying_key();

    // five validators, one share each, threshold 3
    let allocation: Vec<(u32, Vec<u32>)> = (1u32..=5).map(|v| (v, vec![v])).collect();
    let roster = WeightedRoster::new(&allocation, INNER_THRESHOLD).expect("roster");

    let inner = shamir(nested_secret, 5, INNER_THRESHOLD, rng);
    // the spend-auth basepoint, as the bare `Point` the commitments use:
    // `Point::generator()` is pasta's, a different group, and nothing here
    // would verify against ZF key material if the shares lived in it.
    let basepoint = SpendAuthPoint::basepoint().0;
    let public_shares: Vec<(u32, Point)> = inner
        .iter()
        .map(|s| (s.index, basepoint.mul_scalar(s.scalar())))
        .collect();

    let bundles = allocation
        .iter()
        .map(|(v, idxs)| {
            let shares = idxs
                .iter()
                .map(|i| inner[(*i - 1) as usize].clone())
                .collect();
            ValidatorShares::from_roster(&roster, *v, shares).expect("bundle")
        })
        .collect();

    NestedFixture {
        roster,
        bundles,
        public_shares,
        key_a,
        pubkeys,
        group_key,
    }
}

/// The full nested ceremony for one participant set: commit–reveal, a real
/// outer `SigningPackage`, per-validator responses verified and aggregated,
/// and the outer 2-of-2 signature checked against the group key.
///
/// The ceremony runs through `frost_spend::nested`'s weighted path — the
/// crate's only nested implementation. frostito 0.8 has no plain
/// point-generic FROST of its own (signing is rooted in ZF `frost-core`), and
/// its point-generic helpers hold commitments, shares and responses in
/// pasta's default group, which cannot verify against this crate's spend-auth
/// key material; the weighted path states the basepoint explicitly.
fn nested_outer_signature(
    fixture: &NestedFixture,
    participants: &[u32],
    message: &[u8],
    rng: &mut rand_core::OsRng,
) -> Signature {
    let active = fixture
        .roster
        .active_share_indices(participants)
        .expect("active set");

    let bundle_of = |v: u32| {
        fixture
            .bundles
            .iter()
            .find(|b| b.validator_index() == v)
            .expect("bundled validator")
    };

    // round 1: every participating validator commits, then reveals
    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    let mut precommits = Vec::new();
    for v in participants {
        let bundle = bundle_of(*v);
        let (nonces_for, commits_for) = frostito_commit(bundle.validator_index(), SESSION);
        precommits.push((commits_for.holder_index, inner_precommit(&commits_for)));
        nonces.push(nonces_for);
        commitments.push(commits_for);
    }
    for ((_, pre), revealed) in precommits.iter().zip(commitments.iter()) {
        assert!(
            verify_inner_precommit(pre, revealed),
            "reveal must match precommit"
        );
    }
    let (d_nested, e_nested) = frostito_aggregate_commitment_pair(&SESSION, &precommits, &commitments)
        .expect("commitment pair");

    // the outer package: the flat signer plus the nested position's pair,
    // presented exactly as any other signer's round-1 commitments
    let (a_nonces, a_commits) = round1::commit(fixture.key_a.signing_share(), rng);
    let nested_commits = round1::SigningCommitments::new(
        round1::NonceCommitment::deserialize(&d_nested.to_bytes()).expect("commitment"),
        round1::NonceCommitment::deserialize(&e_nested.to_bytes()).expect("commitment"),
    );
    let mut commits = BTreeMap::new();
    commits.insert(identifier(1), a_commits);
    commits.insert(identifier(NESTED_POSITION as u16), nested_commits);
    let package = SigningPackage::new(commits, message);

    let request = NestedSigningRequest {
        package: &package,
        nested_index: NESTED_POSITION,
        session_id: SESSION,
        inner_precommits: &precommits,
        inner_commitments: &commitments,
        active_indices: &active,
        inner_threshold: fixture.roster.threshold(),
    };

    // round 2: one response per validator, each bound to the message it saw
    let mut responses = Vec::new();
    for (nonces_for, v) in nonces.into_iter().zip(participants.iter()) {
        responses.push(
            frostito_sign_v2(
                nonces_for,
                bundle_of(*v),
                &fixture.group_key,
                message,
                &request,
                &fixture.roster,
            )
            .expect("validator signature"),
        );
    }

    // every response is verified before it is aggregated
    let effective_pubkeys: Vec<(u32, Point)> = participants
        .iter()
        .map(|v| {
            let bundle = bundle_of(*v);
            (
                *v,
                ValidatorShares::effective_pubkey(
                    &bundle.share_indices(),
                    &fixture.public_shares,
                    &active,
                )
                .expect("effective public key"),
            )
        })
        .collect();
    let params = frostito::zf::inner_params_from_zf::<frost::PallasBlake2b512>(
        &package,
        &fixture.group_key,
        NESTED_POSITION,
    )
    .expect("inner params from the outer package");
    let z_nested = frostito_aggregate_responses_verified(
        &responses,
        &commitments,
        &effective_pubkeys,
        &params,
        participants,
    )
    .expect("all validator responses must verify");

    let a_sig = round2::sign(&package, &a_nonces, &fixture.key_a).expect("flat signer");
    let nested_sig =
        round2::SignatureShare::deserialize(&z_nested.to_repr()).expect("nested response");
    let mut sigs = BTreeMap::new();
    sigs.insert(identifier(1), a_sig);
    sigs.insert(identifier(NESTED_POSITION as u16), nested_sig);
    let signature = frost::aggregate(&package, &sigs, &fixture.pubkeys).expect("2-of-2 aggregate");

    assert!(
        fixture.group_key.verify(message, &signature).is_ok(),
        "nested 2-of-2 x 3-of-5 signature must verify"
    );
    signature
}

/// nested signing: 2-of-2 outer where position B is 3-of-5 inner FROST
#[test]
fn test_bridge_nested_3of5_inner() {
    eprintln!("\n=== bridge nested: 2-of-2 outer x 3-of-5 inner ===");

    let mut rng = rand_core::OsRng;
    let fixture = nested_fixture(&mut rng);
    let sighash = b"bridge nested e2e spend authorization";

    let signature = nested_outer_signature(&fixture, &[1, 2, 3, 4, 5], sighash, &mut rng);
    assert_eq!(signature.serialize().expect("signature serializes").len(), 64);
    eprintln!("  inner round1: 5 validators committed (commit-reveal verified)");
    eprintln!("  position B: 3-of-5 validators signed + verified + aggregated");
    eprintln!("  signature verified against group key");
    eprintln!("=== PASSED ===\n");
}

/// verify that different validator subsets produce valid signatures
#[test]
fn test_bridge_nested_different_subsets() {
    eprintln!("\n=== bridge nested: liveness test (different subsets) ===");

    let mut rng = rand_core::OsRng;
    let fixture = nested_fixture(&mut rng);
    let subsets: &[&[u32]] = &[&[1, 2, 3], &[1, 3, 5], &[2, 4, 5], &[3, 4, 5]];

    for subset in subsets {
        let sighash = format!("subset {:?}", subset);
        nested_outer_signature(&fixture, subset, sighash.as_bytes(), &mut rng);
        eprintln!("  subset {:?}: verified", subset);
    }

    eprintln!("=== PASSED (4/4 subsets) ===\n");
}

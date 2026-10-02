// nested.rs — stake-weighted nested FROST (frostito 0.8)
//
// One physical validator holds N Shamir shares of the nested position's secret,
// N proportional to its stake. Rather than running FROST with one identifier
// per share, each validator aggregates its own shares locally into ONE
// commitment and ONE response:
//
//   effective_k = Σ_{j ∈ bundle_k} λ_j · s_j        (λ over the FULL active set)
//   z_k         = d_k + ρ·e_k + (λ_out · c) · effective_k
//
// Summing over the participating validators, with d = Σd_k, e = Σe_k and
// Σ_k effective_k = σ_out (Lagrange interpolation over the active share set):
//
//   z_nested = d + ρ·e + λ_out · c · σ_out
//
// which is bit-for-bit what a flat FROST signer holding σ_out with nonces
// (d, e) produces. The nested position is therefore indistinguishable from an
// ordinary outer signer, and `frostito_v2_equals_flat_frost_signer` below
// asserts that on real values against a real outer `SigningPackage`.
//
// Messages per round: one per physical validator, not one per share.
//
// ── relationship to frostito::nested ────────────────────────────────────────
//
// This module is the WEIGHTED specialization of `frostito::nested`'s nested
// position: the unweighted inner holder contributes μ_k·σ_k, the weighted
// validator contributes Σ_j λ_j·s_j, and everything else — commit–reveal,
// session binding, the aggregate commitment pair, the outer context derivation,
// per-signer share verification — is frostito's and is used from frostito here.
//
// Concretely it reuses `InnerCommitments`, `InnerSignatureShare`,
// `inner_precommit`/`verify_inner_precommit`, `aggregate_inner_commitment_pair`,
// `verify_nested_commitment`, `NestedSigningRequest`,
// `frostito::zf::inner_params_from_zf` and `verify_inner_share`. Nothing about
// the binding factor or the challenge is recomputed locally;
// `inner_params_from_zf` is the only derivation, so a coordinator cannot
// assert an outer context (W-1).
//
// frostito requires its 0.8 nested API to be generic over a ZF `frost-core`
// ciphersuite, so the signatures below carry `C = crate::frost::PallasBlake2b512`
// where the point-generic helpers do not (`Element<C>` *is* `pallas::Point`
// under the shared `zakura-pasta-curves` backend, so the weighted math stays on
// `Point`/`Scalar`). The outer group key `Y` lives outside
// `NestedSigningRequest` (M-4) and enters the binding factor (M-24, RFC 9591
// §4.4), so `frostito_sign_v2` takes it as a parameter from local key material
// — now a `frost_core::VerifyingKey<C>` — and the commit–reveal round is
// enforced by frostito rather than documented (M-20): the round-0
// precommitments travel in the request and every reveal is checked against
// one.
//
// It cannot call `frostito::nested::inner_sign` itself for two reasons:
//
//   1. `inner_sign` computes μ_k from `share.index` (the Lagrange coefficient
//      at that position in `active_indices`) and multiplies the single share by
//      it. A weighted validator's `effective_share` has the Lagrange
//      coefficients applied already, so routing it through that function would
//      apply them twice.
//   2. `InnerNonces`' scalars are still `pub(crate)` in frostito 0.8, so the
//      nonce pair cannot be consumed outside the crate.
//
// Both are upstream items (see the PR description); until frostito grows an
// `inner_sign` variant taking a precomputed effective scalar, the N-1/N-2
// precondition block is mirrored here, calling frostito for every check it
// exposes — plus, since 0.8, frostito's own new quorum-shape guards, mirrored
// below (see `frostito_sign_v2`).
//
// ── basepoint (ZF / Orchard spend-auth group) ────────────────────────────────
//
// frostito's point-generic helpers instantiate `CurvePoint` for
// `pasta_curves::pallas::Point`, whose `generator()` is pasta's DEFAULT
// generator — not the Orchard spend-auth basepoint the ciphersuite
// `crate::frost` (`reddsa::frost::redpallas`) signs in. Every key this crate
// handles lives in the spend-auth group, so the weighted path states the
// basepoint explicitly (`spend_auth_generator`, and `verify_inner_share`
// instantiated at `SpendAuthPoint`) rather than relying on
// `Point::generator()`. Moving the custody keys into pasta's default group
// instead would silently change what a valid Orchard SpendAuth signature is.
//
// ── weights ─────────────────────────────────────────────────────────────────
//
// Weight is a property of the signed epoch roster ([`WeightedRoster`]), never
// of a message a validator sends (W-2). `WeightedRoster::new` enforces the
// invariant that no single validator can reconstruct alone — `max_weight <
// threshold` (W-3) — plus non-zero, non-duplicate, non-overlapping share
// allocations and checked `u64` weight sums (W-4). The invariant is re-checked
// at signing time.

use crate::frost::{PallasBlake2b512, VerifyingKey};
use frostito::compute_lagrange_coefficients;
use frostito::nested;
use frostito::curve::pallas::SpendAuthPoint;
use frostito::{CurvePoint, CurveScalar, SecretShare};
use pasta_curves::group::ff::Field;
use pasta_curves::pallas::{Point, Scalar};

/// The ZF `frost-core` ciphersuite this crate's FROST types are built on.
///
/// `crate::frost` is `reddsa::frost::redpallas`, whose `PallasBlake2b512`
/// ciphersuite has `Element = pallas::Point` and `Scalar = pallas::Scalar`
/// under the `zakura-pasta-curves` backend that frostito 0.8 shares, so the
/// suite-generic frostito helpers and the point-generic weighted math below
/// line up without conversion.
type Suite = PallasBlake2b512;

pub use nested::{
    aggregate_inner_commitment_pair, inner_precommit, verify_inner_precommit, verify_inner_share,
    verify_nested_commitment, InnerCommitments, InnerNonces, InnerSignatureShare,
    InnerSigningParams, NestedSigningRequest,
};

/// Sample a uniformly random Pallas scalar from a rand_core 0.6 RNG.
///
/// ff 0.14 (Zakura Common 1.0) moved `Field::random` onto rand_core 0.10's
/// `Rng` trait, incompatible with the rand_core 0.6 `OsRng` used here. Sampling
/// 64 bytes and reducing (`FromUniformBytes`) is the standard uniform
/// construction and keeps this module on rand_core 0.6.
fn rand_scalar<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Scalar {
    use pasta_curves::group::ff::FromUniformBytes;
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_uniform_bytes(&bytes)
}

// ── errors ──────────────────────────────────────────────────────────────────

/// Failures specific to the weighted layer.
///
/// The roster rejections have no `frostito::Error` analogue — frostito's only
/// "weights" are verification scalars, not integer stake — so they live here
/// and frostito errors are wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightedError {
    /// An error from frostito itself.
    Frostito(frostito::Error),
    /// A validator or share index was 0; both are 1-indexed.
    ZeroIndex,
    /// A threshold below 2 admits no roster: `max_weight < threshold` and
    /// `weight >= 1` cannot both hold.
    ThresholdTooSmall(u32),
    /// The roster is empty.
    EmptyRoster,
    /// This validator index appears in two allocations.
    DuplicateValidator(u32),
    /// This share index is allocated to two validators, or twice to one — an
    /// overlap would double-count `λ_j·s_j` (W-4).
    DuplicateShareIndex(u32),
    /// A validator was allocated no shares. Weight 0 contributes nonce only
    /// and is never intended (W-4).
    ZeroWeight(u32),
    /// The roster's total weight overflows `u64` (W-4).
    WeightOverflow,
    /// **W-3.** This validator alone holds `threshold` or more shares, so it
    /// can reconstruct the nested position's secret without anybody else.
    WeightReachesThreshold {
        validator_index: u32,
        weight: u32,
        threshold: u32,
    },
    /// Even the whole roster cannot reach the threshold.
    RosterBelowThreshold { total: u64, threshold: u32 },
    /// No allocation for this validator index.
    UnknownValidator(u32),
    /// The share bundle handed to [`ValidatorShares::from_roster`] is not the
    /// set of indices the roster allocates to that validator.
    ShareSetMismatch(u32),
    /// The participating validators' combined weight is below the threshold,
    /// or `active_indices` names fewer share indices than `t_in` — the
    /// weighted analogue of frostito's `InsufficientContributions`.
    InsufficientWeight { got: u64, need: u32 },
    /// The `active_indices` the coordinator supplied are not the ones the
    /// roster derives for the participating validator set (W-2).
    ActiveIndicesMismatch,
    /// No participants were supplied.
    EmptyParticipants,
    /// **M-14.** `NestedSigningRequest::inner_threshold` is not the roster's
    /// threshold. frostito documents the field as caller-anchored; on the
    /// weighted path the roster *is* the anchor, so a coordinator's number is
    /// refused rather than trusted.
    ThresholdMismatch { supplied: u32, roster: u32 },
}

impl core::fmt::Display for WeightedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frostito(e) => write!(f, "{}", e),
            Self::ZeroIndex => write!(f, "validator and share indices are 1-indexed"),
            Self::ThresholdTooSmall(t) => {
                write!(f, "threshold {} admits no valid weight allocation", t)
            }
            Self::EmptyRoster => write!(f, "roster is empty"),
            Self::DuplicateValidator(i) => write!(f, "duplicate validator index {}", i),
            Self::DuplicateShareIndex(i) => write!(f, "share index {} allocated twice", i),
            Self::ZeroWeight(i) => write!(f, "validator {} was allocated no shares", i),
            Self::WeightOverflow => write!(f, "weight sum overflows"),
            Self::WeightReachesThreshold {
                validator_index,
                weight,
                threshold,
            } => write!(
                f,
                "validator {} holds {} of {} shares and can reconstruct alone",
                validator_index, weight, threshold
            ),
            Self::RosterBelowThreshold { total, threshold } => write!(
                f,
                "roster total weight {} is below threshold {}",
                total, threshold
            ),
            Self::UnknownValidator(i) => write!(f, "validator {} is not on the roster", i),
            Self::ShareSetMismatch(i) => {
                write!(f, "share bundle does not match validator {}'s roster entry", i)
            }
            Self::InsufficientWeight { got, need } => {
                write!(f, "participating weight {} is below threshold {}", got, need)
            }
            Self::ActiveIndicesMismatch => write!(
                f,
                "active share indices do not match the roster's for this participant set"
            ),
            Self::EmptyParticipants => write!(f, "no participating validators"),
            Self::ThresholdMismatch { supplied, roster } => write!(
                f,
                "request inner threshold {} is not the roster's {}",
                supplied, roster
            ),
        }
    }
}

impl std::error::Error for WeightedError {}

impl From<frostito::Error> for WeightedError {
    fn from(e: frostito::Error) -> Self {
        Self::Frostito(e)
    }
}

// ── the roster: where weight comes from (W-2/W-3/W-4) ───────────────────────

/// The epoch's stake allocation: which share indices each validator holds.
///
/// This is the object a weight is read from. It is meant to be the *signed*
/// epoch roster — derived from the DKG output and stake at epoch boundary —
/// distributed to every validator, so that no participant's claim about its
/// own weight is ever load-bearing (W-2).
///
/// [`WeightedRoster::new`] is the only constructor and enforces:
///
/// - validator and share indices are 1-indexed;
/// - no duplicate validator index;
/// - every validator holds at least one share (weight 0 rejected, W-4);
/// - no share index appears in two bundles or twice in one (W-4) — an overlap
///   would double-count `λ_j·s_j` in the aggregate;
/// - **`max_weight < threshold`** — no single validator can reconstruct the
///   nested position's secret alone (W-3);
/// - the total weight is summed with `u64` `checked_add` and reaches the
///   threshold (W-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightedRoster {
    /// (validator_index, its share indices), sorted by validator index, each
    /// bundle sorted.
    allocations: Vec<(u32, Vec<u32>)>,
    threshold: u32,
}

impl WeightedRoster {
    /// Build and check an epoch roster. See the type docs for the invariants.
    pub fn new(
        allocations: &[(u32, Vec<u32>)],
        threshold: u32,
    ) -> Result<Self, WeightedError> {
        if threshold < 2 {
            // threshold 0 is meaningless and threshold 1 makes the W-3
            // invariant (weight >= 1 and weight < threshold) unsatisfiable.
            return Err(WeightedError::ThresholdTooSmall(threshold));
        }
        if allocations.is_empty() {
            return Err(WeightedError::EmptyRoster);
        }

        let mut seen_validators: Vec<u32> = Vec::with_capacity(allocations.len());
        let mut seen_shares: Vec<u32> = Vec::new();
        let mut total: u64 = 0;
        let mut owned: Vec<(u32, Vec<u32>)> = Vec::with_capacity(allocations.len());

        for (validator_index, share_indices) in allocations {
            if *validator_index == 0 {
                return Err(WeightedError::ZeroIndex);
            }
            if seen_validators.contains(validator_index) {
                return Err(WeightedError::DuplicateValidator(*validator_index));
            }
            seen_validators.push(*validator_index);

            if share_indices.is_empty() {
                return Err(WeightedError::ZeroWeight(*validator_index));
            }
            let mut bundle = share_indices.clone();
            bundle.sort_unstable();
            for idx in &bundle {
                if *idx == 0 {
                    return Err(WeightedError::ZeroIndex);
                }
                if seen_shares.contains(idx) {
                    return Err(WeightedError::DuplicateShareIndex(*idx));
                }
                seen_shares.push(*idx);
            }

            let weight = bundle.len() as u32;
            if weight >= threshold {
                return Err(WeightedError::WeightReachesThreshold {
                    validator_index: *validator_index,
                    weight,
                    threshold,
                });
            }
            total = total
                .checked_add(weight as u64)
                .ok_or(WeightedError::WeightOverflow)?;

            owned.push((*validator_index, bundle));
        }

        if total < threshold as u64 {
            return Err(WeightedError::RosterBelowThreshold { total, threshold });
        }

        owned.sort_unstable_by_key(|(v, _)| *v);
        Ok(Self {
            allocations: owned,
            threshold,
        })
    }

    /// The number of active share indices a signature needs.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Every (validator index, share indices) pair, sorted by validator index.
    pub fn allocations(&self) -> &[(u32, Vec<u32>)] {
        &self.allocations
    }

    /// The share indices allocated to one validator.
    pub fn share_indices(&self, validator_index: u32) -> Result<&[u32], WeightedError> {
        self.allocations
            .iter()
            .find(|(v, _)| *v == validator_index)
            .map(|(_, idxs)| idxs.as_slice())
            .ok_or(WeightedError::UnknownValidator(validator_index))
    }

    /// One validator's rostered weight.
    pub fn weight(&self, validator_index: u32) -> Result<u32, WeightedError> {
        Ok(self.share_indices(validator_index)?.len() as u32)
    }

    /// The roster's total weight (checked at construction, so no overflow).
    pub fn total_weight(&self) -> u64 {
        self.allocations.iter().map(|(_, i)| i.len() as u64).sum()
    }

    /// The largest single weight. Always `< threshold()` (W-3).
    pub fn max_weight(&self) -> u32 {
        self.allocations
            .iter()
            .map(|(_, i)| i.len() as u32)
            .max()
            .unwrap_or(0)
    }

    /// **The W-2 fix.** Given the participating validator set, return the
    /// active share indices the roster allocates to it — after checking the
    /// combined weight reaches the threshold.
    ///
    /// This return value, not anything a validator asserts, is what the
    /// coordinator puts in the [`NestedSigningRequest`], and every signer
    /// recomputes it for itself before signing.
    ///
    /// # Errors
    ///
    /// [`WeightedError::EmptyParticipants`],
    /// [`WeightedError::DuplicateValidator`],
    /// [`WeightedError::UnknownValidator`],
    /// [`WeightedError::WeightOverflow`],
    /// [`WeightedError::InsufficientWeight`].
    pub fn active_share_indices(
        &self,
        participants: &[u32],
    ) -> Result<Vec<u32>, WeightedError> {
        if participants.is_empty() {
            return Err(WeightedError::EmptyParticipants);
        }
        let mut seen: Vec<u32> = Vec::with_capacity(participants.len());
        let mut active: Vec<u32> = Vec::new();
        let mut total: u64 = 0;
        for v in participants {
            if seen.contains(v) {
                return Err(WeightedError::DuplicateValidator(*v));
            }
            seen.push(*v);
            let idxs = self.share_indices(*v)?;
            total = total
                .checked_add(idxs.len() as u64)
                .ok_or(WeightedError::WeightOverflow)?;
            active.extend_from_slice(idxs);
        }
        if total < self.threshold as u64 {
            return Err(WeightedError::InsufficientWeight {
                got: total,
                need: self.threshold,
            });
        }
        active.sort_unstable();
        Ok(active)
    }

    /// Whether the participating validator set carries enough rostered stake.
    ///
    /// Replaces the old `frostito_threshold_met(&[FrostitoCommitment], t)`,
    /// which summed weights the validators asserted about themselves (W-2) in
    /// `u32` (W-4).
    pub fn threshold_met(&self, participants: &[u32]) -> bool {
        self.active_share_indices(participants).is_ok()
    }
}

// ── a validator's share bundle ──────────────────────────────────────────────

/// One validator's bundle of Shamir shares, checked against the roster.
pub struct ValidatorShares {
    validator_index: u32,
    shares: Vec<SecretShare<Scalar>>,
}

impl core::fmt::Debug for ValidatorShares {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatorShares")
            .field("validator_index", &self.validator_index)
            .field("share_indices", &self.share_indices())
            .field("shares", &"[REDACTED]")
            .finish()
    }
}

impl ValidatorShares {
    /// Bind a share bundle to its roster entry.
    ///
    /// The bundle's share indices must be exactly the set the roster allocates
    /// to `validator_index`; the W-3 invariant is re-checked here, so a bundle
    /// that was somehow assembled against a different roster cannot be used.
    pub fn from_roster(
        roster: &WeightedRoster,
        validator_index: u32,
        shares: Vec<SecretShare<Scalar>>,
    ) -> Result<Self, WeightedError> {
        let rostered = roster.share_indices(validator_index)?;

        let mut mine: Vec<u32> = shares.iter().map(|s| s.index).collect();
        mine.sort_unstable();
        if mine != rostered {
            return Err(WeightedError::ShareSetMismatch(validator_index));
        }
        // W-3, at the second site: a bundle is never allowed to reach quorum
        // on its own, whatever the roster was built from.
        let weight = mine.len() as u32;
        if weight >= roster.threshold() {
            return Err(WeightedError::WeightReachesThreshold {
                validator_index,
                weight,
                threshold: roster.threshold(),
            });
        }

        Ok(Self {
            validator_index,
            shares,
        })
    }

    pub fn validator_index(&self) -> u32 {
        self.validator_index
    }

    /// Stake weight = number of shares held.
    pub fn weight(&self) -> u32 {
        self.shares.len() as u32
    }

    /// All share indices held by this validator.
    pub fn share_indices(&self) -> Vec<u32> {
        self.shares.iter().map(|s| s.index).collect()
    }

    /// `effective = Σ_j λ_j · s_j` over this validator's shares, where λ_j are
    /// the Lagrange coefficients for the FULL active share set.
    pub fn effective_share(&self, all_active_indices: &[u32]) -> Result<Scalar, WeightedError> {
        let all_lambda = compute_lagrange_coefficients::<Scalar>(all_active_indices)?;

        let mut effective = Scalar::ZERO;
        for share in &self.shares {
            let pos = all_active_indices
                .iter()
                .position(|&i| i == share.index)
                .ok_or(frostito::Error::InvalidIndex)?;
            effective += all_lambda[pos] * share.scalar();
        }
        Ok(effective)
    }

    /// The public counterpart of [`Self::effective_share`]:
    /// `Σ_j λ_j · P_j` over this validator's shares, from the public
    /// verification shares. This is what [`frostito_verify_response`] checks
    /// a response against, and it is derivable from the DKG commitments by
    /// anybody.
    pub fn effective_pubkey(
        share_indices: &[u32],
        public_shares: &[(u32, Point)],
        all_active_indices: &[u32],
    ) -> Result<Point, WeightedError> {
        let all_lambda = compute_lagrange_coefficients::<Scalar>(all_active_indices)?;
        let mut acc = Point::identity();
        for idx in share_indices {
            let pos = all_active_indices
                .iter()
                .position(|i| i == idx)
                .ok_or(frostito::Error::InvalidIndex)?;
            let p = public_shares
                .iter()
                .find(|(i, _)| i == idx)
                .map(|(_, p)| p)
                .ok_or(frostito::Error::InvalidIndex)?;
            acc = acc.add(&p.mul_scalar(&all_lambda[pos]));
        }
        Ok(acc)
    }
}

// ── round 1: one nonce per physical validator ───────────────────────────────

/// A validator's nonce pair for one weighted round.
///
/// Local rather than `frostito::nested::InnerNonces` only because that type's
/// scalars are `pub(crate)`; the shape, the session binding and the zeroizing
/// `Drop` are the same. See the module header.
pub struct WeightedNonce {
    /// The validator's index — the `holder_index` of the published
    /// [`InnerCommitments`].
    pub validator_index: u32,
    /// The inner round this pair was committed for.
    pub session_id: [u8; 32],
    hiding: Scalar,
    binding: Scalar,
}

impl Drop for WeightedNonce {
    fn drop(&mut self) {
        self.hiding.zeroize();
        self.binding.zeroize();
    }
}

/// Round 1: a validator generates ONE nonce pair, whatever its weight.
///
/// `session_id` names the inner round; it is public, must be agreed before
/// round 1, and is carried into the precommitment and checked at signing
/// time, exactly as in `frostito::nested` (N-2).
///
/// The published commitment is a `frostito::nested::InnerCommitments`, so
/// `inner_precommit`, `verify_inner_precommit`,
/// `aggregate_inner_commitment_pair` and `verify_nested_commitment` all apply
/// unchanged. Note it carries no weight field: weight comes from the roster
/// (W-2), so there is no self-asserted claim left to bind into the
/// precommitment.
/// The Orchard spend-auth basepoint, as the bare `Point` the frostito nonce
/// and commitment types are parameterized by.
///
/// This is the generator of the FROST group `reddsa::frost::redpallas` signs
/// in (`orchard::SpendAuth::basepoint()`), **not** `pasta_curves`'
/// `Point::generator()`. frostito's point-generic helpers default to the
/// latter, so every group operation this module performs over a scalar on the
/// weighted path states the basepoint explicitly (see the module docs).
#[inline]
fn spend_auth_generator() -> Point {
    SpendAuthPoint::basepoint().0
}

pub fn frostito_commit(
    validator_index: u32,
    session_id: [u8; 32],
) -> (WeightedNonce, InnerCommitments<Point>) {
    let mut rng = rand_core::OsRng;
    let hiding = rand_scalar(&mut rng);
    let binding = rand_scalar(&mut rng);

    let commitment = InnerCommitments {
        holder_index: validator_index,
        session_id,
        hiding: spend_auth_generator().mul_scalar(&hiding),
        binding: spend_auth_generator().mul_scalar(&binding),
    };

    (
        WeightedNonce {
            validator_index,
            session_id,
            hiding,
            binding,
        },
        commitment,
    )
}

/// Coordinator: the PAIR `(Σ D_k, Σ E_k)` the outer protocol consumes as the
/// nested position's `SigningCommitments`.
///
/// Straight through to frostito, which rejects an empty set, a duplicate
/// validator and a commitment from another session.
///
/// **M-20.** The commit–reveal round is no longer caller convention: frostito
/// takes the round-0 precommitments and verifies every reveal against one,
/// returning `PrecommitMismatch(holder)`. `precommits` is
/// `(holder_index, precommit)`; entries for validators that did not reveal are
/// ignored, a reveal without a matching precommitment is rejected.
pub fn frostito_aggregate_commitment_pair(
    session_id: &[u8; 32],
    precommits: &[(u32, [u8; 32])],
    commitments: &[InnerCommitments<Point>],
) -> Result<(Point, Point), WeightedError> {
    Ok(aggregate_inner_commitment_pair::<Point>(
        session_id,
        precommits,
        commitments,
    )?)
}

// ── round 2: one response per physical validator ────────────────────────────

/// Round 2: a validator's single response, bound to the outer context it
/// derives for itself.
///
///   `z_k = d_k + ρ·e_k + (λ_out · c) · effective_k`
///
/// **W-1 / M-4.** The outer binding factor, challenge and Lagrange coefficient
/// are obtained *only* from [`frostito::zf::inner_params_from_zf`] over the
/// outer package and the group key the validator holds. Nothing here recomputes
/// a binding factor locally and no coordinator can supply one: the type has no
/// public fields.
///
/// `local_group_pubkey` is `Y`, and it is a parameter rather than a field of
/// `request` because frostito removed `NestedSigningRequest::group_pubkey`
/// (M-4): with the binding factor now covering `Y` (M-24, RFC 9591 §4.4), a
/// coordinator-asserted `Y'` would give free choice of ρ and c over a fixed
/// message. Pass the key from this validator's own key material — never
/// anything that arrived with the request.
///
/// Before producing a share this refuses unless:
///
/// 1. `approved_message` is byte-for-byte the outer package's message (N-1/W-1)
///    — so the validator signs the payload it approved and an application
///    policy check on those bytes is possible before the call;
/// 2. the nonce pair belongs to `request.session_id`, and the published
///    round-1 set contains this validator's own commitment for that session,
///    matching these nonces (N-2);
/// 3. the outer package's entry for the nested position is exactly
///    `(Σ D_k, Σ E_k)` over that set, every member of which matches its
///    round-0 precommitment (N-2, M-20);
/// 4. `request.inner_threshold` is the roster's threshold (M-14) — on this
///    path the roster is the local anchor for `t_in`;
/// 5. the bundle's weight is the roster's and is `< threshold` (W-3, second
///    site);
/// 6. `request.active_indices` names at least `t_in` shares — frostito's own
///    `InsufficientContributions` guard, mirrored below. Here
///    `active_indices` is the list of active SHARE indices, so its length is
///    the active weight;
/// 7. `request.active_indices` is exactly what the roster derives for the
///    validator set that published round-1 commitments (W-2) — the signer
///    does not take the coordinator's word for which shares are active, since
///    that set drives every λ_j.
///
/// `nonce` is taken BY VALUE: it is consumed and zeroized on drop, so a
/// validator cannot produce two responses from one commitment round without
/// deliberately cloning. Callers persisting state across restarts must
/// additionally record `(session_id, validator_index)` as spent.
pub fn frostito_sign_v2(
    nonce: WeightedNonce,
    bundle: &ValidatorShares,
    local_group_pubkey: &VerifyingKey,
    approved_message: &[u8],
    request: &NestedSigningRequest<'_, Suite>,
    roster: &WeightedRoster,
) -> Result<InnerSignatureShare<Scalar>, WeightedError> {
    // (1) the validator signs a message it holds, not one a coordinator asserts.
    if request.package.message() != approved_message {
        return Err(frostito::Error::MessageMismatch.into());
    }

    // (2) this round is the round the nonces were committed to ...
    if nonce.session_id != request.session_id {
        return Err(frostito::Error::SessionMismatch.into());
    }
    // ... and the published set really contains our own round-1 commitment.
    let mine = request
        .inner_commitments
        .iter()
        .find(|c| c.holder_index == nonce.validator_index)
        .ok_or(frostito::Error::UnexpectedCommitment)?;
    if mine.session_id != request.session_id
        || mine.hiding != spend_auth_generator().mul_scalar(&nonce.hiding)
        || mine.binding != spend_auth_generator().mul_scalar(&nonce.binding)
    {
        return Err(frostito::Error::UnexpectedCommitment.into());
    }

    // (3) the nested position's outer commitment is this round's aggregate,
    // over a commitment set every member of which matches its round-0
    // precommitment (M-20 — verified inside frostito now, not by convention).
    verify_nested_commitment::<Suite>(
        request.package,
        request.nested_index,
        &request.session_id,
        request.inner_precommits,
        request.inner_commitments,
    )?;

    // (4) M-14: t_in is the roster's, never the request's.
    if request.inner_threshold != roster.threshold() {
        return Err(WeightedError::ThresholdMismatch {
            supplied: request.inner_threshold,
            roster: roster.threshold(),
        });
    }

    // (5) W-3 at signing time.
    let rostered_weight = roster.weight(bundle.validator_index)?;
    if rostered_weight != bundle.weight() {
        return Err(WeightedError::ShareSetMismatch(bundle.validator_index));
    }
    if rostered_weight >= roster.threshold() {
        return Err(WeightedError::WeightReachesThreshold {
            validator_index: bundle.validator_index,
            weight: rostered_weight,
            threshold: roster.threshold(),
        });
    }

    // (6) frostito 0.8's `inner_sign` refuses a quorum smaller than `t_in`
    // (`InsufficientContributions`) before it computes any Lagrange
    // coefficient. `active_indices` here is the active SHARE set, so its
    // length is the active weight; mirror that guard. Its per-member checks
    // (`InvalidIndex` on k == 0, `DuplicateIndex`, and the new
    // `UnknownQuorumMember` for a member absent from `inner_commitments`) have
    // no literal analogue on this path: check (7) below requires
    // `active_indices` to equal EXACTLY the roster's bundle union for the
    // validators that published round-1 commitments — which rejects a zero
    // index, a duplicate, and any member the roster did not allocate to a
    // publishing validator. That is strictly stronger than checking each
    // member is merely present in `inner_commitments`, so no weaker copy of
    // `UnknownQuorumMember` is added.
    if (request.active_indices.len() as u64) < roster.threshold() as u64 {
        return Err(WeightedError::InsufficientWeight {
            got: request.active_indices.len() as u64,
            need: roster.threshold(),
        });
    }

    // (7) W-2: the active share set is the roster's, over the validators that
    // actually published round-1 commitments — not a list the coordinator
    // asserts.
    let participants: Vec<u32> = request
        .inner_commitments
        .iter()
        .map(|c| c.holder_index)
        .collect();
    let derived = roster.active_share_indices(&participants)?;
    let mut supplied = request.active_indices.to_vec();
    supplied.sort_unstable();
    if supplied != derived {
        return Err(WeightedError::ActiveIndicesMismatch);
    }

    // W-1/M-4: the only derivation of the outer context, over the group key
    // this validator holds locally.
    let params = frostito::zf::inner_params_from_zf::<Suite>(
        request.package,
        local_group_pubkey,
        request.nested_index,
    )?;

    let mut effective = bundle.effective_share(&derived)?;
    let nonce_part = nonce.hiding + *params.outer_binding() * nonce.binding;
    let secret_part = *params.outer_lambda() * *params.outer_challenge() * effective;
    let response = nonce_part + secret_part;
    // W-4: `effective` is a linear combination of secrets.
    effective.zeroize();

    Ok(InnerSignatureShare {
        holder_index: nonce.validator_index,
        response,
    })
}

/// Verify one validator's response before aggregating:
///
///   `z_k·G  ==  (D_k + ρ·E_k) + (λ_out·c)·EffectivePub_k`
///
/// This is `frostito::nested::verify_inner_share` with `μ_k = 1`: the weighted
/// validator's Lagrange coefficients are already inside `EffectivePub_k`
/// (see [`ValidatorShares::effective_pubkey`]), where the unweighted holder's
/// sit outside its single public share. Same equation, same code.
pub fn frostito_verify_response(
    response: &InnerSignatureShare<Scalar>,
    commitment: &InnerCommitments<Point>,
    effective_pubkey: &Point,
    params: &InnerSigningParams<Scalar>,
) -> bool {
    // Instantiating the same function at the ZF point type is what selects
    // the spend-auth basepoint: `verify_inner_share::<Point>` would multiply
    // by pasta's default generator, which is not the group the outer package
    // and every key on this path live in.
    verify_inner_share::<SpendAuthPoint>(
        response,
        &InnerCommitments {
            holder_index: commitment.holder_index,
            session_id: commitment.session_id,
            hiding: SpendAuthPoint(commitment.hiding),
            binding: SpendAuthPoint(commitment.binding),
        },
        &SpendAuthPoint(*effective_pubkey),
        params,
        &Scalar::ONE,
    )
}

/// Coordinator: verify every validator response, then aggregate into
/// `z_nested`.
///
/// `Err(indices)` names the validators at fault so they can be evicted and the
/// round retried, instead of emitting a signature that simply fails to verify
/// with no attribution. Mirroring frostito's N-3, the multiset of
/// `holder_index` must equal `participants` exactly: a validator that produced
/// no response, and one that produced two, are both named (W-4 — the old
/// version resolved commitments with `find` and so verified and added a
/// duplicate twice).
pub fn frostito_aggregate_responses_verified(
    responses: &[InnerSignatureShare<Scalar>],
    commitments: &[InnerCommitments<Point>],
    effective_pubkeys: &[(u32, Point)],
    params: &InnerSigningParams<Scalar>,
    participants: &[u32],
) -> Result<Scalar, Vec<u32>> {
    let mut bad: Vec<u32> = Vec::new();

    // quorum coverage: every participant exactly once, nothing else.
    let mut seen: Vec<u32> = Vec::with_capacity(responses.len());
    for r in responses {
        if (!participants.contains(&r.holder_index) || seen.contains(&r.holder_index))
            && !bad.contains(&r.holder_index)
        {
            bad.push(r.holder_index);
        }
        seen.push(r.holder_index);
    }
    for &k in participants {
        if !seen.contains(&k) && !bad.contains(&k) {
            bad.push(k);
        }
    }

    let mut z = Scalar::ZERO;
    for r in responses {
        let k = r.holder_index;
        let commitment = commitments.iter().find(|c| c.holder_index == k);
        let pubkey = effective_pubkeys
            .iter()
            .find(|(i, _)| *i == k)
            .map(|(_, p)| p);
        match (commitment, pubkey) {
            (Some(commitment), Some(pubkey)) => {
                if frostito_verify_response(r, commitment, pubkey, params) {
                    z += r.response;
                } else if !bad.contains(&k) {
                    bad.push(k);
                }
            }
            _ => {
                if !bad.contains(&k) {
                    bad.push(k);
                }
            }
        }
    }

    if bad.is_empty() {
        Ok(z)
    } else {
        bad.sort_unstable();
        Err(bad)
    }
}

// ── unweighted (one share per validator) passthroughs ───────────────────────
//
// For a nested position whose holders each own exactly one share, frostito's
// own nested signing is used directly; these wrappers exist only to keep the
// suite type parameter off call sites.
//
// CAVEAT: frostito's suite-generic path is rooted in
// `<Element<C> as CurvePoint>::generator()` — pasta's DEFAULT generator on the
// pallas suite — so these wrappers are consistent only with an outer FROST
// built in that same group. They are NOT usable with the ZF custody key
// material of [`crate::hierarchical`], whose group is the Orchard spend-auth
// group. Use the weighted path for any weight, including one share per holder.
//
// Because no FROST implementation in this workspace signs in that group any
// more (`bin/poker`'s frozen `osst` was the last one), these wrappers have no
// end-to-end test here; the weighted path above is the tested, production
// entry point.

/// Round 1 for an unweighted inner holder.
pub fn validator_commit(
    holder_index: u32,
    session_id: [u8; 32],
) -> (InnerNonces<Scalar>, InnerCommitments<Point>) {
    nested::inner_commit::<Point, _>(holder_index, session_id, &mut rand_core::OsRng)
}

/// Round 2 for an unweighted inner holder: `frostito::nested::inner_sign`.
///
/// `local_group_pubkey` is the outer group key `Y`, taken from the holder's own
/// key material: frostito removed it from `NestedSigningRequest` (M-4) because
/// the binding factor now covers it (M-24).
pub fn validator_sign_v2(
    nonces: InnerNonces<Scalar>,
    share: &SecretShare<Scalar>,
    local_group_pubkey: &VerifyingKey,
    approved_message: &[u8],
    request: &NestedSigningRequest<'_, Suite>,
) -> Result<InnerSignatureShare<Scalar>, frostito::Error> {
    nested::inner_sign::<Suite>(
        nonces,
        share,
        local_group_pubkey,
        approved_message,
        request,
    )
}

/// Verify-then-aggregate for the unweighted path.
pub fn aggregate_validator_shares_verified(
    sigs: &[InnerSignatureShare<Scalar>],
    commitments: &[InnerCommitments<Point>],
    public_shares: &[(u32, Point)],
    params: &InnerSigningParams<Scalar>,
    active_indices: &[u32],
) -> Result<Scalar, Vec<u32>> {
    nested::aggregate_inner_shares_verified::<Point>(
        sigs,
        commitments,
        public_shares,
        params,
        active_indices,
    )
}

// ── tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{self, round1, round2, Identifier, Signature, SigningPackage};
    use crate::frost_keys::{self, IdentifierList};
    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::group::GroupEncoding;
    use std::collections::BTreeMap;

    const SESSION: [u8; 32] = [7u8; 32];

    fn id(i: u16) -> Identifier {
        Identifier::try_from(i).expect("small identifier")
    }

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

    /// The standard fixture: a 3-validator, 10-share, threshold-7 nested
    /// position sitting in a 2-of-2 outer FROST group alongside a flat signer.
    struct Fixture {
        roster: WeightedRoster,
        bundles: Vec<ValidatorShares>,
        public_shares: Vec<(u32, Point)>,
        nested_secret: Scalar,
        key_a: frost_keys::KeyPackage,
        pubkeys: frost_keys::PublicKeyPackage,
        group_key: VerifyingKey,
    }

    const NESTED_INDEX: u32 = 2;

    // ── a real outer FROST group ───────────────────────────────────────────
    //
    // W-1's point is that the nested position is indistinguishable from an
    // ordinary outer signer, so the tests drive it through the SAME path a flat
    // signer uses: a genuine `frost_keys` 2-of-2 key pair, the flat signer's
    // `round1::commit` / `round2::sign`, and `frost::aggregate`. The nested
    // position's secret is read out of its dealer share only to seed the inner
    // Shamir split — nothing about the outer group is reconstructed by hand.

    /// The flat signer (identifier 1) and the nested position (identifier 2).
    struct Outer {
        key_a: frost_keys::KeyPackage,
        pubkeys: frost_keys::PublicKeyPackage,
        group_key: VerifyingKey,
        nested_secret: Scalar,
    }

    fn outer_2of2(rng: &mut rand_core::OsRng) -> Outer {
        let (shares, pubkeys) =
            frost_keys::generate_with_dealer(2, 2, IdentifierList::Default, rng)
                .expect("2-of-2 dealer keygen");
        let key_a =
            frost_keys::KeyPackage::try_from(shares[&id(1)].clone()).expect("share 1 verifies");
        let nested_secret = shares[&id(2)].signing_share().to_scalar();
        let group_key = *pubkeys.verifying_key();
        Outer {
            key_a,
            pubkeys,
            group_key,
            nested_secret,
        }
    }

    /// The outer signing package: the flat signer's round-1 commitments plus
    /// the nested position's aggregate commitment pair.
    fn outer_package(
        a_commits: round1::SigningCommitments,
        d_nested: Point,
        e_nested: Point,
        message: &[u8],
    ) -> SigningPackage {
        let mut commits = BTreeMap::new();
        commits.insert(id(1), a_commits);
        commits.insert(
            id(2),
            round1::SigningCommitments::new(
                round1::NonceCommitment::deserialize(&GroupEncoding::to_bytes(&d_nested))
                    .expect("commitment"),
                round1::NonceCommitment::deserialize(&GroupEncoding::to_bytes(&e_nested))
                    .expect("commitment"),
            ),
        );
        SigningPackage::new(commits, message)
    }

    /// Sign with the flat signer, wrap the aggregated nested response as the
    /// nested position's share, and aggregate the outer 2-of-2 signature.
    fn outer_sign(
        package: &SigningPackage,
        key_a: &frost_keys::KeyPackage,
        a_nonces: round1::SigningNonces,
        z_nested: Scalar,
        pubkeys: &frost_keys::PublicKeyPackage,
    ) -> Signature {
        let a_sig = round2::sign(package, &a_nonces, key_a).expect("flat signer");
        let nested_sig =
            round2::SignatureShare::deserialize(&z_nested.to_repr()).expect("nested response");
        let mut sigs = BTreeMap::new();
        sigs.insert(id(1), a_sig);
        sigs.insert(id(2), nested_sig);
        frost::aggregate(package, &sigs, pubkeys).expect("2-of-2 aggregate")
    }

    fn fixture(rng: &mut rand_core::OsRng) -> Fixture {
        let allocation = vec![
            (1u32, vec![1u32, 2, 3, 4]),
            (2u32, vec![5u32, 6, 7]),
            (3u32, vec![8u32, 9, 10]),
        ];
        let roster = WeightedRoster::new(&allocation, 7).unwrap();

        // Outer 2-of-2: identifier 1 flat, identifier 2 nested, real key
        // material from the dealer.
        let outer = outer_2of2(rng);

        // the nested position's secret, split 7-of-10 among the share indices
        let inner = shamir(outer.nested_secret, 10, 7, rng);
        let public_shares: Vec<(u32, Point)> = inner
            .iter()
            .map(|s| (s.index, spend_auth_generator().mul_scalar(s.scalar())))
            .collect();

        let bundles = allocation
            .iter()
            .map(|(v, idxs)| {
                let shares = idxs.iter().map(|i| inner[(*i - 1) as usize].clone()).collect();
                ValidatorShares::from_roster(&roster, *v, shares).unwrap()
            })
            .collect();

        Fixture {
            roster,
            bundles,
            public_shares,
            nested_secret: outer.nested_secret,
            key_a: outer.key_a,
            pubkeys: outer.pubkeys,
            group_key: outer.group_key,
        }
    }

    /// W-1's regression test: the outer context is derived from a REAL outer
    /// signing package, and the weighted nested position produces exactly what
    /// a flat FROST signer holding the nested secret would — so the whole
    /// 2-of-2 signature verifies end to end.
    ///
    /// The old version of this test handed the signer three uniformly random
    /// scalars as its "outer context", which is precisely the defect W-1
    /// names: `frostito_sign_v2` can no longer be called that way.
    #[test]
    fn frostito_v2_equals_flat_frost_signer() {
        let mut rng = rand_core::OsRng;
        let f = fixture(&mut rng);
        let message = b"weighted nested spend authorization";
        let participants: Vec<u32> = vec![1, 2, 3];
        let active = f.roster.active_share_indices(&participants).unwrap();

        // ── round 0/1: commit–reveal ───────────────────────────────────────
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        let mut precommits = Vec::new();
        for b in &f.bundles {
            let (n, c) = frostito_commit(b.validator_index(), SESSION);
            precommits.push((c.holder_index, inner_precommit(&c)));
            nonces.push(n);
            commitments.push(c);
        }
        for ((_, pre), revealed) in precommits.iter().zip(commitments.iter()) {
            assert!(verify_inner_precommit(pre, revealed));
        }
        {
            let mut bad = commitments[0].clone();
            bad.hiding = bad.hiding.add(&Point::generator());
            assert!(!verify_inner_precommit(&precommits[0].1, &bad));
        }

        // M-20: frostito now verifies the reveals against the precommitments
        // here, so a substituted reveal is refused by the aggregate itself
        // rather than only by the caller's own convention.
        let (d_nested, e_nested) =
            frostito_aggregate_commitment_pair(&SESSION, &precommits, &commitments).unwrap();
        {
            let mut tampered = commitments.clone();
            tampered[0].hiding = tampered[0].hiding.add(&Point::generator());
            assert!(matches!(
                frostito_aggregate_commitment_pair(&SESSION, &precommits, &tampered),
                Err(WeightedError::Frostito(frostito::Error::PrecommitMismatch(1)))
            ));
        }

        // ── a real outer package ───────────────────────────────────────────
        let (a_nonces, a_commits) = round1::commit(f.key_a.signing_share(), &mut rng);
        let package = outer_package(a_commits, d_nested, e_nested, message);

        let request = NestedSigningRequest {
            package: &package,
            nested_index: NESTED_INDEX,
            session_id: SESSION,
            inner_precommits: &precommits,
            inner_commitments: &commitments,
            active_indices: &active,
            inner_threshold: f.roster.threshold(),
        };

        // ── validators sign; every response is verified ────────────────────
        let effective_pubkeys: Vec<(u32, Point)> = f
            .bundles
            .iter()
            .map(|b| {
                (
                    b.validator_index(),
                    ValidatorShares::effective_pubkey(
                        &b.share_indices(),
                        &f.public_shares,
                        &active,
                    )
                    .unwrap(),
                )
            })
            .collect();

        let mut responses = Vec::new();
        for (n, b) in nonces.into_iter().zip(f.bundles.iter()) {
            responses.push(frostito_sign_v2(n, b, &f.group_key, message, &request, &f.roster).unwrap());
        }

        let params =
            frostito::zf::inner_params_from_zf::<Suite>(&package, &f.group_key, NESTED_INDEX)
                .unwrap();
        let z_nested = frostito_aggregate_responses_verified(
            &responses,
            &commitments,
            &effective_pubkeys,
            &params,
            &participants,
        )
        .expect("all validator responses must verify");

        // ── equivalence: a flat signer holding the nested secret ───────────
        // z_flat = λ·c·σ + d + ρ·e, with (d, e) the nested position's nonces —
        // check it through the inner-share equation of the nested position as
        // an ordinary signer.
        let nested_public = spend_auth_generator().mul_scalar(&f.nested_secret);
        assert!(
            frostito_verify_response(
                &InnerSignatureShare {
                    holder_index: NESTED_INDEX,
                    response: z_nested,
                },
                &InnerCommitments {
                    holder_index: NESTED_INDEX,
                    session_id: SESSION,
                    hiding: d_nested,
                    binding: e_nested,
                },
                &nested_public,
                &params,
            ),
            "the weighted nested response must be a flat signer's response"
        );

        // ── and the whole outer signature verifies ─────────────────────────
        let signature = outer_sign(&package, &f.key_a, a_nonces, z_nested, &f.pubkeys);
        assert!(
            f.group_key.verify(message, &signature).is_ok(),
            "2-of-2 outer × weighted 7-of-10 inner must verify"
        );
    }

        #[test]
    fn frostito_v2_rejects_a_message_the_validator_did_not_approve() {
        let mut rng = rand_core::OsRng;
        let f = fixture(&mut rng);
        let participants: Vec<u32> = vec![1, 2, 3];
        let active = f.roster.active_share_indices(&participants).unwrap();

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for b in &f.bundles {
            let (n, c) = frostito_commit(b.validator_index(), SESSION);
            nonces.push(n);
            commitments.push(c);
        }
        let precommits: Vec<(u32, [u8; 32])> = commitments
            .iter()
            .map(|c| (c.holder_index, inner_precommit(c)))
            .collect();
        let (d, e) =
            frostito_aggregate_commitment_pair(&SESSION, &precommits, &commitments).unwrap();
        let (_, a_commits) = round1::commit(f.key_a.signing_share(), &mut rng);
        let package = outer_package(a_commits, d, e, b"coordinator's own payload");
        let request = NestedSigningRequest {
            package: &package,
            nested_index: NESTED_INDEX,
            session_id: SESSION,
            inner_precommits: &precommits,
            inner_commitments: &commitments,
            active_indices: &active,
            inner_threshold: f.roster.threshold(),
        };

        let err = frostito_sign_v2(
            nonces.remove(0),
            &f.bundles[0],
            &f.group_key,
            b"what the validator approved",
            &request,
            &f.roster,
        )
        .expect_err("a mismatched message must be refused");
        assert_eq!(err, WeightedError::Frostito(frostito::Error::MessageMismatch));
    }

    /// N-2/W-2: the signer refuses a coordinator-chosen active share set, and
    /// refuses nonces from another session.
    #[test]
    fn frostito_v2_rejects_a_tampered_request() {
        let mut rng = rand_core::OsRng;
        let f = fixture(&mut rng);
        let message = b"spend";
        let participants: Vec<u32> = vec![1, 2, 3];
        let active = f.roster.active_share_indices(&participants).unwrap();

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for b in &f.bundles {
            let (n, c) = frostito_commit(b.validator_index(), SESSION);
            nonces.push(n);
            commitments.push(c);
        }
        let precommits: Vec<(u32, [u8; 32])> = commitments
            .iter()
            .map(|c| (c.holder_index, inner_precommit(c)))
            .collect();
        let (d, e) =
            frostito_aggregate_commitment_pair(&SESSION, &precommits, &commitments).unwrap();
        let (_, a_commits) = round1::commit(f.key_a.signing_share(), &mut rng);
        let package = outer_package(a_commits, d, e, message);

        // W-2: the coordinator drops validator 3's shares from the active set,
        // which would change every λ_j.
        let mut shrunk = active.clone();
        shrunk.retain(|i| *i <= 7);
        let bad_request = NestedSigningRequest {
            package: &package,
            nested_index: NESTED_INDEX,
            session_id: SESSION,
            inner_precommits: &precommits,
            inner_commitments: &commitments,
            active_indices: &shrunk,
            inner_threshold: f.roster.threshold(),
        };
        let err = frostito_sign_v2(
            nonces.remove(0),
            &f.bundles[0],
            &f.group_key,
            message,
            &bad_request,
            &f.roster,
        )
        .expect_err("a coordinator-chosen active set must be refused");
        assert_eq!(err, WeightedError::ActiveIndicesMismatch);

        // N-2: nonces from another session.
        let (other_nonce, _) = frostito_commit(2, [9u8; 32]);
        let request = NestedSigningRequest {
            package: &package,
            nested_index: NESTED_INDEX,
            session_id: SESSION,
            inner_precommits: &precommits,
            inner_commitments: &commitments,
            active_indices: &active,
            inner_threshold: f.roster.threshold(),
        };
        let err =
            frostito_sign_v2(
                other_nonce,
                &f.bundles[1],
                &f.group_key,
                message,
                &request,
                &f.roster,
            )
                .expect_err("nonces from another session must be refused");
        assert_eq!(err, WeightedError::Frostito(frostito::Error::SessionMismatch));
    }

    /// A validator that tampers with its response is NAMED, and so is one that
    /// answers twice or not at all (W-4).
    #[test]
    fn frostito_v2_names_the_faulty_validator() {
        let mut rng = rand_core::OsRng;
        let f = fixture(&mut rng);
        let message = b"spend";
        let participants: Vec<u32> = vec![1, 2, 3];
        let active = f.roster.active_share_indices(&participants).unwrap();

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for b in &f.bundles {
            let (n, c) = frostito_commit(b.validator_index(), SESSION);
            nonces.push(n);
            commitments.push(c);
        }
        let precommits: Vec<(u32, [u8; 32])> = commitments
            .iter()
            .map(|c| (c.holder_index, inner_precommit(c)))
            .collect();
        let (d, e) =
            frostito_aggregate_commitment_pair(&SESSION, &precommits, &commitments).unwrap();
        let (_, a_commits) = round1::commit(f.key_a.signing_share(), &mut rng);
        let package = outer_package(a_commits, d, e, message);
        let request = NestedSigningRequest {
            package: &package,
            nested_index: NESTED_INDEX,
            session_id: SESSION,
            inner_precommits: &precommits,
            inner_commitments: &commitments,
            active_indices: &active,
            inner_threshold: f.roster.threshold(),
        };
        let params =
            frostito::zf::inner_params_from_zf::<Suite>(&package, &f.group_key, NESTED_INDEX)
                .unwrap();
        let effective_pubkeys: Vec<(u32, Point)> = f
            .bundles
            .iter()
            .map(|b| {
                (
                    b.validator_index(),
                    ValidatorShares::effective_pubkey(
                        &b.share_indices(),
                        &f.public_shares,
                        &active,
                    )
                    .unwrap(),
                )
            })
            .collect();

        let mut responses = Vec::new();
        for (n, b) in nonces.into_iter().zip(f.bundles.iter()) {
            responses.push(frostito_sign_v2(n, b, &f.group_key, message, &request, &f.roster).unwrap());
        }

        // validator 2 goes rogue
        responses[1].response += Scalar::ONE;
        let err = frostito_aggregate_responses_verified(
            &responses,
            &commitments,
            &effective_pubkeys,
            &params,
            &participants,
        )
        .expect_err("a tampered response must be rejected");
        assert_eq!(err, vec![2]);
        responses[1].response -= Scalar::ONE;

        // a duplicated response is named rather than counted twice
        let dup = InnerSignatureShare {
            holder_index: responses[0].holder_index,
            response: responses[0].response,
        };
        let mut with_dup: Vec<InnerSignatureShare<Scalar>> = responses
            .iter()
            .map(|r| InnerSignatureShare {
                holder_index: r.holder_index,
                response: r.response,
            })
            .collect();
        with_dup.push(dup);
        let err = frostito_aggregate_responses_verified(
            &with_dup,
            &commitments,
            &effective_pubkeys,
            &params,
            &participants,
        )
        .expect_err("a duplicated response must be rejected");
        assert_eq!(err, vec![1]);

        // a missing response is named too
        let short: Vec<InnerSignatureShare<Scalar>> = responses
            .iter()
            .take(2)
            .map(|r| InnerSignatureShare {
                holder_index: r.holder_index,
                response: r.response,
            })
            .collect();
        let err = frostito_aggregate_responses_verified(
            &short,
            &commitments,
            &effective_pubkeys,
            &params,
            &participants,
        )
        .expect_err("a missing response must be rejected");
        assert_eq!(err, vec![3]);
    }

    // ── roster invariants (W-2/W-3/W-4) ─────────────────────────────────────

    /// **W-3.** An allocation that hands one validator the threshold is
    /// rejected at construction: it would hold `t` points on a degree-`t−1`
    /// polynomial and could reconstruct the nested secret alone.
    #[test]
    fn roster_rejects_a_validator_that_can_reconstruct_alone() {
        let err = WeightedRoster::new(
            &[(1u32, vec![1u32, 2, 3, 4, 5, 6, 7]), (2u32, vec![8u32, 9, 10])],
            7,
        )
        .expect_err("weight >= threshold must be rejected");
        assert_eq!(
            err,
            WeightedError::WeightReachesThreshold {
                validator_index: 1,
                weight: 7,
                threshold: 7,
            }
        );

        // the boundary is exact: t-1 is fine.
        let ok = WeightedRoster::new(
            &[(1u32, vec![1u32, 2, 3, 4, 5, 6]), (2u32, vec![7u32, 8, 9, 10])],
            7,
        )
        .unwrap();
        assert_eq!(ok.max_weight(), 6);
        assert!(ok.max_weight() < ok.threshold());
    }

    /// **W-4.** Weight 0, duplicate identifiers, overlapping bundles, zero
    /// indices and unreachable thresholds are all rejected.
    #[test]
    fn roster_rejects_malformed_allocations() {
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![]), (2u32, vec![1u32, 2, 3])], 3).unwrap_err(),
            WeightedError::ZeroWeight(1)
        );
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![1u32, 2]), (1u32, vec![3u32, 4])], 5).unwrap_err(),
            WeightedError::DuplicateValidator(1)
        );
        // overlap between two validators double-counts λ_j·s_j
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![1u32, 2]), (2u32, vec![2u32, 3])], 4).unwrap_err(),
            WeightedError::DuplicateShareIndex(2)
        );
        // and a repeat inside one bundle does the same
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![1u32, 1]), (2u32, vec![2u32, 3])], 4).unwrap_err(),
            WeightedError::DuplicateShareIndex(1)
        );
        assert_eq!(
            WeightedRoster::new(&[(0u32, vec![1u32, 2])], 3).unwrap_err(),
            WeightedError::ZeroIndex
        );
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![0u32, 2])], 3).unwrap_err(),
            WeightedError::ZeroIndex
        );
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![1u32]), (2u32, vec![2u32])], 5).unwrap_err(),
            WeightedError::RosterBelowThreshold {
                total: 2,
                threshold: 5
            }
        );
        assert_eq!(
            WeightedRoster::new(&[(1u32, vec![1u32])], 1).unwrap_err(),
            WeightedError::ThresholdTooSmall(1)
        );
        assert_eq!(
            WeightedRoster::new(&[], 3).unwrap_err(),
            WeightedError::EmptyRoster
        );
    }

    /// **W-2.** Stake is counted off the roster, never off a claim in a
    /// validator's own message, and the sum is checked.
    #[test]
    fn threshold_is_counted_from_the_roster() {
        let roster = WeightedRoster::new(
            &[(1u32, vec![1u32, 2, 3, 4]), (2u32, vec![5u32, 6, 7]), (3u32, vec![8u32, 9, 10])],
            7,
        )
        .unwrap();
        assert_eq!(roster.total_weight(), 10);

        // 1+2 = 7 shares, exactly the threshold
        assert!(roster.threshold_met(&[1, 2]));
        assert_eq!(
            roster.active_share_indices(&[1, 2]).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7]
        );
        // 2+3 = 6 shares, below it
        assert!(!roster.threshold_met(&[2, 3]));
        assert_eq!(
            roster.active_share_indices(&[2, 3]).unwrap_err(),
            WeightedError::InsufficientWeight { got: 6, need: 7 }
        );
        // a validator claiming to be two validators gains nothing
        assert_eq!(
            roster.active_share_indices(&[1, 1, 1]).unwrap_err(),
            WeightedError::DuplicateValidator(1)
        );
        // an off-roster validator is not counted at all
        assert_eq!(
            roster.active_share_indices(&[1, 2, 9]).unwrap_err(),
            WeightedError::UnknownValidator(9)
        );
        assert_eq!(
            roster.active_share_indices(&[]).unwrap_err(),
            WeightedError::EmptyParticipants
        );
    }

    /// A share bundle must be the roster's bundle.
    #[test]
    fn validator_shares_must_match_the_roster() {
        let mut rng = rand_core::OsRng;
        let roster = WeightedRoster::new(
            &[(1u32, vec![1u32, 2, 3, 4]), (2u32, vec![5u32, 6, 7]), (3u32, vec![8u32, 9, 10])],
            7,
        )
        .unwrap();
        let shares = shamir(rand_scalar(&mut rng), 10, 7, &mut rng);

        // validator 2 helps itself to one of validator 1's shares
        let greedy = vec![
            shares[4].clone(),
            shares[5].clone(),
            shares[6].clone(),
            shares[0].clone(),
        ];
        assert_eq!(
            ValidatorShares::from_roster(&roster, 2, greedy).unwrap_err(),
            WeightedError::ShareSetMismatch(2)
        );
        assert_eq!(
            ValidatorShares::from_roster(&roster, 9, vec![shares[0].clone()]).unwrap_err(),
            WeightedError::UnknownValidator(9)
        );
    }
}

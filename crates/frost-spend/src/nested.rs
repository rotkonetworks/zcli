// nested.rs — stake-weighted nested FROST v2 (osst 0.5)
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
// ── relationship to osst::nested ────────────────────────────────────────────
//
// This module is the WEIGHTED specialization of `osst::nested`'s v2 nested
// position: the unweighted inner holder contributes μ_k·σ_k, the weighted
// validator contributes Σ_j λ_j·s_j, and everything else — commit–reveal,
// session binding, the aggregate commitment pair, the outer context derivation,
// per-signer share verification — is osst's and is used from osst here.
//
// Concretely it reuses `InnerCommitments`, `InnerSignatureShare`,
// `inner_precommit`/`verify_inner_precommit`, `aggregate_inner_commitment_pair`,
// `verify_nested_commitment`, `NestedSigningRequest`,
// `InnerSigningParamsV2::from_outer` and `verify_inner_share`. Nothing about
// the binding factor or the challenge is recomputed locally; `from_outer` is
// the only derivation, so a coordinator cannot assert an outer context (W-1).
//
// osst 0.5 moves the outer group key `Y` out of `NestedSigningRequest` (M-4)
// and into the binding factor (M-24, RFC 9591 §4.4), so `frostito_sign_v2`
// takes `Y` as a parameter from local key material, and the commit–reveal
// round is enforced by osst rather than documented (M-20): the round-0
// precommitments travel in the request and every reveal is checked against
// one.
//
// It cannot call `osst::nested::inner_sign_v2` itself for two reasons:
//
//   1. `inner_sign_v2` computes μ_k from `share.index` and multiplies the
//      single share by it. A weighted validator's `effective_share` has the
//      Lagrange coefficients applied already, so routing it through that
//      function would apply them twice.
//   2. `InnerNonces`' scalars are `pub(crate)` in osst, so the nonce pair
//      cannot be consumed outside the crate.
//
// Both are upstream items (see the PR description); until osst grows an
// `inner_sign_v2` variant taking a precomputed effective scalar, the
// N-1/N-2 precondition block is mirrored here, calling osst for every check it
// exposes.
//
// ── weights ─────────────────────────────────────────────────────────────────
//
// Weight is a property of the signed epoch roster ([`WeightedRoster`]), never
// of a message a validator sends (W-2). `WeightedRoster::new` enforces the
// invariant that no single validator can reconstruct alone — `max_weight <
// threshold` (W-3) — plus non-zero, non-duplicate, non-overlapping share
// allocations and checked `u64` weight sums (W-4). The invariant is re-checked
// at signing time.

use osst::compute_lagrange_coefficients;
use osst::curve::{OsstPoint, OsstScalar};
use osst::nested;
use osst::SecretShare;
use pasta_curves::group::ff::Field;
use pasta_curves::pallas::{Point, Scalar};

pub use nested::{
    aggregate_inner_commitment_pair, inner_precommit, verify_inner_precommit, verify_inner_share,
    verify_nested_commitment, InnerCommitments, InnerNonces, InnerSignatureShare,
    InnerSigningParamsV2, NestedSigningRequest,
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
/// The roster rejections have no `OsstError` analogue — osst's only "weights"
/// are verification scalars, not integer stake — so they live here and osst
/// errors are wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightedError {
    /// An error from osst itself.
    Osst(osst::OsstError),
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
    /// The participating validators' combined weight is below the threshold.
    InsufficientWeight { got: u64, need: u32 },
    /// The `active_indices` the coordinator supplied are not the ones the
    /// roster derives for the participating validator set (W-2).
    ActiveIndicesMismatch,
    /// No participants were supplied.
    EmptyParticipants,
    /// **M-14.** `NestedSigningRequest::inner_threshold` is not the roster's
    /// threshold. osst documents the field as caller-anchored; on the weighted
    /// path the roster *is* the anchor, so a coordinator's number is refused
    /// rather than trusted.
    ThresholdMismatch { supplied: u32, roster: u32 },
}

impl core::fmt::Display for WeightedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Osst(e) => write!(f, "{}", e),
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

impl From<osst::OsstError> for WeightedError {
    fn from(e: osst::OsstError) -> Self {
        Self::Osst(e)
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
                .ok_or(osst::OsstError::InvalidIndex)?;
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
                .ok_or(osst::OsstError::InvalidIndex)?;
            let p = public_shares
                .iter()
                .find(|(i, _)| i == idx)
                .map(|(_, p)| p)
                .ok_or(osst::OsstError::InvalidIndex)?;
            acc = acc.add(&p.mul_scalar(&all_lambda[pos]));
        }
        Ok(acc)
    }
}

// ── round 1: one nonce per physical validator ───────────────────────────────

/// A validator's nonce pair for one weighted round.
///
/// Local rather than `osst::nested::InnerNonces` only because that type's
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
/// time, exactly as in `osst::nested` (N-2).
///
/// The published commitment is an `osst::nested::InnerCommitments`, so
/// `inner_precommit`, `verify_inner_precommit`,
/// `aggregate_inner_commitment_pair` and `verify_nested_commitment` all apply
/// unchanged. Note it carries no weight field: weight comes from the roster
/// (W-2), so there is no self-asserted claim left to bind into the
/// precommitment.
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
        hiding: Point::generator().mul_scalar(&hiding),
        binding: Point::generator().mul_scalar(&binding),
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
/// Straight through to osst, which rejects an empty set, a duplicate validator
/// and a commitment from another session.
///
/// **M-20.** The commit–reveal round is no longer caller convention: osst 0.5
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
/// are obtained *only* from [`InnerSigningParamsV2::from_outer`] over the outer
/// package and the group key the validator holds. Nothing here recomputes a
/// binding factor locally and no coordinator can supply one: the type has no
/// public fields.
///
/// `local_group_pubkey` is `Y`, and it is a parameter rather than a field of
/// `request` because osst 0.5 removed `NestedSigningRequest::group_pubkey`
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
/// 6. `request.active_indices` is exactly what the roster derives for the
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
    local_group_pubkey: &Point,
    approved_message: &[u8],
    request: &NestedSigningRequest<'_, Point>,
    roster: &WeightedRoster,
) -> Result<InnerSignatureShare<Scalar>, WeightedError> {
    // (1) the validator signs a message it holds, not one a coordinator asserts.
    if request.package.message() != approved_message {
        return Err(osst::OsstError::MessageMismatch.into());
    }

    // (2) this round is the round the nonces were committed to ...
    if nonce.session_id != request.session_id {
        return Err(osst::OsstError::SessionMismatch.into());
    }
    // ... and the published set really contains our own round-1 commitment.
    let mine = request
        .inner_commitments
        .iter()
        .find(|c| c.holder_index == nonce.validator_index)
        .ok_or(osst::OsstError::UnexpectedCommitment)?;
    if mine.session_id != request.session_id
        || mine.hiding != Point::generator().mul_scalar(&nonce.hiding)
        || mine.binding != Point::generator().mul_scalar(&nonce.binding)
    {
        return Err(osst::OsstError::UnexpectedCommitment.into());
    }

    // (3) the nested position's outer commitment is this round's aggregate,
    // over a commitment set every member of which matches its round-0
    // precommitment (M-20 — verified inside osst now, not by convention).
    verify_nested_commitment::<Point>(
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

    // (6) W-2: the active share set is the roster's, over the validators that
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
    let params = InnerSigningParamsV2::from_outer::<Point>(
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
/// This is `osst::nested::verify_inner_share` with `μ_k = 1`: the weighted
/// validator's Lagrange coefficients are already inside `EffectivePub_k`
/// (see [`ValidatorShares::effective_pubkey`]), where the unweighted holder's
/// sit outside its single public share. Same equation, same code.
pub fn frostito_verify_response(
    response: &InnerSignatureShare<Scalar>,
    commitment: &InnerCommitments<Point>,
    effective_pubkey: &Point,
    params: &InnerSigningParamsV2<Scalar>,
) -> bool {
    verify_inner_share::<Point>(
        response,
        commitment,
        effective_pubkey,
        params,
        &Scalar::ONE,
    )
}

/// Coordinator: verify every validator response, then aggregate into
/// `z_nested`.
///
/// `Err(indices)` names the validators at fault so they can be evicted and the
/// round retried, instead of emitting a signature that simply fails to verify
/// with no attribution. Mirroring osst's N-3, the multiset of
/// `holder_index` must equal `participants` exactly: a validator that produced
/// no response, and one that produced two, are both named (W-4 — the old
/// version resolved commitments with `find` and so verified and added a
/// duplicate twice).
pub fn frostito_aggregate_responses_verified(
    responses: &[InnerSignatureShare<Scalar>],
    commitments: &[InnerCommitments<Point>],
    effective_pubkeys: &[(u32, Point)],
    params: &InnerSigningParamsV2<Scalar>,
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
// For a nested position whose holders each own exactly one share, osst's own
// v2 is used directly; these wrappers exist only to keep the Pallas type
// parameter off call sites.

/// Round 1 for an unweighted inner holder.
pub fn validator_commit(
    holder_index: u32,
    session_id: [u8; 32],
) -> (InnerNonces<Scalar>, InnerCommitments<Point>) {
    nested::inner_commit::<Point, _>(holder_index, session_id, &mut rand_core::OsRng)
}

/// Round 2 for an unweighted inner holder: `osst::nested::inner_sign_v2`.
///
/// `local_group_pubkey` is the outer group key `Y`, taken from the holder's own
/// key material: osst 0.5 removed it from `NestedSigningRequest` (M-4) because
/// the binding factor now covers it (M-24).
pub fn validator_sign_v2(
    nonces: InnerNonces<Scalar>,
    share: &SecretShare<Scalar>,
    local_group_pubkey: &Point,
    approved_message: &[u8],
    request: &NestedSigningRequest<'_, Point>,
) -> Result<InnerSignatureShare<Scalar>, osst::OsstError> {
    nested::inner_sign_v2::<Point>(
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
    params: &InnerSigningParamsV2<Scalar>,
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
    use osst::frost as osst_frost;

    const SESSION: [u8; 32] = [7u8; 32];

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
        position_a_share: SecretShare<Scalar>,
        group_key: Point,
    }

    const NESTED_INDEX: u32 = 2;

    fn fixture(rng: &mut rand_core::OsRng) -> Fixture {
        let allocation = vec![
            (1u32, vec![1u32, 2, 3, 4]),
            (2u32, vec![5u32, 6, 7]),
            (3u32, vec![8u32, 9, 10]),
        ];
        let roster = WeightedRoster::new(&allocation, 7).unwrap();

        // outer 2-of-2: a degree-1 polynomial, position 1 flat, position 2 nested.
        let outer_secret = rand_scalar(rng);
        let outer_shares = shamir(outer_secret, 2, 2, rng);
        let group_key = Point::generator().mul_scalar(&outer_secret);
        let position_a_share = outer_shares[0].clone();
        let nested_secret = *outer_shares[1].scalar();

        // the nested position's secret, split 7-of-10 among the share indices
        let inner = shamir(nested_secret, 10, 7, rng);
        let public_shares: Vec<(u32, Point)> = inner
            .iter()
            .map(|s| (s.index, Point::generator().mul_scalar(s.scalar())))
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
            nested_secret,
            position_a_share,
            group_key,
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

        // M-20: osst now verifies the reveals against the precommitments here,
        // so a substituted reveal is refused by the aggregate itself rather
        // than only by the caller's own convention.
        let (d_nested, e_nested) =
            frostito_aggregate_commitment_pair(&SESSION, &precommits, &commitments).unwrap();
        {
            let mut tampered = commitments.clone();
            tampered[0].hiding = tampered[0].hiding.add(&Point::generator());
            assert!(matches!(
                frostito_aggregate_commitment_pair(&SESSION, &precommits, &tampered),
                Err(WeightedError::Osst(osst::OsstError::PrecommitMismatch(1)))
            ));
        }

        // ── a real outer package ───────────────────────────────────────────
        let (a_nonces, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng).unwrap();
        let nested_commits = osst_frost::SigningCommitments {
            index: NESTED_INDEX,
            hiding: d_nested,
            binding: e_nested,
        };
        let package =
            osst_frost::SigningPackage::new(message.to_vec(), vec![a_commits, nested_commits])
                .unwrap();

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
            InnerSigningParamsV2::from_outer::<Point>(&package, &f.group_key, NESTED_INDEX)
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
        // check it through osst's own verification of the nested position as
        // an ordinary signer.
        let nested_public = Point::generator().mul_scalar(&f.nested_secret);
        assert!(
            verify_inner_share::<Point>(
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
                &Scalar::ONE,
            ),
            "the weighted nested response must be a flat signer's response"
        );

        // ── and the whole outer signature verifies ─────────────────────────
        let a_sig = osst_frost::sign::<Point>(
            &package,
            a_nonces,
            &f.position_a_share,
            &f.group_key,
        )
        .unwrap();
        let nested_sig = osst_frost::SignatureShare {
            index: NESTED_INDEX,
            response: z_nested,
        };
        let signature =
            osst_frost::aggregate::<Point>(&package, &[a_sig, nested_sig], &f.group_key, None)
                .unwrap();
        assert!(
            osst_frost::verify_signature(&f.group_key, message, &signature),
            "2-of-2 outer × weighted 7-of-10 inner must verify"
        );
    }

    /// W-1: a coordinator cannot get a signature over a payload the validators
    /// never approved.
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
        let (_, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng).unwrap();
        let package = osst_frost::SigningPackage::new(
            b"coordinator's own payload".to_vec(),
            vec![
                a_commits,
                osst_frost::SigningCommitments {
                    index: NESTED_INDEX,
                    hiding: d,
                    binding: e,
                },
            ],
        )
        .unwrap();
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
        assert_eq!(err, WeightedError::Osst(osst::OsstError::MessageMismatch));
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
        let (_, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng).unwrap();
        let package = osst_frost::SigningPackage::new(
            message.to_vec(),
            vec![
                a_commits,
                osst_frost::SigningCommitments {
                    index: NESTED_INDEX,
                    hiding: d,
                    binding: e,
                },
            ],
        )
        .unwrap();

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
        assert_eq!(err, WeightedError::Osst(osst::OsstError::SessionMismatch));
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
        let (_, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng).unwrap();
        let package = osst_frost::SigningPackage::new(
            message.to_vec(),
            vec![
                a_commits,
                osst_frost::SigningCommitments {
                    index: NESTED_INDEX,
                    hiding: d,
                    binding: e,
                },
            ],
        )
        .unwrap();
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
            InnerSigningParamsV2::from_outer::<Point>(&package, &f.group_key, NESTED_INDEX)
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

    /// The unweighted path still works: osst's own v2, one share per holder,
    /// inside a 2-of-2 outer group.
    #[test]
    fn unweighted_nested_v2_still_verifies() {
        let mut rng = rand_core::OsRng;
        let message = b"unweighted nested spend";

        let outer_secret = rand_scalar(&mut rng);
        let outer_shares = shamir(outer_secret, 2, 2, &mut rng);
        let group_key = Point::generator().mul_scalar(&outer_secret);
        let nested_secret = *outer_shares[1].scalar();
        let inner = shamir(nested_secret, 5, 3, &mut rng);
        let active: Vec<u32> = vec![1, 3, 5];

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &k in &active {
            let (n, c) = validator_commit(k, SESSION);
            nonces.push(n);
            commitments.push(c);
        }
        let precommits: Vec<(u32, [u8; 32])> = commitments
            .iter()
            .map(|c| (c.holder_index, inner_precommit(c)))
            .collect();
        let (d, e) =
            aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits, &commitments).unwrap();

        let (a_nonces, a_commits) = osst_frost::commit::<Point, _>(1, &mut rng).unwrap();
        let package = osst_frost::SigningPackage::new(
            message.to_vec(),
            vec![
                a_commits,
                osst_frost::SigningCommitments {
                    index: NESTED_INDEX,
                    hiding: d,
                    binding: e,
                },
            ],
        )
        .unwrap();
        let request = NestedSigningRequest {
            package: &package,
            nested_index: NESTED_INDEX,
            session_id: SESSION,
            inner_precommits: &precommits,
            inner_commitments: &commitments,
            active_indices: &active,
            inner_threshold: 3,
        };

        let mut sigs = Vec::new();
        for (n, &k) in nonces.into_iter().zip(active.iter()) {
            sigs.push(
                validator_sign_v2(n, &inner[(k - 1) as usize], &group_key, message, &request).unwrap(),
            );
        }
        let public_shares: Vec<(u32, Point)> = active
            .iter()
            .map(|&k| {
                (
                    k,
                    Point::generator().mul_scalar(inner[(k - 1) as usize].scalar()),
                )
            })
            .collect();
        let params =
            InnerSigningParamsV2::from_outer::<Point>(&package, &group_key, NESTED_INDEX).unwrap();
        let z_nested = aggregate_validator_shares_verified(
            &sigs,
            &commitments,
            &public_shares,
            &params,
            &active,
        )
        .unwrap();

        let a_sig =
            osst_frost::sign::<Point>(&package, a_nonces, &outer_shares[0], &group_key).unwrap();
        let signature = osst_frost::aggregate::<Point>(
            &package,
            &[
                a_sig,
                osst_frost::SignatureShare {
                    index: NESTED_INDEX,
                    response: z_nested,
                },
            ],
            &group_key,
            None,
        )
        .unwrap();
        assert!(osst_frost::verify_signature(&group_key, message, &signature));
    }
}

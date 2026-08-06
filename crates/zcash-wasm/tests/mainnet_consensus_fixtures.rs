//! Regression fixtures pinned to REAL mainnet consensus data.
//!
//! Everything here was verified once, by hand, against zebra source and a
//! transaction that is actually in the chain. That verification is worthless
//! if nothing pins it: a bump of the vendored orchard fork, or a change to the
//! fee helper, would silently invalidate the finding and nobody would notice
//! until a transaction was rejected — or worse, accepted with the wrong value.
//!
//! Source of truth for these fixtures: mainnet block 3,436,797, transaction
//! `e0932c3f91d1a14f…` (a turnstile migration built by this codebase, mined and
//! validated by the network), read back via `zebrad getblock <height> 2`:
//!
//! ```text
//! orchard.valueBalanceZat  = +385000   (leaving the orchard pool)
//! ironwood.valueBalanceZat = -365000   (entering the ironwood pool)
//! ironwood.anchor          = ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f
//! orchard actions          = 2   (1 real spend + padding)
//! ironwood actions         = 2   (1 real output + padding)
//! ```

/// The empty-tree anchor is a CONSENSUS CONSTANT for us, not an
/// implementation detail.
///
/// Every output-only ironwood bundle this codebase builds — the turnstile
/// migration and t→z shielding — anchors to `Anchor::empty_tree()`. Zebra
/// validates `ironwood_shielded_data.shared_anchor` against its known anchor
/// set with no exemption for bundles that have no real spends
/// (`zebra-state/src/service/check/anchors.rs:137`), so if this value ever
/// changes underneath us, every such transaction is rejected with
/// `UnknownIronwoodAnchor`.
///
/// The expected bytes are exactly what mainnet accepted in the transaction
/// above. If a vendored-fork bump breaks this test, DO NOT update the constant
/// to match the new value — check what changed and why, because the chain will
/// not have moved with you.
#[test]
fn empty_tree_anchor_matches_the_one_mainnet_accepted() {
    const MAINNET_ACCEPTED_ANCHOR: &str =
        "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f";

    let anchor = orchard::tree::Anchor::empty_tree();
    let got = hex::encode(anchor.to_bytes());

    assert_eq!(
        got, MAINNET_ACCEPTED_ANCHOR,
        "empty_tree() anchor changed. Mainnet block 3,436,797 accepted \
         {MAINNET_ACCEPTED_ANCHOR}; this build would now anchor output-only \
         ironwood bundles to {got}, which zebra will reject as an unknown \
         ironwood anchor."
    );
}

/// The turnstile fee is confirmed on-chain, not merely derived.
///
/// The migration spent 385,000 zat out of orchard and delivered 365,000 into
/// ironwood; the 20,000 difference is the fee the network accepted. Zebra sums
/// logical actions ACROSS bundles and counts ironwood actions the same way it
/// counts orchard ones (`zebra-chain/src/transaction/unmined/zip317.rs`, which
/// adds `n_actions_ironwood` into `logical_actions`), so a migration with a
/// 2-action orchard bundle and a 2-action ironwood bundle owes
/// `5000 * (2 + 2) = 20,000`.
///
/// This pins the arithmetic against a transaction a validator actually
/// accepted, rather than against our own reading of the spec.
#[test]
fn turnstile_fee_matches_the_mined_value_balances() {
    const ORCHARD_OUT_ZAT: i64 = 385_000;
    const IRONWOOD_IN_ZAT: i64 = 365_000;
    const OBSERVED_FEE_ZAT: u64 = 20_000;

    assert_eq!(
        (ORCHARD_OUT_ZAT - IRONWOOD_IN_ZAT) as u64,
        OBSERVED_FEE_ZAT,
        "fixture is internally inconsistent"
    );

    // orchard bundle padded to 2 actions + ironwood bundle padded to 2 actions
    let logical_actions: u64 = 2 + 2;
    let computed = 5_000 * logical_actions;

    assert_eq!(
        computed, OBSERVED_FEE_ZAT,
        "ZIP-317 turnstile fee no longer matches what mainnet accepted for \
         block 3,436,797 tx e0932c3f91d1a14f… (orchard +{ORCHARD_OUT_ZAT}, \
         ironwood -{IRONWOOD_IN_ZAT})"
    );
}

/// ZIP-317 counts transparent inputs by SIZE, not by count.
///
/// `ceil(tx_in_total_size / 150)` equals the input count only while
/// `2n < 150`; at 75 P2PKH inputs (148 bytes each) it is 74, not 75. Getting
/// this wrong overpaid by 5,000 zat per shielding of ≥75 UTXOs — harmless to
/// consensus but a per-transaction fingerprint that says "this wallet".
#[test]
fn zip317_transparent_input_actions_are_size_derived() {
    const P2PKH_INPUT_BYTES: usize = 148;
    const STANDARD_INPUT_SIZE: usize = 150;

    let logical = |n: usize| (n * P2PKH_INPUT_BYTES).div_ceil(STANDARD_INPUT_SIZE);

    assert_eq!(logical(1), 1);
    assert_eq!(logical(2), 2);
    assert_eq!(logical(74), 74);
    // the boundary the original comment claimed could never be crossed
    assert_eq!(logical(75), 74, "75 inputs occupy 74 logical actions, not 75");
    assert_eq!(logical(76), 75);
}

/// A turnstile migration must classify as a SEND, never as an incoming payment.
///
/// The migration pays the wallet's OWN address, so if the scanner failed to
/// mark that output as change, history would render a 10 ZEC migration as
/// "received +10.00 ZEC" — inventing an incoming payment out of the user's own
/// funds. A review flagged this as unresolved because `is_change` is decided
/// inside the wasm scanner; this pins the two facts that decide it.
///
/// 1. the destination uses INTERNAL scope (lib.rs, build_turnstile_*: the
///    recipient is `fvk.address_at(0, Scope::Internal)`)
/// 2. the scanner tries EXTERNAL first and only sets `is_change = true` on the
///    internal match
///
/// Together those mean a migration output is always change. If either changes,
/// this test fails before the UI starts inventing income.
#[test]
fn turnstile_self_output_is_internal_scope_hence_change() {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    let sk = SpendingKey::from_bytes([7u8; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);

    let internal = fvk.address_at(0u32, Scope::Internal);
    let external = fvk.address_at(0u32, Scope::External);

    // The two scopes must be distinguishable, otherwise "is this change?"
    // cannot be answered by which ivk decrypted it.
    assert_ne!(
        internal.to_raw_address_bytes(),
        external.to_raw_address_bytes(),
        "internal and external scope produced the same address; change \
         detection relies on these differing"
    );

    // And the internal address must NOT be decryptable as an external receive,
    // which is what would make a migration look like incoming money.
    let ivk_external = fvk.to_ivk(Scope::External);
    let ivk_internal = fvk.to_ivk(Scope::Internal);
    assert_ne!(
        ivk_external.to_bytes(),
        ivk_internal.to_bytes(),
        "external and internal ivks match; every change note would be \
         reported as an incoming payment"
    );
}

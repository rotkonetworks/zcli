//! FROST 2-of-3 IRONWOOD SEND end-to-end (native): a real V3 ironwood note owned
//! by a FROST *group* key is spent to a different recipient, proved on the
//! post-NU6.3 circuit, signed by a threshold of participants over the ZIP-244
//! sighash, completed with the aggregated SpendAuth signatures, and extracted as
//! a broadcastable V6 transaction.
//!
//! This is the test the wallet-side gate was waiting on. Before it, multisig
//! sends refused post-NU6.3 because the ironwood builder returned no sighash and
//! no per-spend randomizers, so a FROST caller ran zero signing rounds and handed
//! an empty signature set to an orchard-only completion step.
//!
//! What it actually proves:
//!   1. the builder hands back one alpha per real ironwood spend, and a sighash;
//!   2. FROST signing is pool-independent - the same RedPallas spend-auth
//!      machinery used for orchard produces a signature an ironwood action
//!      accepts;
//!   3. the completion step applies those aggregated signatures to the ironwood
//!      bundle and extracts a transaction whose proof, spend-auth and binding
//!      signatures all verify (extract_signed_tx_from_pczt_bytes re-verifies
//!      them, so a wrong sighash fails HERE rather than on the network).
//!
//! Sibling of `signed_ironwood_send_v6.rs`, which covers the same money path
//! with a single local spend-authorizing key instead of a threshold.
//!
//! Run with --release: it builds the post-NU6.3 Halo 2 proving key and proves an
//! ironwood bundle.
//!   cargo test --release --test frost_ironwood_send_v6

use zafu_wasm::{
    build_ironwood_send_pczt_proven, complete_ironwood_pczt_core, IronwoodRecipient,
};

use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;

const NU6_3_BRANCH_ID: u32 = 0x37a5_165b;

/// Test network with NU6.3 active from height 10 (same fixture as the siblings).
#[derive(Clone, Copy, Debug)]
struct Nu63TestNet;

impl Parameters for Nu63TestNet {
    fn network_type(&self) -> NetworkType {
        NetworkType::Test
    }
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu6_3 => Some(BlockHeight::from_u32(10)),
            _ => MainNetwork.activation_height(nu),
        }
    }
}

/// A real V3 ironwood note owned by `fvk`, with a valid one-leaf merkle path and
/// the anchor that path roots to.
fn owned_note_with_witness(
    fvk: &orchard::keys::FullViewingKey,
    value: u64,
) -> (
    orchard::Note,
    orchard::tree::MerklePath,
    orchard::tree::Anchor,
) {
    let rho = orchard::note::Rho::from_bytes(&[7u8; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .expect("test rseed");
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, orchard::keys::Scope::External),
        orchard::value::NoteValue::from_raw(value),
        rho,
        rseed,
        orchard::note::NoteVersion::V3,
    ))
    .expect("test note");

    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .expect("zero merkle hash");
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
    let anchor = witness.root(cmx);
    (note, witness, anchor)
}

#[test]
fn frost_2_of_3_signs_and_extracts_an_ironwood_send() {
    // ── (1) a 2-of-3 FROST group, and the wallet FVK it controls ────────────
    let dealer = frost_spend::orchestrate::dealer_keygen(2, 3).expect("dealer keygen 2-of-3");
    assert_eq!(dealer.packages.len(), 3, "three key packages");

    // `packages` are SignedMessage-wrapped bundles, not bare key packages:
    // { ephemeral_seed, key_package, public_key_package }. Unwrap to the seed +
    // key package each participant actually signs with.
    let participants: Vec<(String, String)> = dealer
        .packages
        .iter()
        .map(|hexed| {
            let signed: frost_spend::message::SignedMessage =
                frost_spend::orchestrate::from_hex(hexed).expect("parse signed package");
            let (_vk, payload) = signed.verify().expect("dealer signature verifies");
            let v: serde_json::Value =
                serde_json::from_slice(payload).expect("bundle json");
            (
                v["ephemeral_seed"].as_str().expect("seed").to_string(),
                v["key_package"].as_str().expect("key package").to_string(),
            )
        })
        .collect();

    let pubkeys: frost_spend::frost_keys::PublicKeyPackage =
        frost_spend::orchestrate::from_hex(&dealer.public_key_package_hex)
            .expect("parse public key package");

    // The group verifying key becomes the wallet's `ak`; `sk` supplies the rest
    // of the FVK. No single participant holds spend authority.
    let fvk = frost_spend::keys::derive_fvk_from_sk([9u8; 32], &pubkeys)
        .expect("derive FVK from FROST group key");

    // ── (2) a different recipient ───────────────────────────────────────────
    let other = frost_spend::orchestrate::dealer_keygen(2, 2).expect("recipient keygen");
    let other_pubkeys: frost_spend::frost_keys::PublicKeyPackage =
        frost_spend::orchestrate::from_hex(&other.public_key_package_hex)
            .expect("parse recipient pubkeys");
    let recip_fvk = frost_spend::keys::derive_fvk_from_sk([11u8; 32], &other_pubkeys)
        .expect("derive recipient FVK");
    let recipient_addr = recip_fvk.address_at(0u32, orchard::keys::Scope::External);
    assert_ne!(
        recipient_addr.to_raw_address_bytes(),
        fvk.address_at(0u32, orchard::keys::Scope::External)
            .to_raw_address_bytes(),
        "recipient must differ from the group's own external address"
    );

    // ── (3) build + prove the ironwood send ─────────────────────────────────
    let note_value = 1_000_000u64;
    let amount = 600_000u64;
    let fee = 10_000u64;
    let (note, witness, ironwood_anchor) = owned_note_with_witness(&fvk, note_value);

    let target_height = 10_000_000u32;
    assert_eq!(
        u32::from(BranchId::for_height(
            &Nu63TestNet,
            BlockHeight::from_u32(target_height)
        )),
        NU6_3_BRANCH_ID,
        "must bind the real NU6.3 branch id"
    );

    let built = build_ironwood_send_pczt_proven(
        Nu63TestNet,
        &fvk,
        vec![(note, witness)],
        IronwoodRecipient::Shielded(recipient_addr),
        amount,
        fee,
        ironwood_anchor,
        target_height,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("build + prove ironwood send");

    // THE regression this whole change exists for: before it, both of these
    // were empty and a FROST caller ran zero signing rounds.
    assert_eq!(
        built.alphas.len(),
        1,
        "one alpha per real ironwood spend - empty here is the original bug"
    );
    assert_eq!(
        built.spend_indices.len(),
        built.alphas.len(),
        "alphas and spend indices must correspond"
    );

    // ── (4) the sighash the signers commit to ───────────────────────────────
    let sighash = pczt::roles::signer::Signer::new(built.pczt.clone())
        .expect("signer init")
        .shielded_sighash();

    // ── (5) FROST threshold signing, one round per real spend ───────────────
    let mut sigs: Vec<[u8; 64]> = Vec::new();
    for alpha_hex in &built.alphas {
        let alpha: [u8; 32] = hex::decode(alpha_hex)
            .expect("alpha hex")
            .try_into()
            .expect("alpha is 32 bytes");

        // Two of the three sign; the third stays offline.
        let signers = &participants[0..2];
        let mut nonces: Vec<String> = Vec::new();
        let mut commitments: Vec<String> = Vec::new();
        for (seed_hex, kp) in signers.iter() {
            let seed: [u8; 32] = hex::decode(seed_hex)
                .expect("seed hex")
                .try_into()
                .expect("seed is 32 bytes");
            let (n, c) = frost_spend::orchestrate::sign_round1(&seed, kp).expect("sign_round1");
            nonces.push(n);
            commitments.push(c);
        }

        let mut shares: Vec<String> = Vec::new();
        for (i, (_seed, kp)) in signers.iter().enumerate() {
            let share = frost_spend::orchestrate::spend_sign_round2(
                kp,
                &nonces[i],
                &sighash,
                &alpha,
                &commitments,
            )
            .expect("spend_sign_round2");
            shares.push(share);
        }

        let sig_hex = frost_spend::orchestrate::spend_aggregate(
            &dealer.public_key_package_hex,
            &sighash,
            &alpha,
            &commitments,
            &shares,
        )
        .expect("spend_aggregate");
        let sig: [u8; 64] = hex::decode(&sig_hex)
            .expect("sig hex")
            .try_into()
            .expect("spend-auth signature is 64 bytes");
        sigs.push(sig);
    }

    // ── (6) complete: apply the aggregated sigs, extract, re-verify ─────────
    // extract_signed_tx_from_pczt_bytes verifies the ironwood proof and every
    // spend-auth + binding signature against the sighash, so reaching Ok here
    // means the threshold signature was accepted by the ironwood action.
    let pczt_bytes = built.pczt.serialize().expect("serialize pczt");
    let tx_bytes = complete_ironwood_pczt_core(&pczt_bytes, &sigs, &built.spend_indices)
        .expect("complete ironwood pczt with aggregated FROST signatures");
    assert!(!tx_bytes.is_empty(), "extracted transaction must be non-empty");

    // ── (7) NEGATIVE: an empty signature set must be refused ───────────────
    // This is exactly what the wallet used to produce post-NU6.3, and what the
    // fail-closed gate existed to prevent reaching a halo2 prove.
    let err = complete_ironwood_pczt_core(&pczt_bytes, &[], &[])
        .expect_err("an empty signature set must be refused");
    assert!(
        err.contains("no ironwood signatures"),
        "unexpected error for empty signature set: {err}"
    );

    // ── (8) NEGATIVE: a signature over the WRONG message must not verify ────
    // Guards the display<->sighash binding: if the joiner were shown one
    // transaction and made to sign another, completion must fail rather than
    // emit a transaction the network would reject.
    let mut wrong_sighash = sighash;
    wrong_sighash[0] ^= 0xff;
    let alpha: [u8; 32] = hex::decode(&built.alphas[0])
        .expect("alpha hex")
        .try_into()
        .expect("alpha is 32 bytes");
    let signers = &participants[0..2];
    let mut nonces: Vec<String> = Vec::new();
    let mut commitments: Vec<String> = Vec::new();
    for (seed_hex, kp) in signers.iter() {
        let seed: [u8; 32] = hex::decode(seed_hex)
            .expect("seed hex")
            .try_into()
            .expect("seed is 32 bytes");
        let (n, c) = frost_spend::orchestrate::sign_round1(&seed, kp).expect("round1");
        nonces.push(n);
        commitments.push(c);
    }
    let mut shares: Vec<String> = Vec::new();
    for (i, (_seed, kp)) in signers.iter().enumerate() {
        shares.push(
            frost_spend::orchestrate::spend_sign_round2(
                kp,
                &nonces[i],
                &wrong_sighash,
                &alpha,
                &commitments,
            )
            .expect("round2 over the wrong message still produces a share"),
        );
    }
    let bad_sig_hex = frost_spend::orchestrate::spend_aggregate(
        &dealer.public_key_package_hex,
        &wrong_sighash,
        &alpha,
        &commitments,
        &shares,
    )
    .expect("aggregate over the wrong message");
    let bad_sig: [u8; 64] = hex::decode(&bad_sig_hex)
        .expect("sig hex")
        .try_into()
        .expect("64 bytes");

    complete_ironwood_pczt_core(&pczt_bytes, &[bad_sig], &built.spend_indices)
        .expect_err("a signature over a different sighash must not complete");
}

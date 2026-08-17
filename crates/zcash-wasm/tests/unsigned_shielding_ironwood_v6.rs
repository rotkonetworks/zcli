//! DIFFERENTIAL correctness gate for the UNSIGNED (cold / watch-only / zigner)
//! ironwood shielding builder.
//!
//! The money risk: a wrong sighash or serialization on the cold path yields an
//! invalid tx AFTER the user has published their UTXOs. So we do not assert the
//! cold path is correct - we PROVE it against the already-proven hot signed path.
//!
//! `test_cold_seam_is_byte_identical_to_hot_modulo_binding_sig` is the strong
//! test: it builds ONE proven, IO-finalized PCZT via the shared
//! `build_shielding_pczt_proven`, then drives BOTH seams off that single PCZT:
//!   - HOT: `Signer::sign_transparent` (secret key) -> SpendFinalizer -> extract
//!   - COLD: Updater(preimages) -> serialize -> re-parse ->
//!     `Signer::transparent_sighash` -> sign each sighash EXTERNALLY with the same
//!     key -> `complete_shielding_pczt_bytes` (append_transparent_signature ->
//!     SpendFinalizer -> extract)
//! and asserts the two broadcast-ready V6 transactions are BYTE-IDENTICAL except
//! for a single contiguous 64-byte run - the ironwood binding signature, which is
//! the only randomized step left (RedPallas binding sig, applied with OsRng at
//! extract time). Everything else is deterministic off the shared PCZT: the same
//! Halo 2 proof, the same commitments/ciphertexts, and - because ECDSA here is
//! RFC 6979 deterministic over the same sighash and key - the same transparent
//! scriptSigs. This proves the cold seam is exactly equivalent to the hot path.
//!
//! `test_public_entrypoints_agree_structurally` drives the real public builders
//! end to end (independent PCZTs, so only structural equality is possible) and
//! asserts both extract + verify. `test_wrong_message_signature_is_rejected`
//! proves the verify-on-append property that makes the PCZT completion strictly
//! safer than blind scriptSig patching.
//!
//! Run with --release (builds + uses the post-NU6.3 ironwood proving key):
//!   cargo test -p zafu-wasm --release --test unsigned_shielding_ironwood_v6

use zafu_wasm::{
    build_shielding_pczt_proven, build_shielding_transaction_ironwood_core,
    build_unsigned_shielding_pczt_ironwood_core, complete_shielding_pczt_bytes,
    complete_shielding_transaction, extract_signed_tx_from_pczt_bytes, zip317_shielding_fee,
    NU6_3_BRANCH_ID,
};

use orchard::keys::Scope;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::bundle::{OutPoint, TxOut};

/// Test network with NU6.3 active from height 10 (same fixture as the sibling
/// signed/shielding ironwood tests and the fork's end_to_end.rs).
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

const TARGET_HEIGHT: u32 = 100;

fn test_key() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let secp = secp256k1::Secp256k1::signing_only();
    let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).expect("valid test secret key");
    let pk = sk.public_key(&secp);
    (sk, pk)
}

/// A P2PKH coin locked to `pk`, worth `value` zat.
fn coin(pk: &secp256k1::PublicKey, value: u64, txid_byte: u8, vout: u32) -> (OutPoint, TxOut) {
    let script = TransparentAddress::from_pubkey(pk).script().into();
    (
        OutPoint::new([txid_byte; 32], vout),
        TxOut::new(Zatoshis::const_from_u64(value), script),
    )
}

fn recipient() -> orchard::Address {
    let sk = orchard::keys::SpendingKey::from_bytes([3u8; 32]).unwrap();
    orchard::keys::FullViewingKey::from(&sk).address_at(0u32, Scope::External)
}

/// Externally sign a 32-byte sighash the way an air-gapped signer / zigner does:
/// RFC 6979 deterministic ECDSA over the sighash, DER-encoded, with a trailing
/// SIGHASH_ALL byte appended.
fn external_sign(sk: &secp256k1::SecretKey, sighash: [u8; 32]) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::signing_only();
    let msg = secp256k1::Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&msg, sk);
    let mut bytes = sig.serialize_der().to_vec();
    bytes.push(0x01); // SIGHASH_ALL
    bytes
}

#[test]
fn cold_seam_is_byte_identical_to_hot_modulo_binding_sig() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xa1, 0), coin(&pk, 50_000, 0xa2, 1)];
    let fee = zip317_shielding_fee(inputs.len());

    // ONE proven, IO-finalized PCZT, shared by both seams. The expensive
    // proof + all commitments are fixed here, so anything downstream that
    // differs is a seam difference, not builder nondeterminism.
    let base = build_shielding_pczt_proven(
        Nu63TestNet,
        &pk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("shared proven pczt");
    let n_inputs = base.transparent().inputs().len();
    assert_eq!(n_inputs, 2);

    // --- HOT seam: sign with the secret key, finalize, extract ---
    let hot_tx = {
        let mut signer = pczt::roles::signer::Signer::new(base.clone()).expect("hot signer");
        for i in 0..n_inputs {
            signer.sign_transparent(i, &sk).expect("hot sign_transparent");
        }
        let finalized = pczt::roles::spend_finalizer::SpendFinalizer::new(signer.finish())
            .finalize_spends()
            .expect("hot finalize_spends");
        extract_signed_tx_from_pczt_bytes(&finalized.serialize().expect("hot pczt serialize"))
            .expect("hot extract")
    };

    // --- COLD seam: preimages, serialize carrier, sighash, external sign, complete ---
    let cold_tx = {
        // Record pubkey as the hash160 preimage on every transparent input (the
        // same step the unsigned core performs) so the completion can recover it.
        let pubkey_bytes = pk.serialize().to_vec();
        let cold_pczt = pczt::roles::updater::Updater::new(base.clone())
            .update_transparent_with(|mut tu| {
                for i in 0..n_inputs {
                    tu.update_input_with(i, |mut inp| {
                        inp.set_hash160_preimage(pubkey_bytes.clone());
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .expect("updater preimages")
            .finish();
        let carrier = cold_pczt.serialize().expect("cold pczt serialize");

        // Per-input sighashes from a re-parse of the exact carrier bytes.
        let reparsed = pczt::Pczt::parse(&carrier).expect("carrier re-parse");
        let signer = pczt::roles::signer::Signer::new(reparsed).expect("cold signer");
        let sigs: Vec<Vec<u8>> = (0..n_inputs)
            .map(|i| {
                let sighash = signer.transparent_sighash(i).expect("transparent_sighash");
                external_sign(&sk, sighash)
            })
            .collect();

        complete_shielding_pczt_bytes(&carrier, &sigs).expect("cold completion")
    };

    // Both must be valid, extractable, verifying V6 txs (extract re-verifies the
    // proof + every transparent signature against the sighash).
    let hot = Transaction::read(&hot_tx[..], BranchId::Nu6_3).expect("hot tx parses");
    let cold = Transaction::read(&cold_tx[..], BranchId::Nu6_3).expect("cold tx parses");
    for (label, tx) in [("hot", &hot), ("cold", &cold)] {
        assert_eq!(tx.version(), TxVersion::V6, "{label} must be V6");
        assert_eq!(
            u32::from(tx.consensus_branch_id()),
            NU6_3_BRANCH_ID,
            "{label} must bind NU6.3"
        );
        let transparent = tx.transparent_bundle().expect("transparent bundle");
        assert_eq!(transparent.vin.len(), 2, "{label} inputs");
        assert!(tx.orchard_bundle().is_none(), "{label} no orchard bundle");
        assert!(tx.ironwood_bundle().is_some(), "{label} ironwood bundle");
    }

    // The transparent seam must be EXACTLY equivalent: same prevouts, sequences,
    // and - the load-bearing part - byte-identical scriptSigs. Same shared PCZT =>
    // same tx sighash => RFC 6979 => identical DER, so `transparent_sighash` +
    // external-sign + `append_transparent_signature` + SpendFinalizer reproduces
    // `sign_transparent` + SpendFinalizer byte for byte.
    let hot_t = hot.transparent_bundle().unwrap();
    let cold_t = cold.transparent_bundle().unwrap();
    for (a, b) in hot_t.vin.iter().zip(cold_t.vin.iter()) {
        assert_eq!(a.prevout(), b.prevout(), "prevouts must match");
        assert_eq!(a.sequence(), b.sequence(), "sequences must match");
        assert_eq!(
            a.script_sig(),
            b.script_sig(),
            "cold scriptSig must be byte-identical to the hot signed scriptSig"
        );
    }

    // THE differential assertion: identical lengths, and every differing byte is
    // confined to a single contiguous run of AT MOST 64 bytes - the ironwood
    // binding signature, the only randomized step left (RedPallas binding sig,
    // applied with OsRng at extract). (It can be 63, not 64, when one of the 64
    // random bytes happens to coincide - 1/256 per byte.) Because the scriptSigs
    // above are already proven byte-identical, this residual difference cannot be
    // in the transparent section; it is the shielded binding sig alone.
    assert_eq!(hot_tx.len(), cold_tx.len(), "tx lengths must match");
    let diff: Vec<usize> = hot_tx
        .iter()
        .zip(cold_tx.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    assert!(!diff.is_empty(), "two independent binding sigs should differ");
    assert!(
        diff.len() <= 64,
        "at most 64 bytes (the binding sig) may differ; got {}",
        diff.len()
    );
    assert!(
        diff.last().unwrap() - diff.first().unwrap() <= 63,
        "differing bytes must lie within one contiguous 64-byte window (the binding sig); span = {}",
        diff.last().unwrap() - diff.first().unwrap()
    );
}

#[test]
fn public_entrypoints_agree_structurally() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xb1, 0), coin(&pk, 50_000, 0xb2, 1)];
    let total_in = 250_000u64;
    let fee = zip317_shielding_fee(inputs.len());

    // HOT via the signed core (its own fresh PCZT).
    let hot_bytes = build_shielding_transaction_ironwood_core(
        Nu63TestNet,
        &sk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("hot build");

    // COLD via the unsigned core + external signing + completion (a different
    // fresh PCZT, so only structural equality is possible here).
    let (sighashes, carrier) = build_unsigned_shielding_pczt_ironwood_core(
        Nu63TestNet,
        &pk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("unsigned build");
    assert_eq!(sighashes.len(), 2, "one sighash per input");
    assert!(
        carrier.starts_with(b"PCZT"),
        "unsigned carrier must be a serialized PCZT (magic 'PCZT')"
    );
    let sigs: Vec<Vec<u8>> = sighashes.iter().map(|s| external_sign(&sk, *s)).collect();
    let cold_bytes = complete_shielding_pczt_bytes(&carrier, &sigs).expect("cold completion");

    let hot = Transaction::read(&hot_bytes[..], BranchId::Nu6_3).expect("hot parses");
    let cold = Transaction::read(&cold_bytes[..], BranchId::Nu6_3).expect("cold parses");

    assert_eq!(hot.version(), TxVersion::V6);
    assert_eq!(cold.version(), TxVersion::V6);

    let (ht, ct) = (
        hot.transparent_bundle().expect("hot transparent"),
        cold.transparent_bundle().expect("cold transparent"),
    );
    assert_eq!(ht.vin.len(), ct.vin.len(), "same input count");
    assert_eq!(ht.vout.len(), 0);
    assert_eq!(ct.vout.len(), 0);
    // Same prevouts, in the same selection order.
    for (a, b) in ht.vin.iter().zip(ct.vin.iter()) {
        assert_eq!(a.prevout(), b.prevout(), "same prevout");
    }

    let (hi, ci) = (
        hot.ironwood_bundle().expect("hot ironwood"),
        cold.ironwood_bundle().expect("cold ironwood"),
    );
    assert_eq!(hi.actions().len(), ci.actions().len(), "same action count");
    let hv: i64 = (*hi.value_balance()).into();
    let cv: i64 = (*ci.value_balance()).into();
    assert_eq!(hv, cv, "same ironwood value balance");
    assert_eq!(
        hv,
        -((total_in - fee) as i64),
        "value balance == -(inputs - fee)"
    );
    assert!(hot.orchard_bundle().is_none() && cold.orchard_bundle().is_none());
}

#[test]
fn complete_shielding_transaction_sniffs_pczt_and_delegates() {
    // PRODUCTION ROUTE: the wallet's existing completion call site invokes
    // `complete_shielding_transaction`. For a v6 ironwood carrier that is a
    // serialized PCZT (not a raw tx), it must detect the `b"PCZT"` magic and
    // delegate to the PCZT completion, so the TS call site needs no change.
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xd1, 0), coin(&pk, 40_000, 0xd2, 1)];
    let fee = zip317_shielding_fee(inputs.len());

    let (sighashes, carrier) = build_unsigned_shielding_pczt_ironwood_core(
        Nu63TestNet,
        &pk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("unsigned build");

    let pubkey_hex = hex::encode(pk.serialize());
    let sigs_json = serde_json::json!(sighashes
        .iter()
        .map(|s| serde_json::json!({
            "sig_hex": hex::encode(external_sign(&sk, *s)),
            "pubkey_hex": pubkey_hex,
        }))
        .collect::<Vec<_>>())
    .to_string();

    // `.ok()` avoids requiring Debug on JsError off-wasm; the success path
    // constructs no JsError.
    let tx_hex = complete_shielding_transaction(&hex::encode(&carrier), &sigs_json)
        .ok()
        .expect("sniff route must complete the PCZT carrier");
    let tx_bytes = hex::decode(&tx_hex).expect("result is hex");
    let tx = Transaction::read(&tx_bytes[..], BranchId::Nu6_3).expect("result parses as V6 tx");
    assert_eq!(tx.version(), TxVersion::V6);
    assert_eq!(
        tx.transparent_bundle().expect("transparent").vin.len(),
        2,
        "both inputs signed via the sniff route"
    );
}

#[test]
fn wrong_message_signature_is_rejected() {
    let (sk, pk) = test_key();
    let inputs = vec![coin(&pk, 200_000, 0xc1, 0)];
    let fee = zip317_shielding_fee(inputs.len());

    let (_sighashes, carrier) = build_unsigned_shielding_pczt_ironwood_core(
        Nu63TestNet,
        &pk,
        &inputs,
        recipient(),
        fee,
        TARGET_HEIGHT,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .expect("unsigned build");

    // Sign the WRONG message (all-zero sighash) with the right key. append's
    // verify_ecdsa must reject it before it can be spliced into a scriptSig -
    // the property that makes PCZT completion strictly safer than blind patching.
    let bad = external_sign(&sk, [0u8; 32]);
    let err = complete_shielding_pczt_bytes(&carrier, &[bad])
        .expect_err("a signature over the wrong message must be rejected");
    assert!(
        err.contains("external signature rejected") || err.contains("input 0"),
        "unexpected rejection error: {err}"
    );

    // And a non-SIGHASH_ALL type is refused up front.
    let secp = secp256k1::Secp256k1::signing_only();
    let reparsed = pczt::Pczt::parse(&carrier).unwrap();
    let signer = pczt::roles::signer::Signer::new(reparsed).unwrap();
    let sighash = signer.transparent_sighash(0).unwrap();
    let msg = secp256k1::Message::from_digest(sighash);
    let mut wrong_type = secp.sign_ecdsa(&msg, &sk).serialize_der().to_vec();
    wrong_type.push(0x81); // SIGHASH_ALL | ANYONECANPAY
    let err = complete_shielding_pczt_bytes(&carrier, &[wrong_type])
        .expect_err("non-SIGHASH_ALL must be refused");
    assert!(err.contains("SIGHASH_ALL"), "unexpected sighash-type error: {err}");
}

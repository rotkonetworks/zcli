//! Hot signing split from proving.
//!
//! The offscreen prover now builds every hot transaction with the seed-free cold
//! builders, and the zcash worker signs the proven PCZT with `SpendKeys` /
//! `sign_pczt_spends`. These tests drive exactly that split on the same fixtures
//! the signed_* tests use and prove that:
//!   - the split output has the same structure as the in-prover hot builders
//!     (version, branch id, expiry, bundle shapes, value balances), and its
//!     proofs, spend-auth and binding signatures verify against an
//!     independently recomputed ZIP-244 sighash;
//!   - signing works on both the retained (unredacted) PCZT and the
//!     redacted-for-signer copy the cold builders return;
//!   - another account's keys are refused, and nothing is signed;
//!   - `SpendKeys` derives the same keys the old hot builders derived;
//!   - no wasm export outside the worker-side key holders takes a phrase,
//!     seed or private key.
//!
//! Run with --release (it builds the post-NU6.3 proving keys):
//!   cargo test -p zafu-wasm --release --test hot_sign_split

use zafu_wasm::{
    build_ironwood_send_pczt_proven, build_signed_ironwood_send_core,
    build_signed_turnstile_migration_core, build_turnstile_migration_pczt_core,
    redact_pczt_for_signer, sign_pczt_spends, sign_transparent_sighash,
    transparent_pubkey_from_ufvk, IronwoodPcztWithFrost, IronwoodRecipient, SpendKeys,
    LEGACY_PCZT_EXPIRY_DELTA, NU6_3_BRANCH_ID,
};

use orchard::keys::Scope;
use zcash_primitives::transaction::sighash::{signature_hash, SignableInput};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{Authorization, Transaction, TransactionData, TxVersion};
use zcash_protocol::consensus::{
    BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters,
};
use zcash_protocol::memo::MemoBytes;

#[derive(Debug)]
struct ShieldedSighashAuth;

impl Authorization for ShieldedSighashAuth {
    type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

/// NU6.3 from height 10, as in the signed_* tests.
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

const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon about";
const TARGET: u32 = 10_000_000;

/// The worker's key holder for `account` on testnet (coin type 1, matching
/// Nu63TestNet), and the keys it derives.
fn spend_keys(
    account: u32,
) -> (
    SpendKeys,
    orchard::keys::FullViewingKey,
    orchard::keys::SpendAuthorizingKey,
) {
    let seed = bip39::Mnemonic::parse(SEED).unwrap().to_seed("");
    let keys = SpendKeys::from_seed_bytes(seed, account, false).unwrap();
    let (fvk, ask) = keys.orchard_keys().unwrap();
    (keys, fvk, ask)
}

/// A note of `version` owned by `fvk`, with a single-leaf witness and its anchor.
fn owned_note(
    fvk: &orchard::keys::FullViewingKey,
    value: u64,
    version: orchard::note::NoteVersion,
    rho_seed: u8,
) -> (
    orchard::Note,
    orchard::tree::MerklePath,
    orchard::tree::Anchor,
) {
    let rho = orchard::note::Rho::from_bytes(&[rho_seed; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| Option::from(orchard::note::RandomSeed::from_bytes([b; 32], &rho)))
        .unwrap();
    let note: orchard::Note = Option::from(orchard::Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        orchard::value::NoteValue::from_raw(value),
        rho,
        rseed,
        version,
    ))
    .unwrap();
    let zero = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
    let witness = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let anchor = witness.root(note.commitment().into());
    (note, witness, anchor)
}

/// Re-verify every proof, spend-auth and binding signature of a shielded-only
/// V6 tx against a sighash recomputed here, independently of the extractor.
fn verify_shielded(tx: &Transaction) {
    use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
    assert!(tx.transparent_bundle().is_none());
    let data: TransactionData<ShieldedSighashAuth> = TransactionData::from_parts_v6(
        tx.consensus_branch_id(),
        tx.lock_time(),
        tx.expiry_height(),
        None,
        None,
        tx.orchard_bundle().cloned(),
        tx.ironwood_bundle().cloned(),
    );
    let sighash =
        *signature_hash(&data, &SignableInput::Shielded, &data.digest(TxIdDigester)).as_ref();
    if let Some(b) = tx.orchard_bundle() {
        let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
        let mut v = orchard::bundle::BatchValidator::new(&vk);
        assert!(v.add_bundle(b, sighash).is_ok());
        assert!(
            v.validate(zafu_wasm::OsRng10),
            "orchard proof or signatures do not verify"
        );
    }
    if let Some(b) = tx.ironwood_bundle() {
        let vk =
            VerifyingKey::build(orchard::bundle::BundleVersion::ironwood_v3().circuit_version());
        let mut v = orchard::bundle::BatchValidator::new(&vk);
        assert!(v.add_bundle(b, sighash).is_ok());
        assert!(
            v.validate(zafu_wasm::OsRng10),
            "ironwood proof or signatures do not verify"
        );
    }
}

/// Everything that must match between the old hot path and the split path.
/// Commitments, proofs and signatures are randomized per build, so this is the
/// structural identity; validity is checked separately by `verify_shielded`.
fn shape(
    tx: &Transaction,
) -> (
    TxVersion,
    u32,
    u32,
    Option<(usize, i64)>,
    Option<(usize, i64)>,
) {
    let bundle = |b: Option<
        &orchard::Bundle<orchard::bundle::Authorized, zcash_protocol::value::ZatBalance>,
    >| { b.map(|b| (b.actions().len(), i64::from(*b.value_balance()))) };
    (
        tx.version(),
        u32::from(tx.consensus_branch_id()),
        u32::from(tx.expiry_height()),
        bundle(tx.orchard_bundle()),
        bundle(tx.ironwood_bundle()),
    )
}

fn parse(tx: &[u8]) -> Transaction {
    Transaction::read(tx, BranchId::Nu6_3).expect("tx parses")
}

#[test]
fn spend_keys_derive_the_old_hot_keys_and_ufvk() {
    // the old in-prover builders: SpendingKey::from_zip32_seed(seed, coin, account)
    let seed = bip39::Mnemonic::parse(SEED).unwrap().to_seed("");
    for account in [0u32, 3] {
        let sk = orchard::keys::SpendingKey::from_zip32_seed(
            &seed,
            1,
            zip32::AccountId::try_from(account).unwrap(),
        )
        .unwrap();
        let (_, fvk, _) = spend_keys(account);
        assert_eq!(
            fvk.to_bytes(),
            orchard::keys::FullViewingKey::from(&sk).to_bytes()
        );
    }
    // the UFVK handed to the prover carries exactly that orchard FVK
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::TestNetwork;
    let (keys, fvk, _) = spend_keys(2);
    let ufvk = UnifiedFullViewingKey::decode(&TestNetwork, &keys.ufvk().unwrap()).unwrap();
    assert_eq!(ufvk.orchard().unwrap().to_bytes(), fvk.to_bytes());
}

#[test]
fn transparent_keys_match_the_ufvk_and_sign_low_s_sighash_all() {
    // mainnet: the BIP44 path m/44'/133'/a'/0/i is the UFVK's transparent branch
    let seed = bip39::Mnemonic::parse(SEED).unwrap().to_seed("");
    let keys = SpendKeys::from_seed_bytes(seed, 1, true).unwrap();
    let ufvk = keys.ufvk().unwrap();
    for index in [0u32, 7] {
        assert_eq!(
            keys.transparent_pubkey(index).unwrap(),
            transparent_pubkey_from_ufvk(&ufvk, index).unwrap()
        );
    }
    let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let digest = [0x5au8; 32];
    let sig = sign_transparent_sighash(&sk, digest);
    assert_eq!(*sig.last().unwrap(), 0x01, "SIGHASH_ALL");
    let parsed = secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
    let mut normalized = parsed;
    normalized.normalize_s();
    assert_eq!(parsed, normalized, "low-S");
    let secp = secp256k1::Secp256k1::verification_only();
    secp.verify_ecdsa(
        &secp256k1::Message::from_digest(digest),
        &parsed,
        &sk.public_key(&secp256k1::Secp256k1::signing_only()),
    )
    .expect("signature verifies against the sighash");
}

#[test]
fn ironwood_send_split_matches_hot_and_verifies() {
    let (_, fvk, ask) = spend_keys(0);
    let (recip_fvk, _) = {
        let (_, f, a) = spend_keys(9);
        (f, a)
    };
    let recipient = IronwoodRecipient::Shielded(recip_fvk.address_at(0u32, Scope::External));
    let (amount, fee, value) = (600_000u64, 10_000u64, 1_000_000u64);
    let build = |rho| owned_note(&fvk, value, orchard::note::NoteVersion::V3, rho);

    let (n, w, anchor) = build(1);
    let old = parse(
        &build_signed_ironwood_send_core(
            Nu63TestNet,
            &fvk,
            &ask,
            vec![(n, w)],
            recipient,
            amount,
            fee,
            anchor,
            TARGET,
            NU6_3_BRANCH_ID,
            MemoBytes::empty(),
        )
        .unwrap(),
    );

    // prover side: the cold builder, from the FVK only
    let (n, w, anchor) = build(1);
    let IronwoodPcztWithFrost { pczt, .. } = build_ironwood_send_pczt_proven(
        Nu63TestNet,
        &fvk,
        vec![(n, w)],
        recipient,
        amount,
        fee,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
        LEGACY_PCZT_EXPIRY_DELTA,
    )
    .unwrap();
    // worker side: sign the retained copy, and the redacted copy as well
    let retained = pczt.clone().serialize().unwrap();
    let redacted = redact_pczt_for_signer(pczt).serialize().unwrap();
    for bytes in [retained, redacted] {
        let new = parse(&sign_pczt_spends(&bytes, &fvk, &ask).expect("worker signs"));
        assert_eq!(shape(&new), shape(&old));
        assert_eq!(
            u32::from(new.expiry_height()),
            TARGET + LEGACY_PCZT_EXPIRY_DELTA
        );
        assert!(new.orchard_bundle().is_none());
        assert_eq!(
            i64::from(*new.ironwood_bundle().unwrap().value_balance()),
            fee as i64
        );
        verify_shielded(&new);
    }
    verify_shielded(&old);
}

#[test]
fn turnstile_split_matches_hot_and_verifies() {
    let (_, fvk, ask) = spend_keys(0);
    let fee = 10_000u64;
    let (n, w, anchor) = owned_note(&fvk, 1_000_000, orchard::note::NoteVersion::V2, 1);
    let old = parse(
        &build_signed_turnstile_migration_core(
            Nu63TestNet,
            &fvk,
            &ask,
            vec![(n, w)],
            fee,
            anchor,
            TARGET,
            NU6_3_BRANCH_ID,
            MemoBytes::empty(),
        )
        .unwrap(),
    );

    // prover side returns only the redacted PCZT; the worker signs it
    let (n, w, anchor) = owned_note(&fvk, 1_000_000, orchard::note::NoteVersion::V2, 1);
    let built = build_turnstile_migration_pczt_core(
        Nu63TestNet,
        &fvk,
        vec![(n, w)],
        fee,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .unwrap();
    let new = parse(&sign_pczt_spends(&built.pczt_bytes, &fvk, &ask).expect("worker signs"));

    assert_eq!(shape(&new), shape(&old));
    assert_eq!(new.version(), TxVersion::V6);
    assert_eq!(u32::from(new.consensus_branch_id()), NU6_3_BRANCH_ID);
    let migrated = -i64::from(*new.ironwood_bundle().unwrap().value_balance());
    let spent = i64::from(*new.orchard_bundle().unwrap().value_balance());
    assert_eq!(
        spent - migrated,
        fee as i64,
        "orchard in - ironwood out = fee"
    );
    verify_shielded(&new);
    verify_shielded(&old);
}

#[test]
fn another_accounts_keys_sign_nothing() {
    let (_, fvk, _) = spend_keys(0);
    let (_, other_fvk, other_ask) = spend_keys(1);
    let (n, w, anchor) = owned_note(&fvk, 1_000_000, orchard::note::NoteVersion::V2, 1);
    let built = build_turnstile_migration_pczt_core(
        Nu63TestNet,
        &fvk,
        vec![(n, w)],
        10_000,
        anchor,
        TARGET,
        NU6_3_BRANCH_ID,
        MemoBytes::empty(),
    )
    .unwrap();
    // the redacted copy hides the note, so only the rk check stands between a
    // foreign key and a signature: it must hold
    let err = sign_pczt_spends(&built.pczt_bytes, &other_fvk, &other_ask).unwrap_err();
    assert!(err.contains("another account"), "{err}");
}

/// Every wasm export that takes a phrase, seed or private key, by file. These
/// are the worker-side key holders; nothing the offscreen prover dispatches may
/// join this list. FROST shares and the voting hotkey are separate key material
/// with their own flows and are matched by their own names, not these.
#[test]
fn only_worker_side_exports_take_wallet_secrets() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let secret = |p: &str| {
        ["seed_phrase", "mnemonic", "privkey", "seed:"]
            .iter()
            .any(|n| p.contains(n))
    };
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_name().unwrap().to_string_lossy().to_string();
        let src = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        let mut exported = false;
        let mut in_exported_impl = false;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("#[wasm_bindgen") {
                exported = true;
                continue;
            }
            if t.starts_with("impl ") {
                in_exported_impl = exported;
                exported = false;
                continue;
            }
            if *line == "}" {
                in_exported_impl = false;
            }
            if let Some(rest) = t.strip_prefix("pub fn ") {
                if exported || in_exported_impl {
                    let name = rest.split(['(', '<']).next().unwrap().to_string();
                    let sig: String = lines[i..]
                        .iter()
                        .take(20)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(" ");
                    let params = sig
                        .split_once('(')
                        .map_or("", |(_, p)| p.split(')').next().unwrap_or(""));
                    if secret(params) {
                        found.push(format!("{file}::{name}"));
                    }
                }
                exported = false;
            } else if !t.starts_with("#[") && !t.starts_with("//") && !t.is_empty() {
                exported = false;
            }
        }
    }
    found.sort();
    assert_eq!(
        found,
        [
            "hot_sign.rs::new",
            "lib.rs::from_seed_phrase",
            "lib.rs::from_seed_phrase_account",
            "lib.rs::validate_seed_phrase",
        ],
        "a wasm export takes a phrase, seed or private key"
    );
}

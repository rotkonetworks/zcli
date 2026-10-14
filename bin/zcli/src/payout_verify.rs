// payout_verify.rs — a co-signer's check on a payout PCZT, before its share.
//
// A 2-of-3 escrow vault (the zk.poker escrow, say) holds one share; a payout
// needs one player's share too. A player that signed whatever `SIGN` arrived
// would let the escrow spend the vault anywhere. This is what makes the
// second signature mean "I agree with this payout".
//
// Ported from zk.poker's poker-escrow `payout_verify`, so the player's side
// and the escrow's own test of it apply the same rules. The PCZT is accepted
// only when:
// - the sighash we are asked to sign is the PCZT's own shielded sighash, and
//   the alphas are exactly the randomizers of its real spends;
// - every real spend is a note of the vault (nullifier and rk check against
//   the vault's viewing key);
// - every output's plaintext (recipient, value) matches its note commitment,
//   so the cleartext we judge cannot differ from what the transaction pays;
// - the outputs that carry value are exactly the agreed plan (as a multiset),
//   plus change back to the vault's own addresses;
// - the implied fee is at most the cap, and no transparent or Sapling part
//   exists;
// - the Orchard bundle is empty: the vault holds Ironwood notes only, so
//   every spend and output lives in the Ironwood bundle.

use ff::PrimeField;
use orchard::keys::FullViewingKey;
use orchard::Address;
use pczt::roles::signer::Signer;
use pczt::roles::verifier::{OrchardError, Verifier};

/// What the coordinator put on the wire in its `SIGN:` message.
#[derive(Debug, Clone)]
pub struct SignRequest {
    pub sighash: [u8; 32],
    pub alphas: Vec<[u8; 32]>,
    /// hex of the standard PCZT; empty if the host sent none (then nothing
    /// can be checked)
    pub pczt_hex: String,
}

/// Parse `SIGN:<sighash>:<alphas>:<recipient>:<amount>:<fee>[:<pczt_hex>]`.
///
/// The recipient/amount/fee fields are the host's own summary and are not
/// trusted: the PCZT is what gets checked.
pub fn parse_sign(text: &str) -> Result<SignRequest, String> {
    let body = text.strip_prefix("SIGN:").ok_or("not a SIGN message")?;
    let parts: Vec<&str> = body.splitn(6, ':').collect();
    if parts.len() < 5 {
        return Err("SIGN message is missing fields".into());
    }
    let sighash = decode32(parts[0]).ok_or("bad sighash")?;
    let alphas = parts[1]
        .split(',')
        .map(decode32)
        .collect::<Option<Vec<_>>>()
        .ok_or("bad alpha")?;
    Ok(SignRequest {
        sighash,
        alphas,
        pczt_hex: parts.get(5).map(|s| s.to_string()).unwrap_or_default(),
    })
}

fn decode32(h: &str) -> Option<[u8; 32]> {
    hex::decode(h.trim()).ok()?.try_into().ok()
}

/// One value-carrying output: who it pays and how much.
struct Paid {
    recipient: Address,
    value: u64,
}

/// Accept `req` for co-signing only if its PCZT pays exactly `plan` (plus
/// change to `vault`) with a fee of at most `max_fee_zat`.
pub fn verify_payout(
    req: &SignRequest,
    vault: &FullViewingKey,
    plan: &[(Address, u64)],
    max_fee_zat: u64,
) -> Result<(), String> {
    if req.pczt_hex.is_empty() {
        return Err("the coordinator sent no PCZT: nothing to check, refusing to sign".into());
    }
    let bytes = hex::decode(req.pczt_hex.trim()).map_err(|_| "PCZT is not hex")?;
    let pczt = pczt::Pczt::parse(&bytes).map_err(|e| format!("PCZT parse: {e:?}"))?;

    if pczt.has_data_in_pool(zcash_protocol::PoolType::TRANSPARENT)
        || pczt.has_data_in_pool(zcash_protocol::PoolType::SAPLING)
    {
        return Err("payout has a transparent or Sapling part".into());
    }
    if !pczt.orchard().actions().is_empty() {
        return Err("payout has an Orchard action: the vault is Ironwood-only".into());
    }

    let mut spent: u64 = 0;
    let mut outputs: Vec<Paid> = Vec::new();
    let mut alphas: Vec<[u8; 32]> = Vec::new();

    let mut walk = |b: &orchard::pczt::Bundle| -> Result<(), String> {
        for (i, a) in b.actions().iter().enumerate() {
            let s = a.spend();
            let value = s
                .value()
                .ok_or(format!("action {i}: spend value redacted"))?
                .inner();
            // padding spends are zero-value dummies (parsing drops their
            // dummy_sk); a vault deposit always carries value, and only those
            // are signed for
            if value > 0 {
                s.verify_nullifier(Some(vault))
                    .map_err(|e| format!("action {i}: spend is not a vault note: {e:?}"))?;
                s.verify_rk(Some(vault))
                    .map_err(|e| format!("action {i}: rk does not match the vault key: {e:?}"))?;
                let alpha = s.alpha().ok_or(format!("action {i}: alpha redacted"))?;
                alphas.push(alpha.to_repr());
                spent = spent.checked_add(value).ok_or("spend overflow")?;
            }
            let o = a.output();
            o.verify_note_commitment(s).map_err(|e| {
                format!("action {i}: output fields do not match its commitment: {e:?}")
            })?;
            let value = o
                .value()
                .ok_or(format!("action {i}: output value redacted"))?
                .inner();
            if value > 0 {
                let recipient = o
                    .recipient()
                    .ok_or(format!("action {i}: recipient redacted"))?;
                outputs.push(Paid { recipient, value });
            }
        }
        Ok(())
    };

    // vault notes are Ironwood notes, signed in Ironwood action order
    let verifier = Verifier::new(pczt)
        .with_ironwood(|b| walk(b).map_err(OrchardError::Custom))
        .map_err(|e| format!("ironwood bundle: {e:?}"))?;

    if alphas != req.alphas {
        return Err("the alphas to sign are not the PCZT's spend randomizers".into());
    }
    let sighash = Signer::new(verifier.finish())
        .map_err(|e| format!("PCZT signer: {e:?}"))?
        .shielded_sighash();
    if sighash != req.sighash {
        return Err("the sighash to sign is not this PCZT's sighash".into());
    }

    // match the plan as a multiset; whatever is left must be change to the vault
    let mut rest = outputs;
    for (addr, amount) in plan {
        let raw = addr.to_raw_address_bytes();
        let pos = rest
            .iter()
            .position(|p| p.recipient.to_raw_address_bytes() == raw && p.value == *amount)
            .ok_or_else(|| format!("the agreed payout of {amount} zat is not in the PCZT"))?;
        rest.remove(pos);
    }
    if let Some(p) = rest
        .iter()
        .find(|p| vault.scope_for_address(&p.recipient).is_none())
    {
        return Err(format!(
            "the PCZT pays {} zat to an address outside the plan",
            p.value
        ));
    }

    let paid: u64 = plan
        .iter()
        .map(|(_, v)| v)
        .chain(rest.iter().map(|p| &p.value))
        .sum();
    let fee = spent
        .checked_sub(paid)
        .ok_or("the PCZT pays out more than it spends")?;
    if fee > max_fee_zat {
        return Err(format!("fee {fee} zat exceeds the {max_fee_zat} zat cap"));
    }
    Ok(())
}

/// [`verify_payout`] for a stored share: the vault's FVK as hex (96 bytes)
/// and the plan as (unified address, zatoshi) pairs.
pub fn verify_payout_for_share(
    req: &SignRequest,
    vault_fvk_hex: &str,
    plan: &[(String, u64)],
    mainnet: bool,
    max_fee_zat: u64,
) -> Result<(), String> {
    let fvk_bytes: [u8; 96] = hex::decode(vault_fvk_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("vault FVK is not 96 bytes of hex")?;
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).ok_or("invalid vault FVK")?;
    let plan = plan
        .iter()
        .map(|(ua, v)| {
            crate::tx::parse_orchard_address(ua, mainnet)
                .map(|a| (a, *v))
                .map_err(|e| format!("plan address {ua}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_payout(req, &fvk, &plan, max_fee_zat)
}

#[cfg(test)]
mod tests {
    //! Mirrors poker-escrow's `cosigner_accepts_only_the_agreed_payout` and
    //! `cosigner_refuses_an_orchard_spend`, with the payout built by the same
    //! standard builder the escrow uses (unproven: the check needs no proofs).
    use super::*;
    use orchard::keys::{Scope, SpendingKey};
    use orchard::note::{NoteVersion, RandomSeed, Rho};
    use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
    use orchard::value::NoteValue;
    use orchard::Note;
    use pczt::roles::creator::Creator;
    use pczt::roles::io_finalizer::IoFinalizer;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::fixed::FeeRule;
    use zcash_primitives::transaction::TxVersion;
    use zcash_protocol::consensus::{BlockHeight, MainNetwork};
    use zcash_protocol::memo::MemoBytes;
    use zcash_protocol::value::Zatoshis;

    type FeError = <FeeRule as zcash_primitives::transaction::fees::FeeRule>::Error;

    /// past mainnet NU6.3 activation, so the V6 / Ironwood builder exists
    const TARGET: u32 = 3_428_143 + 100;

    fn fvk(seed: u8) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
    }

    fn addr(seed: u8) -> Address {
        fvk(seed).address_at(0u32, Scope::External)
    }

    /// A note of `fvk`'s external address with a single-leaf witness.
    fn note(fvk: &FullViewingKey, value: u64, version: NoteVersion) -> (Note, MerklePath) {
        let rho = Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| Option::from(RandomSeed::from_bytes([b; 32], &rho)))
            .unwrap();
        let note = Option::from(Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(value),
            rho,
            rseed,
            version,
        ))
        .unwrap();
        let zero = Option::from(MerkleHashOrchard::from_bytes(&[0u8; 32])).unwrap();
        (note, MerklePath::from_parts(0, [zero; 32]))
    }

    /// The randomizers of the real (non-dummy) spends, in action order.
    fn alphas(b: &Option<orchard::pczt::Bundle>) -> Vec<[u8; 32]> {
        b.iter()
            .flat_map(|b| b.actions())
            .filter(|a| a.spend().dummy_sk().is_none())
            .filter_map(|a| a.spend().alpha().map(|x| x.to_repr()))
            .collect()
    }

    /// Spend `spend` (in the Ironwood pool, or the Orchard pool if
    /// `in_orchard`), pay `outputs` and the change back to the vault's
    /// internal address, as the escrow's payout builder does.
    fn payout(
        vault: &FullViewingKey,
        spend: (Note, MerklePath),
        outputs: &[(Address, u64)],
        fee: u64,
        in_orchard: bool,
    ) -> SignRequest {
        let anchor = spend.1.root(spend.0.commitment().into());
        let change = spend.0.value().inner() - outputs.iter().map(|(_, v)| v).sum::<u64>() - fee;
        let mut b = Builder::new(
            MainNetwork,
            BlockHeight::from(TARGET),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(if in_orchard {
                    anchor
                } else {
                    Anchor::empty_tree()
                }),
                ironwood_anchor: Some(if in_orchard {
                    Anchor::empty_tree()
                } else {
                    anchor
                }),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        b.propose_version::<FeError>(TxVersion::V6).unwrap();
        if in_orchard {
            b.add_orchard_spend::<FeError>(vault.clone(), spend.0, spend.1)
                .unwrap();
        } else {
            b.add_ironwood_spend::<FeError>(vault.clone(), spend.0, spend.1)
                .unwrap();
        }
        let ovk = vault.to_ovk(Scope::External);
        for (to, v) in outputs {
            b.add_ironwood_output::<FeError>(
                Some(ovk.clone()),
                *to,
                Zatoshis::from_u64(*v).unwrap(),
                MemoBytes::empty(),
            )
            .unwrap();
        }
        if change > 0 {
            b.add_ironwood_output::<FeError>(
                Some(vault.to_ovk(Scope::Internal)),
                vault.address_at(0u64, Scope::Internal),
                Zatoshis::from_u64(change).unwrap(),
                MemoBytes::empty(),
            )
            .unwrap();
        }
        let parts = b
            .build_for_pczt(
                crate::tx::OsRng10,
                &FeeRule::non_standard(Zatoshis::from_u64(fee).unwrap()),
            )
            .unwrap()
            .pczt_parts;
        let alphas = alphas(if in_orchard {
            &parts.orchard
        } else {
            &parts.ironwood
        });
        assert_eq!(alphas.len(), 1, "one real spend");
        let pczt = IoFinalizer::new(Creator::build_from_parts(parts).unwrap())
            .finalize_io()
            .unwrap();
        let sighash = Signer::new(pczt.clone()).unwrap().shielded_sighash();
        SignRequest {
            sighash,
            alphas,
            pczt_hex: hex::encode(pczt.serialize().unwrap()),
        }
    }

    #[test]
    fn cosigner_accepts_only_the_agreed_payout() {
        let vault = fvk(9);
        let (winner, stranger) = (addr(11), addr(12));
        let (deposit, pay, fee) = (1_000_000u64, 600_000u64, 10_000u64);
        let req = payout(
            &vault,
            note(&vault, deposit, NoteVersion::V3),
            &[(winner, pay)],
            fee,
            false,
        );

        // the agreed plan; the 390k remainder is change back to the vault
        verify_payout(&req, &vault, &[(winner, pay)], fee).expect("agreed payout is accepted");

        let refuse = |r: &SignRequest, plan: &[(Address, u64)], max_fee: u64, why: &str| {
            assert!(verify_payout(r, &vault, plan, max_fee).is_err(), "{why}");
        };
        refuse(&req, &[(winner, pay + 1)], fee, "wrong amount");
        refuse(&req, &[(stranger, pay)], fee, "wrong recipient");
        refuse(
            &req,
            &[(winner, pay), (stranger, 1)],
            fee,
            "a plan line the PCZT does not pay",
        );
        refuse(&req, &[(winner, pay)], fee - 1, "fee above the cap");
        // a plan expecting less than the PCZT pays leaves value going to the
        // winner, which is not vault change
        refuse(&req, &[], fee, "an output outside the plan");

        let mut bad = req.clone();
        bad.sighash[0] ^= 1;
        refuse(&bad, &[(winner, pay)], fee, "sighash not the PCZT's");
        let mut bad = req.clone();
        bad.alphas[0][0] ^= 1;
        refuse(&bad, &[(winner, pay)], fee, "alpha not the PCZT's");
        let mut bad = req.clone();
        bad.pczt_hex.clear();
        refuse(&bad, &[(winner, pay)], fee, "no PCZT to check");

        // a different vault key: the spend is not ours to vouch for
        assert!(
            verify_payout(&req, &fvk(13), &[(winner, pay)], fee).is_err(),
            "foreign vault"
        );
    }

    /// A PCZT spending a vault note in the Orchard bundle is refused even
    /// when it pays exactly the plan: custody is Ironwood-only.
    #[test]
    fn cosigner_refuses_an_orchard_spend() {
        let vault = fvk(9);
        let winner = addr(11);
        let (deposit, pay, fee) = (1_000_000u64, 990_000u64, 10_000u64);
        let req = payout(
            &vault,
            note(&vault, deposit, NoteVersion::V2),
            &[(winner, pay)],
            fee,
            true,
        );
        let err = verify_payout(&req, &vault, &[(winner, pay)], fee)
            .expect_err("a PCZT with an Orchard action must be refused");
        assert!(
            err.contains("Orchard"),
            "refused for the Orchard action, got: {err}"
        );
    }

    #[test]
    fn sign_message_parses_with_and_without_a_pczt() {
        let h = "11".repeat(32);
        let a = "22".repeat(32);
        let r = parse_sign(&format!("SIGN:{h}:{a},{a}:u1x:5:10000:beef")).unwrap();
        assert_eq!(r.alphas.len(), 2);
        assert_eq!(r.pczt_hex, "beef");
        assert!(parse_sign(&format!("SIGN:{h}:{a}:u1x:5:10000"))
            .unwrap()
            .pczt_hex
            .is_empty());
        assert!(parse_sign("SIGN:zz:aa:u:1:1").is_err());
        assert!(parse_sign("C:abc").is_err());
    }
}

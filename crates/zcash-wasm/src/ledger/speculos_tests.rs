// Device round trips of the protocol layer against Speculos running the Ledger
// Zcash app. Ignored unless SPECULOS_URL is set (e.g. http://127.0.0.1:5000).
//
// Portions adapted from vizor-wallet (chainapsis/vizor-wallet, Apache-2.0), modified.

// Device-harness test code, ignored without SPECULOS_URL.
#![allow(
    clippy::vec_init_then_push,
    for_loops_over_fallibles,
    clippy::needless_borrow,
    clippy::type_complexity
)]

use super::*;
use orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    bundle::BundleVersion,
    keys::{FullViewingKey, Scope},
    note::{RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Note,
};
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztParts},
    fees::fixed::FeeRule as FixedFeeRule,
    TxVersion,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork, NetworkUpgrade, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};

const SPEND_VALUE: u64 = 100_000;
const NO_MEMO: [u8; 512] = {
    let mut m = [0; 512];
    m[0] = 0xf6;
    m
};

fn api() -> Option<String> {
    std::env::var("SPECULOS_URL").ok()
}

fn http(method: &str, path: &str, body: &str) -> String {
    let base = api().unwrap();
    let hostport = base.trim_start_matches("http://").trim_end_matches('/');
    let mut s = TcpStream::connect(hostport).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(90))).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {hostport}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    if !head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return body.to_string();
    }
    let mut rest = body;
    let mut decoded = String::new();
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        decoded.push_str(&tail[..n]);
        rest = &tail[n..].trim_start_matches("\r\n");
    }
    decoded
}

fn screen() -> String {
    let v: serde_json::Value =
        serde_json::from_str(&http("GET", "/events?currentscreenonly=true", "")).unwrap_or_default();
    v["events"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["text"].as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn press(button: &str) {
    http("POST", &format!("/button/{button}"), r#"{"action":"press-and-release"}"#);
}

fn wait_idle() {
    for _ in 0..100 {
        if screen().to_lowercase().contains("app is ready") {
            return;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// (data, sw)
fn apdu(cmd: &ApduCommand) -> (Vec<u8>, u16) {
    let mut bytes = vec![cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data.len() as u8];
    bytes.extend_from_slice(&cmd.data);
    let v: serde_json::Value = serde_json::from_str(&http(
        "POST",
        "/apdu",
        &format!(r#"{{"data":"{}"}}"#, hex::encode(&bytes)),
    ))
    .unwrap();
    let all = hex::decode(v["data"].as_str().unwrap()).unwrap();
    let sw = u16::from_be_bytes([all[all.len() - 2], all[all.len() - 1]]);
    (all[..all.len() - 2].to_vec(), sw)
}

/// Walks one review and approves it; records every screen it saw.
struct Approver {
    done: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Vec<String>>,
}

impl Approver {
    fn start() -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut started = false;
            let mut pressed_final = false;
            while !d.load(Ordering::SeqCst) {
                let text = screen();
                if seen.last() != Some(&text) {
                    seen.push(text.clone());
                }
                let low = text.to_lowercase();
                if low.contains("review") || low.contains("export") || low.contains("viewing key") {
                    started = true;
                }
                if started {
                    let approve = low.contains("approve")
                        || low.contains("accept")
                        || low.contains("confirm")
                        || low.contains("sign transaction");
                    if approve {
                        press("both");
                        pressed_final = true;
                        std::thread::sleep(Duration::from_millis(400));
                        continue;
                    } else if pressed_final {
                        break;
                    } else {
                        press("right");
                    }
                }
                std::thread::sleep(Duration::from_millis(120));
            }
            seen
        });
        Self { done, handle }
    }

    fn finish(self) -> Vec<String> {
        self.done.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

fn finishes_review(cmd: &ApduCommand) -> bool {
    (cmd.ins == 0x50 && cmd.p1 == 0x00)
        || ((cmd.ins == 0x56 || cmd.ins == 0x58) && cmd.p2 == 0x01)
}

/// Sends `plan`, approving the review. Err((index, sw)) on the first failure.
fn exchange(plan: &[ApduCommand]) -> (Result<Vec<Vec<u8>>, (usize, u8, u16)>, Vec<String>) {
    wait_idle();
    let mut out = Vec::new();
    let mut screens = Vec::new();
    for (i, cmd) in plan.iter().enumerate() {
        let approver = finishes_review(cmd).then(Approver::start);
        if matches!(cmd.ins, 0x55 | 0x57 | 0x59) || finishes_review(cmd) {
            eprintln!("  -> apdu {i} ins {:#04x} p1 {:#04x} p2 {:#04x}", cmd.ins, cmd.p1, cmd.p2);
        }
        let (data, sw) = apdu(cmd);
        if matches!(cmd.ins, 0x55 | 0x57 | 0x59) || finishes_review(cmd) || sw != 0x9000 {
            eprintln!("  <- apdu {i} sw {sw:#06x} len {}", data.len());
        }
        if let Some(a) = approver {
            screens.extend(a.finish());
            if std::env::var("SPECULOS_SETTLE_AFTER_REVIEW").is_ok() {
                wait_idle();
            }
        }
        if sw != 0x9000 {
            wait_idle();
            return (Err((i, cmd.ins, sw)), screens);
        }
        out.push(data);
    }
    wait_idle();
    (Ok(out), screens)
}

struct LedgerAccount {
    ufvk: zcash_keys::keys::UnifiedFullViewingKey,
    fingerprint: [u8; 32],
}

fn export_account() -> LedgerAccount {
    let plan = ufvk_plan(0).unwrap();
    let (first, _) = exchange(&plan[..1]);
    let mut responses = first.unwrap();
    while apdu::ufvk_remaining_bytes(&responses).unwrap() > 0 {
        let (next, _) = exchange(&plan[1..2]);
        responses.extend(next.unwrap());
    }
    let export = parse_ufvk(&responses, "main", 0).unwrap();
    LedgerAccount {
        ufvk: zcash_keys::keys::UnifiedFullViewingKey::decode(&MainNetwork, &export.ufvk).unwrap(),
        fingerprint: export.seed_fingerprint,
    }
}

fn nu6_3_height() -> BlockHeight {
    MainNetwork.activation_height(NetworkUpgrade::Nu6_3).unwrap() + 100
}

/// One bundle spending a note of the Ledger's own account (with the account's
/// ZIP-32 derivation) into `outputs`; post-NU6.3 Orchard pairs change outputs
/// with zero-value wallet spends.
fn bundle(
    version: BundleVersion,
    fvk: &FullViewingKey,
    fingerprint: [u8; 32],
    outputs: &[u64],
) -> orchard::pczt::Bundle {
    bundle_with(version, fvk, fingerprint, outputs, false)
}

fn bundle_with(
    version: BundleVersion,
    fvk: &FullViewingKey,
    fingerprint: [u8; 32],
    outputs: &[u64],
    padded: bool,
) -> orchard::pczt::Bundle {
    let rho = Rho::from_bytes(&[1; 32]).into_option().unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| RandomSeed::from_bytes([b; 32], &rho).into_option())
        .unwrap();
    let note = Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(SPEND_VALUE),
        rho,
        rseed,
        version.note_version(),
    )
    .into_option()
    .unwrap();
    let path = MerklePath::from_parts(0, [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32]);
    let mut builder = OrchardBuilder::new(
        if padded { BundleType::DEFAULT } else { BundleType::UNPADDED },
        version,
        version.default_flags(),
        path.root(note.commitment().into()),
    )
    .unwrap();
    builder.add_spend(fvk.clone(), note, path).unwrap();
    // an external recipient (another wallet), so the review shows an output
    let other = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([0x43; 32]).unwrap());
    for value in outputs {
        if version.default_flags().cross_address_enabled() {
            builder
                .add_output(
                    Some(fvk.to_ovk(Scope::External)),
                    other.address_at(0u32, Scope::External),
                    NoteValue::from_raw(*value),
                    NO_MEMO,
                )
                .unwrap();
        } else {
            builder
                .add_change_output(
                    fvk.clone(),
                    Some(fvk.to_ovk(Scope::Internal)),
                    fvk.address_at(0u32, Scope::Internal),
                    NoteValue::from_raw(*value),
                    [0; 512],
                )
                .unwrap();
        }
    }
    let (mut bundle, metadata) = builder.build_for_pczt(crate::OsRng10).unwrap();
    // like the protocol's own fixtures (and zafu's builder): only the real
    // spend carries the account derivation; the paired zero-value spend does not
    bundle
        .update_with(|mut b| {
            b.update_action_with(metadata.spend_action_index(0).unwrap(), |mut a| {
                a.set_spend_zip32_derivation(
                    orchard::pczt::Zip32Derivation::parse(
                        fingerprint,
                        vec![0x8000_0020, 0x8000_0085, 0x8000_0000],
                    )
                    .unwrap(),
                );
                Ok(())
            })
        })
        .unwrap();
    bundle
}

fn pczt_from(
    branch: BranchId,
    orchard: Option<orchard::pczt::Bundle>,
    ironwood: Option<orchard::pczt::Bundle>,
) -> Vec<u8> {
    let pczt = Creator::build_from_parts(PcztParts {
        params: MainNetwork,
        version: TxVersion::suggested_for_branch(branch),
        consensus_branch_id: branch,
        lock_time: 0,
        expiry_height: BlockHeight::from_u32(0),
        transparent: None,
        sapling: None,
        orchard,
        ironwood,
    })
    .unwrap();
    IoFinalizer::new(pczt).finalize_io().unwrap().serialize().unwrap()
}

/// transparent P2PKH (the Ledger's m/44'/133'/0'/0/0) -> one Ironwood output
/// to the Ledger's own Orchard address, NU6.3.
fn shielding_pczt(acct: &LedgerAccount) -> Vec<u8> {
    shielding_pczt_with(acct, true, false)
}

fn shielding_pczt_with(acct: &LedgerAccount, ironwood: bool, with_ovk: bool) -> Vec<u8> {
    use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
    let pubkey = acct
        .ufvk
        .transparent()
        .unwrap()
        .derive_address_pubkey(TransparentKeyScope::EXTERNAL, NonHardenedChildIndex::ZERO)
        .unwrap();
    let address = TransparentAddress::from_pubkey(&pubkey);
    let fvk = acct.ufvk.orchard().unwrap().clone();
    let fee = 15_000u64;
    let input = 1_000_000u64;
    let height = if ironwood {
        nu6_3_height()
    } else {
        MainNetwork.activation_height(NetworkUpgrade::Nu6_3).unwrap() - 100
    };
    let mut builder = Builder::new(
        MainNetwork,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: (!ironwood).then(orchard::Anchor::empty_tree),
            ironwood_anchor: ironwood.then(orchard::Anchor::empty_tree),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    type FeError = <FixedFeeRule as zcash_primitives::transaction::fees::FeeRule>::Error;
    if ironwood {
        builder.propose_version::<FeError>(TxVersion::V6).unwrap();
    }
    builder
        .add_transparent_p2pkh_input(
            pubkey,
            OutPoint::new([1; 32], 0),
            TxOut::new(Zatoshis::const_from_u64(input), address.script().into()),
        )
        .unwrap();
    let ovk = with_ovk.then(|| fvk.to_ovk(Scope::External));
    let to = fvk.address_at(0u32, Scope::External);
    let value = Zatoshis::from_u64(input - fee).unwrap();
    if ironwood {
        builder.add_ironwood_output::<FeError>(ovk, to, value, MemoBytes::empty()).unwrap();
    } else {
        builder.add_orchard_output::<FeError>(ovk, to, value, MemoBytes::empty()).unwrap();
    }
    let parts = builder
        .build_for_pczt(crate::OsRng10, &FixedFeeRule::non_standard(Zatoshis::from_u64(fee).unwrap()))
        .unwrap()
        .pczt_parts;
    let pczt = IoFinalizer::new(Creator::build_from_parts(parts).unwrap())
        .finalize_io()
        .unwrap();
    let derivation = transparent::pczt::Bip32Derivation::parse(
        acct.fingerprint,
        vec![0x8000_002c, 0x8000_0085, 0x8000_0000, 0, 0],
    )
    .unwrap();
    Updater::new(pczt)
        .update_transparent_with(|mut b| {
            b.update_input_with(0, |mut i| {
                i.set_bip32_derivation(pubkey.serialize(), derivation);
                Ok(())
            })
        })
        .unwrap()
        .finish()
        .serialize()
        .unwrap()
}

/// "orchard[0]=real(100000) orchard[1]=zero(wallet) ironwood[0]=dummy ..."
fn inventory(pczt: &[u8]) -> String {
    let p = parse::parse_pczt(pczt).unwrap();
    let mut out = Vec::new();
    let describe = |pool: &str, i: usize, a: &parse::ShieldedAction| {
        let kind = if a.is_dummy {
            "dummy".to_string()
        } else if a.spend_value == 0 {
            "zero(wallet)".to_string()
        } else {
            format!("real({})", a.spend_value)
        };
        let sign = if a.needs_signature { "+needs_sig" } else { "" };
        format!("{pool}[{i}]={kind}{sign}")
    };
    for b in &p.orchard_bundle {
        for (i, a) in b.actions.iter().enumerate() {
            out.push(describe("orchard", i, a));
        }
    }
    for b in &p.ironwood_bundle {
        for (i, a) in b.actions.iter().enumerate() {
            out.push(describe("ironwood", i, &a.action));
        }
    }
    out.join(" ")
}

fn run_case(name: &str, pczt: &[u8]) -> Result<(), String> {
    run_case_with(name, pczt, false)
}

fn run_case_with(name: &str, pczt: &[u8], reverse_signs: bool) -> Result<(), String> {
    println!("[{name}] actions: {}", inventory(pczt));
    let mut plan = pczt_signing_plan(pczt, true).map_err(|e| format!("plan: {e}"))?;
    if std::env::var("SPECULOS_ONLY_REAL").is_ok() && name.ends_with("_realonly") {
        let parsed = parse::parse_pczt(pczt).unwrap();
        let zero: Vec<usize> = parsed.orchard_bundle.iter().flat_map(|b| b.actions.iter().enumerate())
            .filter(|(_, a)| a.spend_value == 0).map(|(i, _)| i).collect();
        plan.retain(|c| !(c.ins == 0x57 && zero.contains(&(c.p2 as usize))));
    }
    if reverse_signs {
        let first_sign = plan.iter().position(|c| matches!(c.ins, 0x55 | 0x57 | 0x59)).unwrap();
        plan[first_sign..].reverse();
    }
    let signs: Vec<String> = plan
        .iter()
        .filter(|c| matches!(c.ins, 0x55 | 0x57 | 0x59))
        .map(|c| format!("{:02x}/{}", c.ins, c.p2))
        .collect();
    println!("[{name}] plan: {} apdus, sign requests {:?}", plan.len(), signs);
    let (res, screens) = exchange(&plan);
    println!("[{name}] review screens: {:?}", screens);
    let responses = res.map_err(|(i, ins, sw)| {
        format!("device refused apdu {i} (ins {ins:#04x}) with status {sw:#06x}")
    })?;
    if reverse_signs || name.ends_with("_realonly") {
        println!("[{name}] every sign apdu answered (order reversed; finalize skipped)");
        return Ok(());
    }
    finalize_pczt_signing(pczt, &responses).map_err(|e| format!("finalize: {e}"))?;
    println!("[{name}] SIGNED + verified");
    Ok(())
}

#[test]
#[ignore = "needs SPECULOS_URL (Speculos running the Ledger Zcash app, default seed)"]
fn speculos_device_round_trips() {
    if api().is_none() {
        return;
    }
    let acct = export_account();
    let fvk = acct.ufvk.orchard().unwrap().clone();
    let fp = acct.fingerprint;

    let mut results = Vec::new();
    results.push((
        "orchard_v2 pre-NU6.3 send",
        run_case(
            "orchard_v2",
            &pczt_from(
                BranchId::Nu6_2,
                Some(bundle(BundleVersion::orchard_v2(), &fvk, fp, &[90_000])),
                None,
            ),
        ),
    ));
    results.push((
        "orchard_v3 NU6.3 spend + change (zero-value paired spend)",
        run_case(
            "orchard_v3_change_pair",
            &pczt_from(
                BranchId::Nu6_3,
                Some(bundle(BundleVersion::orchard_v3(), &fvk, fp, &[90_000])),
                None,
            ),
        ),
    ));
    results.push((
        "ironwood_v3 send",
        run_case(
            "ironwood_v3",
            &pczt_from(
                BranchId::Nu6_3,
                None,
                Some(bundle(BundleVersion::ironwood_v3(), &fvk, fp, &[90_000])),
            ),
        ),
    ));
    results.push((
        "orchard_v3 change pair, sign order reversed",
        run_case_with(
            "orchard_v3_change_pair_rev",
            &pczt_from(
                BranchId::Nu6_3,
                Some(bundle(BundleVersion::orchard_v3(), &fvk, fp, &[90_000])),
                None,
            ),
            true,
        ),
    ));
    results.push((
        "orchard_v3 change pair, real spend only (zero-value skipped)",
        run_case(
            "orchard_v3_realonly",
            &pczt_from(
                BranchId::Nu6_3,
                Some(bundle(BundleVersion::orchard_v3(), &fvk, fp, &[90_000])),
                None,
            ),
        ),
    ));
    results.push((
        "orchard_v2 send, DEFAULT padding (dummy spend)",
        run_case(
            "orchard_v2_padded",
            &pczt_from(
                BranchId::Nu6_2,
                Some(bundle_with(BundleVersion::orchard_v2(), &fvk, fp, &[90_000], true)),
                None,
            ),
        ),
    ));
    results.push((
        "ironwood_v3 send, DEFAULT padding (dummy spend)",
        run_case(
            "ironwood_v3_padded",
            &pczt_from(
                BranchId::Nu6_3,
                None,
                Some(bundle_with(BundleVersion::ironwood_v3(), &fvk, fp, &[90_000], true)),
            ),
        ),
    ));
    results.push(("transparent -> ironwood shielding", run_case("shielding", &shielding_pczt(&acct))));
    results.push((
        "transparent -> ironwood shielding, with ovk",
        run_case("shielding_ovk", &shielding_pczt_with(&acct, true, true)),
    ));
    results.push((
        "transparent -> orchard shielding (pre-NU6.3, V5)",
        run_case("shielding_orchard_v5", &shielding_pczt_with(&acct, false, false)),
    ));

    println!("\n==== Speculos device results ====");
    for (name, r) in &results {
        println!("{:<60} {}", name, match r {
            Ok(()) => "SIGNED".to_string(),
            Err(e) => format!("FAILED: {e}"),
        });
    }
    assert!(results.iter().all(|(_, r)| r.is_ok()), "see results above");
}

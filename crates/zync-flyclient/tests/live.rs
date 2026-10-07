//! A live mainnet proof, saved from zcash.rotko.net (lambda 2, tail 4, tip
//! 3,509,049): full proof-of-work verification, the wallet floors, and the
//! checkpoint derivation used to raise [`Checkpoint::mainnet`].

use primitive_types::U256;
use zync_flyclient::floor::{MAX_TIP_AGE_SECS, MAX_TIP_LEAD_SECS};
use zync_flyclient::header::bits_work;
use zync_flyclient::proto::{decode_response, Response};
use zync_flyclient::store::peaks;
use zync_flyclient::{
    verify_flyclient, verify_wallet, Anchor, Checkpoint, FlyError, FlyParams, HistoryNode, Network,
};

const FIXTURE: &str = "tests/fixtures/flyclient_3509049_lambda2_tail4.pb";
const PARAMS: FlyParams = FlyParams { lambda: 2, tail: 4 };
const TIP: u32 = 3_509_049;

fn load(path: &str) -> Response {
    let full = format!("{}/{path}", env!("CARGO_MANIFEST_DIR"));
    decode_response(&std::fs::read(&full).unwrap_or_else(|e| panic!("{full}: {e}"))).unwrap()
}

fn tip_time(r: &Response) -> u64 {
    let raw = &r.proof.epochs[0].commit_header;
    u64::from(u32::from_le_bytes(raw[100..104].try_into().unwrap()))
}

fn wallet(r: &Response, now: u64, min_height: u32) -> Result<u32, FlyError> {
    verify_wallet(
        &r.proof,
        Network::Mainnet,
        &PARAMS,
        &Checkpoint::mainnet(),
        now,
        min_height,
    )
    .map(|c| c.tip_height)
}

#[test]
fn live_proof_passes_the_wallet_floors() {
    let r = load(FIXTURE);
    assert_eq!(r.anchor_height, Anchor::nu6_3_mainnet().height);
    let now = tip_time(&r) + 60;
    assert_eq!(wallet(&r, now, TIP), Ok(TIP));
    assert_eq!(wallet(&r, now, 0), Ok(TIP));
}

#[test]
fn a_stale_or_future_tip_is_refused() {
    let r = load(FIXTURE);
    let t = tip_time(&r);
    assert!(wallet(&r, t + MAX_TIP_AGE_SECS, TIP).is_ok());
    assert!(matches!(
        wallet(&r, t + MAX_TIP_AGE_SECS + 1, TIP),
        Err(FlyError::Stale(_))
    ));
    assert!(matches!(
        wallet(&r, t - MAX_TIP_LEAD_SECS - 1, TIP),
        Err(FlyError::Stale(_))
    ));
}

#[test]
fn a_tip_below_what_the_wallet_has_seen_is_refused() {
    let r = load(FIXTURE);
    assert!(matches!(
        wallet(&r, tip_time(&r) + 60, TIP + 1),
        Err(FlyError::Stale(_))
    ));
}

#[test]
fn tampering_with_the_live_proof_is_caught() {
    let r = load(FIXTURE);
    let now = tip_time(&r) + 60;
    let mut p = r.proof.clone();
    p.epochs[0].leaves[3].header[120] ^= 1; // a nonce: Equihash fails
    assert!(verify_wallet(
        &p,
        Network::Mainnet,
        &PARAMS,
        &Checkpoint::mainnet(),
        now,
        0
    )
    .is_err());
    let mut p = r.proof.clone();
    p.epochs[0].peaks[1][40] ^= 1; // a peak: the tip no longer commits to it
    assert!(verify_wallet(
        &p,
        Network::Mainnet,
        &PARAMS,
        &Checkpoint::mainnet(),
        now,
        0
    )
    .is_err());
    let mut p = r.proof.clone();
    p.epochs[0].commit_header[104] ^= 1; // the tip's nBits
    assert!(verify_wallet(
        &p,
        Network::Mainnet,
        &PARAMS,
        &Checkpoint::mainnet(),
        now,
        0
    )
    .is_err());
}

/// Blocks a derived checkpoint stays below the tip, so a reorg cannot move it.
const CHECKPOINT_DEPTH: u32 = 1_000;

/// Prints a checkpoint for [`Checkpoint::mainnet`] from a saved proof:
/// `FLY_PROOF=proof.pb [FLY_LAMBDA=40 FLY_TAIL=16] cargo test -p zync-flyclient
/// --release --test live -- --ignored derive_checkpoint --nocapture`.
/// The proof is verified first, so every printed value is committed to by
/// proof-of-work headers. Also prints how the opened headers' work spreads
/// around `block_work`, to keep the 4x difficulty slack honest.
#[test]
#[ignore]
fn derive_checkpoint() {
    let path = std::env::var("FLY_PROOF").unwrap_or_else(|_| FIXTURE.into());
    let env = |k: &str, d: u32| std::env::var(k).map_or(d, |v| v.parse().unwrap());
    let params = FlyParams {
        lambda: env("FLY_LAMBDA", PARAMS.lambda),
        tail: env("FLY_TAIL", PARAMS.tail),
    };
    let r = if path.starts_with('/') {
        decode_response(&std::fs::read(&path).unwrap()).unwrap()
    } else {
        load(&path)
    };
    let anchor = Anchor::nu6_3_mainnet();
    let t = std::time::Instant::now();
    let chain = verify_flyclient(&r.proof, Network::Mainnet, &params, &anchor).unwrap();
    println!("verified tip {} in {:?}", chain.tip_height, t.elapsed());

    let ep = &r.proof.epochs[0];
    let v = &chain.epochs[0];
    assert_eq!(
        ep.activation, anchor.height,
        "checkpoints are for the anchor epoch"
    );
    let mut leaves = 0u64;
    let mut work = U256::zero();
    let mut picked = None;
    for (shape, bytes) in peaks(ep.n_leaves).iter().zip(&ep.peaks) {
        let node = HistoryNode::from_bytes(v.epoch.version, v.epoch.branch_id, bytes).unwrap();
        leaves += shape.leaves();
        work += node.work();
        let height = ep.activation + leaves as u32 - 1;
        if height + CHECKPOINT_DEPTH <= chain.tip_height {
            let recent = node.work() / U256::from(shape.leaves());
            picked = Some((height, work, recent, shape.leaves()));
        }
    }
    let (height, work, recent, recent_blocks) = picked.expect("a peak boundary deep enough");
    println!("checkpoint height {height}");
    println!("checkpoint work {work:#x}");
    println!("checkpoint block_work {recent:#x} (average of its last {recent_blocks} blocks)");

    let ratio = |w: U256| w.low_u128() as f64 / recent.low_u128() as f64;
    for (label, from) in [("all", 0), ("past the checkpoint", height)] {
        let ratios: Vec<f64> = v
            .checked_bits
            .iter()
            .filter(|(h, _)| *h >= from)
            .map(|(_, b)| ratio(bits_work(*b).unwrap()))
            .collect();
        let max = ratios.iter().cloned().fold(f64::MIN, f64::max);
        let min = ratios.iter().cloned().fold(f64::MAX, f64::min);
        println!(
            "header work / block_work, {label}: min {min:.3}, max {max:.3} ({} headers)",
            ratios.len()
        );
    }
}

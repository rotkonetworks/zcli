//! FlyClient tests: real mainnet headers for proof of work and epoch links,
//! `zcash_history::Tree` as the reference for the MMR, and synthetic epochs
//! for the full verifier (synthetic headers cannot carry Equihash solutions,
//! so those run without the PoW check).

use std::collections::BTreeSet;

use primitive_types::U256;
use zcash_history::{Entry, NodeData, NodeDataV2, NodeDataV3, Tree, Version, V2, V3};

use super::epochs::{epoch_activated_at, Epoch, Network};
use super::header::{bits_work, sha256d, BlockHeader, HEADER_LEN};
use super::node::{HistoryNode, NodeVersion};
use super::proof::{assemble_epoch, plan_epoch, EpochProof, FlyClientProof};
use super::sampling::FlyParams;
use super::store::HistoryStore;
use super::verify::{block_commitments, verify_flyclient_without_pow, Anchor};
use super::FlyError;

fn fixture(height: u32) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/header_{height}.hex",
        env!("CARGO_MANIFEST_DIR")
    );
    hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
}

// ---------------------------------------------------------------- headers

#[test]
fn real_headers_have_valid_pow() {
    for h in [1_687_103, 1_687_104, 3_000_000, 3_428_142, 3_428_143, 3_428_144] {
        BlockHeader::parse_and_verify(&fixture(h), h, Network::Mainnet)
            .unwrap_or_else(|e| panic!("height {h}: {e}"));
    }
}

#[test]
fn nu5_activation_header_is_the_compiled_anchor() {
    let h = BlockHeader::parse(&fixture(1_687_104)).unwrap();
    assert_eq!(h.hash, Anchor::nu5_mainnet().hash);
}

#[test]
fn nu6_3_activation_header_is_the_compiled_anchor() {
    let h = BlockHeader::parse(&fixture(3_428_143)).unwrap();
    assert_eq!(h.hash, Anchor::nu6_3_mainnet().hash);
}

#[test]
fn activation_blocks_link_to_the_previous_epoch() {
    for (last, activation) in [(1_687_103, 1_687_104), (3_428_142, 3_428_143)] {
        let prev = BlockHeader::parse(&fixture(last)).unwrap();
        let act = BlockHeader::parse(&fixture(activation)).unwrap();
        assert_eq!(act.prev_hash, prev.hash);
    }
}

#[test]
fn tampered_headers_fail_pow() {
    let mut raw = fixture(3_000_000);
    raw[120] ^= 1; // nonce
    assert_eq!(
        BlockHeader::parse_and_verify(&raw, 3_000_000, Network::Mainnet),
        Err(FlyError::Equihash(3_000_000))
    );
    let mut raw = fixture(3_000_000);
    raw[143 + 100] ^= 1; // solution
    assert!(BlockHeader::parse_and_verify(&raw, 3_000_000, Network::Mainnet).is_err());
    let mut raw = fixture(3_000_000);
    raw[100] ^= 1; // time: hash no longer matches the solution's input
    assert!(BlockHeader::parse_and_verify(&raw, 3_000_000, Network::Mainnet).is_err());
}

// ---------------------------------------------------------------- MMR shape

fn synth_v1(branch_id: u32, height: u64, i: u64) -> NodeData {
    NodeData {
        consensus_branch_id: branch_id,
        subtree_commitment: sha256d(&height.to_le_bytes()),
        start_time: 1_700_000_000 + i as u32 * 75,
        end_time: 1_700_000_000 + i as u32 * 75,
        start_target: 0x1c01_0000 + (i as u32 % 97),
        end_target: 0x1c01_0000 + (i as u32 % 97),
        start_sapling_root: [i as u8; 32],
        end_sapling_root: [i as u8; 32],
        subtree_total_work: U256::from(1000 + i % 13),
        start_height: height,
        end_height: height,
        sapling_tx: i % 3,
    }
}

fn synth_v2(branch_id: u32, height: u64, i: u64) -> NodeDataV2 {
    NodeDataV2 {
        v1: synth_v1(branch_id, height, i),
        start_orchard_root: [(i * 7) as u8; 32],
        end_orchard_root: [(i * 7) as u8; 32],
        orchard_tx: i % 5,
    }
}

fn synth_v3(branch_id: u32, height: u64, i: u64) -> NodeDataV3 {
    NodeDataV3 {
        v2: synth_v2(branch_id, height, i),
        start_ironwood_root: [(i * 11) as u8; 32],
        end_ironwood_root: [(i * 11) as u8; 32],
        ironwood_tx: i % 4,
    }
}

fn reference_root<V: Version>(leaves: Vec<V::NodeData>) -> [u8; 32] {
    let mut it = leaves.into_iter();
    let mut tree = Tree::<V>::new(1, vec![(0, Entry::new_leaf(it.next().unwrap()))], vec![]);
    for l in it {
        tree.append_leaf(l).unwrap();
    }
    V::hash(tree.root_node().unwrap().data())
}

#[test]
fn store_root_matches_zcash_history_v2_and_v3() {
    for n in 1..=130u64 {
        let mut s2 = HistoryStore::new();
        let mut s3 = HistoryStore::new();
        let mut l2 = Vec::new();
        let mut l3 = Vec::new();
        for i in 0..n {
            let h = 5_000 + i;
            l2.push(synth_v2(0xc2d6_d0b4, h, i));
            l3.push(synth_v3(0x37a5_165b, h, i));
            s2.push(HistoryNode::V2(synth_v2(0xc2d6_d0b4, h, i))).unwrap();
            s3.push(HistoryNode::V3(synth_v3(0x37a5_165b, h, i))).unwrap();
        }
        assert_eq!(s2.root().unwrap().hash(), reference_root::<V2>(l2), "V2 n={n}");
        assert_eq!(s3.root().unwrap().hash(), reference_root::<V3>(l3), "V3 n={n}");
    }
}

#[test]
fn truncate_then_regrow_gives_the_same_root() {
    let mut a = HistoryStore::new();
    for i in 0..300 {
        a.push(HistoryNode::V2(synth_v2(1, 100 + i, i))).unwrap();
    }
    let full = a.root().unwrap().hash();
    a.truncate(171);
    assert_eq!(a.len(), 171);
    for i in 171..300 {
        a.push(HistoryNode::V2(synth_v2(1, 100 + i, i))).unwrap();
    }
    assert_eq!(a.root().unwrap().hash(), full);
}

#[test]
fn combine_rejects_hostile_children_instead_of_panicking() {
    let a = HistoryNode::V2(synth_v2(1, 10, 0));
    let b = HistoryNode::V2(synth_v2(2, 11, 1));
    assert!(HistoryNode::combine(&a, &b).is_err()); // branch ids
    let c = HistoryNode::V2(synth_v2(1, 13, 3));
    assert!(HistoryNode::combine(&a, &c).is_err()); // not adjacent
    let mut big = synth_v2(1, 11, 1);
    big.v1.subtree_total_work = U256::MAX;
    let mut big0 = synth_v2(1, 10, 0);
    big0.v1.subtree_total_work = U256::MAX;
    assert!(HistoryNode::combine(&HistoryNode::V2(big0), &HistoryNode::V2(big)).is_err());
}

// ---------------------------------------------------------------- full proofs

/// A synthetic block: a 1487-byte header whose fields the leaf mirrors.
struct Block {
    header: Vec<u8>,
    hash: [u8; 32],
}

fn make_header(prev: [u8; 32], commitments: [u8; 32], time: u32, bits: u32, nonce: u64) -> Block {
    let mut h = vec![0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&4u32.to_le_bytes());
    h[4..36].copy_from_slice(&prev);
    h[68..100].copy_from_slice(&commitments);
    h[100..104].copy_from_slice(&time.to_le_bytes());
    h[104..108].copy_from_slice(&bits.to_le_bytes());
    h[108..116].copy_from_slice(&nonce.to_le_bytes());
    h[140..143].copy_from_slice(&[0xfd, 0x40, 0x05]);
    let hash = sha256d(&h);
    Block { header: h, hash }
}

fn leaf_for(epoch: &Epoch, height: u32, b: &BlockHeader, i: u64) -> HistoryNode {
    let mut v1 = synth_v1(epoch.branch_id, height as u64, i);
    v1.subtree_commitment = b.hash;
    v1.start_time = b.time;
    v1.end_time = b.time;
    v1.start_target = b.bits;
    v1.end_target = b.bits;
    v1.subtree_total_work = bits_work(b.bits).unwrap();
    match epoch.version {
        NodeVersion::V1 => HistoryNode::V1(v1),
        NodeVersion::V2 => {
            let mut v2 = synth_v2(epoch.branch_id, height as u64, i);
            v2.v1 = v1;
            HistoryNode::V2(v2)
        }
        NodeVersion::V3 => {
            let mut v3 = synth_v3(epoch.branch_id, height as u64, i);
            v3.v2.v1 = v1;
            HistoryNode::V3(v3)
        }
    }
}

/// A synthetic epoch of `n` blocks starting at its real activation height,
/// whose first block's parent is `prev`, plus its committing block.
struct SynthEpoch {
    epoch: Epoch,
    store: HistoryStore,
    headers: Vec<Vec<u8>>,
    commit: Block,
    adr: [u8; 32],
}

fn synth_epoch(activation: u32, n: u64, prev: [u8; 32], seed: u64) -> SynthEpoch {
    let epoch = epoch_activated_at(Network::Mainnet, activation).unwrap();
    let mut store = HistoryStore::new();
    let mut headers = Vec::new();
    let mut prev = prev;
    for i in 0..n {
        let height = activation + i as u32;
        // vary the target so blocks carry different work
        let bits = 0x1c00_8000 + ((i * 2_654_435_761 + seed) % 0x7000) as u32;
        let b = make_header(prev, [0u8; 32], 1_700_000_000 + i as u32 * 75, bits, i ^ seed);
        let parsed = BlockHeader::parse(&b.header).unwrap();
        store.push(leaf_for(&epoch, height, &parsed, i)).unwrap();
        prev = b.hash;
        headers.push(b.header);
    }
    let root_hash = store.root().unwrap().hash();
    let adr = [0xadu8; 32];
    let commitments = if epoch.commits_root_directly() {
        root_hash
    } else {
        block_commitments(&root_hash, &adr)
    };
    let commit = make_header(prev, commitments, 1_800_000_000, 0x1c00_9000, seed);
    SynthEpoch { epoch, store, headers, commit, adr }
}

fn prove(e: &SynthEpoch, params: &FlyParams) -> EpochProof {
    let n = e.store.len();
    let plan = plan_epoch(&e.store, n, &e.epoch, &e.commit.hash, params).unwrap();
    assemble_epoch(
        &e.store,
        n,
        &e.epoch,
        e.commit.header.clone(),
        Some(e.adr),
        &plan,
        |i| e.headers.get(i as usize).cloned(),
    )
    .unwrap()
}

/// NU6.2 (V2, full real length) then NU6.3 (V3, `tip_leaves` blocks).
fn two_epochs(tip_leaves: u64) -> (SynthEpoch, SynthEpoch) {
    let nu62 = epoch_activated_at(Network::Mainnet, 3_364_600).unwrap();
    let nu63 = epoch_activated_at(Network::Mainnet, 3_428_143).unwrap();
    let old = synth_epoch(nu62.activation, (nu63.activation - nu62.activation - 1) as u64, [9u8; 32], 1);
    let new = synth_epoch(nu63.activation, tip_leaves, old.commit.hash, 2);
    (old, new)
}

fn anchor_of(e: &SynthEpoch) -> Anchor {
    Anchor {
        height: e.epoch.activation,
        hash: BlockHeader::parse(&e.headers[0]).unwrap().hash,
    }
}

#[test]
fn two_epoch_proof_verifies_and_reports_the_tip() {
    let params = FlyParams::default();
    let (old, new) = two_epochs(777);
    let proof = FlyClientProof { epochs: vec![prove(&new, &params), prove(&old, &params)] };
    let chain = verify_flyclient_without_pow(&proof, Network::Mainnet, &params, &anchor_of(&old)).unwrap();
    assert_eq!(chain.tip_height, 3_428_143 + 777);
    assert_eq!(chain.tip_hash, new.commit.hash);
    let expected_work = bits_work(0x1c00_9000).unwrap()
        + old.store.root().unwrap().work()
        + new.store.root().unwrap().work();
    assert_eq!(chain.total_work, expected_work);
    assert_eq!(chain.tip_root().ironwood_tx(), new.store.root().unwrap().ironwood_tx());

    let bytes = bincode::serialize(&proof).unwrap();
    let opened: usize = proof.epochs.iter().map(|e| e.leaves.len()).sum();
    eprintln!("two-epoch proof: {opened} leaves opened, {} bytes", bytes.len());
}

#[test]
fn every_epoch_size_round_trips() {
    let params = FlyParams { lambda: 20, tail: 4 };
    for n in [1u64, 2, 3, 4, 5, 7, 8, 9, 31, 64, 65, 200] {
        let e = synth_epoch(3_428_143, n, [3u8; 32], n);
        let proof = FlyClientProof { epochs: vec![prove(&e, &params)] };
        verify_flyclient_without_pow(&proof, Network::Mainnet, &params, &anchor_of(&e))
            .unwrap_or_else(|err| panic!("n={n}: {err}"));
    }
}

fn single(n: u64) -> (SynthEpoch, EpochProof, FlyParams) {
    let params = FlyParams { lambda: 30, tail: 8 };
    let e = synth_epoch(3_428_143, n, [5u8; 32], 7);
    let p = prove(&e, &params);
    (e, p, params)
}

fn check(e: &SynthEpoch, p: EpochProof, params: &FlyParams) -> Result<(), FlyError> {
    verify_flyclient_without_pow(&FlyClientProof { epochs: vec![p] }, Network::Mainnet, params, &anchor_of(e))
        .map(|_| ())
}

fn sampled_index(p: &EpochProof, params: &FlyParams) -> usize {
    let required: BTreeSet<u64> = super::sampling::required_leaves(params, p.n_leaves);
    p.leaves.iter().position(|l| !required.contains(&l.index)).expect("a sampled leaf")
}

#[test]
fn dropping_a_sampled_leaf_is_caught() {
    let (e, mut p, params) = single(5000);
    let j = sampled_index(&p, &params);
    p.leaves.remove(j);
    assert!(matches!(check(&e, p, &params), Err(FlyError::Uncovered(_))));
}

#[test]
fn answering_a_sample_with_a_different_leaf_is_caught() {
    // the server picks its own block instead of the one under the work point:
    // a valid leaf with a valid path, just not the one Fiat-Shamir asked for
    let (e, mut p, params) = single(5000);
    let j = sampled_index(&p, &params);
    let opened: BTreeSet<u64> = p.leaves.iter().map(|l| l.index).collect();
    let other = (1..p.n_leaves).find(|i| !opened.contains(i)).unwrap();
    let swap = super::proof::LeafProof {
        index: other,
        header: e.headers[other as usize].clone(),
        leaf: e.store.leaf(other).unwrap().to_bytes(),
        path: e.store.path(other).unwrap().into_iter().map(|n| n.to_bytes()).collect(),
    };
    p.leaves[j] = swap;
    assert!(matches!(check(&e, p, &params), Err(FlyError::Uncovered(_))));
}

#[test]
fn relabelling_a_leaf_is_caught() {
    let (e, mut p, params) = single(5000);
    let j = sampled_index(&p, &params);
    p.leaves[j].index += 1;
    assert!(check(&e, p, &params).is_err());
}

#[test]
fn leaf_that_disagrees_with_its_header_is_caught() {
    let (e, p0, params) = single(600);
    let j = sampled_index(&p0, &params);
    let mut p = p0.clone();
    p.leaves[j].header[100] ^= 1; // time
    assert!(matches!(check(&e, p, &params), Err(FlyError::Leaf { .. })));
    let mut p = p0.clone();
    let other = (p.leaves[j].index + 1) as usize;
    p.leaves[j].header = e.headers[other].clone();
    assert!(matches!(check(&e, p, &params), Err(FlyError::Leaf { .. })));
}

#[test]
fn forged_path_or_peaks_are_caught() {
    let (e, p0, params) = single(600);
    let j = sampled_index(&p0, &params);
    let mut p = p0.clone();
    let k = p.leaves[j].path.len() - 1;
    p.leaves[j].path[k][40] ^= 1;
    assert!(check(&e, p, &params).is_err());
    let mut p = p0.clone();
    p.peaks[0][0] ^= 1;
    assert!(matches!(check(&e, p, &params), Err(FlyError::Tree(_))));
    let mut p = p0.clone();
    p.auth_data_root = Some([0u8; 32]);
    assert!(matches!(check(&e, p, &params), Err(FlyError::Tree(_))));
}

#[test]
fn missing_tail_or_first_leaf_is_caught() {
    let (e, p0, params) = single(600);
    let mut p = p0.clone();
    p.leaves.retain(|l| l.index != 0);
    assert!(matches!(check(&e, p, &params), Err(FlyError::Missing(0))));
    let mut p = p0.clone();
    p.leaves.retain(|l| l.index != 599);
    assert!(check(&e, p, &params).is_err());
}

#[test]
fn wrong_anchor_or_broken_link_is_caught() {
    let params = FlyParams { lambda: 20, tail: 4 };
    let (old, new) = two_epochs(300);
    let good = FlyClientProof { epochs: vec![prove(&new, &params), prove(&old, &params)] };

    let mut anchor = anchor_of(&old);
    anchor.hash[0] ^= 1;
    assert!(matches!(
        verify_flyclient_without_pow(&good, Network::Mainnet, &params, &anchor),
        Err(FlyError::Anchor(_))
    ));

    // an NU6.3 epoch built on a different parent does not link
    let stray = synth_epoch(3_428_143, 300, [0x77u8; 32], 2);
    let bad = FlyClientProof { epochs: vec![prove(&stray, &params), prove(&old, &params)] };
    assert!(matches!(
        verify_flyclient_without_pow(&bad, Network::Mainnet, &params, &anchor_of(&old)),
        Err(FlyError::Link(_))
    ));

    // the tip epoch alone does not reach the anchor
    let short = FlyClientProof { epochs: vec![prove(&new, &params)] };
    assert!(matches!(
        verify_flyclient_without_pow(&short, Network::Mainnet, &params, &anchor_of(&old)),
        Err(FlyError::Anchor(_))
    ));
}

#[test]
fn the_server_cannot_shrink_the_tree() {
    // claiming fewer leaves changes the root, so the committing header no
    // longer matches
    let (e, mut p, params) = single(600);
    p.n_leaves -= 1;
    assert!(check(&e, p, &params).is_err());
}

#[test]
fn proofs_over_a_prefix_match_a_tree_of_that_size() {
    // the server's store already holds the tip's own leaf; the tip commits to
    // the prefix without it
    let params = FlyParams { lambda: 20, tail: 4 };
    let e = synth_epoch(3_428_143, 300, [1u8; 32], 9);
    let mut bigger = HistoryStore::new();
    for i in 0..e.store.len() {
        bigger.push(e.store.leaf(i).unwrap().clone()).unwrap();
    }
    let extra = HistoryNode::V3(synth_v3(e.epoch.branch_id, 3_428_143 + 300, 300));
    bigger.push(extra).unwrap();
    assert_eq!(bigger.root_at(300).unwrap().hash(), e.store.root().unwrap().hash());
    let plan = plan_epoch(&bigger, 300, &e.epoch, &e.commit.hash, &params).unwrap();
    let p = assemble_epoch(&bigger, 300, &e.epoch, e.commit.header.clone(), Some(e.adr), &plan, |i| {
        e.headers.get(i as usize).cloned()
    })
    .unwrap();
    assert_eq!(p, prove(&e, &params));
    check(&e, p, &params).unwrap();
}

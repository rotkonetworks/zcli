//! FlyClient chain verification from a single zidecar.

use serde::Serialize;
use wasm_bindgen::prelude::*;
use zync_flyclient::proto::decode_response;
use zync_flyclient::{verify_burial, verify_wallet, Checkpoint, FlyParams, Network};

/// What a verified proof tells the wallet. Hashes and roots are lowercase
/// hex; see [`verify_flyclient`] for their byte order.
#[derive(Debug, Serialize)]
pub struct FlyChain {
    pub tip_height: u32,
    pub tip_hash: String,
    /// Work from the NU6.3 anchor through the tip, decimal.
    pub total_work: String,
    pub orchard_root: String,
    /// `None` before NU6.3 (no Ironwood tree).
    pub ironwood_root: Option<String>,
    /// The roots are the note commitment trees after this block.
    pub roots_height: u32,
}

/// Verify a zidecar `GetFlyClientProofResponse` (protobuf bytes, requested
/// with default `lambda`/`tail`, i.e. 0/0) for a wallet that trusts no
/// other source: full proof of work from the NU6.3 activation block, the
/// compiled checkpoint's work and difficulty floors, a tip within 90 minutes
/// of `now_secs` (unix seconds), and a tip at or above `min_height` (pass
/// the highest tip this wallet has verified, to refuse a rollback).
///
/// Returns JSON `{tip_height, tip_hash, total_work, orchard_root,
/// ironwood_root, roots_height}`:
/// - `tip_hash` is display order (byte-reversed, as explorers and
///   `TreeState.hash` print it);
/// - `orchard_root` / `ironwood_root` are the 32-byte roots in their
///   canonical encoding, the same bytes and hex as
///   `tree_root_hex(treeState.orchardTree)` /
///   `tree_root_hex_ironwood(treeState.ironwoodTree)` for the tree state at
///   `roots_height`, so a plain string compare checks a server's tree state;
/// - `roots_height` is `tip_height - 1` (the tip header commits to the tree
///   of earlier blocks), or `tip_height - d` when the request asked for
///   `burial = d` (2..=17) and the server sent one.
///
/// Mainnet only: testnet's minimum-difficulty rule admits pow-limit blocks,
/// so no floor applies there.
#[wasm_bindgen]
pub fn verify_flyclient(
    resp_proto: &[u8],
    now_secs: u64,
    min_height: u32,
    mainnet: bool,
) -> Result<String, JsError> {
    let chain = verify(
        resp_proto,
        now_secs,
        min_height,
        mainnet,
        &FlyParams::default(),
    )
    .map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&chain).map_err(|e| JsError::new(&e.to_string()))
}

pub fn verify(
    resp_proto: &[u8],
    now_secs: u64,
    min_height: u32,
    mainnet: bool,
    params: &FlyParams,
) -> Result<FlyChain, String> {
    let network = if mainnet {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    let checkpoint = Checkpoint::compiled(network)
        .ok_or("flyclient: no checkpoint for testnet, so no single-server floor")?;
    let resp = decode_response(resp_proto).map_err(|e| format!("flyclient: {e}"))?;
    if resp.anchor_height != checkpoint.anchor.height {
        return Err(format!(
            "flyclient: server anchors at {}, not {}",
            resp.anchor_height, checkpoint.anchor.height
        ));
    }
    let chain = verify_wallet(
        &resp.proof,
        network,
        params,
        &checkpoint,
        now_secs,
        min_height,
    )
    .map_err(|e| format!("flyclient: {e}"))?;
    let (root, roots_height) = match &resp.burial {
        Some(b) => {
            let buried =
                verify_burial(&resp.proof, &chain, b).map_err(|e| format!("flyclient: {e}"))?;
            (buried.root, buried.height)
        }
        None => (chain.tip_root().clone(), chain.tip_height - 1),
    };
    let orchard_root = root
        .end_orchard_root()
        .ok_or("flyclient: the tip epoch has no orchard tree")?;
    let mut tip_hash = chain.tip_hash;
    tip_hash.reverse();
    Ok(FlyChain {
        tip_height: chain.tip_height,
        tip_hash: hex::encode(tip_hash),
        total_work: chain.total_work.to_string(),
        orchard_root: hex::encode(orchard_root),
        ironwood_root: root.end_ironwood_root().map(hex::encode),
        roots_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::compute_tree_root;

    /// The live proof zync-flyclient tests (lambda 2, tail 4, tip 3,509,049)
    /// and `z_gettreestate` for block 3,509,048 from the same server.
    fn fixtures() -> (Vec<u8>, serde_json::Value) {
        let dir = env!("CARGO_MANIFEST_DIR");
        let proof = std::fs::read(format!(
            "{dir}/../zync-flyclient/tests/fixtures/flyclient_3509049_lambda2_tail4.pb"
        ))
        .unwrap();
        let state: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/tests/fixtures/treestate_3509048.json"))
                .unwrap(),
        )
        .unwrap();
        (proof, state)
    }

    const PARAMS: FlyParams = FlyParams { lambda: 2, tail: 4 };

    fn tip_time(proof: &[u8]) -> u64 {
        let r = decode_response(proof).unwrap();
        let h = &r.proof.epochs[0].commit_header;
        u64::from(u32::from_le_bytes(h[100..104].try_into().unwrap()))
    }

    #[test]
    fn roots_match_tree_root_hex_of_the_servers_tree_state() {
        let (proof, state) = fixtures();
        let now = tip_time(&proof) + 60;
        let chain = verify(&proof, now, 3_509_049, true, &PARAMS).unwrap();
        assert_eq!(chain.tip_height, 3_509_049);
        assert_eq!(chain.roots_height, 3_509_048);
        assert_eq!(state["height"], 3_509_048);

        let root = |k: &str| {
            let frontier = hex::decode(state[k].as_str().unwrap()).unwrap();
            hex::encode(compute_tree_root(&frontier).unwrap())
        };
        // the strings zafu already gets from tree_root_hex / _ironwood
        assert_eq!(chain.orchard_root, root("orchardTree"));
        assert_eq!(
            chain.ironwood_root.as_deref(),
            Some(root("ironwoodTree").as_str())
        );

        // tip_hash is display order: the tip's parent, printed the same way,
        // is the tree state's block hash
        let r = decode_response(&proof).unwrap();
        let mut parent = r.proof.epochs[0].commit_header[4..36].to_vec();
        parent.reverse();
        assert_eq!(hex::encode(parent), state["hash"].as_str().unwrap());
        assert!(chain.tip_hash.starts_with("0000000"));

        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&chain).unwrap()).unwrap();
        for k in [
            "tip_height",
            "tip_hash",
            "total_work",
            "orchard_root",
            "ironwood_root",
            "roots_height",
        ] {
            assert!(json.get(k).is_some(), "{k}");
        }
    }

    #[test]
    fn stale_rolled_back_testnet_or_garbage_is_refused() {
        let (proof, _) = fixtures();
        let now = tip_time(&proof) + 60;
        assert!(verify(&proof, now + 90 * 60, 0, true, &PARAMS).is_err());
        assert!(verify(&proof, now, 3_509_050, true, &PARAMS).is_err());
        assert!(verify(&proof, now, 0, false, &PARAMS).is_err());
        assert!(verify(&proof[..proof.len() / 2], now, 0, true, &PARAMS).is_err());
        // the wrong parameters open the wrong blocks
        assert!(verify(&proof, now, 0, true, &FlyParams::default()).is_err());
    }
}

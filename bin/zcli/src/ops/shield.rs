use crate::address;
use crate::client::ZidecarClient;
use crate::error::Error;
use crate::key::WalletSeed;
use crate::tx;

const MARGINAL_FEE: u64 = 5_000;
const GRACE_ACTIONS: u64 = 2;
const MIN_ORCHARD_ACTIONS: u64 = 2;

/// Serialized size of one P2PKH `tx_in`: 32 (txid) + 4 (index) + 1 (script len)
/// + 107 (script_sig) + 4 (sequence).
const P2PKH_TX_IN_SIZE: u64 = 148;
/// ZIP-317 divides the transparent byte total by this to get logical actions.
const ZIP317_TX_BYTES_PER_ACTION: u64 = 150;

/// ZIP-317 transparent-side logical actions for `n` P2PKH inputs:
/// `ceil(tx_in_total_size / 150)`.
///
/// NOT `n`: `ceil(148n/150) == n` only while `2n < 150`. At `n == 75` the byte
/// total is exactly `11_100 == 74 * 150`, so the count is 74, and it stays below
/// `n` from there on. Treating it as `n` overpaid one marginal fee per ~75
/// inputs - harmless to consensus (nodes only reject UNDER-payment) but a wallet
/// fingerprint on every large consolidation. Kept numerically identical to
/// `zafu_wasm::zip317_transparent_actions` and to the extension's worker.
fn zip317_transparent_actions(n_t_inputs: usize) -> u64 {
    (n_t_inputs as u64 * P2PKH_TX_IN_SIZE).div_ceil(ZIP317_TX_BYTES_PER_ACTION)
}

/// ZIP-317 fee for shielding: 0 spends, 1 output (padded to MIN=2), plus the
/// transparent input side (see [`zip317_transparent_actions`]).
fn compute_shield_fee(n_t_inputs: usize) -> u64 {
    let logical_actions = MIN_ORCHARD_ACTIONS + zip317_transparent_actions(n_t_inputs);
    MARGINAL_FEE * logical_actions.max(GRACE_ACTIONS)
}


pub async fn shield(
    seed: &WalletSeed,
    endpoint: &str,
    fee_override: Option<u64>,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    let taddr = address::transparent_address(seed, mainnet)?;

    let client = ZidecarClient::connect(endpoint).await?;

    // fetch UTXOs
    let utxos = client.get_address_utxos(vec![taddr.clone()]).await?;
    if utxos.is_empty() {
        return Err(Error::Transaction("no transparent UTXOs to shield".into()));
    }

    let fee = fee_override.unwrap_or_else(|| compute_shield_fee(utxos.len()));
    let total: u64 = utxos.iter().map(|u| u.value_zat).sum();
    if total <= fee {
        return Err(Error::InsufficientFunds {
            have: total,
            need: fee,
        });
    }

    // get current tip for expiry
    let (tip, _) = client.get_tip().await?;
    // consensus branch id from the LIVE chain (auto-tracks network upgrades)
    let branch_id = client.resolve_branch_id().await?;

    // convert to tx builder format
    let tx_utxos: Vec<tx::TransparentUtxo> = utxos
        .iter()
        .map(|u| tx::TransparentUtxo {
            txid: hex::encode(u.txid),
            vout: u.output_index,
            value: u.value_zat,
            script: hex::encode(&u.script),
        })
        .collect();

    // recipient is our own orchard address
    let recipient = tx::self_shielding_address(seed, mainnet)?;

    if !json {
        eprintln!(
            "shielding {:.8} ZEC ({} UTXOs, fee {:.8} ZEC)",
            (total - fee) as f64 / 1e8,
            tx_utxos.len(),
            fee as f64 / 1e8,
        );
        eprintln!("building transaction (halo 2 proving, this takes a moment)...");
    }

    let tx_bytes = tx::build_shielding_tx(seed, &tx_utxos, &recipient, fee, tip, branch_id, mainnet)?;

    // broadcast
    let result = client.send_transaction(tx_bytes).await?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "txid": result.txid,
                "shielded_zat": total - fee,
                "fee_zat": fee,
                "success": result.is_success(),
                "error": result.error_message,
            })
        );
    } else if result.is_success() {
        println!("txid: {}", result.txid);
    } else {
        return Err(Error::Transaction(format!(
            "broadcast failed ({}): {}",
            result.error_code, result.error_message
        )));
    }

    Ok(())
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    #[test]
    fn shield_fee_uses_ceil_148n_over_150_not_the_input_count() {
        assert_eq!(compute_shield_fee(0), 10_000);
        assert_eq!(compute_shield_fee(1), 15_000);
        assert_eq!(compute_shield_fee(2), 20_000);
        assert_eq!(compute_shield_fee(10), 60_000);
        // 148 * 74 = 10_952 -> 74 actions; 148 * 75 = 11_100 = 74 * 150 -> also
        // 74 actions. Both price 76 logical actions, not 76 and 77.
        assert_eq!(zip317_transparent_actions(74), 74);
        assert_eq!(zip317_transparent_actions(75), 74);
        assert_eq!(compute_shield_fee(74), 380_000);
        assert_eq!(compute_shield_fee(75), 380_000);
        assert_eq!(compute_shield_fee(76), 385_000);
    }
}

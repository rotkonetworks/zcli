//! `zcli tx send` — spending IRONWOOD notes.
//!
//! Past NU6.3 orchard OUTPUTS are consensus-disabled, so the orchard send path
//! (which pinned the pre-NU6.2 orchard bundle protocol) cannot produce a valid
//! transaction at all. Rather than keep a second, unreachable spend path with
//! its own note selection, fee arithmetic and broadcast handling, `send` routes
//! unconditionally to [`crate::ops::send_ironwood`]; `zcli tx migrate` is what
//! moves value through the one-way turnstile into the pool that path spends.
//!
//! [`select_notes`] and [`compute_fee`] stay: the orchard-spending services
//! (`bridge`, `merchant`, `airgap`) still use them.

use crate::error::Error;
use crate::key::WalletSeed;

const MARGINAL_FEE: u64 = 5_000;
const GRACE_ACTIONS: usize = 2;
const MIN_ORCHARD_ACTIONS: usize = 2;

/// ZIP-317 fee computation
pub fn compute_fee(
    n_spends: usize,
    n_z_outputs: usize,
    n_t_outputs: usize,
    has_change: bool,
) -> u64 {
    let n_orchard_outputs = n_z_outputs + if has_change { 1 } else { 0 };
    let n_orchard_actions = n_spends.max(n_orchard_outputs).max(MIN_ORCHARD_ACTIONS);
    let n_t_logical = n_t_outputs; // no transparent inputs in orchard spends
    let logical_actions = n_orchard_actions + n_t_logical;
    MARGINAL_FEE * logical_actions.max(GRACE_ACTIONS) as u64
}

#[allow(clippy::too_many_arguments)]
pub async fn send(
    seed: &WalletSeed,
    amount_str: &str,
    recipient: &str,
    memo: Option<&str>,
    endpoint: &str,
    dry_run: bool,
    fee_override: Option<u64>,
    mainnet: bool,
    json: bool,
) -> Result<(), Error> {
    // Unconditional: ironwood is the only spendable pool. The NU6.3 branch
    // check that used to gate this routing lives in `send_ironwood`, which
    // fails closed by name before spending minutes on Halo 2 proving.
    let amount_zat = parse_amount(amount_str)?;
    crate::ops::send_ironwood::send_ironwood(
        seed,
        amount_zat,
        recipient,
        memo,
        endpoint,
        fee_override,
        dry_run,
        mainnet,
        json,
    )
    .await
}

/// select notes covering target amount (largest first)
pub(crate) fn select_notes(
    notes: &[crate::wallet::WalletNote],
    target: u64,
) -> Result<Vec<crate::wallet::WalletNote>, Error> {
    // This selector serves the orchard-spending paths (bridge, merchant,
    // airgap), so only orchard notes are candidates here. Ironwood value still
    // shows in the balance, so surface the gap explicitly when funds fall
    // short, naming the command that does spend it.
    let ironwood_zat: u64 = notes
        .iter()
        .filter(|n| n.pool == crate::wallet::Pool::Ironwood)
        .map(|n| n.value)
        .sum();
    let mut sorted: Vec<_> = notes
        .iter()
        .filter(|n| n.pool == crate::wallet::Pool::Orchard)
        .cloned()
        .collect();
    // sort by value descending, then by position descending (prefer recent notes
    // to minimize merkle witness replay distance from stale checkpoints)
    sorted.sort_by(|a, b| b.value.cmp(&a.value).then(b.position.cmp(&a.position)));

    let mut selected = Vec::new();
    let mut total = 0u64;
    for note in sorted {
        total += note.value;
        selected.push(note);
        if total >= target {
            return Ok(selected);
        }
    }

    if ironwood_zat > 0 {
        eprintln!(
            "note: {:.8} ZEC held in ironwood notes is not spendable from this \
             path (it spends orchard notes); use `zcli tx send` to spend \
             ironwood value",
            ironwood_zat as f64 / 100_000_000.0
        );
    }
    Err(Error::InsufficientFunds {
        have: total,
        need: target,
    })
}

pub fn parse_amount(s: &str) -> Result<u64, Error> {
    // accept both ZEC (decimal) and zatoshi (integer)
    if s.contains('.') {
        let zec: f64 = s
            .parse()
            .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))?;
        if zec < 0.0 {
            return Err(Error::Transaction("amount must be positive".into()));
        }
        Ok((zec * 1e8).round() as u64)
    } else {
        let zat: u64 = s
            .parse()
            .map_err(|_| Error::Transaction(format!("invalid amount: {}", s)))?;
        Ok(zat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zec_amount() {
        assert_eq!(parse_amount("0.001").unwrap(), 100_000);
        assert_eq!(parse_amount("1.0").unwrap(), 100_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
    }

    #[test]
    fn parse_zatoshi_amount() {
        assert_eq!(parse_amount("100000").unwrap(), 100_000);
        assert_eq!(parse_amount("1").unwrap(), 1);
    }

    fn note(value: u64, pool: crate::wallet::Pool) -> crate::wallet::WalletNote {
        crate::wallet::WalletNote {
            value,
            nullifier: [0u8; 32],
            cmx: [0u8; 32],
            block_height: 0,
            is_change: false,
            recipient: vec![],
            rho: [0u8; 32],
            rseed: [0u8; 32],
            position: 0,
            txid: vec![],
            memo: None,
            pool,
        }
    }

    /// ironwood notes are never selected by the ORCHARD selector — they are
    /// spent by `send_ironwood`, not by the orchard-spending services — even
    /// when they would cover the target.
    #[test]
    fn select_notes_skips_ironwood() {
        use crate::wallet::Pool;
        let notes = vec![note(50_000, Pool::Orchard), note(1_000_000, Pool::Ironwood)];

        // orchard alone covers a small target
        let sel = select_notes(&notes, 40_000).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].pool, Pool::Orchard);

        // ironwood value must not count toward spendable funds
        let err = select_notes(&notes, 500_000).unwrap_err();
        match err {
            Error::InsufficientFunds { have, need } => {
                assert_eq!(have, 50_000);
                assert_eq!(need, 500_000);
            }
            other => panic!("expected InsufficientFunds, got {:?}", other),
        }
    }

    /// notes stored before ironwood support (no `pool` field in JSON)
    /// deserialize as orchard and stay spendable.
    #[test]
    fn wallet_note_pool_default_is_orchard() {
        let zeros = vec![0u8; 32];
        let legacy_json = serde_json::json!({
            "value": 123u64,
            "nullifier": zeros,
            "cmx": zeros,
            "block_height": 1u32,
            "is_change": false,
            "recipient": [],
            "rho": zeros,
            "rseed": zeros,
            "position": 7u64,
        });
        let note: crate::wallet::WalletNote = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(note.pool, crate::wallet::Pool::Orchard);
        assert!(select_notes(&[note], 100).is_ok());
    }
}

//! Deposit memo + wallet-command construction for the paid path.
//!
//! To fund a seat the operator's wallet sends the required deposit to the escrow's
//! diversified deposit UA with a memo that (a) pins the seat's PERSONAL payout
//! address and (b) pins the seat's session identity pubkey. The escrow scanner
//! (`poker-escrow::scanner::parse_payout_memo`) recovers both from the memo:
//!   memo = "zk.poker/v1/payout:{ua};id:{hex}"
//! The `;id:{hex}` binding is what lets the escrow require a settlement signature
//! from exactly the key that funded the seat — the operator can't substitute its
//! own. The `{hex}` MUST equal `identity.pubkey_hex()` and the `sessionPub`
//! announced in `seated`.
//!
//! The bot only BUILDS the memo + wallet argv; live deposits are operator-run
//! (see MEMORY: "agent-does-NOT-broadcast-txs"). The returned argv is never
//! executed here.

use crate::srv::ServerMsg;

/// zatoshi per ZEC.
const ZAT_PER_ZEC: u64 = 100_000_000;

/// The deposit memo binding the seat's payout address + identity pubkey.
/// Exactly `zk.poker/v1/payout:{ua};id:{hex}` — the format the escrow scanner parses.
pub fn deposit_memo(my_payout_ua: &str, my_identity_pubkey_hex: &str) -> String {
    format!("zk.poker/v1/payout:{my_payout_ua};id:{my_identity_pubkey_hex}")
}

/// Format a zatoshi amount as the ZEC decimal string `zcli send` expects (e.g.
/// 100_000 zat → "0.001"). `zcli send` takes the amount in ZEC as its FIRST
/// positional arg (see `bin/zcli/src/cli.rs` `Send { amount: String, .. }`), NOT
/// in zatoshi — so escrow-side zatoshi amounts must be converted here. Trailing
/// zeros are trimmed; a whole number keeps no decimal point.
pub fn zat_to_zec_string(zat: u64) -> String {
    let whole = zat / ZAT_PER_ZEC;
    let frac = zat % ZAT_PER_ZEC;
    if frac == 0 {
        return whole.to_string();
    }
    // 8 fractional digits, trailing zeros trimmed.
    let frac_str = format!("{frac:08}");
    let frac_trimmed = frac_str.trim_end_matches('0');
    format!("{whole}.{frac_trimmed}")
}

/// Build (do NOT execute) the argv for the operator's wallet to fund a seat:
///   `zcli transaction send <amount_zec> <escrow_ua> --memo <memo>`
/// matching the installed `zcli`'s command tree: `send` is a subcommand of
/// `transaction` (alias `tx`), NOT top-level — `Usage: zcli transaction send
/// [OPTIONS] <AMOUNT> <RECIPIENT>`, AMOUNT is the ZEC decimal string, RECIPIENT is
/// the positional UA. `zcli_bin` is argv[0] (path to the zcli binary). The caller
/// (operator) runs this later.
pub fn deposit_command(zcli_bin: &str, escrow_ua: &str, amount_zat: u64, memo: &str) -> Vec<String> {
    vec![
        zcli_bin.to_string(),
        "transaction".to_string(),
        "send".to_string(),
        zat_to_zec_string(amount_zat),
        escrow_ua.to_string(),
        "--memo".to_string(),
        memo.to_string(),
    ]
}

/// Extract the `(escrow, required_deposit)` from a `RoomInfo` if it is present.
/// Returns `None` for any other ServerMsg. Convenience for the paid-path driver.
pub fn parse_room_info(msg: &ServerMsg) -> Option<(String, u64)> {
    match msg {
        ServerMsg::RoomInfo { escrow, required_deposit, .. } => {
            Some((escrow.clone(), *required_deposit))
        }
        _ => None,
    }
}

/// The deposit gate: true once the escrow reports both seats' CONFIRMED deposits
/// meet the requirement. Mirrors the escrow's `ready` flag (which is gated on
/// confirmed — never mempool-pending — totals), so the bot only starts a hand when
/// the money is actually escrowed.
pub fn gate_ready(status: &ServerMsg) -> bool {
    match status {
        ServerMsg::DepositStatus { ready, player_a_deposit, player_b_deposit, required, .. } => {
            // trust the escrow's `ready`, but also require both confirmed totals to
            // meet `required` as a belt-and-braces local check.
            *ready && *player_a_deposit >= *required && *player_b_deposit >= *required
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deposit_memo_exact_string() {
        let pk = "ab".repeat(32); // 64 hex chars
        let memo = deposit_memo("u1exampleaddressxxxxxxxx", &pk);
        assert_eq!(
            memo,
            format!("zk.poker/v1/payout:u1exampleaddressxxxxxxxx;id:{pk}"),
        );
        // sanity: prefix + separator exactly as the escrow scanner expects.
        assert!(memo.starts_with("zk.poker/v1/payout:"));
        assert!(memo.contains(";id:"));
    }

    #[test]
    fn zat_to_zec_conversion() {
        assert_eq!(zat_to_zec_string(100_000), "0.001"); // typical buy-in fraction
        assert_eq!(zat_to_zec_string(100_000_000), "1"); // 1 ZEC, no decimal
        assert_eq!(zat_to_zec_string(110_000), "0.0011");
        assert_eq!(zat_to_zec_string(1), "0.00000001"); // 1 zatoshi
        assert_eq!(zat_to_zec_string(0), "0");
        assert_eq!(zat_to_zec_string(150_000_000), "1.5");
    }

    #[test]
    fn deposit_command_argv() {
        let argv = deposit_command("zcli", "u1escrowaddr", 100_000, "zk.poker/v1/payout:u1p;id:abcd");
        assert_eq!(
            argv,
            vec![
                "zcli".to_string(),
                "transaction".to_string(),
                "send".to_string(),
                "0.001".to_string(),
                "u1escrowaddr".to_string(),
                "--memo".to_string(),
                "zk.poker/v1/payout:u1p;id:abcd".to_string(),
            ],
        );
    }

    #[test]
    fn parse_room_info_and_gate() {
        let ri: ServerMsg = serde_json::from_value(json!({
            "type": "RoomInfo", "code": "R", "escrow": "u1esc", "required_deposit": 110_000,
        })).unwrap();
        assert_eq!(parse_room_info(&ri), Some(("u1esc".to_string(), 110_000)));

        let not_ready: ServerMsg = serde_json::from_value(json!({
            "type": "DepositStatus", "escrow_address": "u1esc",
            "player_a_deposit": 100_000, "player_b_deposit": 0,
            "required": 110_000, "ready": false,
        })).unwrap();
        assert!(!gate_ready(&not_ready));

        let ready: ServerMsg = serde_json::from_value(json!({
            "type": "DepositStatus", "escrow_address": "u1esc",
            "player_a_deposit": 110_000, "player_b_deposit": 110_000,
            "required": 110_000, "ready": true,
        })).unwrap();
        assert!(gate_ready(&ready));

        // a RoomInfo is not a deposit gate.
        assert!(!gate_ready(&ri));
        assert_eq!(parse_room_info(&ready), None);
    }
}

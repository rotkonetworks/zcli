//! `srv` escrow-bridge messages — the relay's server/escrow control channel.
//!
//! Unlike peer game messages (which ride inside `msg.text` as an E2EE `_enc`
//! envelope), these are TOP-LEVEL relay frames the relay/escrow itself reads:
//!   - the bot SENDS   `{"t":"srv","msg":<ClientMsg>}`  (NOT encrypted, NOT peer-routed)
//!   - the bot RECEIVES `{"t":"srv","msg":<ServerMsg>}` (server-originated, staked tables)
//!
//! Both `ClientMsg` and `ServerMsg` are internally tagged with `"type"` — matching
//! the browser `types.ts` and poker-server `main.rs` enums byte-for-byte. This is
//! the message plumbing for the live paid path (deposits, settlement submission,
//! payout signing requests); the co-sign itself lives in `settle.rs`.
//!
//! There are MANY game-flow ServerMsg variants the bot ignores (HandStarted,
//! ActionRequired, …). Rather than model them all, `parse_server_msg` decodes into
//! a `serde_json::Value` first and only matches the variants the bot acts on;
//! everything else becomes `ServerMsg::Other` so an unknown frame never crashes
//! deserialization.

use serde::{Deserialize, Serialize};

/// Messages the bot SENDS to the server/escrow bridge (`{"t":"srv","msg":<this>}`).
/// Internally tagged with `type`, matching poker-server `ClientMsg`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMsg {
    /// Announce this seat, optionally pinning the session identity pubkey and the
    /// personal payout Zcash address the escrow should recover / verify against.
    Join {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pubkey: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        zcash_address: Option<String>,
    },
    /// Report this seat's on-chain deposit to the escrow (txid + zatoshi amount).
    ReportDeposit { txid: String, amount: u64 },
    /// This seat's half of the co-signed final outcome. Field names/order mirror
    /// `settle::Settlement` and the escrow's `SettleReq` exactly.
    Settlement {
        a_stack: u64,
        b_stack: u64,
        a_addr: String,
        b_addr: String,
        log_hash: String,
        sig: String,
    },
    /// Leave the table — triggers the escrow's payout/refund path.
    Leave,
    /// This seat's view of the escrow UA + Orchard FVK after the FROST DKG completes.
    DkgComplete { escrow_ua: String, orchard_fvk: String },
    /// Client-detected escrow fault → escrow's durable journal.
    EscrowFault { phase: String, detail: String },
}

/// One line of an escrow-computed payout plan (recipient UA + zatoshi amount).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutLine {
    pub seat: u8,
    pub address: String,
    pub amount_zat: u64,
}

/// Messages the bot RECEIVES from the server/escrow bridge (`{"t":"srv","msg":<this>}`).
/// Only the variants the bot acts on are modelled; every other server frame parses as
/// `Other` (see `parse_server_msg`). Optional/absent fields use `#[serde(default)]` so
/// a frame missing a field still parses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMsg {
    /// Table class + escrow coords. `staked == true` (or FROST coords present) means
    /// real money; the bot only surfaces deposit UX then.
    RoomInfo {
        code: String,
        escrow: String,
        #[serde(default)]
        required_deposit: u64,
        #[serde(default)]
        buyin_zat: u64,
        #[serde(default)]
        fee_per_seat: u64,
        #[serde(default)]
        staked: bool,
        #[serde(default)]
        seat_addresses: Vec<Option<String>>,
        #[serde(default)]
        frost_relay_url: Option<String>,
        #[serde(default)]
        frost_room_code: Option<String>,
        #[serde(default)]
        jury_nodes: u8,
        #[serde(default)]
        jury_threshold: u8,
    },
    /// Deposit-gating state, broadcast on change by the escrow-poll loop. `ready`
    /// flips true once both confirmed deposits meet `required`.
    DepositStatus {
        #[serde(default)]
        escrow_address: String,
        #[serde(default)]
        seat_addresses: Vec<Option<String>>,
        #[serde(default)]
        seat_payout_addresses: Vec<Option<String>>,
        #[serde(default)]
        player_a_deposit: u64,
        #[serde(default)]
        player_b_deposit: u64,
        #[serde(default)]
        player_a_pending: u64,
        #[serde(default)]
        player_b_pending: u64,
        #[serde(default)]
        required: u64,
        #[serde(default)]
        ready: bool,
    },
    /// FROST relay coords + payout plan + priority signer. The priority seat runs
    /// `join_sign_pczt` against the relay room (see `payout.rs`).
    PayoutSigningRequest {
        relay_room: String,
        #[serde(default)]
        plan: Vec<PayoutLine>,
        #[serde(default)]
        priority_seat: u8,
        #[serde(default)]
        fallback_secs_remaining: u64,
    },
    /// Final payout tx is on chain.
    PayoutComplete { txid: String },
    /// Payout never completed.
    PayoutFailed { reason: String },
    /// Game over — settlement complete, per-seat payouts.
    GameOver {
        reason: String,
        #[serde(default)]
        payouts: Vec<(u8, u64)>,
    },
    /// Server error frame.
    Error { message: String },
    /// Catch-all for the many game-flow variants the bot ignores. Never emitted by
    /// the bot; produced by `parse_server_msg` for any unmatched frame.
    #[serde(other)]
    Other,
}

/// Decode a server-originated `srv.msg` payload, matching ONLY the variants the bot
/// acts on and mapping everything else to `ServerMsg::Other`. Decoding via `Value`
/// first (rather than straight `from_value`) means an unknown/extra field or a
/// game-flow variant we don't model can never error out the demux loop.
pub fn parse_server_msg(v: &serde_json::Value) -> ServerMsg {
    serde_json::from_value(v.clone()).unwrap_or(ServerMsg::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Round-trip a ClientMsg through JSON and confirm the tag + fields.
    fn client_tag(m: &ClientMsg) -> String {
        serde_json::to_value(m).unwrap()["type"].as_str().unwrap().to_string()
    }

    #[test]
    fn client_join_serde() {
        let m = ClientMsg::Join {
            name: "p1".into(),
            pubkey: Some("aa".repeat(32)),
            zcash_address: Some("u1abc".into()),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["type"], "Join");
        assert_eq!(v["name"], "p1");
        assert_eq!(v["zcash_address"], "u1abc");
        let back: ClientMsg = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
        // absent optionals: `Join` with just a name must still parse.
        let bare: ClientMsg = serde_json::from_value(json!({"type":"Join","name":"anon"})).unwrap();
        assert_eq!(bare, ClientMsg::Join { name: "anon".into(), pubkey: None, zcash_address: None });
    }

    #[test]
    fn client_report_deposit_serde() {
        let m = ClientMsg::ReportDeposit { txid: "deadbeef".into(), amount: 100_000 };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["type"], "ReportDeposit");
        assert_eq!(v["amount"], 100_000);
        assert_eq!(serde_json::from_value::<ClientMsg>(v).unwrap(), m);
    }

    #[test]
    fn client_settlement_serde() {
        let m = ClientMsg::Settlement {
            a_stack: 1500, b_stack: 500,
            a_addr: "u1a".into(), b_addr: "u1b".into(),
            log_hash: "abcd".into(), sig: "ff".repeat(64),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["type"], "Settlement");
        assert_eq!(v["a_stack"], 1500);
        assert_eq!(v["b_addr"], "u1b");
        assert_eq!(serde_json::from_value::<ClientMsg>(v).unwrap(), m);
    }

    #[test]
    fn client_leave_dkg_fault_serde() {
        assert_eq!(client_tag(&ClientMsg::Leave), "Leave");
        let dkg = ClientMsg::DkgComplete { escrow_ua: "u1esc".into(), orchard_fvk: "fvk".into() };
        let v = serde_json::to_value(&dkg).unwrap();
        assert_eq!(v["type"], "DkgComplete");
        assert_eq!(serde_json::from_value::<ClientMsg>(v).unwrap(), dkg);
        let fault = ClientMsg::EscrowFault { phase: "deposit".into(), detail: "x".into() };
        let v = serde_json::to_value(&fault).unwrap();
        assert_eq!(v["type"], "EscrowFault");
        assert_eq!(serde_json::from_value::<ClientMsg>(v).unwrap(), fault);
    }

    #[test]
    fn server_room_info_serde_full_and_sparse() {
        // full frame (as poker-server emits it).
        let v = json!({
            "type": "RoomInfo", "code": "R", "escrow": "u1esc",
            "required_deposit": 110_000, "buyin_zat": 100_000, "fee_per_seat": 10_000,
            "staked": true,
            "seat_addresses": ["u1s0", null],
            "frost_relay_url": "wss://frost", "frost_room_code": "fr",
            "jury_nodes": 5, "jury_threshold": 3,
        });
        match parse_server_msg(&v) {
            ServerMsg::RoomInfo { code, escrow, required_deposit, buyin_zat, staked, seat_addresses, frost_room_code, jury_threshold, .. } => {
                assert_eq!(code, "R");
                assert_eq!(escrow, "u1esc");
                assert_eq!(required_deposit, 110_000);
                assert_eq!(buyin_zat, 100_000);
                assert!(staked);
                assert_eq!(seat_addresses, vec![Some("u1s0".into()), None]);
                assert_eq!(frost_room_code.as_deref(), Some("fr"));
                assert_eq!(jury_threshold, 3);
            }
            other => panic!("expected RoomInfo, got {other:?}"),
        }
        // sparse frame (older escrow omits many fields) must still parse via defaults.
        let sparse = json!({ "type": "RoomInfo", "code": "R2", "escrow": "" });
        match parse_server_msg(&sparse) {
            ServerMsg::RoomInfo { required_deposit, staked, seat_addresses, .. } => {
                assert_eq!(required_deposit, 0);
                assert!(!staked);
                assert!(seat_addresses.is_empty());
            }
            other => panic!("expected RoomInfo, got {other:?}"),
        }
    }

    #[test]
    fn server_deposit_status_serde() {
        let v = json!({
            "type": "DepositStatus", "escrow_address": "u1esc",
            "seat_addresses": ["u1s0", "u1s1"],
            "seat_payout_addresses": ["u1p0", null],
            "player_a_deposit": 100_000, "player_b_deposit": 50_000,
            "player_a_pending": 0, "player_b_pending": 25_000,
            "required": 110_000, "ready": false,
        });
        match parse_server_msg(&v) {
            ServerMsg::DepositStatus { escrow_address, seat_payout_addresses, player_a_deposit, required, ready, .. } => {
                assert_eq!(escrow_address, "u1esc");
                assert_eq!(seat_payout_addresses, vec![Some("u1p0".into()), None]);
                assert_eq!(player_a_deposit, 100_000);
                assert_eq!(required, 110_000);
                assert!(!ready);
            }
            other => panic!("expected DepositStatus, got {other:?}"),
        }
    }

    #[test]
    fn server_payout_signing_request_serde() {
        let v = json!({
            "type": "PayoutSigningRequest", "relay_room": "fr42",
            "plan": [{"seat":0,"address":"u1w","amount_zat":190_000}],
            "priority_seat": 0, "fallback_secs_remaining": 90,
        });
        match parse_server_msg(&v) {
            ServerMsg::PayoutSigningRequest { relay_room, plan, priority_seat, fallback_secs_remaining } => {
                assert_eq!(relay_room, "fr42");
                assert_eq!(plan, vec![PayoutLine { seat: 0, address: "u1w".into(), amount_zat: 190_000 }]);
                assert_eq!(priority_seat, 0);
                assert_eq!(fallback_secs_remaining, 90);
            }
            other => panic!("expected PayoutSigningRequest, got {other:?}"),
        }
    }

    #[test]
    fn server_payout_complete_failed_gameover_error_serde() {
        assert!(matches!(parse_server_msg(&json!({"type":"PayoutComplete","txid":"tx1"})),
            ServerMsg::PayoutComplete { txid } if txid == "tx1"));
        assert!(matches!(parse_server_msg(&json!({"type":"PayoutFailed","reason":"nope"})),
            ServerMsg::PayoutFailed { reason } if reason == "nope"));
        match parse_server_msg(&json!({"type":"GameOver","reason":"fold","payouts":[[0,190000]]})) {
            ServerMsg::GameOver { reason, payouts } => {
                assert_eq!(reason, "fold");
                assert_eq!(payouts, vec![(0u8, 190_000u64)]);
            }
            other => panic!("expected GameOver, got {other:?}"),
        }
        assert!(matches!(parse_server_msg(&json!({"type":"Error","message":"boom"})),
            ServerMsg::Error { message } if message == "boom"));
    }

    #[test]
    fn server_unknown_variant_is_other_not_error() {
        // a game-flow frame the bot doesn't model must NOT crash the demux.
        let v = json!({ "type": "HandStarted", "hand_number": 3, "button": 0, "stacks": [1000, 1000] });
        assert_eq!(parse_server_msg(&v), ServerMsg::Other);
        // even a totally unknown type parses as Other.
        assert_eq!(parse_server_msg(&json!({ "type": "FutureThing", "x": 1 })), ServerMsg::Other);
    }
}

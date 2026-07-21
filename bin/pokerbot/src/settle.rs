//! Settlement co-sign — THE core money invariant.
//!
//! This is the exact algorithm the browser `game.ts::sendSettlement` and the
//! escrow `poker-escrow::settlement_message` / `verify_settlement_sig` implement.
//! It is what guards the original refund bug: the two engines MUST produce the
//! byte-identical settlement message so their two Ed25519 co-signs verify against
//! the SAME message. If the engines fork (different final stacks, or a format
//! drift), the escrow can't get a matching co-signed pair and refunds instead of
//! paying the winner. Here we reconstruct + verify offline over many hands.
//!
//! Byte format (must match browser + escrow EXACTLY):
//! ```text
//!   log_hash            = hex( SHA256( "zk.poker/log/v1:{code}:{a_stack}:{b_stack}:{a_addr}:{b_addr}" ) )
//!   settlement_message  = "zk.poker/settle/v1:{code}:{a_stack}:{b_stack}:{a_addr}:{b_addr}:{log_hash}"
//!   sig                 = ed25519_sign(identity, settlement_message.as_bytes())   // 128 hex
//! ```
//! where `a_stack`/`b_stack` are the FINAL chip stacks of seat 0 / seat 1, and
//! `a_addr`/`b_addr` are the seat payout Zcash addresses (`u1…`/`utest1…`). Seat 0
//! is always player A and seat 1 always player B, regardless of "me".

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{self, Identity};

/// One seat's half of the co-signed outcome. Serialises straight into the
/// `srv` `ClientMsg::Settlement` fields (same names), so the bot can forward it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    pub a_stack: u64,
    pub b_stack: u64,
    pub a_addr: String,
    pub b_addr: String,
    /// hex SHA-256 of the canonical log/v1 string (64 hex chars).
    pub log_hash: String,
    /// hex Ed25519 signature (128 hex) by THIS seat's identity over `settlement_message`.
    pub sig: String,
}

/// A disputed settlement claim — what one party ASSERTS the hand ended as, for
/// the transcript verifier ("the jury") to cross-check against a replay.
///
/// `log_hash` here is the SAME outcome hash the production settlement carries:
/// the SHA-256 of the canonical `"zk.poker/log/v1:{code}:{a}:{b}:{aAddr}:{bAddr}"`
/// string (see `settle::log_hash`), NOT a hash of the action entries. The jury
/// replays the transcript, asserts the replayed final stacks equal `a_stack` /
/// `b_stack`, then recomputes `settle::log_hash(code, a_stack, b_stack, a_addr,
/// b_addr)` and requires it to equal this `log_hash` — the claim's internal
/// consistency. (`code` = the transcript `room`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub a_stack: u64,
    pub b_stack: u64,
    pub a_addr: String,
    pub b_addr: String,
    /// hex SHA-256 of the canonical `zk.poker/log/v1:…` outcome string (64 hex).
    pub log_hash: String,
}

/// Canonical action-log hash both peers derive identically: the full 32-byte
/// SHA-256 (64 hex chars) of the agreed, public match-end facts. Matches
/// browser `sha256Hex("zk.poker/log/v1:…")`.
pub fn log_hash(code: &str, a_stack: u64, b_stack: u64, a_addr: &str, b_addr: &str) -> String {
    let preimage = format!("zk.poker/log/v1:{code}:{a_stack}:{b_stack}:{a_addr}:{b_addr}");
    let digest = Sha256::digest(preimage.as_bytes());
    hex::encode(digest)
}

/// The message both seats sign. Byte-identical to escrow `settlement_message`.
pub fn settlement_message(
    code: &str, a_stack: u64, b_stack: u64, a_addr: &str, b_addr: &str, log_hash: &str,
) -> String {
    format!("zk.poker/settle/v1:{code}:{a_stack}:{b_stack}:{a_addr}:{b_addr}:{log_hash}")
}

/// Build + sign this seat's settlement: derive the log hash, build the message,
/// sign it with `identity`. Both seats call this with the IDENTICAL seat-indexed
/// inputs, so both produce the identical `log_hash` + message (and each a sig the
/// peer can verify against its pinned pubkey).
pub fn build_and_sign(
    identity: &Identity,
    code: &str,
    a_stack: u64,
    b_stack: u64,
    a_addr: &str,
    b_addr: &str,
) -> Settlement {
    let log_hash = log_hash(code, a_stack, b_stack, a_addr, b_addr);
    let msg = settlement_message(code, a_stack, b_stack, a_addr, b_addr, &log_hash);
    let sig = identity.sign(msg.as_bytes());
    Settlement {
        a_stack,
        b_stack,
        a_addr: a_addr.to_string(),
        b_addr: b_addr.to_string(),
        log_hash,
        sig,
    }
}

/// Verify a peer's settlement against its pinned identity pubkey. Reconstructs the
/// message from the settlement's OWN fields (never from local state) and checks the
/// sig — exactly what the escrow does at `/settle`. `code` is the room code (the one
/// field not carried in `Settlement`, taken from the pinned room). Also re-derives
/// `log_hash` from the fields and requires it to match the claimed one, so a peer
/// can't smuggle a mismatched hash past the sig.
pub fn verify(peer_pubkey_hex: &str, code: &str, s: &Settlement) -> bool {
    let expected_hash = log_hash(code, s.a_stack, s.b_stack, &s.a_addr, &s.b_addr);
    if expected_hash != s.log_hash {
        return false;
    }
    let msg = settlement_message(code, s.a_stack, s.b_stack, &s.a_addr, &s.b_addr, &s.log_hash);
    identity::verify(peer_pubkey_hex, msg.as_bytes(), &s.sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNOWN-VECTOR: pins the exact log_hash + settlement_message bytes for a fixed
    // input so ANY accidental format drift (separator, field order, hash encoding)
    // is caught here — and can be eyeballed against the browser `game.ts` format.
    #[test]
    fn known_vector_log_hash_and_message() {
        let (code, a_stack, b_stack, a_addr, b_addr) = ("ROOM1", 1500u64, 500u64, "u1alice", "u1bob");
        let lh = log_hash(code, a_stack, b_stack, a_addr, b_addr);
        assert_eq!(
            lh,
            "1b363128ff511ec484d010c48a3d68994f5923e4c4f3d8f12d916029fee4d8db",
            "log_hash bytes drifted from the browser/escrow format",
        );
        let msg = settlement_message(code, a_stack, b_stack, a_addr, b_addr, &lh);
        assert_eq!(
            msg,
            "zk.poker/settle/v1:ROOM1:1500:500:u1alice:u1bob:\
             1b363128ff511ec484d010c48a3d68994f5923e4c4f3d8f12d916029fee4d8db",
            "settlement_message bytes drifted from the browser/escrow format",
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = Identity::for_selfplay(1, 0);
        let s = build_and_sign(&id, "ROOM1", 1500, 500, "u1alice", "u1bob");
        assert_eq!(s.a_stack, 1500);
        assert_eq!(s.log_hash.len(), 64);
        assert_eq!(s.sig.len(), 128);
        // the peer verifies against THIS seat's pinned pubkey.
        assert!(verify(&id.pubkey_hex(), "ROOM1", &s), "co-sign must verify");
    }

    #[test]
    fn tamper_detection() {
        let id = Identity::for_selfplay(2, 1);
        let s = build_and_sign(&id, "ROOM1", 1500, 500, "u1alice", "u1bob");

        // flip a stack → sig no longer covers these fields (log_hash also mismatches).
        let mut t1 = s.clone();
        t1.a_stack = 2000;
        assert!(!verify(&id.pubkey_hex(), "ROOM1", &t1), "stack tamper must fail");

        // flip an address.
        let mut t2 = s.clone();
        t2.b_addr = "u1mallory".into();
        assert!(!verify(&id.pubkey_hex(), "ROOM1", &t2), "addr tamper must fail");

        // stale/forged log_hash that doesn't match the fields is rejected even if
        // the rest is untouched.
        let mut t3 = s.clone();
        t3.log_hash = "00".repeat(32);
        assert!(!verify(&id.pubkey_hex(), "ROOM1", &t3), "log_hash tamper must fail");

        // wrong room code (not carried in the struct) → different signed message.
        assert!(!verify(&id.pubkey_hex(), "ROOM2", &s), "room-code mismatch must fail");
    }

    // Both seats, signing the IDENTICAL seat-indexed outcome, produce the SAME
    // message + log_hash and each sig verifies under the peer's pubkey. This is the
    // in-the-small version of the whole selfplay invariant.
    #[test]
    fn both_seats_cosign_the_same_outcome() {
        let id0 = Identity::for_selfplay(9, 0);
        let id1 = Identity::for_selfplay(9, 1);
        let (code, s0, s1, a, b) = ("RM", 1200u64, 800u64, "u1a", "u1b");
        let set0 = build_and_sign(&id0, code, s0, s1, a, b);
        let set1 = build_and_sign(&id1, code, s0, s1, a, b);
        assert_eq!(set0.log_hash, set1.log_hash, "both derive the same log_hash");
        // each verifies under the OTHER's pinned pubkey.
        assert!(verify(&id0.pubkey_hex(), code, &set0));
        assert!(verify(&id1.pubkey_hex(), code, &set1));
    }
}

// frost_ceremony.rs — run a FROST ceremony over a standard frostd relay.
//
// The existing `multisig` subcommands are stateless: each takes hex in and
// prints hex out, leaving the operator to shuttle blobs between machines by
// hand. That works, and it is why the old relay client had no callers — the
// CLI never needed one.
//
// This is the other half: the relay does the shuttling. Same FROST
// primitives, same frost-spend calls, just with the messages routed through
// frostd instead of a terminal and a chat window.
//
// The orchestration lives here rather than in the CLI so that the integration
// test drives exactly the code the binary runs. A ceremony that only works in
// a test is not worth much.

use frost_client::cipher::PublicKey;
use frost_spend::orchestrate::{dkg_part1, dkg_part2, dkg_part3, Dkg3Result};

use crate::frostd_transport::{FrostdTransport, Result, TransportError};

/// How long to wait for peers at each round before giving up.
///
/// Generous: the humans on the other end may be reading a prompt, comparing a
/// fingerprint, or fetching a device from a drawer. A ceremony that times out
/// halfway is worse than one that waits.
const ROUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Messages carry a round tag.
///
/// Without one, a participant that has already moved on can have several
/// rounds sitting in its peers' queues at once — `receive` drains everything
/// available — and round 1 would happily consume a round-2 packet and try to
/// parse it as a commitment. Three concurrent processes hit this immediately;
/// a test that sends in lockstep never does.
const TAG_ROUND1: &str = "dkg1";
const TAG_ROUND2: &str = "dkg2";

/// Buffers messages that belong to a later round instead of discarding them.
///
/// A peer running slightly ahead is normal, not an error: its round-2 packet
/// may arrive while we are still collecting round 1. Dropping it would
/// deadlock the ceremony, so it waits here until asked for.
#[derive(Default)]
struct Mailbox {
    pending: Vec<(String, String)>,
}

impl Mailbox {
    fn take(&mut self, tag: &str, want: usize) -> Option<Vec<String>> {
        let matching: Vec<String> = self
            .pending
            .iter()
            .filter(|(t, _)| t == tag)
            .map(|(_, body)| body.clone())
            .collect();
        if matching.len() >= want {
            self.pending.retain(|(t, _)| t != tag);
            Some(matching)
        } else {
            None
        }
    }

    fn push(&mut self, raw: Vec<u8>) -> Result<()> {
        let text = String::from_utf8(raw).map_err(|_| {
            TransportError::Server("a peer sent a message that is not valid UTF-8".into())
        })?;
        let (tag, body) = text.split_once(':').ok_or_else(|| {
            TransportError::Server(
                "a peer sent an untagged message - it is probably running an older build".into(),
            )
        })?;
        self.pending.push((tag.to_string(), body.to_string()));
        Ok(())
    }
}

/// Collect `want` messages carrying `tag`, or fail with something actionable.
async fn collect(
    t: &mut FrostdTransport,
    mailbox: &mut Mailbox,
    tag: &str,
    want: usize,
    round: &str,
) -> Result<Vec<String>> {
    let deadline = std::time::Instant::now() + ROUND_TIMEOUT;
    loop {
        if let Some(got) = mailbox.take(tag, want) {
            return Ok(got);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        let batch = t.receive(false).await?;
        let got_something = !batch.is_empty();
        for (_, msg) in batch {
            mailbox.push(msg)?;
        }
        // Only back off when the queue was empty; otherwise loop straight
        // back and check whether the new arrivals completed the round.
        if !got_something {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    Err(TransportError::Server(format!(
        "{round}: waited {}s for {want} peer messages. \
         Everyone must be on the same session and running the same version.",
        ROUND_TIMEOUT.as_secs(),
    )))
}

/// Run all three DKG rounds over the relay and return this participant's
/// share material.
///
/// `peers` is everyone else. The caller must already be connected and in a
/// session — created by the coordinator, joined by everyone else.
pub async fn run_dkg(
    t: &mut FrostdTransport,
    peers: Vec<PublicKey>,
    min_signers: u16,
    max_signers: u16,
) -> Result<Dkg3Result> {
    let n_peers = peers.len();
    let mut mailbox = Mailbox::default();

    // ── round 1: broadcast our commitment ──
    let r1 = dkg_part1(max_signers, min_signers).map_err(|e| TransportError::Server(e.to_string()))?;
    t.send(
        peers.clone(),
        format!("{TAG_ROUND1}:{}", r1.broadcast_hex).into_bytes(),
    )
    .await?;
    let broadcasts = collect(t, &mut mailbox, TAG_ROUND1, n_peers, "DKG round 1").await?;

    // ── round 2: one sealed package per recipient ──
    //
    // Sent to everyone rather than routed individually: each package is
    // already sealed to its recipient by Noise_K, so the ones that are not
    // ours simply will not open, and round 3 filters by recipient anyway.
    let r2 = dkg_part2(&r1.secret_hex, &broadcasts)
        .map_err(|e| TransportError::Server(e.to_string()))?;
    t.send(
        peers.clone(),
        format!("{TAG_ROUND2}:{}", r2.peer_packages.join("\n")).into_bytes(),
    )
    .await?;

    let mut all_packages = r2.peer_packages.clone();
    for chunk in collect(t, &mut mailbox, TAG_ROUND2, n_peers, "DKG round 2").await? {
        all_packages.extend(chunk.split('\n').map(str::to_string));
    }

    // ── round 3: finalize ──
    dkg_part3(&r2.secret_hex, &broadcasts, &all_packages)
        .map_err(|e| TransportError::Server(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: three concurrent participants put more than one round in a
    /// peer's queue at once. Before tagging, round 1 consumed a round-2
    /// packet and the ceremony died with "bad hex: Odd number of digits" —
    /// found by running three real processes, not by any unit test, because
    /// tests send in lockstep and real participants do not.
    #[test]
    fn a_later_round_does_not_satisfy_an_earlier_one() {
        let mut m = Mailbox::default();
        m.push(format!("{TAG_ROUND2}:deadbeef").into_bytes()).unwrap();
        m.push(format!("{TAG_ROUND2}:cafebabe").into_bytes()).unwrap();

        // two messages are queued, but neither is round 1
        assert!(m.take(TAG_ROUND1, 1).is_none());
        // and they are still there for round 2
        assert_eq!(
            m.take(TAG_ROUND2, 2).unwrap(),
            vec!["deadbeef".to_string(), "cafebabe".to_string()]
        );
    }

    /// An early arrival must be kept, not dropped — dropping deadlocks the
    /// ceremony, since the peer will not send it again.
    #[test]
    fn an_early_arrival_is_buffered_until_its_round() {
        let mut m = Mailbox::default();
        m.push(format!("{TAG_ROUND2}:early").into_bytes()).unwrap();
        m.push(format!("{TAG_ROUND1}:first").into_bytes()).unwrap();

        assert_eq!(m.take(TAG_ROUND1, 1).unwrap(), vec!["first".to_string()]);
        assert_eq!(m.take(TAG_ROUND2, 1).unwrap(), vec!["early".to_string()]);
    }

    /// A partial round must not be consumed — taking 1 of 2 would leave the
    /// ceremony believing it had everything.
    #[test]
    fn a_partial_round_is_left_alone() {
        let mut m = Mailbox::default();
        m.push(format!("{TAG_ROUND1}:one").into_bytes()).unwrap();

        assert!(m.take(TAG_ROUND1, 2).is_none());
        assert_eq!(m.take(TAG_ROUND1, 1).unwrap(), vec!["one".to_string()]);
    }

    /// An older build sends untagged messages. Say so, rather than failing
    /// later with a hex parse error.
    #[test]
    fn an_untagged_message_is_reported_clearly() {
        let mut m = Mailbox::default();
        let err = m.push(b"no-tag-here".to_vec()).unwrap_err();
        assert!(format!("{err}").contains("older build"), "got: {err}");
    }
}

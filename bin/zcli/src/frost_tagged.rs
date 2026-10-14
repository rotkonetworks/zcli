// frost_tagged.rs — zafu's tagged FROST wire, joiner side.
//
// zcli's own ceremony (frost_ceremony.rs) and zafu's predate each other and
// grew different wires. zafu's is the one the zk.poker escrow speaks too, so
// a player who wants to hold a share of an escrow vault with nothing but zcli
// has to speak it. One protocol everywhere: this is that protocol, not a
// third one.
//
// DKG (the coordinator is the host):
//   host R1:   "R1:<t>:<n>:SK:<fvk_sk_hex>:<part1_broadcast_hex>"
//   joiner R1: "R1:<part1_broadcast_hex>"
//   R2:        "R2:<package_hex>"            (each party sends n-1, one per recipient)
//   echo:      "FVK:<ufvk>"                  (everyone must send the same string)
//
// The host's SK is the seed of the vault's nullifier/ivk keys; spend authority
// stays with the FROST group key. Every party derives the same address and
// viewing key from (group key, SK), and the FVK echo makes a disagreement a
// failed ceremony rather than a vault nobody can see.
//
// Spend signing (the coordinator built the transaction):
//   host:   "SIGN:<sighash>:<alpha,alpha,...>:<recipient>:<amount>:<fee>[:<pczt_hex>]"
//   both:   "C:<commit>|<commit>|..."        (one per action)
//   both:   "S:<i>:<share>"                  (one per action)
//
// A co-signer that signs whatever SIGN arrives would let the host spend the
// vault anywhere; `join_sign` hands the request to a caller-supplied check
// before any nonce exists, and `payout_verify` is that check for a payout.

use std::time::{Duration, Instant};

use frost_client::cipher::PublicKey;
use frost_spend::orchestrate as fs;
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::NetworkType;

use crate::frost_ceremony::{collect, Mailbox};
use crate::frostd_transport::{FrostdTransport, Result, TransportError};
use crate::payout_verify::{parse_sign, SignRequest};

/// A joiner's share of a vault made over the tagged wire.
#[derive(Debug, Clone)]
pub struct TaggedDkg {
    pub key_package_hex: String,
    pub public_key_package_hex: String,
    pub ephemeral_seed_hex: String,
    /// the host's viewing-key seed (not a spending key: spending needs t shares)
    pub sk_hex: String,
    /// raw 96-byte Orchard FVK, hex
    pub fvk_hex: String,
    pub ufvk: String,
    /// the vault's unified address (diversifier 0)
    pub address: String,
    pub min_signers: u16,
    pub max_signers: u16,
}

fn err(s: impl Into<String>) -> TransportError {
    TransportError::Server(s.into())
}

/// The host-only `<t>:<n>:SK:<sk>:<broadcast>` header of an R1 body, if any.
pub fn parse_host_r1(body: &str) -> Option<(u16, u16, String, String)> {
    if !body.chars().next()?.is_ascii_digit() {
        return None;
    }
    let (t, rest) = body.split_once(':')?;
    let (n, rest) = rest.split_once(':')?;
    let rest = rest.strip_prefix("SK:")?;
    let (sk, broadcast) = rest.split_once(':')?;
    if sk.len() != 64 || !sk.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((
        t.parse().ok()?,
        n.parse().ok()?,
        sk.to_string(),
        broadcast.to_string(),
    ))
}

/// The vault's unified address and viewing key from (group key, host SK).
/// Mirrors zafu's `frost_derive_ufvk` and the escrow's `orchard_ua`, so all
/// parties land on the same strings.
pub fn vault_keys(
    public_key_package_hex: &str,
    sk_hex: &str,
    network: NetworkType,
) -> std::result::Result<(String, String, String), String> {
    let sk: [u8; 32] = hex::decode(sk_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the host's SK is not 32 bytes of hex")?;
    let pkg: frost_spend::frost_keys::PublicKeyPackage =
        fs::from_hex(public_key_package_hex).map_err(|e| e.to_string())?;
    let fvk = frost_spend::keys::derive_fvk_from_sk(sk, &pkg)
        .ok_or("the group key and the host's SK give no viewing key")?;
    let fvk_bytes = fvk.to_bytes();
    let raw = frost_spend::keys::derive_address(&fvk, 0).to_raw_address_bytes();
    let ua = unified::Address::try_from_items(vec![unified::Receiver::Orchard(raw)])
        .map_err(|e| format!("unified address: {e}"))?
        .encode(&network);
    let ufvk = unified::Ufvk::try_from_items(vec![unified::Fvk::Orchard(fvk_bytes)])
        .map_err(|e| format!("unified viewing key: {e}"))?
        .encode(&network);
    Ok((ua, ufvk, hex::encode(fvk_bytes)))
}

/// Run the tagged DKG as a joiner. `mailbox` holds whatever arrived before
/// we knew which wire this was (see `frost_ceremony::detect_dialect`).
pub async fn run_dkg(
    t: &mut FrostdTransport,
    mut mailbox: Mailbox,
    peers: Vec<PublicKey>,
    min_signers: u16,
    max_signers: u16,
    network: NetworkType,
) -> Result<TaggedDkg> {
    let n_peers = peers.len();
    if n_peers + 1 != usize::from(max_signers) {
        return Err(err(format!(
            "{} participants in the session, but the vault is {min_signers}-of-{max_signers}",
            n_peers + 1
        )));
    }

    // ── round 1 ──
    let r1 = fs::dkg_part1(max_signers, min_signers).map_err(|e| err(e.to_string()))?;
    t.send(
        peers.clone(),
        format!("R1:{}", r1.broadcast_hex).into_bytes(),
    )
    .await?;
    let mut broadcasts = Vec::with_capacity(n_peers);
    let mut host_sk = None;
    for body in collect(t, &mut mailbox, "R1", n_peers, "DKG round 1").await? {
        match parse_host_r1(&body) {
            Some((ht, hn, sk, broadcast)) => {
                if (ht, hn) != (min_signers, max_signers) {
                    return Err(err(format!(
                        "the host runs a {ht}-of-{hn} ceremony, the room said {min_signers}-of-{max_signers}"
                    )));
                }
                if host_sk.replace(sk).is_some() {
                    return Err(err("two participants claim to be the host"));
                }
                broadcasts.push(broadcast);
            }
            None => broadcasts.push(body),
        }
    }
    let sk_hex = host_sk.ok_or_else(|| err("no host in the ceremony: no R1 carried the SK"))?;

    // ── round 2: one message per package; each is sealed to its recipient ──
    let r2 = fs::dkg_part2(&r1.secret_hex, &broadcasts).map_err(|e| err(e.to_string()))?;
    for pkg in &r2.peer_packages {
        t.send(peers.clone(), format!("R2:{pkg}").into_bytes())
            .await?;
    }
    let packages = collect(t, &mut mailbox, "R2", n_peers * n_peers, "DKG round 2").await?;

    // ── round 3 ──
    let r3 =
        fs::dkg_part3(&r2.secret_hex, &broadcasts, &packages).map_err(|e| err(e.to_string()))?;
    let (address, ufvk, fvk_hex) =
        vault_keys(&r3.public_key_package_hex, &sk_hex, network).map_err(err)?;

    // ── echo: every party must have landed on the same viewing key ──
    t.send(peers.clone(), format!("FVK:{ufvk}").into_bytes())
        .await?;
    for theirs in collect(t, &mut mailbox, "FVK", n_peers, "viewing-key echo").await? {
        if theirs != ufvk {
            return Err(err(format!(
                "a participant derived a different vault (ours ends ...{}, theirs ...{}) - do not use it",
                &ufvk[ufvk.len().saturating_sub(8)..],
                &theirs[theirs.len().saturating_sub(8)..],
            )));
        }
    }

    Ok(TaggedDkg {
        key_package_hex: r3.key_package_hex,
        public_key_package_hex: r3.public_key_package_hex,
        ephemeral_seed_hex: r3.ephemeral_seed_hex,
        sk_hex,
        fvk_hex,
        ufvk,
        address,
        min_signers,
        max_signers,
    })
}

/// Our share, as the signing rounds need it.
pub struct Signer<'a> {
    pub key_package_hex: &'a str,
    pub public_key_package_hex: &'a str,
    pub ephemeral_seed_hex: &'a str,
}

/// Messages of a signing session, buffered so a peer running ahead costs
/// nothing (its shares may arrive before we asked for them).
#[derive(Default)]
struct Inbox(Vec<String>);

impl Inbox {
    async fn next_matching<F: Fn(&str) -> bool>(
        &mut self,
        t: &mut FrostdTransport,
        deadline: Instant,
        what: &str,
        want: F,
    ) -> Result<String> {
        loop {
            if let Some(i) = self.0.iter().position(|m| want(m)) {
                return Ok(self.0.remove(i));
            }
            if Instant::now() >= deadline {
                return Err(err(format!("timed out waiting for {what}")));
            }
            let batch = t.receive(false).await?;
            if batch.is_empty() {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            for (_, msg) in batch {
                self.0
                    .push(String::from_utf8(msg).map_err(|_| err("a non-UTF-8 signing message"))?);
            }
        }
    }
}

/// Join a signing session someone else opened, as the one other signer
/// (`peers` = the coordinator). `check` sees the whole request, PCZT
/// included, before any nonce is drawn; a refusal ends the session having
/// contributed nothing. Returns the aggregated SpendAuth signatures.
pub async fn join_sign(
    t: &mut FrostdTransport,
    peers: Vec<PublicKey>,
    us: &Signer<'_>,
    timeout: Duration,
    check: impl FnOnce(&SignRequest) -> std::result::Result<(), String>,
) -> Result<Vec<[u8; 64]>> {
    let deadline = Instant::now() + timeout;
    let mut inbox = Inbox::default();
    let sign = inbox
        .next_matching(t, deadline, "the SIGN request", |m| m.starts_with("SIGN:"))
        .await?;
    let req = parse_sign(&sign).map_err(err)?;
    check(&req).map_err(|e| err(format!("refusing to sign: {e}")))?;

    let seed: [u8; 32] = hex::decode(us.ephemeral_seed_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err("ephemeral seed is not 32 bytes of hex"))?;
    let n = req.alphas.len();

    // round 1: a fresh nonce per action
    let mut nonces = Vec::with_capacity(n);
    let mut commits = Vec::with_capacity(n);
    for _ in 0..n {
        let (nonce, commit) =
            fs::sign_round1(&seed, us.key_package_hex).map_err(|e| err(e.to_string()))?;
        nonces.push(nonce);
        commits.push(commit);
    }
    t.send(
        peers.clone(),
        format!("C:{}", commits.join("|")).into_bytes(),
    )
    .await?;
    let theirs = inbox
        .next_matching(t, deadline, "the coordinator's commitments", |m| {
            m.starts_with("C:")
        })
        .await?;
    let theirs: Vec<String> = theirs["C:".len()..]
        .split('|')
        .map(str::to_string)
        .collect();
    if theirs.len() != n {
        return Err(err(format!("{} commitments for {n} actions", theirs.len())));
    }

    // round 2: per action, share, exchange, aggregate
    let mut sigs = Vec::with_capacity(n);
    for i in 0..n {
        let all_commits = vec![commits[i].clone(), theirs[i].clone()];
        let share = fs::spend_sign_round2_signed(
            &seed,
            us.key_package_hex,
            &nonces[i],
            &req.sighash,
            &req.alphas[i],
            &all_commits,
        )
        .map_err(|e| err(format!("action {i}: {e}")))?;
        t.send(peers.clone(), format!("S:{i}:{share}").into_bytes())
            .await?;
        let prefix = format!("S:{i}:");
        let their_share = inbox
            .next_matching(t, deadline, &format!("share {i}"), |m| {
                m.starts_with(&prefix)
            })
            .await?;
        let sig = fs::spend_aggregate(
            us.public_key_package_hex,
            &req.sighash,
            &req.alphas[i],
            &all_commits,
            &[share, their_share[prefix.len()..].to_string()],
        )
        .map_err(|e| err(format!("aggregate action {i}: {e}")))?;
        sigs.push(
            hex::decode(&sig)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| err("aggregate signature is not 64 bytes"))?,
        );
    }
    Ok(sigs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_r1_carries_t_n_and_the_sk() {
        let sk = "ab".repeat(32);
        let (t, n, got, b) = parse_host_r1(&format!("2:3:SK:{sk}:cafe")).unwrap();
        assert_eq!(
            (t, n, got.as_str(), b.as_str()),
            (2, 3, sk.as_str(), "cafe")
        );
        // a joiner's R1 is a bare broadcast
        assert!(parse_host_r1("cafe").is_none());
        // a short SK is not a host header
        assert!(parse_host_r1("2:3:SK:abcd:cafe").is_none());
    }

    /// Everyone who runs the derivation on the same (group key, SK) gets the
    /// same vault, and the SK actually matters.
    #[test]
    fn the_vault_follows_from_the_group_key_and_the_sk() {
        let dealt = fs::dealer_keygen(2, 3).unwrap();
        let sk = sample_sk();
        let a = vault_keys(&dealt.public_key_package_hex, &sk, NetworkType::Test).unwrap();
        let b = vault_keys(&dealt.public_key_package_hex, &sk, NetworkType::Test).unwrap();
        assert_eq!(a, b);
        assert!(a.0.starts_with("utest1"), "{}", a.0);
        assert!(a.1.starts_with("uviewtest1"), "{}", a.1);
        assert_eq!(a.2.len(), 192);
        let c = vault_keys(
            &dealt.public_key_package_hex,
            &sample_sk(),
            NetworkType::Test,
        )
        .unwrap();
        assert_ne!(a.0, c.0);
    }

    fn sample_sk() -> String {
        use ff::PrimeField;
        use rand::RngCore;
        loop {
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            if bool::from(pasta_curves::pallas::Scalar::from_repr(b).is_some()) {
                return hex::encode(b);
            }
        }
    }
}

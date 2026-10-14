// custody.rs — hold a share of a 2-of-3 vault and co-sign its payouts.
//
// The vault is made with zafu's tagged DKG (frost_tagged.rs): the wire the
// zk.poker escrow and zafu speak. What a player keeps afterwards is a share,
// the vault's viewing key and the relay identity it was made with; this
// module stores that, and co-signs a payout only after checking the PCZT
// pays exactly the plan (payout_verify.rs).
//
// The relay identity is kept on purpose: the escrow admits a co-signer to a
// payout session by the relay key the caller names, so `multisig join --json`
// prints it and `cosign` signs with it.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::Error;
use crate::frost_tagged::TaggedDkg;
use crate::frostd_transport::FrostdTransport;
use crate::wallet::Wallet;

/// The default cap on the network fee a co-signed payout may pay.
pub const DEFAULT_MAX_FEE_ZAT: u64 = 10_000;

/// How long a co-signer waits for the coordinator's signing request and rounds.
const SIGN_TIMEOUT: Duration = Duration::from_secs(600);

/// One vault share, as stored in `<zcli dir>/multisig/<label>.json` (0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub label: String,
    /// the rendezvous code the vault was made in
    pub room_code: String,
    /// the frostd relay it was made on
    pub server: String,
    /// "main" or "test"
    pub network: String,
    /// "tagged" (zafu / zk.poker escrow wire)
    pub protocol: String,
    pub min_signers: u16,
    pub max_signers: u16,
    pub address: String,
    pub ufvk: String,
    /// raw 96-byte Orchard FVK, hex
    pub fvk: String,
    pub public_key_package: String,
    pub key_package: String,
    pub ephemeral_seed: String,
    /// the host's viewing-key seed (derives addresses; cannot spend)
    pub sk: String,
    pub relay_private: String,
    pub relay_public: String,
}

fn dir() -> PathBuf {
    PathBuf::from(Wallet::multisig_dir())
}

/// A label is a file name: keep it to a safe alphabet.
pub fn check_label(label: &str) -> Result<(), Error> {
    if label.is_empty()
        || label.len() > 128
        || label.starts_with('.')
        || !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(Error::Other(format!(
            "vault label {label:?}: use letters, digits, '-', '_' or '.'"
        )));
    }
    Ok(())
}

fn path_of(label: &str) -> PathBuf {
    dir().join(format!("{label}.json"))
}

/// Refuse before a ceremony, not after: a second share under one label
/// would overwrite the first, and a share is money.
pub fn ensure_free(label: &str) -> Result<(), Error> {
    check_label(label)?;
    if path_of(label).exists() {
        return Err(Error::Other(format!(
            "a vault labelled {label:?} already exists ({}) - pick another --label",
            path_of(label).display()
        )));
    }
    Ok(())
}

impl Vault {
    pub fn save(&self) -> Result<PathBuf, Error> {
        use std::io::Write;
        ensure_free(&self.label)?;
        let d = dir();
        std::fs::create_dir_all(&d)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = path_of(&self.label);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&path)?;
        f.write_all(
            serde_json::to_string_pretty(self)
                .map_err(|e| Error::Other(e.to_string()))?
                .as_bytes(),
        )?;
        f.sync_all()?;
        Ok(path)
    }

    /// Find a vault by its label, or by the room code it was joined from.
    pub fn load(name: &str) -> Result<Self, Error> {
        let parse = |p: &std::path::Path| -> Result<Vault, Error> {
            serde_json::from_slice(&std::fs::read(p)?)
                .map_err(|e| Error::Other(format!("{}: {e}", p.display())))
        };
        if check_label(name).is_ok() && path_of(name).exists() {
            return parse(&path_of(name));
        }
        if let Ok(entries) = std::fs::read_dir(dir()) {
            for e in entries.flatten() {
                if e.path().extension().is_some_and(|x| x == "json") {
                    if let Ok(v) = parse(&e.path()) {
                        if v.room_code == name {
                            return Ok(v);
                        }
                    }
                }
            }
        }
        Err(Error::Other(format!(
            "no vault {name:?} in {} (by label or room code)",
            dir().display()
        )))
    }

    fn check_network(&self, mainnet: bool) -> Result<(), Error> {
        let ours = if mainnet { "main" } else { "test" };
        if self.network != ours {
            return Err(Error::Other(format!(
                "vault {} is a {} vault; run with{} --testnet",
                self.label,
                self.network,
                if mainnet { "" } else { "out" }
            )));
        }
        Ok(())
    }

    /// What `--json` shows: everything a caller needs, no secrets.
    pub fn public_json(&self, path: &std::path::Path) -> Value {
        json!({
            "protocol": self.protocol,
            "label": self.label,
            "room_code": self.room_code,
            "address": self.address,
            "ufvk": self.ufvk,
            "threshold": self.min_signers,
            "signers": self.max_signers,
            "public_key_package": self.public_key_package,
            "relay_pubkey": self.relay_public,
            "server": self.server,
            "vault_file": path.display().to_string(),
        })
    }
}

/// Keep a finished tagged DKG as a vault.
#[allow(clippy::too_many_arguments)]
pub fn store_tagged(
    dkg: TaggedDkg,
    label: &str,
    room_code: &str,
    server: &str,
    mainnet: bool,
    relay_private: &str,
    relay_public: &str,
) -> Result<(Vault, PathBuf), Error> {
    let v = Vault {
        label: label.to_string(),
        room_code: room_code.to_string(),
        server: server.to_string(),
        network: if mainnet { "main" } else { "test" }.into(),
        protocol: "tagged".into(),
        min_signers: dkg.min_signers,
        max_signers: dkg.max_signers,
        address: dkg.address,
        ufvk: dkg.ufvk,
        fvk: dkg.fvk_hex,
        public_key_package: dkg.public_key_package_hex,
        key_package: dkg.key_package_hex,
        ephemeral_seed: dkg.ephemeral_seed_hex,
        sk: dkg.sk_hex,
        relay_private: relay_private.to_lowercase(),
        relay_public: relay_public.to_lowercase(),
    };
    let path = v.save()?;
    Ok((v, path))
}

/// A payout plan, from any of the shapes it travels in: a bare
/// `[{address, amount}]`, `{outputs: [...]}`, or the escrow's
/// `{payout_plan: {...}}` / `{refund_plan: {...}}`.
pub fn parse_plan(v: &Value) -> Result<Vec<(String, u64)>, Error> {
    let outputs = if v.is_array() {
        v
    } else if let Some(o) = v.get("outputs") {
        o
    } else if let Some(p) = v.get("payout_plan").or_else(|| v.get("refund_plan")) {
        return parse_plan(p);
    } else {
        return Err(Error::Other(
            "a plan is [{address, amount}] or {outputs: [...]}".into(),
        ));
    };
    outputs
        .as_array()
        .ok_or_else(|| Error::Other("plan outputs are not a list".into()))?
        .iter()
        .map(|o| {
            let address = o["address"].as_str();
            let amount = o["amount"].as_u64().or_else(|| o["amount_zat"].as_u64());
            match (address, amount) {
                (Some(a), Some(z)) if z > 0 => Ok((a.to_string(), z)),
                _ => Err(Error::Other(format!("bad plan output: {o}"))),
            }
        })
        .collect()
}

pub fn read_plan(file: &str) -> Result<Vec<(String, u64)>, Error> {
    let raw = std::fs::read(file).map_err(|e| Error::Other(format!("{file}: {e}")))?;
    let v: Value =
        serde_json::from_slice(&raw).map_err(|e| Error::Other(format!("{file}: {e}")))?;
    parse_plan(&v)
}

/// Join the signing session `session` the coordinator `peer` opened and
/// co-sign it, only if its PCZT pays exactly `plan` (plus change to the vault)
/// with a fee of at most `max_fee_zat`. Returns the number of spends signed.
pub async fn cosign(
    vault: &Vault,
    server: &str,
    session: &str,
    peer: &str,
    plan: &[(String, u64)],
    max_fee_zat: u64,
    mainnet: bool,
) -> Result<usize, Error> {
    vault.check_network(mainnet)?;
    let session: uuid::Uuid = session
        .parse()
        .map_err(|e| Error::Other(format!("session is not a uuid: {e}")))?;
    let decode = |h: &str, what: &str| {
        hex::decode(h.trim()).map_err(|e| Error::Other(format!("{what}: bad hex: {e}")))
    };
    let peer = frost_client::cipher::PublicKey(decode(peer, "--peer")?);
    let private =
        frost_client::cipher::PrivateKey::from(decode(&vault.relay_private, "relay key")?);
    let public = frost_client::cipher::PublicKey(decode(&vault.relay_public, "relay key")?);

    let mut t = FrostdTransport::connect(server.to_string(), private, public, vec![peer.clone()])
        .await
        .map_err(|e| Error::Network(e.to_string()))?;
    t.join_session(session);
    let us = crate::frost_tagged::Signer {
        key_package_hex: &vault.key_package,
        public_key_package_hex: &vault.public_key_package,
        ephemeral_seed_hex: &vault.ephemeral_seed,
    };
    let sigs = crate::frost_tagged::join_sign(&mut t, vec![peer], &us, SIGN_TIMEOUT, |req| {
        crate::payout_verify::verify_payout_for_share(req, &vault.fvk, plan, mainnet, max_fee_zat)
    })
    .await
    .map_err(|e| Error::Other(e.to_string()))?;
    Ok(sigs.len())
}

// ── the zk.poker escrow's HTTP side ──

pub struct Escrow {
    base: String,
    http: reqwest::Client,
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Escrow {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    fn url(&self, room: &str, rest: &str) -> String {
        format!("{}/room/{}{rest}", self.base, urlencode(room))
    }

    async fn call(&self, req: reqwest::RequestBuilder, what: &str) -> Result<Value, Error> {
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Network(format!("escrow {what}: {e}")))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Network(format!("escrow {what}: {e}")))?;
        let v: Value = serde_json::from_slice(&body).map_err(|_| {
            Error::Network(format!(
                "escrow {what}: {status}: {}",
                String::from_utf8_lossy(&body)
            ))
        })?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(Error::Other(format!("escrow {what}: {e}")));
        }
        if !status.is_success() {
            return Err(Error::Network(format!("escrow {what}: {status}: {v}")));
        }
        Ok(v)
    }

    pub async fn get(&self, room: &str, rest: &str) -> Result<Value, Error> {
        self.call(self.http.get(self.url(room, rest)), rest).await
    }

    pub async fn post(&self, room: &str, rest: &str, body: Value) -> Result<Value, Error> {
        let req = self
            .http
            .post(self.url(room, rest))
            .header("content-type", "application/json")
            .body(body.to_string());
        self.call(req, rest).await
    }

    /// Wait for the payout the escrow is signing to reach the network.
    pub async fn wait_broadcast(&self, room: &str) -> Result<String, Error> {
        let deadline = Instant::now() + SIGN_TIMEOUT;
        loop {
            let st = self.get(room, "/payout/status").await?;
            match st["phase"].as_str() {
                Some("Broadcast") => {
                    return Ok(st["txid"].as_str().unwrap_or_default().to_string())
                }
                Some("Failed") => {
                    return Err(Error::Other(format!("payout failed: {}", st["reason"])))
                }
                _ => {}
            }
            if Instant::now() > deadline {
                return Err(Error::Other("the escrow never broadcast the payout".into()));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

/// `to` must be paid by `plan`, if the caller named it.
fn check_pays(plan: &[(String, u64)], to: Option<&str>) -> Result<u64, Error> {
    let ours: u64 = plan
        .iter()
        .filter(|(a, _)| Some(a.as_str()) == to)
        .map(|(_, v)| v)
        .sum();
    if to.is_some() && ours == 0 {
        return Err(Error::Other(format!(
            "the plan pays nothing to {}: {plan:?}",
            to.unwrap_or_default()
        )));
    }
    Ok(ours)
}

/// The escrow's session reply: `{session_id, escrow_relay_pubkey}`.
fn session_of(v: &Value) -> Result<(String, String), Error> {
    if let Some(e) = v.get("error") {
        return Err(Error::Other(format!(
            "escrow could not open the signing session: {e}"
        )));
    }
    let s = v["session_id"]
        .as_str()
        .ok_or_else(|| Error::Other(format!("escrow opened no signing session: {v}")))?;
    let p = v["escrow_relay_pubkey"]
        .as_str()
        .ok_or_else(|| Error::Other(format!("escrow sent no relay key: {v}")))?;
    Ok((s.to_string(), p.to_string()))
}

pub struct Collected {
    pub txid: String,
    pub plan: Vec<(String, u64)>,
    pub ours: u64,
    pub spends: usize,
}

/// Collect a settled pot: ask the escrow to pay out its settled plan (or the
/// `plan` the caller already agreed to), co-sign once the PCZT pays exactly
/// that, and wait for the broadcast.
#[allow(clippy::too_many_arguments)]
pub async fn collect(
    vault: &Vault,
    server: &str,
    escrow_url: &str,
    room: &str,
    token: &str,
    plan: Option<Vec<(String, u64)>>,
    to: Option<&str>,
    max_fee_zat: u64,
    mainnet: bool,
) -> Result<Collected, Error> {
    vault.check_network(mainnet)?;
    let escrow = Escrow::new(escrow_url);
    let plan = match plan {
        Some(p) => p,
        None => parse_plan(&escrow.get(room, "/payout").await?)?,
    };
    let ours = check_pays(&plan, to)?;
    let started = escrow
        .post(
            room,
            "/payout/initiate",
            json!({ "outputs": [], "payout_token": token, "cosigner_pubkeys": [vault.relay_public] }),
        )
        .await?;
    let (session, peer) = session_of(&started)?;
    let spends = cosign(vault, server, &session, &peer, &plan, max_fee_zat, mainnet).await?;
    let txid = escrow.wait_broadcast(room).await?;
    Ok(Collected {
        txid,
        plan,
        ours,
        spends,
    })
}

/// Cancel an unplayed table and co-sign the escrow's refund of each seat's
/// own confirmed deposit. `to`, if given, must get something back.
#[allow(clippy::too_many_arguments)]
pub async fn refund(
    vault: &Vault,
    server: &str,
    escrow_url: &str,
    room: &str,
    token: &str,
    to: Option<&str>,
    max_fee_zat: u64,
    mainnet: bool,
) -> Result<Collected, Error> {
    vault.check_network(mainnet)?;
    let escrow = Escrow::new(escrow_url);
    let v = escrow
        .post(
            room,
            "/cancel",
            json!({ "payout_token": token, "cosigner_pubkeys": [vault.relay_public] }),
        )
        .await?;
    let plan = parse_plan(&v["refund_plan"])?;
    let ours = check_pays(&plan, to)?;
    let (session, peer) = session_of(&v["payout"])?;
    let spends = cosign(vault, server, &session, &peer, &plan, max_fee_zat, mainnet).await?;
    let txid = escrow.wait_broadcast(room).await?;
    Ok(Collected {
        txid,
        plan,
        ours,
        spends,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_parse_from_every_shape_they_travel_in() {
        let want = vec![("ua".to_string(), 5u64), ("ub".to_string(), 7)];
        let outs = json!([{"address": "ua", "amount": 5}, {"address": "ub", "amount": 7}]);
        assert_eq!(parse_plan(&outs).unwrap(), want);
        assert_eq!(parse_plan(&json!({"outputs": outs})).unwrap(), want);
        assert_eq!(
            parse_plan(&json!({"payout_plan": {"outputs": outs, "escrow_value": 12}})).unwrap(),
            want
        );
        assert_eq!(
            parse_plan(&json!({"refund_plan": {"outputs": outs}})).unwrap(),
            want
        );
        assert!(parse_plan(&json!([{"address": "ua"}])).is_err());
        assert!(parse_plan(&json!({"nope": 1})).is_err());
    }

    #[test]
    fn labels_are_file_names() {
        assert!(check_label("7-apple-river").is_ok());
        assert!(check_label("room_1.v2").is_ok());
        for bad in ["", "../x", "a/b", ".hidden", "sp ace"] {
            assert!(check_label(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_named_recipient_must_be_paid() {
        let plan = vec![("ua".to_string(), 5u64)];
        assert_eq!(check_pays(&plan, Some("ua")).unwrap(), 5);
        assert!(check_pays(&plan, Some("ub")).is_err());
        assert_eq!(check_pays(&plan, None).unwrap(), 0);
    }
}

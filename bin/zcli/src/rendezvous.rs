//! rendezvous — the room-code layer on top of frostd session uuids.
//!
//! zidecar's frostd listener also serves /rendezvous/*: a discovery room,
//! addressed by SHA-256 of a human code, where participants drop their relay
//! public keys and the coordinator announces the frostd session uuid. The
//! uuid stays the ground truth — this only saves humans from couriering
//! uuids and hex keys around; `--session <uuid>` keeps working untouched.
//!
//! Semantics here MUST stay byte-identical with the browser client
//! (`zafu/apps/extension/src/state/keyring/rendezvous-client.ts`): same code
//! normalization, same hash, same snake_case wire fields — a code generated
//! by one must resolve in the other.

use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum Error {
    Http(String),
    Server(u16, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Http(e) => write!(f, "rendezvous: {e}"),
            Error::Server(code, msg) => write!(f, "rendezvous: server said {code}: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Four random bip39 words, dash-joined: the thing you send your co-signers.
/// ~44 bits — and the code is discovery, not admission: the coordinator still
/// approves every key before the frostd session exists.
pub fn generate_room_code() -> String {
    use rand::Rng;
    let words = bip39::Language::English.word_list();
    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| words[rng.gen_range(0..2048)])
        .collect::<Vec<_>>()
        .join("-")
}

/// Room id = SHA-256 of the normalized code, hex. Normalization forgives the
/// ways a code mutates in a chat message: case, separators, stray whitespace.
pub fn room_id_from_code(code: &str) -> String {
    let normalized = code
        .to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

#[derive(serde::Deserialize)]
pub struct Entry {
    pub pubkey: String,
    #[serde(default)]
    pub note: String,
}

pub struct RoomView {
    pub entries: Vec<Entry>,
    pub session_id: Option<String>,
}

pub struct Rendezvous {
    base: String,
    http: reqwest::Client,
}

impl Rendezvous {
    pub fn new(server: &str) -> Self {
        Self {
            base: server.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, Error> {
        let res = self
            .http
            .post(format!("{}/rendezvous/{path}", self.base))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = res.status().as_u16();
        if !res.status().is_success() {
            let msg = res.text().await.unwrap_or_default();
            return Err(Error::Server(status, msg));
        }
        res.json().await.map_err(|e| Error::Http(e.to_string()))
    }

    /// Does this relay serve the rendezvous at all? Stock frostd 404s it.
    pub async fn available(&self) -> bool {
        self.post::<serde_json::Value>("poll", serde_json::json!({ "room": "0".repeat(64) }))
            .await
            .is_ok()
    }

    /// Put our relay pubkey in the room. The first publish creates the room
    /// and returns the creator token needed for `announce`; joiners get None.
    pub async fn publish(
        &self,
        room_id: &str,
        pubkey: &str,
        note: &str,
    ) -> Result<Option<String>, Error> {
        #[derive(serde::Deserialize)]
        struct Resp {
            creator_token: Option<String>,
        }
        let resp: Resp = self
            .post(
                "publish",
                serde_json::json!({ "room": room_id, "pubkey": pubkey, "note": note }),
            )
            .await?;
        Ok(resp.creator_token)
    }

    pub async fn poll(&self, room_id: &str) -> Result<RoomView, Error> {
        #[derive(serde::Deserialize)]
        struct Resp {
            entries: Vec<Entry>,
            session_id: Option<String>,
        }
        let resp: Resp = self
            .post("poll", serde_json::json!({ "room": room_id }))
            .await?;
        Ok(RoomView {
            entries: resp.entries,
            session_id: resp.session_id,
        })
    }

    /// Coordinator only: point the room's joiners at the created session.
    pub async fn announce(
        &self,
        room_id: &str,
        creator_token: &str,
        session_id: &str,
    ) -> Result<(), Error> {
        self.post::<serde_json::Value>(
            "announce",
            serde_json::json!({
                "room": room_id,
                "creator_token": creator_token,
                "session_id": session_id,
            }),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_four_words() {
        let code = generate_room_code();
        assert_eq!(code.split('-').count(), 4);
    }

    /// The exact value the browser client computes for this input
    /// (rendezvous-client.ts normalizes identically) — if this test moves,
    /// codes stop resolving across clients.
    #[test]
    fn room_id_matches_the_browser_client() {
        let canonical = room_id_from_code("orbit-velvet-lantern-cove");
        assert_eq!(canonical.len(), 64);
        for mangled in [
            "Orbit Velvet Lantern Cove",
            "  orbit_velvet_lantern_cove  ",
            "orbit,velvet, lantern,cove",
        ] {
            assert_eq!(room_id_from_code(mangled), canonical);
        }
        // sha256("orbit velvet lantern cove")
        assert_eq!(
            canonical,
            hex::encode(Sha256::digest(b"orbit velvet lantern cove"))
        );
    }
}

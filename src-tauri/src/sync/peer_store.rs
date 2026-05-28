// Trusted peers. Stored as a single JSON document in the `settings` table
// under key `sync_peers`. Small dataset (usually 1–2 entries) — no need
// for a dedicated table.

use serde::{Deserialize, Serialize};

use crate::db::Database;

const SETTING_KEY: &str = "sync_peers";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// Stable ID — first 8 hex chars of the peer's public key.
    pub id: String,
    /// Full hex-encoded 32-byte X25519 public key.
    pub pk_hex: String,
    /// User-visible label (e.g. "Pixel 8").
    pub label: String,
    /// RFC3339 timestamp of pairing.
    pub paired_at: String,
    /// Last successful sync, RFC3339. None if never synced.
    pub last_synced_at: Option<String>,
    /// Hex-encoded 32-byte shared secret established during pairing (mobile peers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_secret: Option<String>,
}

pub fn list(db: &Database) -> Result<Vec<Peer>, String> {
    let raw = match db.get_setting(SETTING_KEY)? {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn save(db: &Database, peers: &[Peer]) -> Result<(), String> {
    let raw = serde_json::to_string(peers).map_err(|e| e.to_string())?;
    db.set_setting(SETTING_KEY, &raw)
}

pub fn upsert(db: &Database, peer: Peer) -> Result<(), String> {
    let mut peers = list(db)?;
    if let Some(existing) = peers.iter_mut().find(|p| p.id == peer.id) {
        *existing = peer;
    } else {
        peers.push(peer);
    }
    save(db, &peers)
}

pub fn remove(db: &Database, id: &str) -> Result<(), String> {
    let mut peers = list(db)?;
    peers.retain(|p| p.id != id);
    save(db, &peers)
}

pub fn peer_id_from_pk(pk_hex: &str) -> String {
    pk_hex.chars().take(8).collect()
}

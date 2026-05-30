// Sync wire protocol — Hello / VaultMeta / Index / Want / Rows / Bye.
// See docs/sync-protocol.md.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::crypto::Envelope;
use crate::db::Database;
use crate::sync::transport::Session;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    Hello { device: String, vault_meta_hash: String },
    VaultMeta { vault_meta: VaultMetaWire },
    Index { rows: Vec<IndexRow> },
    Want  { ids: Vec<RowId> },
    Rows  { rows: Vec<Row> },
    Bye,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetaWire {
    pub kdf: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub verifier: Envelope,
    pub updated_at: Option<String>,
    /// New master key wrapped under the previous key (present only on a meta
    /// produced by a password rotation). Lets a peer holding the old key adopt
    /// the rotation without the new password. Older builds ignore it.
    /// Omitted from the wire when absent so a non-rotated meta keeps the same
    /// hash across versions (no spurious meta exchanges).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_token: Option<Envelope>,
    /// Salt of the key that `rekey_token` is wrapped under, so a peer can tell
    /// whether its current key is the one that can unwrap the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_salt: Option<String>,
    /// Verifier of the previous key — lets a peer derive/confirm the old key
    /// (e.g. by prompting for the old password) when it isn't already unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_verifier: Option<Envelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexRow {
    pub table: String,
    pub id: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowId {
    pub table: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub table: String,
    pub row: serde_json::Value,
}

// ─── Helpers ─────────────────────────────────────────────────

pub fn vault_meta_hash(meta: &VaultMetaWire) -> String {
    let canonical = serde_json::to_vec(meta).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(&canonical);
    hex::encode(h.finalize())
}

pub fn load_vault_meta(db: &Database) -> Result<Option<VaultMetaWire>, String> {
    db.get_vault_meta_wire()
}

// ─── Sync state machine (both sides drive the same loop) ─────

pub struct SyncStats {
    pub pulled: usize,
    pub pushed: usize,
}

/// Run a full bidirectional sync over an established Noise transport.
/// The caller is responsible for handshake + setting up `session`.
pub async fn run_sync(
    stream: &mut TcpStream,
    session: &mut Session,
    db: &Database,
    device_label: &str,
) -> Result<SyncStats, String> {
    // 1. Hello exchange
    let our_meta = load_vault_meta(db)?;
    let our_hash = our_meta.as_ref().map(vault_meta_hash).unwrap_or_default();
    session.send(stream, &Message::Hello {
        device: device_label.into(),
        vault_meta_hash: our_hash.clone(),
    }).await?;

    let peer_hello: Message = session.recv(stream).await?;
    let peer_meta_hash = match peer_hello {
        Message::Hello { vault_meta_hash, .. } => vault_meta_hash,
        _ => return Err("expected Hello".into()),
    };

    // 2. Vault meta exchange if hashes diverge
    if our_hash != peer_meta_hash {
        if let Some(meta) = our_meta.as_ref() {
            session.send(stream, &Message::VaultMeta { vault_meta: meta.clone() }).await?;
        }
        // Receive the peer's VaultMeta (only if they have one). Newer wins
        // by updated_at — if ours is older or missing, persist theirs.
        let msg: Message = session.recv(stream).await?;
        if let Message::VaultMeta { vault_meta } = msg {
            apply_vault_meta_if_newer(db, &vault_meta, &our_meta)?;
        }
    }

    // 3. Index exchange
    let our_index = build_index(db)?;
    session.send(stream, &Message::Index { rows: our_index.clone() }).await?;
    let peer_index = match session.recv::<Message>(stream).await? {
        Message::Index { rows } => rows,
        _ => return Err("expected Index".into()),
    };

    // 4. Diff: figure out which rows we want from the peer.
    let want_from_peer = diff_want(&our_index, &peer_index);
    let want_from_us   = diff_want(&peer_index, &our_index);

    session.send(stream, &Message::Want { ids: want_from_peer.clone() }).await?;
    let peer_want = match session.recv::<Message>(stream).await? {
        Message::Want { ids } => ids,
        _ => return Err("expected Want".into()),
    };

    // 5. Send rows the peer asked for
    let rows_to_send = collect_rows(db, &peer_want)?;
    session.send(stream, &Message::Rows { rows: rows_to_send }).await?;
    let pushed = peer_want.len();
    let _ = want_from_us; // (only informational on this side)

    // 6. Receive rows we asked for
    let pulled_rows = match session.recv::<Message>(stream).await? {
        Message::Rows { rows } => rows,
        _ => return Err("expected Rows".into()),
    };
    let pulled = pulled_rows.len();
    apply_rows(db, &pulled_rows)?;

    // 7. Bye
    session.send(stream, &Message::Bye).await?;
    let _: Option<Message> = session.recv(stream).await.ok();

    Ok(SyncStats { pulled, pushed })
}

pub async fn run_sync_mobile(
    stream: &mut TcpStream,
    session: &mut crate::sync::transport::MobileSession,
    db: &Database,
    device_label: &str,
) -> Result<SyncStats, String> {
    // 1. Hello exchange
    let our_meta = load_vault_meta(db)?;
    let our_hash = our_meta.as_ref().map(vault_meta_hash).unwrap_or_default();
    session.send(stream, &Message::Hello {
        device: device_label.into(),
        vault_meta_hash: our_hash.clone(),
    }).await?;

    let peer_hello: Message = session.recv(stream).await?;
    let peer_meta_hash = match peer_hello {
        Message::Hello { vault_meta_hash, .. } => vault_meta_hash,
        _ => return Err("expected Hello".into()),
    };

    // 2. Vault meta exchange if hashes diverge
    if our_hash != peer_meta_hash {
        if let Some(meta) = our_meta.as_ref() {
            session.send(stream, &Message::VaultMeta { vault_meta: meta.clone() }).await?;
        }
        let msg: Message = session.recv(stream).await?;
        if let Message::VaultMeta { vault_meta } = msg {
            apply_vault_meta_if_newer(db, &vault_meta, &our_meta)?;
        }
    }

    // 3. Index exchange
    let our_index = build_index(db)?;
    session.send(stream, &Message::Index { rows: our_index.clone() }).await?;
    let peer_index = match session.recv::<Message>(stream).await? {
        Message::Index { rows } => rows,
        _ => return Err("expected Index".into()),
    };

    // 4. Diff
    let want_from_peer = diff_want(&our_index, &peer_index);
    session.send(stream, &Message::Want { ids: want_from_peer.clone() }).await?;
    let peer_want = match session.recv::<Message>(stream).await? {
        Message::Want { ids } => ids,
        _ => return Err("expected Want".into()),
    };

    // 5. Send rows
    let rows_to_send = collect_rows(db, &peer_want)?;
    session.send(stream, &Message::Rows { rows: rows_to_send }).await?;
    let pushed = peer_want.len();

    // 6. Receive rows
    let pulled_rows = match session.recv::<Message>(stream).await? {
        Message::Rows { rows } => rows,
        _ => return Err("expected Rows".into()),
    };
    let pulled = pulled_rows.len();
    apply_rows(db, &pulled_rows)?;

    // 7. Bye
    session.send(stream, &Message::Bye).await?;
    let _: Option<Message> = session.recv(stream).await.ok();

    Ok(SyncStats { pulled, pushed })
}

// ─── Diff & DB I/O ────────────────────────────────────────────

fn build_index(db: &Database) -> Result<Vec<IndexRow>, String> {
    let mut out = Vec::new();
    out.extend(db.sync_index_table("connections")?);
    out.extend(db.sync_index_table("ssh_keys")?);
    out.extend(db.sync_index_table("snippets")?);
    out.extend(db.sync_index_table("groups")?);
    Ok(out)
}

fn diff_want(local: &[IndexRow], remote: &[IndexRow]) -> Vec<RowId> {
    use std::collections::HashMap;
    let local_map: HashMap<(String, String), &IndexRow> = local
        .iter()
        .map(|r| ((r.table.clone(), r.id.clone()), r))
        .collect();

    let mut want = Vec::new();
    for r in remote {
        let key = (r.table.clone(), r.id.clone());
        match local_map.get(&key) {
            None => want.push(RowId { table: r.table.clone(), id: r.id.clone() }),
            Some(ours) => {
                // Want the peer's row if theirs is newer.
                if r.updated_at > ours.updated_at {
                    want.push(RowId { table: r.table.clone(), id: r.id.clone() });
                }
            }
        }
    }
    want
}

fn collect_rows(db: &Database, ids: &[RowId]) -> Result<Vec<Row>, String> {
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(value) = db.sync_get_row(&id.table, &id.id)? {
            rows.push(Row { table: id.table.clone(), row: value });
        }
    }
    Ok(rows)
}

fn apply_rows(db: &Database, rows: &[Row]) -> Result<(), String> {
    for r in rows {
        db.sync_upsert_row(&r.table, &r.row)?;
    }
    Ok(())
}

fn apply_vault_meta_if_newer(
    db: &Database,
    incoming: &VaultMetaWire,
    ours: &Option<VaultMetaWire>,
) -> Result<(), String> {
    match ours {
        // Fresh device with no vault yet: adopt directly — there are no
        // local secrets under an old key, so nothing can be bricked.
        None => db.set_vault_meta_wire(incoming),
        // We already have a vault. Only act if the incoming meta is strictly
        // newer (a rotation). We do NOT swap it here — doing so without
        // re-encrypting our local-only secrets to the new key would brick
        // them. Instead we park it as a pending rotation; a key-holding step
        // (vault_unlock / post-sync, see vault::apply_pending_rotation) unwraps
        // the rekey_token with the old key, re-keys every local secret, then
        // promotes it. Data-only here, so the sync path needs no master key.
        Some(o) => {
            let newer = match (o.updated_at.as_deref(), incoming.updated_at.as_deref()) {
                (Some(a), Some(b)) => b > a,
                (None, Some(_))    => true,
                _                  => false,
            };
            // Identical meta (same hash differing only by our diff trigger) or
            // older — ignore. Also ignore a "newer" meta we can't ever adopt
            // (no token and not the same vault), to avoid a permanently dirty
            // pending row; the universal new-password fallback is handled at
            // the vault layer when prev_verifier is present.
            if newer && (incoming.rekey_token.is_some() || incoming.prev_verifier.is_some()) {
                db.set_pending_rotation(incoming)?;
            }
            Ok(())
        }
    }
}

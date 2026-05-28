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
    let Some((kdf, verifier)) = db.get_vault_meta()? else { return Ok(None) };
    Ok(Some(VaultMetaWire {
        kdf: kdf.kdf,
        salt: kdf.salt,
        m_cost: kdf.m_cost,
        t_cost: kdf.t_cost,
        p_cost: kdf.p_cost,
        verifier,
        updated_at: db.get_vault_meta_updated_at()?,
    }))
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
    let take = match ours {
        None => true,
        Some(o) => match (o.updated_at.as_deref(), incoming.updated_at.as_deref()) {
            (Some(a), Some(b)) => b > a,
            (None, Some(_))     => true,
            _                    => false,
        },
    };
    if !take { return Ok(()); }
    // We never overwrite a working vault_meta automatically — that would
    // brick the local vault. Instead we accept only if local has none.
    if ours.is_none() {
        db.set_vault_meta_wire(incoming)?;
    }
    Ok(())
}

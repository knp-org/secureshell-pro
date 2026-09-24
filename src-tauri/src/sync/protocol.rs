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
    Hello {
        device: String,
        vault_meta_hash: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },
    VaultMeta {
        vault_meta: VaultMetaWire,
    },
    Index {
        rows: Vec<IndexRow>,
    },
    Want {
        ids: Vec<RowId>,
    },
    Rows {
        rows: Vec<Row>,
    },
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

pub async fn run_sync(
    stream: &mut TcpStream,
    session: &mut Session,
    db: &Database,
    device_label: &str,
) -> Result<SyncStats, String> {
    let our_meta = load_vault_meta(db)?;
    let our_hash = our_meta.as_ref().map(vault_meta_hash).unwrap_or_default();
    let hello: Message = session
        .exchange(
            stream,
            &Message::Hello {
                device: device_label.into(),
                vault_meta_hash: our_hash.clone(),
                capabilities: vec!["chunks-v1".into()],
            },
        )
        .await?;
    let peer_hash = match hello {
        Message::Hello {
            vault_meta_hash,
            capabilities,
            ..
        } => {
            session.chunked = capabilities.iter().any(|c| c == "chunks-v1");
            vault_meta_hash
        }
        _ => return Err("expected Hello".into()),
    };
    if our_hash != peer_hash {
        let incoming = match (our_meta.as_ref(), peer_hash.is_empty()) {
            (Some(meta), false) => Some(
                session
                    .exchange::<_, Message>(
                        stream,
                        &Message::VaultMeta {
                            vault_meta: meta.clone(),
                        },
                    )
                    .await?,
            ),
            (Some(meta), true) => {
                session
                    .send(
                        stream,
                        &Message::VaultMeta {
                            vault_meta: meta.clone(),
                        },
                    )
                    .await?;
                None
            }
            (None, false) => Some(session.recv::<Message>(stream).await?),
            (None, true) => None,
        };
        if let Some(message) = incoming {
            let Message::VaultMeta { vault_meta } = message else {
                return Err("expected VaultMeta".into());
            };
            if vault_meta_hash(&vault_meta) != peer_hash {
                return Err("Vault metadata hash mismatch".into());
            }
            apply_vault_meta_if_newer(db, &vault_meta, &our_meta)?;
        }
    }
    let our_index = build_index(db)?;
    let peer_index = match session
        .exchange(
            stream,
            &Message::Index {
                rows: our_index.clone(),
            },
        )
        .await?
    {
        Message::Index { rows } => rows,
        _ => return Err("expected Index".into()),
    };
    let wanted = diff_want(&our_index, &peer_index);
    let peer_want = match session
        .exchange(stream, &Message::Want { ids: wanted })
        .await?
    {
        Message::Want { ids } => ids,
        _ => return Err("expected Want".into()),
    };
    let rows = collect_rows(db, &peer_want)?;
    let pushed = rows.len();
    let pulled_rows = match session.exchange(stream, &Message::Rows { rows }).await? {
        Message::Rows { rows } => rows,
        _ => return Err("expected Rows".into()),
    };
    let pulled = pulled_rows.len();
    apply_rows(db, &pulled_rows)?;
    let _: Message = session.exchange(stream, &Message::Bye).await?;
    Ok(SyncStats { pulled, pushed })
}

pub async fn run_sync_mobile(
    stream: &mut TcpStream,
    session: &mut crate::sync::transport::MobileSession,
    db: &Database,
    device_label: &str,
) -> Result<SyncStats, String> {
    let our_meta = load_vault_meta(db)?;
    let our_hash = our_meta.as_ref().map(vault_meta_hash).unwrap_or_default();
    let hello: Message = session
        .exchange(
            stream,
            &Message::Hello {
                device: device_label.into(),
                vault_meta_hash: our_hash.clone(),
                capabilities: vec!["chunks-v1".into()],
            },
        )
        .await?;
    let peer_hash = match hello {
        Message::Hello {
            vault_meta_hash,
            capabilities,
            ..
        } => {
            session.chunked = capabilities.iter().any(|c| c == "chunks-v1");
            vault_meta_hash
        }
        _ => return Err("expected Hello".into()),
    };
    if our_hash != peer_hash {
        let incoming = match (our_meta.as_ref(), peer_hash.is_empty()) {
            (Some(meta), false) => Some(
                session
                    .exchange::<_, Message>(
                        stream,
                        &Message::VaultMeta {
                            vault_meta: meta.clone(),
                        },
                    )
                    .await?,
            ),
            (Some(meta), true) => {
                session
                    .send(
                        stream,
                        &Message::VaultMeta {
                            vault_meta: meta.clone(),
                        },
                    )
                    .await?;
                None
            }
            (None, false) => Some(session.recv::<Message>(stream).await?),
            (None, true) => None,
        };
        if let Some(message) = incoming {
            let Message::VaultMeta { vault_meta } = message else {
                return Err("expected VaultMeta".into());
            };
            if vault_meta_hash(&vault_meta) != peer_hash {
                return Err("Vault metadata hash mismatch".into());
            }
            apply_vault_meta_if_newer(db, &vault_meta, &our_meta)?;
        }
    }
    let our_index = build_index(db)?;
    let peer_index = match session
        .exchange(
            stream,
            &Message::Index {
                rows: our_index.clone(),
            },
        )
        .await?
    {
        Message::Index { rows } => rows,
        _ => return Err("expected Index".into()),
    };
    let wanted = diff_want(&our_index, &peer_index);
    let peer_want = match session
        .exchange(stream, &Message::Want { ids: wanted })
        .await?
    {
        Message::Want { ids } => ids,
        _ => return Err("expected Want".into()),
    };
    let rows = collect_rows(db, &peer_want)?;
    let pushed = rows.len();
    let pulled_rows = match session.exchange(stream, &Message::Rows { rows }).await? {
        Message::Rows { rows } => rows,
        _ => return Err("expected Rows".into()),
    };
    let pulled = pulled_rows.len();
    apply_rows(db, &pulled_rows)?;
    let _: Message = session.exchange(stream, &Message::Bye).await?;
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
            None => want.push(RowId {
                table: r.table.clone(),
                id: r.id.clone(),
            }),
            Some(ours) => {
                // Want the peer's row if theirs is newer.
                if r.updated_at > ours.updated_at {
                    want.push(RowId {
                        table: r.table.clone(),
                        id: r.id.clone(),
                    });
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
            rows.push(Row {
                table: id.table.clone(),
                row: value,
            });
        }
    }
    Ok(rows)
}

fn apply_rows(db: &Database, rows: &[Row]) -> Result<(), String> {
    db.sync_apply_rows(rows)
}

fn apply_vault_meta_if_newer(
    db: &Database,
    incoming: &VaultMetaWire,
    ours: &Option<VaultMetaWire>,
) -> Result<(), String> {
    let Some(ours) = ours else {
        // Legacy plaintext must be migrated locally before adopting another vault.
        if db
            .get_all_connections()?
            .iter()
            .any(|c| c.password.is_some())
            || db.get_all_keys()?.iter().any(|k| k.private_key.is_some())
        {
            return Err("Initialize the local vault before syncing existing credentials".into());
        }
        return db.set_vault_meta_wire(incoming);
    };
    if same_vault_key(ours, incoming) {
        return Ok(());
    }
    if incoming.prev_salt.as_deref() == Some(ours.salt.as_str())
        && incoming
            .prev_verifier
            .as_ref()
            .map(|v| serde_json::to_string(v).ok())
            == Some(serde_json::to_string(&ours.verifier).ok())
        && incoming.rekey_token.is_some()
    {
        db.set_pending_rotation(incoming)?;
        return Err(
            "Vault password rotation received. Lock and unlock the vault, then sync again.".into(),
        );
    }
    if ours.prev_salt.as_deref() == Some(incoming.salt.as_str())
        && ours
            .prev_verifier
            .as_ref()
            .map(|v| serde_json::to_string(v).ok())
            == Some(serde_json::to_string(&incoming.verifier).ok())
        && ours.rekey_token.is_some()
    {
        return Err("The peer must lock and unlock its vault to adopt the password rotation, then sync again.".into());
    }
    Err("These devices use different vault keys. Sync stopped without importing credentials. Pair a fresh vault or restore a shared vault backup first.".into())
}

fn same_vault_key(a: &VaultMetaWire, b: &VaultMetaWire) -> bool {
    a.kdf == b.kdf
        && a.salt == b.salt
        && a.m_cost == b.m_cost
        && a.t_cost == b.t_cost
        && a.p_cost == b.p_cost
        && serde_json::to_string(&a.verifier).ok() == serde_json::to_string(&b.verifier).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, KdfParams, MasterKey};
    fn init(db: &Database, key: &MasterKey) {
        db.run_initial_encryption(
            key,
            &KdfParams::new_random(),
            &crypto::make_verifier(key).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn unrelated_vault_is_rejected_without_changing_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let first = Database::new(dir.path().join("a.db")).unwrap();
        let second = Database::new(dir.path().join("b.db")).unwrap();
        init(&first, &MasterKey([1; 32]));
        init(&second, &MasterKey([2; 32]));
        let original = load_vault_meta(&first).unwrap();
        assert!(apply_vault_meta_if_newer(
            &first,
            &load_vault_meta(&second).unwrap().unwrap(),
            &original
        )
        .is_err());
        assert_eq!(
            vault_meta_hash(&load_vault_meta(&first).unwrap().unwrap()),
            vault_meta_hash(&original.unwrap())
        );
        assert!(first.get_pending_rotation().unwrap().is_none());
    }

    #[test]
    fn rotation_is_staged_before_any_ciphertext_is_imported() {
        let dir = tempfile::tempdir().unwrap();
        let first = Database::new(dir.path().join("a.db")).unwrap();
        let second = Database::new(dir.path().join("b.db")).unwrap();
        let old = MasterKey([1; 32]);
        let new = MasterKey([2; 32]);
        init(&first, &old);
        let meta = load_vault_meta(&first).unwrap().unwrap();
        second.set_vault_meta_wire(&meta).unwrap();
        let (kdf, verifier) = first.get_vault_meta().unwrap().unwrap();
        first
            .run_rekey(
                &old,
                &new,
                &KdfParams::new_random(),
                &crypto::make_verifier(&new).unwrap(),
                &kdf,
                &verifier,
            )
            .unwrap();
        let rotated = load_vault_meta(&first).unwrap().unwrap();
        assert!(apply_vault_meta_if_newer(&second, &rotated, &Some(meta.clone())).is_err());
        assert!(second.get_pending_rotation().unwrap().is_some());
        assert!(same_vault_key(
            &load_vault_meta(&second).unwrap().unwrap(),
            &meta
        ));
        let recovered = crate::vault::apply_pending_rotation(&second, &old)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.0, new.0);
        assert!(same_vault_key(
            &load_vault_meta(&second).unwrap().unwrap(),
            &rotated
        ));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::crypto::{self, KdfParams, MasterKey};
    use crate::sync::transport::MobileSession;
    use serde_json::json;

    #[tokio::test]
    async fn full_sync_handles_large_grouped_data_and_fresh_vault() {
        let dir = tempfile::tempdir().unwrap();
        let source = Database::new(dir.path().join("source.db")).unwrap();
        let target = Database::new(dir.path().join("target.db")).unwrap();
        source
            .run_initial_encryption(
                &MasterKey([1; 32]),
                &KdfParams::new_random(),
                &crypto::make_verifier(&MasterKey([1; 32])).unwrap(),
            )
            .unwrap();
        let mut rows = vec![Row {
            table: "groups".into(),
            row: json!({"id":"folder", "name":"Folder", "created_at":"2026-01-01"}),
        }];
        for index in 0..200 {
            rows.push(Row {
                table: "snippets".into(),
                row: json!({
                    "id":format!("snippet-{index}"), "label":"Snippet", "command":"x".repeat(2000),
                    "group_id":"folder", "tags":"[]", "connection_ids":"[]", "sort_order":0,
                    "created_at":"2026-01-01", "updated_at":"2026-01-01"
                }),
            });
        }
        source.sync_apply_rows(&rows).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            run_sync_mobile(
                &mut stream,
                &mut MobileSession::new([9; 32]),
                &source,
                "Source",
            )
            .await
            .unwrap()
        };
        let client = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            run_sync_mobile(
                &mut stream,
                &mut MobileSession::new([9; 32]),
                &target,
                "Target",
            )
            .await
            .unwrap()
        };
        let (sent, received) = tokio::join!(server, client);
        assert_eq!(sent.pushed, 201);
        assert_eq!(received.pulled, 201);
        assert_eq!(target.get_all_snippets().unwrap().len(), 200);
        assert_eq!(target.get_all_groups().unwrap().len(), 1);
        assert!(same_vault_key(
            &load_vault_meta(&source).unwrap().unwrap(),
            &load_vault_meta(&target).unwrap().unwrap()
        ));
    }
}

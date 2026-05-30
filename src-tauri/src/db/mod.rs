pub mod migrations;
pub mod models;

use base64::Engine as _;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;

use self::models::{Connection as SshConnection, Group, Snippet, SshKey};
use crate::crypto::{self, Envelope, KdfParams, MasterKey};

/// Database manager wrapping SQLite
pub struct Database {
    pub conn: Mutex<Connection>,
    pub path: PathBuf,
}

impl Database {
    /// Initialize database at the given path
    pub fn new(db_path: PathBuf) -> Result<Self, rusqlite::Error> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        migrations::run_migrations(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: db_path,
        })
    }

    // ─── Vault metadata ────────────────────────────────────────

    pub fn get_vault_meta(&self) -> Result<Option<(KdfParams, Envelope)>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT kdf, salt, m_cost, t_cost, p_cost, verifier FROM vault_meta WHERE id = 1")
            .map_err(|e| e.to_string())?;

        let row = stmt
            .query_row([], |row| {
                let kdf: String = row.get(0)?;
                let salt: String = row.get(1)?;
                let m_cost: i64 = row.get(2)?;
                let t_cost: i64 = row.get(3)?;
                let p_cost: i64 = row.get(4)?;
                let verifier_json: String = row.get(5)?;
                Ok((kdf, salt, m_cost, t_cost, p_cost, verifier_json))
            })
            .ok();

        let Some((kdf, salt, m_cost, t_cost, p_cost, verifier_json)) = row else {
            return Ok(None);
        };
        let params = KdfParams { kdf, salt, m_cost: m_cost as u32, t_cost: t_cost as u32, p_cost: p_cost as u32 };
        let verifier: Envelope = serde_json::from_str(&verifier_json).map_err(|e| e.to_string())?;
        Ok(Some((params, verifier)))
    }

    /// Copy the SQLite file alongside itself with a `.bak.<ts>` suffix.
    /// Best-effort — failure is non-fatal.
    pub fn backup_to_sibling(&self) -> Result<PathBuf, String> {
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string();
        let mut bak = self.path.clone();
        let fname = bak.file_name().and_then(|n| n.to_str()).unwrap_or("secureshell.db").to_string();
        bak.set_file_name(format!("{}.bak.{}", fname, ts));
        std::fs::copy(&self.path, &bak).map_err(|e| e.to_string())?;
        Ok(bak)
    }

    /// One-shot: encrypt every plaintext secret in `connections` and
    /// `ssh_keys`, then write `vault_meta`. All inside a single transaction.
    pub fn run_initial_encryption(
        &self,
        key: &MasterKey,
        kdf: &KdfParams,
        verifier: &Envelope,
    ) -> Result<(), String> {
        let mut conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        // Connections
        {
            let mut select = tx
                .prepare("SELECT id, password FROM connections WHERE password IS NOT NULL")
                .map_err(|e| e.to_string())?;
            let rows: Vec<(String, String)> = select
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?
                .filter_map(|r| r.ok())
                .collect();
            drop(select);
            for (id, pw) in rows {
                if pw.is_empty() || crypto::is_envelope(&pw) {
                    continue;
                }
                let env = crypto::encrypt_field(&pw, key, &id).map_err(|e| e.to_string())?;
                tx.execute(
                    "UPDATE connections SET password = ?1 WHERE id = ?2",
                    rusqlite::params![env, id],
                )
                .map_err(|e| e.to_string())?;
            }
        }

        // SSH keys
        {
            let mut select = tx
                .prepare("SELECT id, private_key FROM ssh_keys WHERE private_key IS NOT NULL")
                .map_err(|e| e.to_string())?;
            let rows: Vec<(String, String)> = select
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?
                .filter_map(|r| r.ok())
                .collect();
            drop(select);
            for (id, pk) in rows {
                if pk.is_empty() || crypto::is_envelope(&pk) {
                    continue;
                }
                let env = crypto::encrypt_field(&pk, key, &id).map_err(|e| e.to_string())?;
                tx.execute(
                    "UPDATE ssh_keys SET private_key = ?1 WHERE id = ?2",
                    rusqlite::params![env, id],
                )
                .map_err(|e| e.to_string())?;
            }
        }

        // vault_meta
        let verifier_json = serde_json::to_string(verifier).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO vault_meta (id, kdf, salt, m_cost, t_cost, p_cost, verifier, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                kdf.kdf,
                kdf.salt,
                kdf.m_cost as i64,
                kdf.t_cost as i64,
                kdf.p_cost as i64,
                verifier_json,
                chrono::Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Re-encrypt every stored secret from `old_key` to `new_key`, then rewrite
    /// `vault_meta` with the new KDF params + verifier. Used when the user
    /// changes their master password. The whole rotation runs in a single
    /// transaction: either all rows and the meta are updated, or nothing is.
    ///
    /// Record ids (the AAD) are stable, so each secret is simply unwrapped with
    /// the old key and re-wrapped with the new one. Any legacy plaintext field
    /// is encrypted fresh under the new key.
    pub fn run_rekey(
        &self,
        old_key: &MasterKey,
        new_key: &MasterKey,
        new_kdf: &KdfParams,
        new_verifier: &Envelope,
        old_kdf: &KdfParams,
        old_verifier: &Envelope,
    ) -> Result<(), String> {
        // Wrap the new key under the old one so paired peers can adopt this
        // rotation without the new password. Built outside the lock.
        let rekey_token = crypto::wrap_master_key(new_key, old_key).map_err(|e| e.to_string())?;
        let rekey_token_json = serde_json::to_string(&rekey_token).map_err(|e| e.to_string())?;
        let prev_verifier_json = serde_json::to_string(old_verifier).map_err(|e| e.to_string())?;
        let prev_salt = old_kdf.salt.clone();

        let mut conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        // Re-wrap one secret column for every row that has a value. Bumping
        // updated_at makes the re-encrypted secret win on the next LAN sync, so
        // paired peers receive ciphertext that matches the new vault key.
        let now = chrono::Utc::now().to_rfc3339();
        let rekey_column = |table: &str, column: &str| -> Result<(), String> {
            let sql = format!("SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL");
            let mut select = tx.prepare(&sql).map_err(|e| e.to_string())?;
            let rows: Vec<(String, String)> = select
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?
                .filter_map(|r| r.ok())
                .collect();
            drop(select);
            for (id, stored) in rows {
                if stored.is_empty() {
                    continue;
                }
                let plaintext = if crypto::is_envelope(&stored) {
                    crypto::decrypt_field(&stored, old_key, &id).map_err(|e| e.to_string())?
                } else {
                    stored // legacy plaintext that was never wrapped
                };
                let env = crypto::encrypt_field(&plaintext, new_key, &id).map_err(|e| e.to_string())?;
                let update = format!("UPDATE {table} SET {column} = ?1, updated_at = ?2 WHERE id = ?3");
                tx.execute(&update, rusqlite::params![env, now, id]).map_err(|e| e.to_string())?;
            }
            Ok(())
        };

        rekey_column("connections", "password")?;
        rekey_column("ssh_keys", "private_key")?;

        // vault_meta — swap in the new salt/params + verifier, plus the re-wrap
        // token and the previous salt/verifier so the rotation can be adopted
        // by peers. Bump updated_at so the rotation propagates on the next sync.
        let verifier_json = serde_json::to_string(new_verifier).map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE vault_meta
             SET kdf = ?1, salt = ?2, m_cost = ?3, t_cost = ?4, p_cost = ?5, verifier = ?6,
                 rekey_token = ?7, prev_salt = ?8, prev_verifier = ?9, updated_at = ?10
             WHERE id = 1",
            rusqlite::params![
                new_kdf.kdf,
                new_kdf.salt,
                new_kdf.m_cost as i64,
                new_kdf.t_cost as i64,
                new_kdf.p_cost as i64,
                verifier_json,
                rekey_token_json,
                prev_salt,
                prev_verifier_json,
                chrono::Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Re-key every stored secret from `old_key` to `new_key` and atomically
    /// promote `meta` to the active `vault_meta`, then clear the pending row.
    /// Used when adopting a rotation received over sync. Unlike [`run_rekey`]
    /// this does NOT bump row `updated_at`: the ciphertext is being brought in
    /// line with a meta the peer already authored, so it must not "win" back
    /// over the peer on the next sync.
    pub fn promote_pending_rotation(
        &self,
        old_key: &MasterKey,
        new_key: &MasterKey,
        meta: &crate::sync::protocol::VaultMetaWire,
    ) -> Result<(), String> {
        let verifier_json = serde_json::to_string(&meta.verifier).map_err(|e| e.to_string())?;
        let rekey_token_json = meta
            .rekey_token
            .as_ref()
            .map(|e| serde_json::to_string(e))
            .transpose()
            .map_err(|e| e.to_string())?;
        let prev_verifier_json = meta
            .prev_verifier
            .as_ref()
            .map(|e| serde_json::to_string(e))
            .transpose()
            .map_err(|e| e.to_string())?;

        let mut conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;

        let rekey_column = |table: &str, column: &str| -> Result<(), String> {
            let sql = format!("SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL");
            let mut select = tx.prepare(&sql).map_err(|e| e.to_string())?;
            let rows: Vec<(String, String)> = select
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?
                .filter_map(|r| r.ok())
                .collect();
            drop(select);
            for (id, stored) in rows {
                if stored.is_empty() || !crypto::is_envelope(&stored) {
                    continue;
                }
                // Rows the peer already re-encrypted are under the new key and
                // won't decrypt with the old key — leave those untouched. Only
                // rows still readable with the old key (our local-only secrets)
                // need re-wrapping to the new key.
                let Ok(plaintext) = crypto::decrypt_field(&stored, old_key, &id) else {
                    continue;
                };
                let env = crypto::encrypt_field(&plaintext, new_key, &id).map_err(|e| e.to_string())?;
                let update = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
                tx.execute(&update, rusqlite::params![env, id]).map_err(|e| e.to_string())?;
            }
            Ok(())
        };
        rekey_column("connections", "password")?;
        rekey_column("ssh_keys", "private_key")?;

        tx.execute(
            "INSERT OR REPLACE INTO vault_meta
             (id, kdf, salt, m_cost, t_cost, p_cost, verifier, created_at, rekey_token, prev_salt, prev_verifier, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6,
                     COALESCE((SELECT created_at FROM vault_meta WHERE id = 1), ?7),
                     ?8, ?9, ?10, ?11)",
            rusqlite::params![
                meta.kdf,
                meta.salt,
                meta.m_cost as i64,
                meta.t_cost as i64,
                meta.p_cost as i64,
                verifier_json,
                chrono::Utc::now().to_rfc3339(),
                rekey_token_json,
                meta.prev_salt,
                prev_verifier_json,
                meta.updated_at.clone().unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            ],
        )
        .map_err(|e| e.to_string())?;

        tx.execute("DELETE FROM pending_vault_rotation WHERE id = 1", [])
            .map_err(|e| e.to_string())?;

        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── Connections ───────────────────────────────────────────

    pub fn get_all_connections(&self) -> Result<Vec<SshConnection>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT id, name, host, port, username, auth_method, password, key_id, group_id, tags, color, last_connected, created_at, updated_at, synced FROM connections ORDER BY name ASC")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                let tags_str: String = row.get(9)?;
                let tags: Vec<String> =
                    serde_json::from_str(&tags_str).unwrap_or_default();
                let synced_int: i32 = row.get(14)?;

                Ok(SshConnection {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    host: row.get(2)?,
                    port: row.get::<_, i32>(3)? as u16,
                    username: row.get(4)?,
                    auth_method: row.get(5)?,
                    password: row.get(6)?,
                    key_id: row.get(7)?,
                    group_id: row.get(8)?,
                    tags,
                    color: row.get(10)?,
                    last_connected: row.get(11)?,
                    created_at: row.get(12)?,
                    updated_at: row.get(13)?,
                    synced: synced_int != 0,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut connections = Vec::new();
        for row in rows {
            connections.push(row.map_err(|e| e.to_string())?);
        }
        Ok(connections)
    }

    pub fn save_connection(&self, conn_data: &SshConnection) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tags_json = serde_json::to_string(&conn_data.tags).unwrap_or_default();

        conn.execute(
            "INSERT OR REPLACE INTO connections (id, name, host, port, username, auth_method, password, key_id, group_id, tags, color, last_connected, created_at, updated_at, synced) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                conn_data.id,
                conn_data.name,
                conn_data.host,
                conn_data.port as i32,
                conn_data.username,
                conn_data.auth_method,
                conn_data.password,
                conn_data.key_id,
                conn_data.group_id,
                tags_json,
                conn_data.color,
                conn_data.last_connected,
                conn_data.created_at,
                conn_data.updated_at,
                conn_data.synced as i32,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_connection(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM connections WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── Snippets ──────────────────────────────────────────────

    pub fn get_all_snippets(&self) -> Result<Vec<Snippet>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT id, label, command, description, tags, connection_ids, group_id, created_at, updated_at, synced FROM snippets ORDER BY label ASC")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                let tags_str: String = row.get(4)?;
                let conn_ids_str: String = row.get(5)?;
                let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
                let connection_ids: Vec<String> =
                    serde_json::from_str(&conn_ids_str).unwrap_or_default();
                let synced_int: i32 = row.get(9)?;

                Ok(Snippet {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    command: row.get(2)?,
                    description: row.get(3)?,
                    tags,
                    connection_ids,
                    group_id: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                    synced: synced_int != 0,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut snippets = Vec::new();
        for row in rows {
            snippets.push(row.map_err(|e| e.to_string())?);
        }
        Ok(snippets)
    }

    pub fn save_snippet(&self, snippet: &Snippet) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tags_json = serde_json::to_string(&snippet.tags).unwrap_or_default();
        let conn_ids_json = serde_json::to_string(&snippet.connection_ids).unwrap_or_default();

        conn.execute(
            "INSERT OR REPLACE INTO snippets (id, label, command, description, tags, connection_ids, group_id, created_at, updated_at, synced) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                snippet.id,
                snippet.label,
                snippet.command,
                snippet.description,
                tags_json,
                conn_ids_json,
                snippet.group_id,
                snippet.created_at,
                snippet.updated_at,
                snippet.synced as i32,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_snippet(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM snippets WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── SSH Keys ──────────────────────────────────────────────

    pub fn get_all_keys(&self) -> Result<Vec<SshKey>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT id, label, key_type, public_key, private_key, fingerprint, created_at, COALESCE(updated_at, created_at), synced FROM ssh_keys ORDER BY label ASC")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                let synced_int: i32 = row.get(8)?;
                Ok(SshKey {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    key_type: row.get(2)?,
                    public_key: row.get(3)?,
                    private_key: row.get(4)?,
                    fingerprint: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    synced: synced_int != 0,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row.map_err(|e| e.to_string())?);
        }
        Ok(keys)
    }

    pub fn save_key(&self, key: &SshKey) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        // Stamp updated_at server-side so every save advances the sync clock.
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO ssh_keys (id, label, key_type, public_key, private_key, fingerprint, created_at, updated_at, synced) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                key.id,
                key.label,
                key.key_type,
                key.public_key,
                key.private_key,
                key.fingerprint,
                key.created_at,
                now,
                key.synced as i32,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_key(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM ssh_keys WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── Groups ────────────────────────────────────────────────

    pub fn get_all_groups(&self) -> Result<Vec<Group>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT id, name, parent_id, icon, color, created_at FROM groups ORDER BY name ASC")
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Group {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    parent_id: row.get(2)?,
                    icon: row.get(3)?,
                    color: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut groups = Vec::new();
        for row in rows {
            groups.push(row.map_err(|e| e.to_string())?);
        }
        Ok(groups)
    }

    pub fn save_group(&self, group: &Group) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO groups (id, name, parent_id, icon, color, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                group.id,
                group.name,
                group.parent_id,
                group.icon,
                group.color,
                group.created_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_group(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        // Move connections out of group before deleting
        conn.execute(
            "UPDATE connections SET group_id = NULL WHERE group_id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "UPDATE snippets SET group_id = NULL WHERE group_id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM groups WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── Settings ──────────────────────────────────────────────

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| e.to_string())?;

        let result = stmt
            .query_row(rusqlite::params![key], |row| row.get(0))
            .ok();

        Ok(result)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── Sync helpers ─────────────────────────────────────────

    /// Full vault_meta as a wire struct, including the rotation re-wrap token
    /// and previous salt/verifier. `None` if the vault isn't initialized.
    pub fn get_vault_meta_wire(&self) -> Result<Option<crate::sync::protocol::VaultMetaWire>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let row = conn
            .query_row(
                "SELECT kdf, salt, m_cost, t_cost, p_cost, verifier, updated_at, rekey_token, prev_salt, prev_verifier
                 FROM vault_meta WHERE id = 1",
                [],
                Self::map_vault_meta_wire_row,
            )
            .ok();
        match row {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    fn map_vault_meta_wire_row(
        r: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<Result<crate::sync::protocol::VaultMetaWire, String>> {
        let kdf: String = r.get(0)?;
        let salt: String = r.get(1)?;
        let m_cost: i64 = r.get(2)?;
        let t_cost: i64 = r.get(3)?;
        let p_cost: i64 = r.get(4)?;
        let verifier_json: String = r.get(5)?;
        let updated_at: Option<String> = r.get(6)?;
        let rekey_token_json: Option<String> = r.get(7)?;
        let prev_salt: Option<String> = r.get(8)?;
        let prev_verifier_json: Option<String> = r.get(9)?;
        Ok((|| {
            let verifier: Envelope = serde_json::from_str(&verifier_json).map_err(|e| e.to_string())?;
            let rekey_token = rekey_token_json
                .as_deref()
                .map(serde_json::from_str::<Envelope>)
                .transpose()
                .map_err(|e| e.to_string())?;
            let prev_verifier = prev_verifier_json
                .as_deref()
                .map(serde_json::from_str::<Envelope>)
                .transpose()
                .map_err(|e| e.to_string())?;
            Ok(crate::sync::protocol::VaultMetaWire {
                kdf,
                salt,
                m_cost: m_cost as u32,
                t_cost: t_cost as u32,
                p_cost: p_cost as u32,
                verifier,
                updated_at,
                rekey_token,
                prev_salt,
                prev_verifier,
            })
        })())
    }

    pub fn set_vault_meta_wire(
        &self,
        meta: &crate::sync::protocol::VaultMetaWire,
    ) -> Result<(), String> {
        let verifier_json = serde_json::to_string(&meta.verifier).map_err(|e| e.to_string())?;
        let rekey_token_json = meta
            .rekey_token
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| e.to_string())?;
        let prev_verifier_json = meta
            .prev_verifier
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| e.to_string())?;
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta
             (id, kdf, salt, m_cost, t_cost, p_cost, verifier, created_at, rekey_token, prev_salt, prev_verifier, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                meta.kdf,
                meta.salt,
                meta.m_cost as i64,
                meta.t_cost as i64,
                meta.p_cost as i64,
                verifier_json,
                now.clone(),
                rekey_token_json,
                meta.prev_salt,
                prev_verifier_json,
                meta.updated_at.clone().unwrap_or(now),
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ─── Pending rotation (received over sync, awaiting key migration) ──

    pub fn set_pending_rotation(
        &self,
        meta: &crate::sync::protocol::VaultMetaWire,
    ) -> Result<(), String> {
        let verifier_json = serde_json::to_string(&meta.verifier).map_err(|e| e.to_string())?;
        let rekey_token_json = meta
            .rekey_token
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| e.to_string())?;
        let prev_verifier_json = meta
            .prev_verifier
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| e.to_string())?;
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO pending_vault_rotation
             (id, kdf, salt, m_cost, t_cost, p_cost, verifier, rekey_token, prev_salt, prev_verifier, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                meta.kdf,
                meta.salt,
                meta.m_cost as i64,
                meta.t_cost as i64,
                meta.p_cost as i64,
                verifier_json,
                rekey_token_json,
                meta.prev_salt,
                prev_verifier_json,
                meta.updated_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_pending_rotation(&self) -> Result<Option<crate::sync::protocol::VaultMetaWire>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let row = conn
            .query_row(
                "SELECT kdf, salt, m_cost, t_cost, p_cost, verifier, updated_at, rekey_token, prev_salt, prev_verifier
                 FROM pending_vault_rotation WHERE id = 1",
                [],
                Self::map_vault_meta_wire_row,
            )
            .ok();
        match row {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Discard a parked rotation (e.g. after the new-password fallback path
    /// promotes it by other means).
    #[allow(dead_code)]
    pub fn clear_pending_rotation(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM pending_vault_rotation WHERE id = 1", [])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Index a single sync-relevant table (id, updated_at, deleted_at).
    pub fn sync_index_table(&self, table: &str) -> Result<Vec<crate::sync::protocol::IndexRow>, String> {
        let (sel, has_updated) = match table {
            "connections" | "snippets" => (
                format!("SELECT id, updated_at, deleted_at FROM {}", table), true
            ),
            // ssh_keys gained updated_at; fall back to created_at for legacy rows.
            "ssh_keys" => (
                "SELECT id, COALESCE(updated_at, created_at) AS updated_at, deleted_at FROM ssh_keys".to_string(), true
            ),
            "groups" => (
                "SELECT id, created_at AS updated_at, deleted_at FROM groups".to_string(), true
            ),
            _ => return Err(format!("unknown sync table {}", table)),
        };
        let _ = has_updated;

        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(&sel).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(crate::sync::protocol::IndexRow {
                    table: table.to_string(),
                    id: r.get::<_, String>(0)?,
                    updated_at: r.get::<_, String>(1)?,
                    deleted_at: r.get::<_, Option<String>>(2)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows { out.push(r.map_err(|e| e.to_string())?); }
        Ok(out)
    }

    /// Fetch a single row as a JSON object for shipping over sync.
    pub fn sync_get_row(&self, table: &str, id: &str) -> Result<Option<serde_json::Value>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let sql = match table {
            "connections" => "SELECT id, name, host, port, username, auth_method, password, key_id, group_id, tags, color, last_connected, created_at, updated_at, deleted_at FROM connections WHERE id = ?1",
            "ssh_keys"    => "SELECT id, label, key_type, public_key, private_key, fingerprint, created_at, updated_at, deleted_at FROM ssh_keys WHERE id = ?1",
            "snippets"    => "SELECT id, label, command, description, tags, connection_ids, group_id, created_at, updated_at, deleted_at FROM snippets WHERE id = ?1",
            "groups"      => "SELECT id, name, parent_id, icon, color, created_at, deleted_at FROM groups WHERE id = ?1",
            _             => return Err(format!("unknown sync table {}", table)),
        };

        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let row = stmt.query_row(rusqlite::params![id], |r| {
            // Read all columns into a generic JSON object using column names.
            let mut obj = serde_json::Map::new();
            let cols = r.as_ref().column_names();
            let names: Vec<String> = cols.iter().map(|s| s.to_string()).collect();
            for (i, name) in names.iter().enumerate() {
                let v: Option<rusqlite::types::Value> = r.get(i)?;
                let j = match v {
                    Some(rusqlite::types::Value::Null)            => serde_json::Value::Null,
                    Some(rusqlite::types::Value::Integer(i))      => serde_json::Value::from(i),
                    Some(rusqlite::types::Value::Real(f))         => serde_json::Value::from(f),
                    Some(rusqlite::types::Value::Text(s))         => serde_json::Value::String(s),
                    Some(rusqlite::types::Value::Blob(b))         => serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b)),
                    None                                          => serde_json::Value::Null,
                };
                obj.insert(name.clone(), j);
            }
            Ok(serde_json::Value::Object(obj))
        });
        match row {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Upsert a row received over sync. The row is a JSON object whose
    /// keys correspond to the columns of the target table.
    pub fn sync_upsert_row(&self, table: &str, row: &serde_json::Value) -> Result<(), String> {
        let obj = row.as_object().ok_or_else(|| "row must be a JSON object".to_string())?;
        let id = obj.get("id").and_then(|v| v.as_str())
            .ok_or_else(|| "row missing id".to_string())?
            .to_string();

        let columns: &[&str] = match table {
            "connections" => &["id","name","host","port","username","auth_method","password","key_id","group_id","tags","color","last_connected","created_at","updated_at","deleted_at"],
            "ssh_keys"    => &["id","label","key_type","public_key","private_key","fingerprint","created_at","updated_at","deleted_at"],
            "snippets"    => &["id","label","command","description","tags","connection_ids","group_id","created_at","updated_at","deleted_at"],
            "groups"      => &["id","name","parent_id","icon","color","created_at","deleted_at"],
            _             => return Err(format!("unknown sync table {}", table)),
        };

        let placeholders: Vec<String> = (1..=columns.len()).map(|i| format!("?{}", i)).collect();
        let sql = format!(
            "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
            table,
            columns.join(","),
            placeholders.join(","),
        );

        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let values: Vec<rusqlite::types::Value> = columns.iter().map(|c| {
            match obj.get(*c) {
                Some(serde_json::Value::Null)       | None => rusqlite::types::Value::Null,
                Some(serde_json::Value::Bool(b))           => rusqlite::types::Value::Integer(if *b {1} else {0}),
                Some(serde_json::Value::Number(n))         => {
                    if let Some(i) = n.as_i64() { rusqlite::types::Value::Integer(i) }
                    else if let Some(f) = n.as_f64() { rusqlite::types::Value::Real(f) }
                    else { rusqlite::types::Value::Null }
                }
                Some(serde_json::Value::String(s))         => rusqlite::types::Value::Text(s.clone()),
                Some(other)                                 => rusqlite::types::Value::Text(other.to_string()),
            }
        }).collect();

        let refs: Vec<&dyn rusqlite::ToSql> = values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        conn.execute(&sql, rusqlite::params_from_iter(refs.iter()))
            .map_err(|e| e.to_string())?;
        let _ = id;
        Ok(())
    }
}

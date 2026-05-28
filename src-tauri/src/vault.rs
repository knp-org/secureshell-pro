// Vault state — holds the in-memory master key and exposes Tauri commands
// for status / init / unlock / lock.
//
// Storage of the long-lived KDF params + verifier lives in the `vault_meta`
// SQLite table (see db::migrations). Records' encrypted secrets live in
// the same TEXT columns they always did, just storing JSON envelopes.

use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

use crate::crypto::{self, decrypt_field, encrypt_field, is_envelope, KdfParams, MasterKey};
use crate::db::Database;

/// Tauri-managed singleton.
#[derive(Default)]
pub struct Vault {
    inner: Mutex<Option<MasterKey>>,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    fn set(&self, key: MasterKey) -> Result<(), String> {
        let mut g = self.inner.lock().map_err(|e| e.to_string())?;
        *g = Some(key);
        Ok(())
    }

    fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            *g = None;
        }
    }

    /// Run a closure with a borrow of the master key. Errors if locked.
    pub fn with_key<F, R>(&self, f: F) -> Result<R, String>
    where
        F: FnOnce(&MasterKey) -> Result<R, String>,
    {
        let g = self.inner.lock().map_err(|e| e.to_string())?;
        let key = g.as_ref().ok_or_else(|| "vault is locked".to_string())?;
        f(key)
    }
}

/// If `value` is a stored envelope, decrypt it. If it's plaintext (no vault
/// migration yet) or `None`, pass through unchanged. Errors only if the
/// envelope can't be decrypted (vault locked or wrong key).
pub fn maybe_decrypt_field(
    value: Option<String>,
    vault: &Vault,
    record_id: &str,
) -> Result<Option<String>, String> {
    let Some(v) = value else { return Ok(None) };
    if !is_envelope(&v) {
        return Ok(Some(v)); // legacy plaintext
    }
    vault.with_key(|key| {
        decrypt_field(&v, key, record_id).map_err(|e| e.to_string()).map(Some)
    })
}

/// Encrypt a plaintext secret for storage. If the vault is locked, return
/// an error — callers must unlock before saving. If `value` is `None`,
/// pass through as `None`.
pub fn encrypt_field_required(
    value: Option<String>,
    vault: &Vault,
    record_id: &str,
) -> Result<Option<String>, String> {
    let Some(v) = value else { return Ok(None) };
    if v.is_empty() {
        return Ok(None);
    }
    // If already an envelope (e.g. round-trip from frontend), don't double-encrypt.
    if is_envelope(&v) {
        return Ok(Some(v));
    }
    vault.with_key(|key| {
        encrypt_field(&v, key, record_id).map_err(|e| e.to_string()).map(Some)
    })
}

// ─── Tauri commands ─────────────────────────────────────────

#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
}

#[tauri::command]
pub fn vault_status(db: State<'_, Database>, vault: State<'_, Vault>) -> Result<VaultStatus, String> {
    Ok(VaultStatus {
        initialized: db.get_vault_meta()?.is_some(),
        unlocked: vault.is_unlocked(),
    })
}

#[tauri::command]
pub fn vault_init(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
    password: String,
) -> Result<(), String> {
    if db.get_vault_meta()?.is_some() {
        return Err("vault already initialized — use vault_unlock".into());
    }
    if password.is_empty() {
        return Err("master password cannot be empty".into());
    }

    // 1. Back up the DB file before we mutate any rows.
    db.backup_to_sibling().ok(); // best-effort

    // 2. Derive key, build verifier.
    let kdf = KdfParams::new_random();
    let key = crypto::derive_key(&password, &kdf).map_err(|e| e.to_string())?;
    let verifier = crypto::make_verifier(&key).map_err(|e| e.to_string())?;

    // 3. Encrypt existing plaintext secrets and write vault_meta atomically.
    db.run_initial_encryption(&key, &kdf, &verifier)?;

    // 4. Keep the key in memory.
    vault.set(key)?;
    Ok(())
}

#[tauri::command]
pub fn vault_unlock(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
    password: String,
) -> Result<(), String> {
    let Some((kdf, verifier)) = db.get_vault_meta()? else {
        return Err("vault not initialized — call vault_init first".into());
    };
    let key = crypto::derive_key(&password, &kdf).map_err(|e| e.to_string())?;
    crypto::verify(&key, &verifier).map_err(|_| "incorrect password".to_string())?;
    vault.set(key)?;
    Ok(())
}

#[tauri::command]
pub fn vault_lock(vault: State<'_, Vault>) -> Result<(), String> {
    vault.clear();
    Ok(())
}


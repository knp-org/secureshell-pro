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

    // If a rotation arrived over sync while we were locked, adopt it now that we
    // hold the (old) key, so this unlock leaves us under the new key.
    if let Some(new_key) = apply_pending_rotation(&db, &key)? {
        vault.set(new_key)?;
    } else {
        vault.set(key)?;
    }
    Ok(())
}

#[tauri::command]
pub fn vault_lock(vault: State<'_, Vault>) -> Result<(), String> {
    vault.clear();
    Ok(())
}

/// Adopt a pending rotation while already unlocked (e.g. right after a sync).
/// Returns `true` if a rotation was adopted. No-op when locked or nothing
/// pending. The frontend can call this after a sync completes.
#[tauri::command]
pub fn vault_apply_pending(db: State<'_, Database>, vault: State<'_, Vault>) -> Result<bool, String> {
    if !vault.is_unlocked() {
        return Ok(false);
    }
    let adopted = vault.with_key(|k| apply_pending_rotation(&db, k))?;
    match adopted {
        Some(new_key) => {
            vault.set(new_key)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Adopt a rotation that arrived over sync (parked as `pending_vault_rotation`)
/// now that we hold the old key: recover the new key from the re-wrap token,
/// re-encrypt our local-only secrets, and promote the meta. Returns the new key
/// so the caller can keep the session unlocked, or `None` if there is nothing
/// pending or it can't be adopted with this key (left for the new-password path).
pub fn apply_pending_rotation(db: &Database, old_key: &MasterKey) -> Result<Option<MasterKey>, String> {
    let Some(pending) = db.get_pending_rotation()? else { return Ok(None) };
    let Some(token) = pending.rekey_token.as_ref() else { return Ok(None) };

    // Recover the new key with our current key. A failure means our key isn't
    // the one this token was wrapped under (we're more than one rotation
    // behind, or it's the wrong key) — leave it pending for the new-password
    // fallback rather than corrupting anything.
    let Ok(new_key) = crypto::unwrap_master_key(token, old_key) else { return Ok(None) };
    crypto::verify(&new_key, &pending.verifier)
        .map_err(|_| "rotation token did not match its verifier".to_string())?;

    db.promote_pending_rotation(old_key, &new_key, &pending)?;
    Ok(Some(new_key))
}

/// Rotate the master password. Verifies `current_password` against the stored
/// verifier, then derives a fresh key under a new random salt and re-encrypts
/// every stored secret to it. On success the in-memory key is swapped so the
/// current session stays unlocked.
#[tauri::command]
pub fn vault_change_password(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    let Some((kdf, verifier)) = db.get_vault_meta()? else {
        return Err("vault not initialized — use vault_init first".into());
    };
    if new_password.is_empty() {
        return Err("new master password cannot be empty".into());
    }

    // 1. Prove the caller knows the current password.
    let old_key = crypto::derive_key(&current_password, &kdf).map_err(|e| e.to_string())?;
    crypto::verify(&old_key, &verifier).map_err(|_| "current password is incorrect".to_string())?;

    if new_password == current_password {
        return Err("new password must differ from the current one".into());
    }

    // 2. Derive a brand-new key from the new password under a fresh salt.
    let new_kdf = KdfParams::new_random();
    let new_key = crypto::derive_key(&new_password, &new_kdf).map_err(|e| e.to_string())?;
    let new_verifier = crypto::make_verifier(&new_key).map_err(|e| e.to_string())?;

    // 3. Back up the DB, then atomically re-key every secret + the meta. The
    //    old salt/verifier and a new-key-wrapped-under-old-key token are stored
    //    so paired peers can adopt this rotation without the new password.
    db.backup_to_sibling().ok(); // best-effort
    db.run_rekey(&old_key, &new_key, &new_kdf, &new_verifier, &kdf, &verifier)?;

    // 4. Keep the session unlocked under the new key.
    vault.set(new_key)?;
    Ok(())
}


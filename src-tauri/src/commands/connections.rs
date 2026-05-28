use tauri::State;

use crate::db::models::Connection;
use crate::db::Database;
use crate::vault::{encrypt_field_required, maybe_decrypt_field, Vault};

#[tauri::command]
pub fn get_connections(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
) -> Result<Vec<Connection>, String> {
    let mut rows = db.get_all_connections()?;
    for c in rows.iter_mut() {
        // If vault is locked, envelopes come back as None so the UI doesn't
        // render ciphertext. Plaintext (pre-init) is passed through.
        c.password = match maybe_decrypt_field(c.password.take(), &vault, &c.id) {
            Ok(v) => v,
            Err(_) if !vault.is_unlocked() => None,
            Err(e) => return Err(e),
        };
    }
    Ok(rows)
}

#[tauri::command]
pub fn save_connection(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
    connection: Connection,
) -> Result<(), String> {
    let mut c = connection;
    // Only encrypt once the user has set up the vault. Before init the field
    // stays plaintext; vault_init migrates it.
    if db.get_vault_meta()?.is_some() {
        c.password = encrypt_field_required(c.password, &vault, &c.id)?;
    }
    db.save_connection(&c)
}

#[tauri::command]
pub fn delete_connection(db: State<'_, Database>, id: String) -> Result<(), String> {
    db.delete_connection(&id)
}

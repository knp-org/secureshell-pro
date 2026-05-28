use serde::Deserialize;
use tauri::{AppHandle, State};

use crate::ssh::SshManager;
use crate::vault::{maybe_decrypt_field, Vault};

use std::os::unix::fs::PermissionsExt;

#[derive(Deserialize)]
pub struct ConnectParams {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_id: Option<String>,
}

#[tauri::command]
pub fn ssh_connect(
    ssh: State<'_, SshManager>,
    db: State<'_, crate::db::Database>,
    vault: State<'_, Vault>,
    app: AppHandle,
    params: ConnectParams,
) -> Result<(), String> {
    let mut key_path_to_use = None;

    // If key_id is provided, fetch from DB and write to a secure temp file
    if let Some(key_id) = &params.key_id {
        if !key_id.is_empty() {
            let keys = db.get_all_keys()?;
            if let Some(key) = keys.into_iter().find(|k| k.id == *key_id) {
                let decrypted = maybe_decrypt_field(key.private_key, &vault, &key.id)?;
                if let Some(priv_key) = decrypted {
                    let tmp_path = std::env::temp_dir().join(format!("ssp_key_{}", uuid::Uuid::new_v4()));
                    std::fs::write(&tmp_path, priv_key).map_err(|e| e.to_string())?;
                    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
                    key_path_to_use = Some(tmp_path);
                }
            }
        }
    }

    ssh.connect(
        &params.session_id,
        &params.host,
        params.port,
        &params.username,
        params.password.as_deref(),
        key_path_to_use,
        &app,
    )
}

#[derive(Deserialize)]
pub struct LocalShellParams {
    pub session_id: String,
}

#[tauri::command]
pub fn local_shell_connect(
    ssh: State<'_, SshManager>,
    app: AppHandle,
    params: LocalShellParams,
) -> Result<(), String> {
    ssh.connect_local(&params.session_id, &app)
}

#[tauri::command]
pub fn ssh_write(ssh: State<'_, SshManager>, session_id: String, data: String) -> Result<(), String> {
    ssh.write(&session_id, data.as_bytes())
}

#[tauri::command]
pub fn ssh_resize(ssh: State<'_, SshManager>, session_id: String, rows: u16, cols: u16) -> Result<(), String> {
    ssh.resize(&session_id, rows, cols)
}

#[tauri::command]
pub fn ssh_disconnect(ssh: State<'_, SshManager>, session_id: String) -> Result<(), String> {
    ssh.disconnect(&session_id)
}

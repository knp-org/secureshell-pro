use serde::Deserialize;
use tauri::{AppHandle, State};

use crate::ssh::SshManager;
use crate::vault::{maybe_decrypt_field, Vault};

use std::io::Write;

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

    if let Some(key_id) = params.key_id.as_ref().filter(|s| !s.is_empty()) {
        let key = db
            .get_all_keys()?
            .into_iter()
            .find(|k| &k.id == key_id)
            .ok_or("SSH key not found")?;
        let private_key = zeroize::Zeroizing::new(
            maybe_decrypt_field(key.private_key, &vault, &key.id)?.ok_or("SSH key is empty")?,
        );
        // NamedTempFile creates a private file atomically and removes it on every failure path.
        let mut file = tempfile::Builder::new()
            .prefix("ssp-key-")
            .tempfile()
            .map_err(|e| e.to_string())?;
        file.write_all(private_key.as_bytes())
            .map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;
        key_path_to_use = Some(file);
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
pub fn ssh_write(
    ssh: State<'_, SshManager>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    ssh.write(&session_id, data.as_bytes())
}

#[tauri::command]
pub fn ssh_resize(
    ssh: State<'_, SshManager>,
    session_id: String,
    rows: u16,
    cols: u16,
) -> Result<(), String> {
    ssh.resize(&session_id, rows, cols)
}

#[tauri::command]
pub fn ssh_disconnect(ssh: State<'_, SshManager>, session_id: String) -> Result<(), String> {
    ssh.disconnect(&session_id)
}

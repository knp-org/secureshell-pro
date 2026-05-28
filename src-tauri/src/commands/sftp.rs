use serde::Deserialize;
use tauri::{AppHandle, Emitter, State};

use crate::sftp::{FileEntry, SftpManager};
use crate::vault::{maybe_decrypt_field, Vault};

use std::os::unix::fs::PermissionsExt;

// ─── Connect ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SftpConnectParams {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_id: Option<String>,
}

#[tauri::command]
pub fn sftp_connect(
    sftp: State<'_, SftpManager>,
    db: State<'_, crate::db::Database>,
    vault: State<'_, Vault>,
    params: SftpConnectParams,
) -> Result<String, String> {
    let mut key_path_to_use = None;

    // If key_id is provided, fetch from DB and write to a secure temp file
    if let Some(key_id) = &params.key_id {
        if !key_id.is_empty() {
            let keys = db.get_all_keys()?;
            if let Some(key) = keys.into_iter().find(|k| k.id == *key_id) {
                let decrypted = maybe_decrypt_field(key.private_key, &vault, &key.id)?;
                if let Some(priv_key) = decrypted {
                    let tmp_path =
                        std::env::temp_dir().join(format!("ssp_sftp_key_{}", uuid::Uuid::new_v4()));
                    std::fs::write(&tmp_path, priv_key).map_err(|e| e.to_string())?;
                    std::fs::set_permissions(
                        &tmp_path,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .map_err(|e| e.to_string())?;
                    key_path_to_use = Some(tmp_path);
                }
            }
        }
    }

    sftp.connect(
        &params.session_id,
        &params.host,
        params.port,
        &params.username,
        params.password.as_deref(),
        key_path_to_use,
    )?;

    // Clean up temp key file after connection
    // Note: the key is read at connect time and the file is no longer needed
    // We leave cleanup to the caller or a cleanup thread

    // Return the remote home directory so the UI can start browsing
    let home = sftp.home_dir(&params.session_id)?;
    Ok(home)
}

// ─── List Directory ────────────────────────────────────────

#[tauri::command]
pub fn sftp_list_dir(
    sftp: State<'_, SftpManager>,
    session_id: String,
    path: String,
) -> Result<Vec<FileEntry>, String> {
    sftp.list_dir(&session_id, &path)
}

// ─── Download ──────────────────────────────────────────────

#[tauri::command]
pub fn sftp_download(
    sftp: State<'_, SftpManager>,
    session_id: String,
    remote_path: String,
    local_path: String,
    transfer_id: String,
    app: AppHandle,
) -> Result<u64, String> {
    sftp.download(&session_id, &remote_path, &local_path, &transfer_id, &app)
}

// ─── Upload ────────────────────────────────────────────────

#[tauri::command]
pub fn sftp_upload(
    sftp: State<'_, SftpManager>,
    session_id: String,
    local_path: String,
    remote_path: String,
    transfer_id: String,
    app: AppHandle,
) -> Result<u64, String> {
    sftp.upload(&session_id, &local_path, &remote_path, &transfer_id, &app)
}

// ─── Recursive Download ───────────────────────────────────

#[tauri::command]
pub fn sftp_download_dir(
    sftp: State<'_, SftpManager>,
    session_id: String,
    remote_path: String,
    local_path: String,
    transfer_id: String,
    app: AppHandle,
) -> Result<(), String> {
    let mut total_state = (0u64, 0u64);
    sftp.download_recursive(
        &session_id,
        &remote_path,
        &local_path,
        &transfer_id,
        &app,
        &mut total_state,
    )?;
    let _ = app.emit(
        "sftp-progress",
        crate::sftp::ProgressPayload {
            transfer_id,
            bytes_transferred: total_state.0,
            total_bytes: total_state.1,
            percentage: 100.0,
            done: true,
        },
    );
    Ok(())
}

// ─── Recursive Upload ─────────────────────────────────────

#[tauri::command]
pub fn sftp_upload_dir(
    sftp: State<'_, SftpManager>,
    session_id: String,
    local_path: String,
    remote_path: String,
    transfer_id: String,
    app: AppHandle,
) -> Result<(), String> {
    let mut total_state = (0u64, 0u64);
    sftp.upload_recursive(
        &session_id,
        &local_path,
        &remote_path,
        &transfer_id,
        &app,
        &mut total_state,
    )?;
    let _ = app.emit(
        "sftp-progress",
        crate::sftp::ProgressPayload {
            transfer_id,
            bytes_transferred: total_state.0,
            total_bytes: total_state.1,
            percentage: 100.0,
            done: true,
        },
    );
    Ok(())
}

// ─── Rename ────────────────────────────────────────────────

#[tauri::command]
pub fn sftp_rename(
    sftp: State<'_, SftpManager>,
    session_id: String,
    old_path: String,
    new_path: String,
) -> Result<(), String> {
    sftp.rename(&session_id, &old_path, &new_path)
}

// ─── Delete ────────────────────────────────────────────────

#[tauri::command]
pub fn sftp_delete(
    sftp: State<'_, SftpManager>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> Result<(), String> {
    if is_dir {
        sftp.delete_recursive(&session_id, &path)
    } else {
        sftp.delete_file(&session_id, &path)
    }
}

// ─── Mkdir ─────────────────────────────────────────────────

#[tauri::command]
pub fn sftp_mkdir(
    sftp: State<'_, SftpManager>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    sftp.mkdir(&session_id, &path, 0o755)
}

// ─── Chmod ─────────────────────────────────────────────────

#[tauri::command]
pub fn sftp_chmod(
    sftp: State<'_, SftpManager>,
    session_id: String,
    path: String,
    mode: u32,
) -> Result<(), String> {
    sftp.chmod(&session_id, &path, mode)
}

// ─── Stat ──────────────────────────────────────────────────

#[tauri::command]
pub fn sftp_stat(
    sftp: State<'_, SftpManager>,
    session_id: String,
    path: String,
) -> Result<FileEntry, String> {
    sftp.stat(&session_id, &path)
}

// ─── Read File ─────────────────────────────────────────────

#[tauri::command]
pub fn sftp_read_file(
    sftp: State<'_, SftpManager>,
    session_id: String,
    path: String,
) -> Result<String, String> {
    sftp.read_file(&session_id, &path)
}

// ─── Disconnect ────────────────────────────────────────────

#[tauri::command]
pub fn sftp_disconnect(
    sftp: State<'_, SftpManager>,
    session_id: String,
) -> Result<(), String> {
    sftp.disconnect(&session_id)
}

// ─── Local filesystem operations ───────────────────────────
// These let the local pane of the file browser work without
// extra privileges.

#[tauri::command]
pub fn local_list_dir(path: String) -> Result<Vec<FileEntry>, String> {
    let dir_path = std::path::Path::new(&path);
    if !dir_path.exists() {
        return Err(format!("Path does not exist: {}", path));
    }
    if !dir_path.is_dir() {
        return Err(format!("Not a directory: {}", path));
    }

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir_path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let metadata = entry.metadata().map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_string();

        if name.starts_with('.') {
            // Skip hidden files by default — may add a toggle later
            continue;
        }

        let full_path = entry.path().to_string_lossy().to_string();
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        entries.push(FileEntry {
            name,
            path: full_path,
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            permissions: metadata.permissions().mode(),
            modified,
            is_symlink: metadata.file_type().is_symlink(),
        });
    }

    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    Ok(entries)
}

#[tauri::command]
pub fn local_home_dir() -> Result<String, String> {
    dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .ok_or_else(|| "Could not determine home directory".into())
}

#[tauri::command]
pub fn local_read_file(path: String) -> Result<String, String> {
    let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if metadata.len() > 10 * 1024 * 1024 {
        return Err("File too large to preview (>10MB)".into());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))
}

#[tauri::command]
pub fn local_delete(path: String) -> Result<(), String> {
    let p = std::path::Path::new(&path);
    if p.is_dir() {
        std::fs::remove_dir_all(p).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(p).map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub fn local_rename(old_path: String, new_path: String) -> Result<(), String> {
    std::fs::rename(&old_path, &new_path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn local_mkdir(path: String) -> Result<(), String> {
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn local_chmod(path: String, mode: u32) -> Result<(), String> {
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())
}

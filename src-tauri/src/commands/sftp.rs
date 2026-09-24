use serde::Deserialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::sftp::{FileEntry, SftpManager};
use crate::vault::{maybe_decrypt_field, Vault};

#[cfg(unix)]
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
    pub trusted_fingerprint: Option<String>,
}

#[tauri::command]
pub async fn sftp_connect(app: AppHandle, params: SftpConnectParams) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        let db = app.state::<crate::db::Database>();
        let vault = app.state::<Vault>();
        let private_key = if let Some(key_id) = params.key_id.as_ref().filter(|s| !s.is_empty()) {
            let key = db
                .get_all_keys()?
                .into_iter()
                .find(|k| &k.id == key_id)
                .ok_or("SSH key not found")?;
            Some(zeroize::Zeroizing::new(
                maybe_decrypt_field(key.private_key, &vault, &key.id)?.ok_or("SSH key is empty")?,
            ))
        } else {
            None
        };
        sftp.connect(
            &params.session_id,
            &params.host,
            params.port,
            &params.username,
            params.password.as_deref(),
            private_key.as_ref().map(|k| k.as_str()),
            params.trusted_fingerprint.as_deref(),
        )?;
        match sftp.home_dir(&params.session_id) {
            Ok(home) => Ok(home),
            Err(error) => {
                let _ = sftp.disconnect(&params.session_id);
                Err(error)
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── List Directory ────────────────────────────────────────

#[tauri::command]
pub async fn sftp_list_dir(
    app: AppHandle,
    session_id: String,
    path: String,
) -> Result<Vec<FileEntry>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.list_dir(&session_id, &path)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Download ──────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_download(
    session_id: String,
    remote_path: String,
    local_path: String,
    transfer_id: String,
    app: AppHandle,
    overwrite: Option<bool>,
) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        let _transfer = sftp.begin_transfer(&transfer_id)?;
        let overwrite = overwrite.unwrap_or(false);
        sftp.download(
            &session_id,
            &remote_path,
            &local_path,
            &transfer_id,
            &|payload| {
                let _ = app.emit("sftp-progress", payload);
            },
            overwrite,
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Upload ────────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_upload(
    session_id: String,
    local_path: String,
    remote_path: String,
    transfer_id: String,
    app: AppHandle,
    overwrite: Option<bool>,
) -> Result<u64, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        let _transfer = sftp.begin_transfer(&transfer_id)?;
        let overwrite = overwrite.unwrap_or(false);
        sftp.upload(
            &session_id,
            &local_path,
            &remote_path,
            &transfer_id,
            &|payload| {
                let _ = app.emit("sftp-progress", payload);
            },
            overwrite,
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Recursive Download ───────────────────────────────────

#[tauri::command]
pub async fn sftp_download_dir(
    session_id: String,
    remote_path: String,
    local_path: String,
    transfer_id: String,
    app: AppHandle,
    overwrite: Option<bool>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        let _transfer = sftp.begin_transfer(&transfer_id)?;
        let overwrite = overwrite.unwrap_or(false);
        let mut total_state = (0u64, 0u64);
        sftp.download_recursive(
            &session_id,
            &remote_path,
            &local_path,
            &transfer_id,
            &|payload| {
                let _ = app.emit("sftp-progress", payload);
            },
            &mut total_state,
            overwrite,
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
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Recursive Upload ─────────────────────────────────────

#[tauri::command]
pub async fn sftp_upload_dir(
    session_id: String,
    local_path: String,
    remote_path: String,
    transfer_id: String,
    app: AppHandle,
    overwrite: Option<bool>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        let _transfer = sftp.begin_transfer(&transfer_id)?;
        let overwrite = overwrite.unwrap_or(false);
        let mut total_state = (0u64, 0u64);
        sftp.upload_recursive(
            &session_id,
            &local_path,
            &remote_path,
            &transfer_id,
            &|payload| {
                let _ = app.emit("sftp-progress", payload);
            },
            &mut total_state,
            overwrite,
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
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Rename ────────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_rename(
    app: AppHandle,
    session_id: String,
    old_path: String,
    new_path: String,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.rename(&session_id, &old_path, &new_path)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Delete ────────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_delete(
    app: AppHandle,
    session_id: String,
    path: String,
    is_dir: bool,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        if is_dir {
            sftp.delete_recursive(&session_id, &path)
        } else {
            sftp.delete_file(&session_id, &path)
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Mkdir ─────────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_mkdir(app: AppHandle, session_id: String, path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.mkdir(&session_id, &path, 0o755)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Chmod ─────────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_chmod(
    app: AppHandle,
    session_id: String,
    path: String,
    mode: u32,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.chmod(&session_id, &path, mode)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Stat ──────────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_stat(
    app: AppHandle,
    session_id: String,
    path: String,
) -> Result<FileEntry, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.stat(&session_id, &path)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Read File ─────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_read_file(
    app: AppHandle,
    session_id: String,
    path: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.read_file(&session_id, &path)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Disconnect ────────────────────────────────────────────

#[tauri::command]
pub async fn sftp_disconnect(app: AppHandle, session_id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let sftp = app.state::<SftpManager>();
        sftp.disconnect(&session_id)
    })
    .await
    .map_err(|e| e.to_string())?
}

// ─── Local filesystem operations ───────────────────────────
// These let the local pane of the file browser work without
// extra privileges.

#[tauri::command]
pub async fn local_list_dir(path: String) -> Result<Vec<FileEntry>, String> {
    tauri::async_runtime::spawn_blocking(move || {
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

            #[cfg(unix)]
            let permissions = metadata.permissions().mode();
            #[cfg(not(unix))]
            let permissions = if metadata.permissions().readonly() {
                if metadata.is_dir() {
                    0o555
                } else {
                    0o444
                }
            } else if metadata.is_dir() {
                0o755
            } else {
                0o644
            };

            entries.push(FileEntry {
                name,
                path: full_path,
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                permissions,
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
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn local_home_dir() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .ok_or_else(|| "Could not determine home directory".into())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn local_read_file(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        if metadata.len() > 10 * 1024 * 1024 {
            return Err("File too large to preview (>10MB)".into());
        }
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read file: {}", e))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn local_delete(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let p = std::path::Path::new(&path);
        if p.is_dir() {
            std::fs::remove_dir_all(p).map_err(|e| e.to_string())
        } else {
            std::fs::remove_file(p).map_err(|e| e.to_string())
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn local_rename(old_path: String, new_path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::rename(&old_path, &new_path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn local_mkdir(path: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::create_dir_all(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn local_chmod(path: String, mode: u32) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(unix)]
        {
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())
        }
        #[cfg(not(unix))]
        {
            // Windows has no Unix permission bits; only the read-only flag is
            // adjustable. Treat the owner-write bit as the read-only toggle.
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_readonly(mode & 0o200 == 0);
            std::fs::set_permissions(&path, perms).map_err(|e| e.to_string())
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn sftp_cancel_transfer(app: AppHandle, transfer_id: String) -> Result<(), String> {
    app.state::<SftpManager>().cancel_transfer(&transfer_id)
}

mod commands;
mod crypto;
mod db;
mod sftp;
mod ssh;
mod sync;
mod vault;

use db::Database;
use sftp::SftpManager;
use ssh::SshManager;
use sync::SyncState;
use vault::Vault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .try_init();

    // Initialize database in user's data directory
    let db_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("secureshell-pro")
        .join("secureshell.db");

    let database = Database::new(db_path).expect("Failed to initialize database");
    let ssh_manager = SshManager::new();
    let sftp_manager = SftpManager::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(database)
        .manage(ssh_manager)
        .manage(sftp_manager)
        .manage(Vault::new())
        .manage(SyncState::new())
        .setup(|app| {
            sync::listener::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Vault
            vault::vault_status,
            vault::vault_init,
            vault::vault_unlock,
            vault::vault_lock,
            // LAN sync — pairing
            sync::pairing_start,
            sync::pairing_cancel,
            sync::pairing_status,
            sync::pairing_confirm,
            sync::peers_list,
            sync::peer_remove,
            sync::sync_now,
            // Connections
            commands::connections::get_connections,
            commands::connections::save_connection,
            commands::connections::delete_connection,
            // Snippets
            commands::snippets::get_snippets,
            commands::snippets::save_snippet,
            commands::snippets::delete_snippet,
            // SSH Keys
            commands::keys::get_keys,
            commands::keys::save_key,
            commands::keys::delete_key,
            commands::keys::detect_keys,
            // Groups
            commands::groups::get_groups,
            commands::groups::save_group,
            commands::groups::delete_group,
            // Settings
            commands::settings::get_setting,
            commands::settings::set_setting,
            // Clipboard
            commands::clipboard::clipboard_read_text,
            commands::clipboard::clipboard_write_text,
            // SSH Terminal Sessions
            commands::ssh::ssh_connect,
            commands::ssh::local_shell_connect,
            commands::ssh::ssh_write,
            commands::ssh::ssh_resize,
            commands::ssh::ssh_disconnect,
            // SFTP File Browser
            commands::sftp::sftp_connect,
            commands::sftp::sftp_list_dir,
            commands::sftp::sftp_download,
            commands::sftp::sftp_upload,
            commands::sftp::sftp_download_dir,
            commands::sftp::sftp_upload_dir,
            commands::sftp::sftp_rename,
            commands::sftp::sftp_delete,
            commands::sftp::sftp_mkdir,
            commands::sftp::sftp_chmod,
            commands::sftp::sftp_stat,
            commands::sftp::sftp_read_file,
            commands::sftp::sftp_disconnect,
            // Local Filesystem (for SFTP dual-pane)
            commands::sftp::local_list_dir,
            commands::sftp::local_home_dir,
            commands::sftp::local_read_file,
            commands::sftp::local_delete,
            commands::sftp::local_rename,
            commands::sftp::local_mkdir,
            commands::sftp::local_chmod,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

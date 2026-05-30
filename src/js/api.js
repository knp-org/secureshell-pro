// ═══════════════════════════════════════════════════════════
// Tauri IPC API Wrapper
// ═══════════════════════════════════════════════════════════

const { invoke } = window.__TAURI__?.core ?? {};

// ─── Connections ───────────────────────────────────────────
export async function getConnections() {
    return await invoke('get_connections');
}

export async function saveConnection(connection) {
    return await invoke('save_connection', { connection });
}

export async function deleteConnection(id) {
    return await invoke('delete_connection', { id });
}

// ─── Snippets ──────────────────────────────────────────────
export async function getSnippets() {
    return await invoke('get_snippets');
}

export async function saveSnippet(snippet) {
    return await invoke('save_snippet', { snippet });
}

export async function deleteSnippet(id) {
    return await invoke('delete_snippet', { id });
}

// ─── SSH Keys ──────────────────────────────────────────────
export async function getKeys() {
    return await invoke('get_keys');
}

export async function saveKey(key) {
    return await invoke('save_key', { key });
}

export async function deleteKey(id) {
    return await invoke('delete_key', { id });
}

export async function detectKeys() {
    return await invoke('detect_keys');
}

// ─── Groups ────────────────────────────────────────────────
export async function getGroups() {
    return await invoke('get_groups');
}

export async function saveGroup(group) {
    return await invoke('save_group', { group });
}

export async function deleteGroup(id) {
    return await invoke('delete_group', { id });
}

// ─── Settings ──────────────────────────────────────────────
export async function getSetting(key) {
    return await invoke('get_setting', { key });
}

export async function setSetting(key, value) {
    return await invoke('set_setting', { key, value });
}

// ─── Vault ─────────────────────────────────────────────────
export async function vaultStatus()        { return await invoke('vault_status'); }
export async function vaultInit(password)  { return await invoke('vault_init',   { password }); }
export async function vaultUnlock(password){ return await invoke('vault_unlock', { password }); }
export async function vaultLock()          { return await invoke('vault_lock'); }
export async function vaultChangePassword(currentPassword, newPassword) {
    return await invoke('vault_change_password', { currentPassword, newPassword });
}

// ─── LAN Sync ──────────────────────────────────────────────
export async function pairingStart()          { return await invoke('pairing_start'); }
export async function pairingCancel()         { return await invoke('pairing_cancel'); }
export async function pairingStatus()         { return await invoke('pairing_status'); }
export async function pairingConfirm(accept)  { return await invoke('pairing_confirm', { accept }); }
export async function peersList()             { return await invoke('peers_list'); }
export async function peerRemove(id)          { return await invoke('peer_remove', { id }); }
export async function syncNow(peerId)         { return await invoke('sync_now',    { peerId }); }

// ─── SSH Terminal Sessions ─────────────────────────────────
export async function sshConnect(params) {
    return await invoke('ssh_connect', { params });
}

export async function localShellConnect(params) {
    return await invoke('local_shell_connect', { params });
}

export async function sshWrite(sessionId, data) {
    return await invoke('ssh_write', { sessionId, data });
}

export async function sshResize(sessionId, rows, cols) {
    return await invoke('ssh_resize', { sessionId, rows, cols });
}

export async function sshDisconnect(sessionId) {
    return await invoke('ssh_disconnect', { sessionId });
}

// ─── Clipboard (system via Rust; WebView API often blocked) ─
export async function clipboardReadText() {
    return await invoke('clipboard_read_text');
}

export async function clipboardWriteText(text) {
    return await invoke('clipboard_write_text', { text });
}

// ─── SFTP File Browser ────────────────────────────────────
export async function sftpConnect(params) {
    return await invoke('sftp_connect', { params });
}

export async function sftpListDir(sessionId, path) {
    return await invoke('sftp_list_dir', { sessionId, path });
}

export async function sftpDownload(sessionId, remotePath, localPath, transferId) {
    return await invoke('sftp_download', { sessionId, remotePath, localPath, transferId });
}

export async function sftpUpload(sessionId, localPath, remotePath, transferId) {
    return await invoke('sftp_upload', { sessionId, localPath, remotePath, transferId });
}

export async function sftpDownloadDir(sessionId, remotePath, localPath, transferId) {
    return await invoke('sftp_download_dir', { sessionId, remotePath, localPath, transferId });
}

export async function sftpUploadDir(sessionId, localPath, remotePath, transferId) {
    return await invoke('sftp_upload_dir', { sessionId, localPath, remotePath, transferId });
}

export async function sftpRename(sessionId, oldPath, newPath) {
    return await invoke('sftp_rename', { sessionId, oldPath, newPath });
}

export async function sftpDelete(sessionId, path, isDir) {
    return await invoke('sftp_delete', { sessionId, path, isDir });
}

export async function sftpMkdir(sessionId, path) {
    return await invoke('sftp_mkdir', { sessionId, path });
}

export async function sftpChmod(sessionId, path, mode) {
    return await invoke('sftp_chmod', { sessionId, path, mode });
}

export async function sftpStat(sessionId, path) {
    return await invoke('sftp_stat', { sessionId, path });
}

export async function sftpReadFile(sessionId, path) {
    return await invoke('sftp_read_file', { sessionId, path });
}

export async function sftpDisconnect(sessionId) {
    return await invoke('sftp_disconnect', { sessionId });
}

// ─── Local Filesystem (for SFTP dual-pane) ────────────────
export async function localListDir(path) {
    return await invoke('local_list_dir', { path });
}

export async function localHomeDir() {
    return await invoke('local_home_dir');
}

export async function localReadFile(path) {
    return await invoke('local_read_file', { path });
}

export async function localDelete(path) {
    return await invoke('local_delete', { path });
}

export async function localRename(oldPath, newPath) {
    return await invoke('local_rename', { oldPath, newPath });
}

export async function localMkdir(path) {
    return await invoke('local_mkdir', { path });
}

export async function localChmod(path, mode) {
    return await invoke('local_chmod', { path, mode });
}

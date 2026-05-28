use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressPayload {
    pub transfer_id: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub percentage: f64,
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub permissions: u32,
    pub modified: i64,
    pub is_symlink: bool,
}

struct SftpSession {
    session: Session,
    _stream: TcpStream,
}

pub struct SftpManager {
    sessions: Mutex<HashMap<String, Arc<Mutex<SftpSession>>>>,
}

impl SftpManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn get_session(&self, session_id: &str) -> Result<Arc<Mutex<SftpSession>>, String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| "SFTP session not found".into())
    }

    pub fn connect(
        &self,
        session_id: &str,
        host: &str,
        port: u16,
        username: &str,
        password: Option<&str>,
        key_path: Option<PathBuf>,
    ) -> Result<(), String> {
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect(&addr)
            .map_err(|e| format!("TCP connection failed: {}", e))?;

        let mut sess = Session::new()
            .map_err(|e| format!("SSH session creation failed: {}", e))?;
        sess.set_tcp_stream(tcp.try_clone().map_err(|e| e.to_string())?);
        sess.handshake()
            .map_err(|e| format!("SSH handshake failed: {}", e))?;

        if let Some(key) = &key_path {
            sess.userauth_pubkey_file(username, None, key, password)
                .map_err(|e| format!("Key auth failed: {}", e))?;
        } else if let Some(pwd) = password {
            sess.userauth_password(username, pwd)
                .map_err(|e| format!("Password auth failed: {}", e))?;
        } else {
            sess.userauth_agent(username)
                .map_err(|e| format!("Agent auth failed: {}", e))?;
        }

        if !sess.authenticated() {
            return Err("Authentication failed".into());
        }

        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        sessions.insert(
            session_id.to_string(),
            Arc::new(Mutex::new(SftpSession {
                session: sess,
                _stream: tcp,
            })),
        );

        Ok(())
    }

    pub fn list_dir(&self, session_id: &str, path: &str) -> Result<Vec<FileEntry>, String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| format!("SFTP init failed: {}", e))?;
        let remote_path = Path::new(path);
        let entries = sftp
            .readdir(remote_path)
            .map_err(|e| format!("Failed to list directory: {}", e))?;

        let mut result: Vec<FileEntry> = entries
            .into_iter()
            .filter_map(|(pathbuf, stat)| {
                let name = pathbuf.file_name()?.to_string_lossy().to_string();
                if name == "." || name == ".." {
                    return None;
                }
                let full_path = if path.ends_with('/') {
                    format!("{}{}", path, name)
                } else {
                    format!("{}/{}", path, name)
                };
                Some(FileEntry {
                    name,
                    path: full_path,
                    is_dir: stat.is_dir(),
                    size: stat.size.unwrap_or(0),
                    permissions: stat.perm.unwrap_or(0o644),
                    modified: stat.mtime.unwrap_or(0) as i64,
                    is_symlink: stat.file_type().is_symlink(),
                })
            })
            .collect();

        result.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        Ok(result)
    }

    pub fn download(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        transfer_id: &str,
        app: &AppHandle,
    ) -> Result<u64, String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        let mut remote_file = sftp
            .open(Path::new(remote_path))
            .map_err(|e| format!("Failed to open remote file: {}", e))?;

        let stat = sftp.stat(Path::new(remote_path)).map_err(|e| e.to_string())?;
        let total_bytes = stat.size.unwrap_or(0);

        if let Some(parent) = Path::new(local_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut local_file = std::fs::File::create(local_path)
            .map_err(|e| format!("Failed to create local file: {}", e))?;

        let mut bytes_transferred = 0u64;
        let mut buf = [0u8; 65536];

        let _ = app.emit("sftp-progress", ProgressPayload {
            transfer_id: transfer_id.to_string(),
            bytes_transferred,
            total_bytes,
            percentage: 0.0,
            done: false,
        });

        let mut last_percentage = 0.0;
        loop {
            match remote_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    local_file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                    bytes_transferred += n as u64;

                    let percentage = if total_bytes > 0 {
                        ((bytes_transferred as f64 / total_bytes as f64) * 1000.0).round() / 10.0
                    } else {
                        0.0
                    };

                    if percentage - last_percentage >= 1.0 || bytes_transferred == total_bytes {
                        last_percentage = percentage;
                        let _ = app.emit("sftp-progress", ProgressPayload {
                            transfer_id: transfer_id.to_string(),
                            bytes_transferred,
                            total_bytes,
                            percentage,
                            done: false,
                        });
                    }
                }
                Err(e) => return Err(format!("Read error: {}", e)),
            }
        }

        let _ = app.emit("sftp-progress", ProgressPayload {
            transfer_id: transfer_id.to_string(),
            bytes_transferred,
            total_bytes,
            percentage: 100.0,
            done: true,
        });

        Ok(bytes_transferred)
    }

    pub fn upload(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        transfer_id: &str,
        app: &AppHandle,
    ) -> Result<u64, String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;

        let metadata = std::fs::metadata(local_path)
            .map_err(|e| format!("Failed to read local file: {}", e))?;
        let total_bytes = metadata.len();

        let mut local_file = std::fs::File::open(local_path)
            .map_err(|e| format!("Failed to open local file: {}", e))?;

        let mut remote_file = sftp
            .create(Path::new(remote_path))
            .map_err(|e| format!("Failed to create remote file: {}", e))?;

        let mut bytes_transferred = 0u64;
        let mut buf = [0u8; 65536];

        let _ = app.emit("sftp-progress", ProgressPayload {
            transfer_id: transfer_id.to_string(),
            bytes_transferred,
            total_bytes,
            percentage: 0.0,
            done: false,
        });

        let mut last_percentage = 0.0;
        loop {
            match local_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    remote_file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                    bytes_transferred += n as u64;

                    let percentage = if total_bytes > 0 {
                        ((bytes_transferred as f64 / total_bytes as f64) * 1000.0).round() / 10.0
                    } else {
                        0.0
                    };

                    if percentage - last_percentage >= 1.0 || bytes_transferred == total_bytes {
                        last_percentage = percentage;
                        let _ = app.emit("sftp-progress", ProgressPayload {
                            transfer_id: transfer_id.to_string(),
                            bytes_transferred,
                            total_bytes,
                            percentage,
                            done: false,
                        });
                    }
                }
                Err(e) => return Err(format!("Read error: {}", e)),
            }
        }

        let _ = app.emit("sftp-progress", ProgressPayload {
            transfer_id: transfer_id.to_string(),
            bytes_transferred,
            total_bytes,
            percentage: 100.0,
            done: true,
        });

        Ok(total_bytes)
    }

    pub fn download_recursive(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        transfer_id: &str,
        app: &AppHandle,
        total_state: &mut (u64, u64),
    ) -> Result<(), String> {
        let entries = self.list_dir(session_id, remote_path)?;
        std::fs::create_dir_all(local_path).map_err(|e| e.to_string())?;

        for entry in &entries {
            let local_child = format!("{}/{}", local_path, entry.name);
            if entry.is_dir {
                self.download_recursive(
                    session_id,
                    &entry.path,
                    &local_child,
                    transfer_id,
                    app,
                    total_state,
                )?;
            } else {
                total_state.0 += entry.size;
            }
        }

        if total_state.1 == 0 {
            total_state.1 = total_state.0;
            total_state.0 = 0;
        }

        for entry in entries {
            let local_child = format!("{}/{}", local_path, entry.name);
            if entry.is_dir {
                continue;
            }
            self.download_file_with_state(
                session_id,
                &entry.path,
                &local_child,
                transfer_id,
                app,
                total_state,
            )?;
        }

        Ok(())
    }

    fn download_file_with_state(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        transfer_id: &str,
        app: &AppHandle,
        total_state: &mut (u64, u64),
    ) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;
        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;

        let mut remote_file = sftp
            .open(Path::new(remote_path))
            .map_err(|e| format!("Failed to open remote file: {}", e))?;

        if let Some(parent) = Path::new(local_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut local_file = std::fs::File::create(local_path)
            .map_err(|e| format!("Failed to create local file: {}", e))?;

        let mut buf = [0u8; 65536];
        let mut last_percentage = if total_state.1 > 0 {
            ((total_state.0 as f64 / total_state.1 as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };

        loop {
            match remote_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    local_file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                    total_state.0 += n as u64;

                    let percentage = if total_state.1 > 0 {
                        ((total_state.0 as f64 / total_state.1 as f64) * 1000.0).round() / 10.0
                    } else {
                        0.0
                    };

                    if percentage - last_percentage >= 1.0 {
                        last_percentage = percentage;
                        let _ = app.emit(
                            "sftp-progress",
                            ProgressPayload {
                                transfer_id: transfer_id.to_string(),
                                bytes_transferred: total_state.0,
                                total_bytes: total_state.1,
                                percentage,
                                done: false,
                            },
                        );
                    }
                }
                Err(e) => return Err(format!("Read error: {}", e)),
            }
        }

        Ok(())
    }

    pub fn upload_recursive(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        transfer_id: &str,
        app: &AppHandle,
        total_state: &mut (u64, u64),
    ) -> Result<(), String> {
        self.mkdir(session_id, remote_path, 0o755).ok();

        let mut files = Vec::new();
        self.collect_local_files(local_path, remote_path, &mut files, session_id, total_state)?;

        if total_state.1 == 0 {
            total_state.1 = total_state.0;
            total_state.0 = 0;
        }

        for (lp, rp) in files {
            self.upload_file_with_state(session_id, &lp, &rp, transfer_id, app, total_state)?;
        }

        Ok(())
    }

    fn collect_local_files(
        &self,
        local_path: &str,
        remote_path: &str,
        files: &mut Vec<(String, String)>,
        session_id: &str,
        total_state: &mut (u64, u64),
    ) -> Result<(), String> {
        let entries = std::fs::read_dir(local_path).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            let local_child = format!("{}/{}", local_path, name);
            let remote_child = format!("{}/{}", remote_path, name);

            if meta.is_dir() {
                self.mkdir(session_id, &remote_child, 0o755).ok();
                self.collect_local_files(&local_child, &remote_child, files, session_id, total_state)?;
            } else {
                total_state.0 += meta.len();
                files.push((local_child, remote_child));
            }
        }
        Ok(())
    }

    fn upload_file_with_state(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        transfer_id: &str,
        app: &AppHandle,
        total_state: &mut (u64, u64),
    ) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;
        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;

        let mut local_file =
            std::fs::File::open(local_path).map_err(|e| format!("Failed to open: {}", e))?;
        let mut remote_file = sftp
            .create(Path::new(remote_path))
            .map_err(|e| format!("Failed to create remote file: {}", e))?;

        let mut buf = [0u8; 65536];
        let mut last_percentage = if total_state.1 > 0 {
            ((total_state.0 as f64 / total_state.1 as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };

        loop {
            match local_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    remote_file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                    total_state.0 += n as u64;

                    let percentage = if total_state.1 > 0 {
                        ((total_state.0 as f64 / total_state.1 as f64) * 1000.0).round() / 10.0
                    } else {
                        0.0
                    };

                    if percentage - last_percentage >= 1.0 {
                        last_percentage = percentage;
                        let _ = app.emit(
                            "sftp-progress",
                            ProgressPayload {
                                transfer_id: transfer_id.to_string(),
                                bytes_transferred: total_state.0,
                                total_bytes: total_state.1,
                                percentage,
                                done: false,
                            },
                        );
                    }
                }
                Err(e) => return Err(format!("Write error: {}", e)),
            }
        }

        Ok(())
    }

    pub fn rename(
        &self,
        session_id: &str,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        sftp.rename(Path::new(old_path), Path::new(new_path), None)
            .map_err(|e| format!("Rename failed: {}", e))
    }

    pub fn delete_file(&self, session_id: &str, path: &str) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        sftp.unlink(Path::new(path))
            .map_err(|e| format!("Delete failed: {}", e))
    }

    pub fn delete_dir(&self, session_id: &str, path: &str) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        sftp.rmdir(Path::new(path))
            .map_err(|e| format!("Delete directory failed: {}", e))
    }

    pub fn delete_recursive(&self, session_id: &str, path: &str) -> Result<(), String> {
        let entries = self.list_dir(session_id, path);
        match entries {
            Ok(items) => {
                for item in items {
                    if item.is_dir {
                        self.delete_recursive(session_id, &item.path)?;
                    } else {
                        self.delete_file(session_id, &item.path)?;
                    }
                }
                self.delete_dir(session_id, path)
            }
            Err(_) => self.delete_file(session_id, path),
        }
    }

    pub fn mkdir(&self, session_id: &str, path: &str, mode: i32) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        sftp.mkdir(Path::new(path), mode)
            .map_err(|e| format!("mkdir failed: {}", e))
    }

    pub fn chmod(&self, session_id: &str, path: &str, mode: u32) -> Result<(), String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        let mut stat = sftp
            .stat(Path::new(path))
            .map_err(|e| format!("Failed to stat: {}", e))?;
        stat.perm = Some(mode);
        sftp.setstat(Path::new(path), stat)
            .map_err(|e| format!("chmod failed: {}", e))
    }

    pub fn stat(&self, session_id: &str, path: &str) -> Result<FileEntry, String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        let stat = sftp
            .stat(Path::new(path))
            .map_err(|e| format!("stat failed: {}", e))?;

        let name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());

        Ok(FileEntry {
            name,
            path: path.to_string(),
            is_dir: stat.is_dir(),
            size: stat.size.unwrap_or(0),
            permissions: stat.perm.unwrap_or(0),
            modified: stat.mtime.unwrap_or(0) as i64,
            is_symlink: stat.file_type().is_symlink(),
        })
    }

    pub fn read_file(&self, session_id: &str, path: &str) -> Result<String, String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;

        let stat = sftp
            .stat(Path::new(path))
            .map_err(|e| format!("stat failed: {}", e))?;
        let size = stat.size.unwrap_or(0);
        if size > 10 * 1024 * 1024 {
            return Err("File too large to preview (>10MB)".into());
        }

        let mut remote_file = sftp
            .open(Path::new(path))
            .map_err(|e| format!("Failed to open file: {}", e))?;

        let mut content = String::new();
        remote_file
            .read_to_string(&mut content)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        Ok(content)
    }

    pub fn home_dir(&self, session_id: &str) -> Result<String, String> {
        let sess_arc = self.get_session(session_id)?;
        let sess = sess_arc.lock().map_err(|e| e.to_string())?;

        let sftp = sess.session.sftp().map_err(|e| e.to_string())?;
        let real = sftp
            .realpath(Path::new("."))
            .map_err(|e| format!("Failed to get home dir: {}", e))?;
        Ok(real.to_string_lossy().to_string())
    }

    pub fn disconnect(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(sess_arc) = sessions.remove(session_id) {
            if let Ok(sess) = sess_arc.lock() {
                let _ = sess.session.disconnect(None, "Closing SFTP session", None);
            }
        }
        Ok(())
    }
}

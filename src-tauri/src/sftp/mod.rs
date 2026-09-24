mod atomic_rename;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use ssh2::Session;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    trust_lock: Mutex<()>,
    known_hosts_path: Option<PathBuf>,
    transfers: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

impl SftpManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            trust_lock: Mutex::new(()),
            known_hosts_path: dirs::home_dir().map(|home| home.join(".ssh").join("known_hosts")),
            transfers: Mutex::new(HashMap::new()),
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
        private_key: Option<&str>,
        trusted_fingerprint: Option<&str>,
    ) -> Result<(), String> {
        let addresses = (host, port).to_socket_addrs().map_err(|e| e.to_string())?;
        let mut connected = None;
        for address in addresses {
            if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(10)) {
                connected = Some(stream);
                break;
            }
        }
        let tcp = connected.ok_or("TCP connection failed or timed out")?;
        tcp.set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;

        let mut sess = Session::new().map_err(|e| format!("SSH session creation failed: {}", e))?;
        sess.set_timeout(15_000);
        sess.set_tcp_stream(tcp.try_clone().map_err(|e| e.to_string())?);
        sess.handshake()
            .map_err(|e| format!("SSH handshake failed: {}", e))?;

        self.verify_host(&sess, host, port, trusted_fingerprint)?;
        if let Some(key) = private_key {
            sess.userauth_pubkey_memory(username, None, key, password)
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

        let sftp = sess
            .session
            .sftp()
            .map_err(|e| format!("SFTP init failed: {}", e))?;
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

    fn verify_host(
        &self,
        session: &Session,
        host: &str,
        port: u16,
        accepted: Option<&str>,
    ) -> Result<(), String> {
        let _lock = self.trust_lock.lock().map_err(|e| e.to_string())?;
        let path = self
            .known_hosts_path
            .as_ref()
            .ok_or("Home directory unavailable")?;
        let mut known = session.known_hosts().map_err(|e| e.to_string())?;
        if path.exists() {
            known
                .read_file(&path, ssh2::KnownHostFileKind::OpenSSH)
                .map_err(|e| format!("Cannot read known_hosts: {e}"))?;
        }
        let (key, kind) = session
            .host_key()
            .ok_or("Server did not supply a host key")?;
        let fingerprint = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(key))
        );
        match check_host_key(session, &known, host, port, key, kind)? {
            ssh2::CheckResult::Match => return Ok(()),
            ssh2::CheckResult::Mismatch => return Err(format!("Server host key changed for {host}:{port}. Connection refused. Verify the change independently before updating known_hosts.")),
            ssh2::CheckResult::Failure => return Err("Host key verification failed".into()),
            ssh2::CheckResult::NotFound => {}
        }
        if accepted != Some(fingerprint.as_str()) {
            return Err(serde_json::json!({"code":"unknown_host_key", "host":host, "port":port, "fingerprint":fingerprint}).to_string());
        }
        let hostname = if port == 22 {
            host.to_owned()
        } else {
            format!("[{host}]:{port}")
        };
        known
            .add(&hostname, key, "SecureShell Pro", kind.into())
            .map_err(|e| e.to_string())?;
        let parent = path.parent().ok_or("Invalid known_hosts path")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        known
            .write_file(temp.path(), ssh2::KnownHostFileKind::OpenSSH)
            .map_err(|e| e.to_string())?;
        temp.persist(path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn begin_transfer(&self, id: &str) -> Result<TransferGuard<'_>, String> {
        let mut transfers = self.transfers.lock().map_err(|e| e.to_string())?;
        if transfers.contains_key(id) {
            return Err("Transfer is already running".into());
        }
        transfers.insert(id.to_owned(), Arc::new(AtomicBool::new(false)));
        Ok(TransferGuard {
            manager: self,
            id: id.to_owned(),
        })
    }

    pub fn cancel_transfer(&self, id: &str) -> Result<(), String> {
        if let Some(flag) = self.transfers.lock().map_err(|e| e.to_string())?.get(id) {
            flag.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn check_cancelled(&self, id: &str) -> Result<(), String> {
        if self
            .transfers
            .lock()
            .map_err(|e| e.to_string())?
            .get(id)
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return Err("Transfer cancelled".into());
        }
        Ok(())
    }

    fn copy_stream(
        &self,
        source: &mut impl Read,
        target: &mut impl Write,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        state: &mut (u64, u64),
    ) -> Result<u64, String> {
        let mut buf = [0u8; 65536];
        let mut copied = 0;
        let mut last = std::time::Instant::now() - Duration::from_millis(100);
        loop {
            self.check_cancelled(id)?;
            let n = source.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            target.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            copied += n as u64;
            state.0 += n as u64;
            if last.elapsed() >= Duration::from_millis(100) {
                emit_progress(app, id, *state, false);
                last = std::time::Instant::now();
            }
        }
        target.flush().map_err(|e| e.to_string())?;
        self.check_cancelled(id)?;
        Ok(copied)
    }

    fn download_one(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        state: &mut (u64, u64),
        overwrite: bool,
    ) -> Result<u64, String> {
        self.check_cancelled(id)?;
        let arc = self.get_session(session_id)?;
        let session = arc.lock().map_err(|e| e.to_string())?;
        let sftp = session.session.sftp().map_err(|e| e.to_string())?;
        let mut source = sftp
            .open(Path::new(remote_path))
            .map_err(|e| e.to_string())?;
        let destination = Path::new(local_path);
        if destination.symlink_metadata().is_ok() && !overwrite {
            return Err("Destination exists; confirm replacement first".into());
        }
        let parent = destination.parent().ok_or("Invalid destination")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        let copied = self.copy_stream(&mut source, &mut temp, id, app, state)?;
        if overwrite {
            if let Ok(metadata) = destination.symlink_metadata() {
                if metadata.is_file() {
                    temp.as_file()
                        .set_permissions(metadata.permissions())
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        self.check_cancelled(id)?;
        if overwrite {
            temp.persist(destination).map_err(|e| e.to_string())?;
        } else {
            temp.persist_noclobber(destination)
                .map_err(|e| e.to_string())?;
        }
        Ok(copied)
    }

    fn upload_one(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        state: &mut (u64, u64),
        overwrite: bool,
    ) -> Result<u64, String> {
        self.check_cancelled(id)?;
        let arc = self.get_session(session_id)?;
        let session = arc.lock().map_err(|e| e.to_string())?;
        let sftp = session.session.sftp().map_err(|e| e.to_string())?;
        let dest = Path::new(remote_path);
        let existing = match sftp.lstat(dest) {
            Ok(stat) => Some(stat),
            Err(e) if e.code() == ssh2::ErrorCode::SFTP(2) => None,
            Err(e) => return Err(e.to_string()),
        };
        if existing.is_some() && !overwrite {
            return Err("Destination exists; confirm replacement first".into());
        }
        let mut source = std::fs::File::open(local_path).map_err(|e| e.to_string())?;
        // Remote paths always use '/', including when this app runs on Windows.
        let remote_parent = remote_path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or(".");
        let path = PathBuf::from(format!(
            "{remote_parent}/.ssp-{}.part",
            uuid::Uuid::new_v4()
        ));
        let mut target = sftp
            .open_mode(
                &path,
                ssh2::OpenFlags::WRITE | ssh2::OpenFlags::CREATE | ssh2::OpenFlags::EXCLUSIVE,
                0o600,
                ssh2::OpenType::File,
            )
            .map_err(|e| e.to_string())?;
        let _cleanup = RemoteTemp {
            sftp: &sftp,
            path: path.clone(),
        };
        let copied = self.copy_stream(&mut source, &mut target, id, app, state)?;
        target.close().map_err(|e| e.to_string())?;
        #[cfg(unix)]
        let default_mode = {
            use std::os::unix::fs::PermissionsExt;
            source
                .metadata()
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o777
        };
        #[cfg(not(unix))]
        let default_mode = 0o644;
        let mode = existing
            .filter(|s| !s.file_type().is_symlink())
            .and_then(|s| s.perm)
            .unwrap_or(default_mode)
            & 0o777;
        sftp.setstat(
            &path,
            ssh2::FileStat {
                size: None,
                uid: None,
                gid: None,
                perm: Some(mode),
                atime: None,
                mtime: None,
            },
        )
        .map_err(|e| e.to_string())?;
        self.check_cancelled(id)?;
        if overwrite {
            atomic_rename::replace(&session.session, &path.to_string_lossy(), remote_path)?;
        } else {
            sftp.rename(&path, dest, Some(ssh2::RenameFlags::empty()))
                .map_err(|e| format!("Could not commit upload: {e}"))?;
        }
        Ok(copied)
    }

    pub fn download(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        overwrite: bool,
    ) -> Result<u64, String> {
        let mut state = (0, self.stat(session_id, remote_path)?.size);
        let n = self.download_one(
            session_id,
            remote_path,
            local_path,
            id,
            app,
            &mut state,
            overwrite,
        )?;
        emit_progress(app, id, state, true);
        Ok(n)
    }

    pub fn upload(
        &self,
        session_id: &str,
        local_path: &str,
        remote_path: &str,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        overwrite: bool,
    ) -> Result<u64, String> {
        let mut state = (
            0,
            std::fs::metadata(local_path)
                .map_err(|e| e.to_string())?
                .len(),
        );
        let n = self.upload_one(
            session_id,
            local_path,
            remote_path,
            id,
            app,
            &mut state,
            overwrite,
        )?;
        emit_progress(app, id, state, true);
        Ok(n)
    }

    pub fn download_recursive(
        &self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        state: &mut (u64, u64),
        overwrite: bool,
    ) -> Result<(), String> {
        let mut files = Vec::new();
        self.collect_remote_files(
            session_id,
            remote_path,
            Path::new(local_path),
            id,
            &mut files,
            0,
        )?;
        state.1 = files.iter().map(|(_, _, size)| size).sum();
        for (remote, local, _) in files {
            self.download_one(
                session_id,
                &remote,
                &local.to_string_lossy(),
                id,
                app,
                state,
                overwrite,
            )?;
        }
        Ok(())
    }

    fn collect_remote_files(
        &self,
        sid: &str,
        remote: &str,
        local: &Path,
        id: &str,
        files: &mut Vec<(String, PathBuf, u64)>,
        depth: usize,
    ) -> Result<(), String> {
        self.check_cancelled(id)?;
        if depth > 64 {
            return Err("Directory nesting exceeds 64 levels".into());
        }
        if local
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err("Refusing to download through a local symlink".into());
        }
        std::fs::create_dir_all(local).map_err(|e| e.to_string())?;
        for entry in self.list_dir(sid, remote)? {
            if entry.name.contains(['/', '\\']) || entry.name == "." || entry.name == ".." {
                return Err("Unsafe remote filename".into());
            }
            if entry.is_symlink {
                return Err("Recursive transfer of symlinks is not supported".into());
            }
            let child = local.join(&entry.name);
            if entry.is_dir {
                self.collect_remote_files(sid, &entry.path, &child, id, files, depth + 1)?;
            } else {
                files.push((entry.path, child, entry.size));
            }
        }
        Ok(())
    }

    pub fn upload_recursive(
        &self,
        sid: &str,
        local: &str,
        remote: &str,
        id: &str,
        app: &dyn Fn(ProgressPayload),
        state: &mut (u64, u64),
        overwrite: bool,
    ) -> Result<(), String> {
        let mut files = Vec::new();
        self.collect_local_files(sid, Path::new(local), remote, id, &mut files, 0)?;
        state.1 = files.iter().map(|(_, _, size)| size).sum();
        for (local, remote, _) in files {
            self.upload_one(
                sid,
                &local.to_string_lossy(),
                &remote,
                id,
                app,
                state,
                overwrite,
            )?;
        }
        Ok(())
    }

    fn collect_local_files(
        &self,
        sid: &str,
        local: &Path,
        remote: &str,
        id: &str,
        files: &mut Vec<(PathBuf, String, u64)>,
        depth: usize,
    ) -> Result<(), String> {
        self.check_cancelled(id)?;
        if depth > 64 {
            return Err("Directory nesting exceeds 64 levels".into());
        }
        if local
            .symlink_metadata()
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("Recursive transfer of symlinks is not supported".into());
        }
        if let Err(error) = self.mkdir(sid, remote, 0o755) {
            if !self.stat(sid, remote)?.is_dir {
                return Err(error);
            }
        }
        for entry in std::fs::read_dir(local).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = entry.path().symlink_metadata().map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err("Recursive transfer of symlinks is not supported".into());
            }
            let remote_child = format!(
                "{}/{}",
                remote.trim_end_matches('/'),
                entry.file_name().to_string_lossy()
            );
            if meta.is_dir() {
                self.collect_local_files(sid, &entry.path(), &remote_child, id, files, depth + 1)?;
            } else if meta.is_file() {
                files.push((entry.path(), remote_child, meta.len()));
            } else {
                return Err("Only regular files and directories can be transferred".into());
            }
        }
        Ok(())
    }

    pub fn rename(&self, session_id: &str, old_path: &str, new_path: &str) -> Result<(), String> {
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

// ssh2::KnownHosts::check_port compares keys without considering their type.
// A server's RSA and Ed25519 keys are different identities, not rotated keys.
// Filter a separate collection so a new type requires explicit trust, while a
// changed key of the same type is still rejected and all saved keys are retained.
fn check_host_key(
    session: &Session,
    known: &ssh2::KnownHosts,
    host: &str,
    port: u16,
    key: &[u8],
    kind: ssh2::HostKeyType,
) -> Result<ssh2::CheckResult, String> {
    let algorithm = match kind {
        ssh2::HostKeyType::Rsa => "ssh-rsa",
        ssh2::HostKeyType::Dss => "ssh-dss",
        ssh2::HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
        ssh2::HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
        ssh2::HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
        ssh2::HostKeyType::Ed25519 => "ssh-ed25519",
        ssh2::HostKeyType::Unknown => return Err("Unsupported server host key type".into()),
    };
    let mut matching = session.known_hosts().map_err(|e| e.to_string())?;
    for entry in known.iter().map_err(|e| e.to_string())? {
        let line = known
            .write_string(&entry, ssh2::KnownHostFileKind::OpenSSH)
            .map_err(|e| e.to_string())?;
        if line.split_whitespace().nth(1) == Some(algorithm) {
            matching
                .read_str(&line, ssh2::KnownHostFileKind::OpenSSH)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(matching.check_port(host, port, key))
}

fn emit_progress(app: &dyn Fn(ProgressPayload), id: &str, state: (u64, u64), done: bool) {
    let percentage = if done {
        100.0
    } else if state.1 == 0 {
        0.0
    } else {
        (state.0 as f64 / state.1 as f64 * 100.0).min(100.0)
    };
    app(ProgressPayload {
        transfer_id: id.into(),
        bytes_transferred: state.0,
        total_bytes: state.1,
        percentage,
        done,
    });
}

pub struct TransferGuard<'a> {
    manager: &'a SftpManager,
    id: String,
}
impl Drop for TransferGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut transfers) = self.manager.transfers.lock() {
            transfers.remove(&self.id);
        }
    }
}
struct RemoteTemp<'a> {
    sftp: &'a ssh2::Sftp,
    path: PathBuf,
}
impl Drop for RemoteTemp<'_> {
    fn drop(&mut self) {
        let _ = self.sftp.unlink(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_verification_distinguishes_new_types_from_changed_keys() {
        let session = Session::new().unwrap();
        // Include OpenSSH's hashed hostname form and a non-default port.
        for (hostname, port) in [
            ("example.test", 22),
            ("[example.test]:2222", 2222),
            (
                "|1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|410uIDcPGPGynJ2kieNHiAb2uZY=",
                2222,
            ),
        ] {
            let mut known = session.known_hosts().unwrap();
            known
                .read_str(
                    &format!("{hostname} ssh-rsa b2xkLXJzYS1rZXk="),
                    ssh2::KnownHostFileKind::OpenSSH,
                )
                .unwrap();
            let check = |known: &ssh2::KnownHosts, key: &[u8]| {
                check_host_key(
                    &session,
                    known,
                    "example.test",
                    port,
                    key,
                    ssh2::HostKeyType::Ed25519,
                )
                .unwrap()
            };
            // This previously reported a changed key and blocked the connection.
            assert!(matches!(
                known.check_port("example.test", port, b"ed25519-key"),
                ssh2::CheckResult::Mismatch
            ));
            assert!(matches!(
                check(&known, b"ed25519-key"),
                ssh2::CheckResult::NotFound
            ));
            known
                .read_str(
                    &format!("{hostname} ssh-ed25519 ZWQyNTUxOS1rZXk="),
                    ssh2::KnownHostFileKind::OpenSSH,
                )
                .unwrap();
            assert!(matches!(
                check(&known, b"ed25519-key"),
                ssh2::CheckResult::Match
            ));
            assert!(matches!(
                check(&known, b"changed-key"),
                ssh2::CheckResult::Mismatch
            ));
            assert_eq!(known.iter().unwrap().len(), 2);
        }
    }

    #[test]
    #[ignore = "requires isolated sshd fixture; run scripts/run-sftp-integration.py"]
    fn isolated_sftp_server() {
        let root = PathBuf::from(std::env::var("SSP_TEST_SFTP_DIR").unwrap());
        let port: u16 = std::env::var("SSP_TEST_SFTP_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let username = std::env::var("SSP_TEST_SFTP_USER").unwrap();
        let private_key = std::fs::read_to_string(root.join("client_key")).unwrap();
        let mut manager = SftpManager::new();
        manager.known_hosts_path = Some(root.join("known_hosts"));
        let connect = |manager: &SftpManager, fingerprint: Option<&str>| {
            manager.connect(
                "test",
                "127.0.0.1",
                port,
                &username,
                Some("integration-passphrase"),
                Some(&private_key),
                fingerprint,
            )
        };
        let unknown = connect(&manager, None).unwrap_err();
        let detail: serde_json::Value = serde_json::from_str(&unknown).unwrap();
        assert_eq!(detail["code"], "unknown_host_key");
        let fingerprint = detail["fingerprint"].as_str().unwrap();
        assert!(connect(&manager, Some("SHA256:incorrect")).is_err());
        connect(&manager, Some(fingerprint)).unwrap();
        manager.disconnect("test").unwrap();
        connect(&manager, None).unwrap();

        let local = root.join("local.txt");
        let remote = root.join("remote.txt");
        let downloaded = root.join("downloaded.txt");
        std::fs::write(&local, vec![b'x'; 256 * 1024]).unwrap();
        std::fs::write(&remote, b"original remote").unwrap();
        std::fs::write(&downloaded, b"original local").unwrap();
        let lp = local.to_str().unwrap();
        let rp = remote.to_str().unwrap();
        let dp = downloaded.to_str().unwrap();
        {
            let _guard = manager.begin_transfer("upload").unwrap();
            assert!(manager
                .upload("test", lp, rp, "upload", &|_| {}, false)
                .is_err());
            assert_eq!(std::fs::read(&remote).unwrap(), b"original remote");
            let cancel = |_: ProgressPayload| {
                manager.cancel_transfer("upload").unwrap();
            };
            assert!(manager
                .upload("test", lp, rp, "upload", &cancel, true)
                .is_err());
            assert_eq!(std::fs::read(&remote).unwrap(), b"original remote");
        }
        {
            let _guard = manager.begin_transfer("successful-upload").unwrap();
            manager
                .upload("test", lp, rp, "successful-upload", &|_| {}, true)
                .unwrap();
            assert_eq!(
                std::fs::read(&remote).unwrap(),
                std::fs::read(&local).unwrap()
            );
        }
        {
            let _guard = manager.begin_transfer("download").unwrap();
            assert!(manager
                .download("test", rp, dp, "download", &|_| {}, false)
                .is_err());
            let cancel = |_: ProgressPayload| {
                manager.cancel_transfer("download").unwrap();
            };
            assert!(manager
                .download("test", rp, dp, "download", &cancel, true)
                .is_err());
            assert_eq!(std::fs::read(&downloaded).unwrap(), b"original local");
        }
        {
            let _guard = manager.begin_transfer("successful-download").unwrap();
            manager
                .download("test", rp, dp, "successful-download", &|_| {}, true)
                .unwrap();
            assert_eq!(
                std::fs::read(&downloaded).unwrap(),
                std::fs::read(&local).unwrap()
            );
        }
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".part")));
        manager.disconnect("test").unwrap();
        let wrong_public = std::fs::read_to_string(root.join("client_key.pub")).unwrap();
        std::fs::write(
            root.join("known_hosts"),
            format!("[127.0.0.1]:{port} {wrong_public}"),
        )
        .unwrap();
        assert!(connect(&manager, Some(fingerprint))
            .unwrap_err()
            .contains("host key changed"));
    }
}

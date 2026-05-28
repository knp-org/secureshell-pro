// ═══════════════════════════════════════════════════════════
// SSH Session Manager
//
// Manages PTY-based SSH sessions. Each session spawns the
// system `ssh` command inside a pseudo-terminal and streams
// I/O via Tauri events.
// ═══════════════════════════════════════════════════════════

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::path::PathBuf;
use tauri::{AppHandle, Emitter};

/// Holds one active SSH session
struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    alive: Arc<Mutex<bool>>,
    key_path: Option<PathBuf>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(path) = &self.key_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Manages all active SSH sessions
pub struct SshManager {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SshManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn default_shell() -> String {
        std::env::var("SHELL").unwrap_or_else(|_| {
            if std::path::Path::new("/bin/bash").exists() {
                "/bin/bash".into()
            } else {
                "sh".into()
            }
        })
    }

    /// Spawn a process in a PTY and stream I/O via Tauri events.
    fn spawn_pty_session(
        &self,
        session_id: &str,
        cmd: CommandBuilder,
        app: &AppHandle,
        key_path: Option<PathBuf>,
    ) -> Result<(), String> {
        let pty_system = native_pty_system();

        let pty_pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("Failed to open PTY: {}", e))?;

        let _child = pty_pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("Failed to spawn process: {}", e))?;

        let reader = pty_pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("Failed to get PTY reader: {}", e))?;

        let writer = pty_pair
            .master
            .take_writer()
            .map_err(|e| format!("Failed to get PTY writer: {}", e))?;

        let alive = Arc::new(Mutex::new(true));

        {
            let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
            sessions.insert(
                session_id.to_string(),
                Session {
                    master: pty_pair.master,
                    writer,
                    alive: alive.clone(),
                    key_path,
                },
            );
        }

        let sid = session_id.to_string();
        let app_handle = app.clone();

        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut reader = reader;

            loop {
                if let Ok(flag) = alive.lock() {
                    if !*flag {
                        break;
                    }
                }
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = app_handle.emit("ssh-closed", &sid);
                        break;
                    }
                    Ok(n) => {
                        let data = String::from_utf8_lossy(&buf[..n]).to_string();
                        let payload = serde_json::json!({
                            "sessionId": sid,
                            "data": data,
                        });
                        let _ = app_handle.emit("ssh-output", payload);
                    }
                    Err(_) => {
                        let _ = app_handle.emit("ssh-closed", &sid);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Open a local interactive shell in a PTY.
    pub fn connect_local(&self, session_id: &str, app: &AppHandle) -> Result<(), String> {
        let shell = Self::default_shell();
        let mut cmd = CommandBuilder::new(&shell);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        if let Some(home) = dirs::home_dir() {
            cmd.cwd(home);
        }
        self.spawn_pty_session(session_id, cmd, app, None)
    }

    /// Open a new SSH connection via system `ssh` in a PTY.
    pub fn connect(
        &self,
        session_id: &str,
        host: &str,
        port: u16,
        username: &str,
        password: Option<&str>,
        key_path: Option<PathBuf>,
        app: &AppHandle,
    ) -> Result<(), String> {
        // Build the ssh command
        let mut cmd = CommandBuilder::new("ssh");
        cmd.arg(format!("{}@{}", username, host));
        cmd.arg("-p");
        cmd.arg(port.to_string());
        cmd.arg("-o");
        cmd.arg("StrictHostKeyChecking=accept-new");
        
        if let Some(path) = &key_path {
            cmd.arg("-i");
            cmd.arg(path);
            cmd.arg("-o");
            cmd.arg("IdentitiesOnly=yes"); // Force using only this key
        }

        // If password provided and sshpass available, use it
        if let Some(pwd) = password {
            if !pwd.is_empty() {
                let mut sshpass_cmd = CommandBuilder::new("sshpass");
                // if it's a key passphrase, sshpass -P passphrase doesn't work easily with standard sshpass.
                // standard sshpass only supports password auth, but sshpass -P "passphrase" is a patched version.
                // Assuming standard sshpass usage for password authentication:
                sshpass_cmd.arg("-p");
                sshpass_cmd.arg(pwd);
                sshpass_cmd.arg("ssh");
                sshpass_cmd.arg(format!("{}@{}", username, host));
                sshpass_cmd.arg("-p");
                sshpass_cmd.arg(port.to_string());
                sshpass_cmd.arg("-o");
                sshpass_cmd.arg("StrictHostKeyChecking=accept-new");
                if let Some(path) = &key_path {
                    sshpass_cmd.arg("-i");
                    sshpass_cmd.arg(path);
                    sshpass_cmd.arg("-o");
                    sshpass_cmd.arg("IdentitiesOnly=yes");
                }
                cmd = sshpass_cmd;
            }
        }

        self.spawn_pty_session(session_id, cmd, app, key_path)
    }

    /// Write data (keystrokes) to a session.
    pub fn write(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions.get_mut(session_id).ok_or("Session not found")?;
        session.writer.write_all(data).map_err(|e| e.to_string())?;
        session.writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Resize the terminal.
    pub fn resize(&self, session_id: &str, rows: u16, cols: u16) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions.get(session_id).ok_or("Session not found")?;
        session.master
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Disconnect a session.
    pub fn disconnect(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.remove(session_id) {
            if let Ok(mut alive) = session.alive.lock() {
                *alive = false;
            }
        }
        Ok(())
    }
}

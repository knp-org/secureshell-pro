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

use tauri::{AppHandle, Emitter};

/// Holds one active SSH session
struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    alive: Arc<Mutex<bool>>,
    _key_file: Option<tempfile::NamedTempFile>,
    killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.killer.kill();
        if let Ok(mut alive) = self.alive.lock() {
            *alive = false;
        }
    }
}

/// Manages all active SSH sessions
pub struct SshManager {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl SshManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn default_shell() -> String {
        #[cfg(windows)]
        {
            std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into())
        }
        #[cfg(not(windows))]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
        }
    }

    /// Spawn a process in a PTY and stream I/O via Tauri events.
    fn spawn_pty_session(
        &self,
        session_id: &str,
        cmd: CommandBuilder,
        app: &AppHandle,
        key_file: Option<tempfile::NamedTempFile>,
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

        let reader = pty_pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("Failed to get PTY reader: {}", e))?;

        let writer = pty_pair
            .master
            .take_writer()
            .map_err(|e| format!("Failed to get PTY writer: {}", e))?;

        let mut child = pty_pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("Failed to spawn process: {}", e))?;

        let alive = Arc::new(Mutex::new(true));
        let killer = child.clone_killer();
        thread::spawn(move || {
            let _ = child.wait();
        });

        let session = Session {
            master: pty_pair.master,
            writer,
            alive: alive.clone(),
            _key_file: key_file,
            killer,
        };
        self.sessions
            .lock()
            .map_err(|e| e.to_string())?
            .insert(session_id.to_string(), session);

        let sid = session_id.to_string();
        let app_handle = app.clone();

        let sessions = self.sessions.clone();
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
                        break;
                    }
                    Ok(n) => {
                        // xterm's streaming UTF-8 decoder handles codepoints split across reads.
                        let data = &buf[..n];
                        let payload = serde_json::json!({
                            "sessionId": sid,
                            "data": data,
                        });
                        let _ = app_handle.emit("ssh-output", payload);
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            if let Ok(mut sessions) = sessions.lock() {
                if sessions
                    .get(&sid)
                    .is_some_and(|session| Arc::ptr_eq(&session.alive, &alive))
                {
                    sessions.remove(&sid);
                    let _ = app_handle.emit("ssh-closed", &sid);
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
        key_file: Option<tempfile::NamedTempFile>,
        app: &AppHandle,
    ) -> Result<(), String> {
        // Build the ssh command
        let mut cmd = CommandBuilder::new("ssh");
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        if host.is_empty()
            || host.starts_with('-')
            || username.starts_with('-')
            || username.is_empty()
        {
            return Err("Invalid SSH host or username".into());
        }
        cmd.arg("-l");
        cmd.arg(username);
        cmd.arg("-p");
        cmd.arg(port.to_string());
        cmd.arg("-o");
        cmd.arg("StrictHostKeyChecking=accept-new");

        if let Some(file) = &key_file {
            cmd.arg("-i");
            cmd.arg(file.path());
            cmd.arg("-o");
            cmd.arg("IdentitiesOnly=yes"); // Force using only this key
        }

        // OpenSSH invokes our executable as an askpass helper. Secrets are never
        // command-line arguments; both password and key-passphrase prompts work.
        if let Some(secret) = password.filter(|s| !s.is_empty()) {
            cmd.env(
                "SSH_ASKPASS",
                std::env::current_exe().map_err(|e| e.to_string())?,
            );
            cmd.env("SSH_ASKPASS_REQUIRE", "force");
            cmd.env("SSP_ASKPASS_SECRET", secret);
            if std::env::var_os("DISPLAY").is_none() {
                cmd.env("DISPLAY", ":0");
            }
        }
        cmd.arg("-o");
        cmd.arg("ConnectTimeout=15");
        cmd.arg("-o");
        cmd.arg("NumberOfPasswordPrompts=1");
        cmd.arg("--");
        cmd.arg(host);
        self.spawn_pty_session(session_id, cmd, app, key_file)
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
        session
            .master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
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

impl Drop for SshManager {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.clear();
        }
    }
}

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SSH Connection / Host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String, // "password" | "key" | "key_passphrase"
    pub password: Option<String>, // Will be encrypted in Phase 3
    pub key_id: Option<String>,
    pub group_id: Option<String>,
    pub tags: Vec<String>,
    pub color: Option<String>,
    pub last_connected: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub synced: bool,
}

/// Connection Group / Folder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub created_at: String,
}

/// Saved Command / Snippet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snippet {
    pub id: String,
    pub label: String,
    pub command: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub connection_ids: Vec<String>,
    pub group_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub synced: bool,
}

/// SSH Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub id: String,
    pub label: String,
    pub key_type: String, // "rsa" | "ed25519" | "ecdsa"
    pub public_key: Option<String>,
    pub private_key: Option<String>, // Will be encrypted in Phase 3
    pub fingerprint: Option<String>,
    pub created_at: String,
    /// Server-managed: stamped on every save so edits (and master-password
    /// re-encryption) propagate over LAN sync. Defaulted for older frontends
    /// that don't send it.
    #[serde(default)]
    pub updated_at: String,
    pub synced: bool,
}

impl SshKey {
    pub fn new(label: String, key_type: String) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            label,
            key_type,
            public_key: None,
            private_key: None,
            fingerprint: None,
            created_at: now.clone(),
            updated_at: now,
            synced: false,
        }
    }
}


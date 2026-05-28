use tauri::State;

use crate::db::models::SshKey;
use crate::db::Database;
use crate::vault::{encrypt_field_required, maybe_decrypt_field, Vault};

#[tauri::command]
pub fn get_keys(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
) -> Result<Vec<SshKey>, String> {
    let mut rows = db.get_all_keys()?;
    for k in rows.iter_mut() {
        k.private_key = match maybe_decrypt_field(k.private_key.take(), &vault, &k.id) {
            Ok(v) => v,
            Err(_) if !vault.is_unlocked() => None,
            Err(e) => return Err(e),
        };
    }
    Ok(rows)
}

#[tauri::command]
pub fn save_key(
    db: State<'_, Database>,
    vault: State<'_, Vault>,
    key: SshKey,
) -> Result<(), String> {
    let mut k = key;
    if db.get_vault_meta()?.is_some() {
        k.private_key = encrypt_field_required(k.private_key, &vault, &k.id)?;
    }
    db.save_key(&k)
}

#[tauri::command]
pub fn delete_key(db: State<'_, Database>, id: String) -> Result<(), String> {
    db.delete_key(&id)
}

#[tauri::command]
pub fn detect_keys() -> Result<Vec<SshKey>, String> {
    let mut detected_keys = Vec::new();
    
    // Get home directory
    let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    let ssh_dir = home_dir.join(".ssh");
    
    if !ssh_dir.exists() || !ssh_dir.is_dir() {
        return Ok(detected_keys);
    }
    
    let entries = match std::fs::read_dir(&ssh_dir) {
        Ok(e) => e,
        Err(_) => return Ok(detected_keys),
    };

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() { continue; }
        
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip known non-private-key files
        if file_name.ends_with(".pub") || file_name == "known_hosts" || 
           file_name == "known_hosts.old" || file_name == "authorized_keys" || 
           file_name == "config" {
            continue;
        }

        // Read file content
        if let Ok(content) = std::fs::read_to_string(&path) {
            // Check if it's a private key (PEM or OpenSSH format)
            if content.contains("-----BEGIN ") && content.contains(" PRIVATE KEY-----") {
                // Read public key if it exists
                let pub_path = ssh_dir.join(format!("{}.pub", file_name));
                let pub_content = std::fs::read_to_string(&pub_path).ok();
                
                // Try to infer key type
                let mut key_type = "ed25519".to_string(); // Default assumption
                if content.contains("RSA PRIVATE KEY") || (pub_content.is_some() && pub_content.as_ref().unwrap().contains("ssh-rsa")) {
                    key_type = "rsa".to_string();
                } else if pub_content.is_some() && pub_content.as_ref().unwrap().contains("ecdsa") {
                    key_type = "ecdsa".to_string();
                }

                let mut key = SshKey::new(file_name.to_string(), key_type);
                key.private_key = Some(content);
                key.public_key = pub_content;
                
                detected_keys.push(key);
            }
        }
    }
    
    Ok(detected_keys)
}

// Long-lived device identity: an X25519 static keypair persisted in the
// settings table. The public key is broadcast in mDNS TXT records and used
// as the peer ID for paired devices.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::db::Database;

const SETTING_KEY: &str = "sync_device_identity";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// 32-byte X25519 secret key, hex-encoded.
    pub sk_hex: String,
    /// 32-byte X25519 public key, hex-encoded.
    pub pk_hex: String,
    /// User-visible label for this device.
    pub label: String,
}

impl DeviceIdentity {
    pub fn load_or_create(db: &Database) -> Result<Self, String> {
        if let Some(raw) = db.get_setting(SETTING_KEY)? {
            if let Ok(id) = serde_json::from_str::<DeviceIdentity>(&raw) {
                return Ok(id);
            }
        }
        let id = Self::generate();
        let raw = serde_json::to_string(&id).map_err(|e| e.to_string())?;
        db.set_setting(SETTING_KEY, &raw)?;
        Ok(id)
    }

    fn generate() -> Self {
        let mut sk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk_bytes);
        let sk = StaticSecret::from(sk_bytes);
        let pk = PublicKey::from(&sk);

        Self {
            sk_hex: hex::encode(sk.to_bytes()),
            pk_hex: hex::encode(pk.to_bytes()),
            label:  hostname::get()
                .ok()
                .and_then(|s| s.into_string().ok())
                .unwrap_or_else(|| "Linux".into()),
        }
    }

    pub fn secret_bytes(&self) -> Result<[u8; 32], String> {
        let v = hex::decode(&self.sk_hex).map_err(|e| e.to_string())?;
        v.try_into().map_err(|_| "bad sk length".to_string())
    }

    pub fn public_bytes(&self) -> Result<[u8; 32], String> {
        let v = hex::decode(&self.pk_hex).map_err(|e| e.to_string())?;
        v.try_into().map_err(|_| "bad pk length".to_string())
    }
}

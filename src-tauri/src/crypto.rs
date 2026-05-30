// Vault crypto — cross-platform, post-quantum-safe symmetric encryption.
//
// Algorithm choices are fixed and documented in docs/vault-format.md so the
// Android port can produce byte-identical envelopes:
//
//   KDF        Argon2id (m=64 MiB, t=3, p=1, output=32B)
//   Cipher     AES-256-GCM (nonce=12B, tag=16B appended to ciphertext)
//   Encoding   Base64 standard (no URL-safe, no padding stripped) for n/ct
//   Verifier   AES-GCM of the ASCII literal "VAULT_VERIFY_v1"
//
// All record secrets (passwords, private keys, key passphrases) are wrapped
// in this envelope. AES-256 is considered PQ-safe; the master key never
// leaves memory and is zeroized on drop.

use aes_gcm::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VAULT_FORMAT_VERSION: u8 = 1;
pub const VERIFIER_PLAINTEXT: &str = "VAULT_VERIFY_v1";

/// Argon2id parameters baked into the spec. Same on every platform.
pub const ARGON2_M_COST: u32 = 65_536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;
pub const ARGON2_OUT_LEN: usize = 32;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// On-disk / on-wire encrypted envelope for a single secret field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,             // version
    pub alg: String,       // "AES-256-GCM"
    pub n: String,         // base64(nonce)
    pub ct: String,        // base64(ciphertext || tag)
}

/// KDF parameters as stored in `vault_meta`. Identifies how to re-derive the
/// master key from the user's password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub kdf: String,        // "argon2id"
    pub salt: String,       // base64(salt)
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub fn new_random() -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            kdf: "argon2id".into(),
            salt: B64.encode(salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

/// Master key held only in memory. Zeroized when dropped or replaced.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; 32]);

impl MasterKey {
    pub fn as_key(&self) -> &Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from_slice(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("bad base64: {0}")]
    Base64(String),
    #[error("bad argon2 params: {0}")]
    Argon2Params(String),
    #[error("KDF failed: {0}")]
    Kdf(String),
    #[error("unsupported envelope version {0}")]
    Version(u8),
    #[error("unsupported algorithm {0}")]
    Algorithm(String),
    #[error("decryption failed (wrong key or tampered ciphertext)")]
    Decrypt,
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("invalid nonce length {0}, expected {NONCE_LEN}")]
    NonceLen(usize),
    #[error("invalid salt length {0}, expected {SALT_LEN}")]
    SaltLen(usize),
    #[error("password verification failed")]
    Verify,
}

/// Derive a 32-byte master key from `password` + KDF params.
pub fn derive_key(password: &str, kdf: &KdfParams) -> Result<MasterKey, CryptoError> {
    if kdf.kdf != "argon2id" {
        return Err(CryptoError::Algorithm(kdf.kdf.clone()));
    }
    let salt = B64
        .decode(&kdf.salt)
        .map_err(|e| CryptoError::Base64(e.to_string()))?;
    if salt.len() != SALT_LEN {
        return Err(CryptoError::SaltLen(salt.len()));
    }

    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(ARGON2_OUT_LEN))
        .map_err(|e| CryptoError::Argon2Params(e.to_string()))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; ARGON2_OUT_LEN];
    a2.hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(MasterKey(out))
}

/// Encrypt `plaintext` under `master_key`. Returns a versioned envelope.
/// `aad` is optional additional authenticated data (e.g. record id) — pass
/// the same value on decrypt or it will fail.
pub fn encrypt(plaintext: &[u8], master_key: &MasterKey, aad: &[u8]) -> Result<Envelope, CryptoError> {
    let cipher = Aes256Gcm::new(master_key.as_key());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = aes_gcm::aead::Payload { msg: plaintext, aad };
    let ct = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    Ok(Envelope {
        v: VAULT_FORMAT_VERSION,
        alg: "AES-256-GCM".into(),
        n: B64.encode(nonce_bytes),
        ct: B64.encode(ct),
    })
}

/// Decrypt an envelope. Returns plaintext bytes.
pub fn decrypt(env: &Envelope, master_key: &MasterKey, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if env.v != VAULT_FORMAT_VERSION {
        return Err(CryptoError::Version(env.v));
    }
    if env.alg != "AES-256-GCM" {
        return Err(CryptoError::Algorithm(env.alg.clone()));
    }
    let nonce_bytes = B64
        .decode(&env.n)
        .map_err(|e| CryptoError::Base64(e.to_string()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::NonceLen(nonce_bytes.len()));
    }
    let ct = B64
        .decode(&env.ct)
        .map_err(|e| CryptoError::Base64(e.to_string()))?;

    let cipher = Aes256Gcm::new(master_key.as_key());
    let payload = aes_gcm::aead::Payload { msg: &ct, aad };
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| CryptoError::Decrypt)
}

/// Build the verifier envelope used by `vault_meta` to prove a password is
/// correct without decrypting any real records.
pub fn make_verifier(master_key: &MasterKey) -> Result<Envelope, CryptoError> {
    encrypt(VERIFIER_PLAINTEXT.as_bytes(), master_key, b"vault-verify")
}

/// AAD for the master-key re-wrap token used during password rotation.
pub const REKEY_AAD: &[u8] = b"vault-rekey";

/// Wrap (encrypt) `new_key` under `old_key`. Shipped in `vault_meta` during
/// rotation so a paired peer that still holds the old key can recover the new
/// key without learning the new password — and thus re-encrypt its local-only
/// secrets without bricking them. The token is only meaningful to a holder of
/// the old key and only travels inside the encrypted sync session.
pub fn wrap_master_key(new_key: &MasterKey, old_key: &MasterKey) -> Result<Envelope, CryptoError> {
    encrypt(&new_key.0, old_key, REKEY_AAD)
}

/// Inverse of [`wrap_master_key`]: recover the new master key from the token
/// using the old key.
pub fn unwrap_master_key(token: &Envelope, old_key: &MasterKey) -> Result<MasterKey, CryptoError> {
    let pt = decrypt(token, old_key, REKEY_AAD)?;
    if pt.len() != ARGON2_OUT_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut out = [0u8; ARGON2_OUT_LEN];
    out.copy_from_slice(&pt);
    Ok(MasterKey(out))
}

/// Confirm that `master_key` matches the stored verifier.
pub fn verify(master_key: &MasterKey, verifier: &Envelope) -> Result<(), CryptoError> {
    let pt = decrypt(verifier, master_key, b"vault-verify")?;
    if pt == VERIFIER_PLAINTEXT.as_bytes() {
        Ok(())
    } else {
        Err(CryptoError::Verify)
    }
}

/// Convenience: encrypt a UTF-8 string field for record `record_id`, serialize
/// the envelope as JSON for storage in a TEXT column.
pub fn encrypt_field(s: &str, master_key: &MasterKey, record_id: &str) -> Result<String, CryptoError> {
    let env = encrypt(s.as_bytes(), master_key, record_id.as_bytes())?;
    serde_json::to_string(&env).map_err(|e| CryptoError::Encrypt(e.to_string()))
}

/// Inverse of `encrypt_field`.
pub fn decrypt_field(json: &str, master_key: &MasterKey, record_id: &str) -> Result<String, CryptoError> {
    let env: Envelope = serde_json::from_str(json).map_err(|e| CryptoError::Base64(e.to_string()))?;
    let pt = decrypt(&env, master_key, record_id.as_bytes())?;
    String::from_utf8(pt).map_err(|_| CryptoError::Decrypt)
}

/// Detect whether a stored TEXT field already holds an envelope (so we don't
/// double-encrypt during migration).
pub fn is_envelope(s: &str) -> bool {
    serde_json::from_str::<Envelope>(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_password() {
        let kdf = KdfParams::new_random();
        let key = derive_key("hunter2", &kdf).unwrap();
        let env = encrypt(b"my-ssh-password", &key, b"record-id-1").unwrap();
        let pt = decrypt(&env, &key, b"record-id-1").unwrap();
        assert_eq!(pt, b"my-ssh-password");
    }

    #[test]
    fn wrong_aad_fails() {
        let kdf = KdfParams::new_random();
        let key = derive_key("hunter2", &kdf).unwrap();
        let env = encrypt(b"secret", &key, b"id-1").unwrap();
        assert!(decrypt(&env, &key, b"id-2").is_err());
    }

    #[test]
    fn wrong_password_fails_verifier() {
        let kdf = KdfParams::new_random();
        let key = derive_key("correct", &kdf).unwrap();
        let v = make_verifier(&key).unwrap();
        let bad = derive_key("wrong", &kdf).unwrap();
        assert!(verify(&bad, &v).is_err());
    }

    #[test]
    fn rekey_token_roundtrip() {
        let old_kdf = KdfParams::new_random();
        let old = derive_key("old-pw", &old_kdf).unwrap();
        let new_kdf = KdfParams::new_random();
        let new = derive_key("new-pw", &new_kdf).unwrap();

        let token = wrap_master_key(&new, &old).unwrap();
        let recovered = unwrap_master_key(&token, &old).unwrap();
        assert_eq!(recovered.0, new.0);

        // A different (wrong) old key must not unwrap the token.
        let wrong = derive_key("wrong", &old_kdf).unwrap();
        assert!(unwrap_master_key(&token, &wrong).is_err());
    }

    #[test]
    fn field_helpers() {
        let kdf = KdfParams::new_random();
        let key = derive_key("pw", &kdf).unwrap();
        let json = encrypt_field("hello", &key, "rid").unwrap();
        assert!(is_envelope(&json));
        assert_eq!(decrypt_field(&json, &key, "rid").unwrap(), "hello");
    }
}

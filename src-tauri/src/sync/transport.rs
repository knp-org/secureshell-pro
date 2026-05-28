// Noise transport layer.
//
// - `responder_handshake`     — for the pairing listener (Noise IKpsk2)
// - `initiator_handshake_ik`  — for an Android scanning the QR (unused on
//                                Linux but kept here for completeness in
//                                case we ever want Linux to be the QR
//                                scanner too)
// - `initiator_handshake_kk`  — for "Sync now" against an already-paired
//                                peer (Noise KKpsk0)
// - `responder_handshake_kk`  — accept side of steady-state sync
// - `TransportSession`        — length-prefixed JSON framing over a Noise
//                                transport-mode session
// - `MobileSession`           — simplified AES-GCM framing for Android
//
// All wire bytes match docs/sync-protocol.md.

use serde::de::DeserializeOwned;
use serde::Serialize;
use snow::{HandshakeState, TransportState};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NOISE_IK:    &str = "Noise_IKpsk2_25519_ChaChaPoly_SHA256";
pub const NOISE_KK:    &str = "Noise_KKpsk0_25519_ChaChaPoly_SHA256";

// Noise message ceiling is 65535; we keep a margin for the auth tag (16).
const MAX_FRAME_PT: usize = 60 * 1024;
const MAX_FRAME_CT: usize = 65535;

pub struct HandshakeResult {
    pub session: TransportState,
    pub peer_static: [u8; 32],
    pub handshake_hash: [u8; 32],
}

// ─── Reading / writing handshake messages (length-prefixed plain bytes) ──

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_CT {
        return Err(format!("bad frame length {}", len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())?;
    Ok(())
}

// ─── Handshakes ──────────────────────────────────────────────

fn finish(hs: HandshakeState) -> Result<HandshakeResult, String> {
    let peer = hs.get_remote_static()
        .ok_or_else(|| "missing peer static key".to_string())?;
    let mut peer_static = [0u8; 32];
    if peer.len() != 32 {
        return Err("peer static key wrong size".into());
    }
    peer_static.copy_from_slice(peer);

    let mut h = [0u8; 32];
    let hash = hs.get_handshake_hash();
    if hash.len() < 32 { return Err("short handshake hash".into()); }
    h.copy_from_slice(&hash[..32]);

    let session = hs.into_transport_mode().map_err(|e| e.to_string())?;
    Ok(HandshakeResult { session, peer_static, handshake_hash: h })
}

/// Pairing-side responder. We know our static key; the initiator (Android)
/// sends its static key in the first handshake message. PSK is the random
/// 32-byte token from the QR.
pub async fn responder_handshake_ik(
    stream: &mut TcpStream,
    local_sk: &[u8; 32],
    psk: &[u8; 32],
) -> Result<HandshakeResult, String> {
    let params = NOISE_IK.parse().map_err(|e: snow::Error| e.to_string())?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(local_sk)
        .psk(2, psk)
        .build_responder()
        .map_err(|e| e.to_string())?;

    // <- e, es, s, ss
    let msg1 = read_frame(stream).await?;
    let mut buf = vec![0u8; MAX_FRAME_PT];
    hs.read_message(&msg1, &mut buf).map_err(|e| e.to_string())?;

    // -> e, ee, se, psk
    let mut out = vec![0u8; MAX_FRAME_CT];
    let n = hs.write_message(b"", &mut out).map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    finish(hs)
}

/// Like `responder_handshake_ik` but the first message has already been read
/// from the stream (e.g. because the caller peeked at it to detect the protocol).
pub async fn responder_handshake_ik_with_first_message(
    stream: &mut TcpStream,
    local_sk: &[u8; 32],
    psk: &[u8; 32],
    first_msg: &[u8],
) -> Result<HandshakeResult, String> {
    let params = NOISE_IK.parse().map_err(|e: snow::Error| e.to_string())?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(local_sk)
        .psk(2, psk)
        .build_responder()
        .map_err(|e| e.to_string())?;

    // <- e, es, s, ss (already read)
    let mut buf = vec![0u8; MAX_FRAME_PT];
    hs.read_message(first_msg, &mut buf).map_err(|e| e.to_string())?;

    // -> e, ee, se, psk
    let mut out = vec![0u8; MAX_FRAME_CT];
    let n = hs.write_message(b"", &mut out).map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    finish(hs)
}

/// Steady-state sync — responder side. Both peers know each other's static
/// keys (loaded from the trust store).
pub async fn responder_handshake_kk(
    stream: &mut TcpStream,
    local_sk: &[u8; 32],
    expected_peer_pk: &[u8; 32],
    psk: &[u8; 32],
) -> Result<HandshakeResult, String> {
    let params = NOISE_KK.parse().map_err(|e: snow::Error| e.to_string())?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(local_sk)
        .remote_public_key(expected_peer_pk)
        .psk(0, psk)
        .build_responder()
        .map_err(|e| e.to_string())?;

    let msg1 = read_frame(stream).await?;
    let mut buf = vec![0u8; MAX_FRAME_PT];
    hs.read_message(&msg1, &mut buf).map_err(|e| e.to_string())?;

    let mut out = vec![0u8; MAX_FRAME_CT];
    let n = hs.write_message(b"", &mut out).map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    finish(hs)
}

/// Steady-state sync — initiator side ("Sync now").
pub async fn initiator_handshake_kk(
    stream: &mut TcpStream,
    local_sk: &[u8; 32],
    peer_pk: &[u8; 32],
    psk: &[u8; 32],
) -> Result<HandshakeResult, String> {
    let params = NOISE_KK.parse().map_err(|e: snow::Error| e.to_string())?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(local_sk)
        .remote_public_key(peer_pk)
        .psk(0, psk)
        .build_initiator()
        .map_err(|e| e.to_string())?;

    let mut out = vec![0u8; MAX_FRAME_CT];
    let n = hs.write_message(b"", &mut out).map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    let msg2 = read_frame(stream).await?;
    let mut buf = vec![0u8; MAX_FRAME_PT];
    hs.read_message(&msg2, &mut buf).map_err(|e| e.to_string())?;

    finish(hs)
}

// ─── Transport session (encrypt/decrypt JSON frames) ──────────

pub struct Session {
    pub state: TransportState,
}

impl Session {
    pub fn new(state: TransportState) -> Self { Self { state } }

    pub async fn send<T: Serialize>(&mut self, stream: &mut TcpStream, msg: &T) -> Result<(), String> {
        let plaintext = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
        if plaintext.len() > MAX_FRAME_PT {
            return Err(format!("frame too large: {} bytes", plaintext.len()));
        }
        let mut ct = vec![0u8; plaintext.len() + 16];
        let n = self.state.write_message(&plaintext, &mut ct).map_err(|e| e.to_string())?;
        write_frame(stream, &ct[..n]).await
    }

    pub async fn recv<T: DeserializeOwned>(&mut self, stream: &mut TcpStream) -> Result<T, String> {
        let ct = read_frame(stream).await?;
        let mut pt = vec![0u8; ct.len()];
        let n = self.state.read_message(&ct, &mut pt).map_err(|e| e.to_string())?;
        serde_json::from_slice(&pt[..n]).map_err(|e| e.to_string())
    }
}

pub struct MobileSession {
    pub key: [u8; 32],
}

impl MobileSession {
    pub fn new(key: [u8; 32]) -> Self { Self { key } }

    pub async fn send<T: Serialize>(&mut self, stream: &mut TcpStream, msg: &T) -> Result<(), String> {
        let plaintext = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .map_err(|e: aes_gcm::Error| e.to_string())?;
        
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        write_frame(stream, &out).await
    }

    pub async fn recv<T: DeserializeOwned>(&mut self, stream: &mut TcpStream) -> Result<T, String> {
        let data = read_frame(stream).await?;
        if data.len() < 28 { return Err("mobile frame too short".into()); }
        let (nonce, ct) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let pt = cipher.decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|e: aes_gcm::Error| e.to_string())?;
        serde_json::from_slice(&pt).map_err(|e| e.to_string())
    }
}

/// Derive the symmetric PSK used for steady-state KKpsk0 between two
/// devices. Same on both sides because we sort the two keys
/// lexicographically before hashing.
pub fn sync_psk(our_pk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"secureshell-sync-v1");
    let (a, b) = if our_pk <= their_pk { (our_pk, their_pk) } else { (their_pk, our_pk) };
    h.update(a);
    h.update(b);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

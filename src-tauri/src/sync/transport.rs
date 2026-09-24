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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine as _;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use snow::{HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NOISE_IK: &str = "Noise_IKpsk2_25519_ChaChaPoly_SHA256";
pub const NOISE_KK: &str = "Noise_KKpsk0_25519_ChaChaPoly_SHA256";

// Noise message ceiling is 65535; we keep a margin for the auth tag (16).
const MAX_FRAME_PT: usize = 60 * 1024;
const MAX_FRAME_CT: usize = 65535;

pub struct HandshakeResult {
    pub session: TransportState,
    pub peer_static: [u8; 32],
    pub handshake_hash: [u8; 32],
}

// ─── Reading / writing handshake messages (length-prefixed plain bytes) ──

async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, String> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| e.to_string())?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_FRAME_CT {
            return Err(format!("bad frame length {}", len));
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        Ok(buf)
    })
    .await
    .map_err(|_| "Sync I/O timed out".to_string())?
}

async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), String> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let len = data.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(data).await.map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|_| "Sync I/O timed out".to_string())?
}

// ─── Handshakes ──────────────────────────────────────────────

fn finish(hs: HandshakeState) -> Result<HandshakeResult, String> {
    let peer = hs
        .get_remote_static()
        .ok_or_else(|| "missing peer static key".to_string())?;
    let mut peer_static = [0u8; 32];
    if peer.len() != 32 {
        return Err("peer static key wrong size".into());
    }
    peer_static.copy_from_slice(peer);

    let mut h = [0u8; 32];
    let hash = hs.get_handshake_hash();
    if hash.len() < 32 {
        return Err("short handshake hash".into());
    }
    h.copy_from_slice(&hash[..32]);

    let session = hs.into_transport_mode().map_err(|e| e.to_string())?;
    Ok(HandshakeResult {
        session,
        peer_static,
        handshake_hash: h,
    })
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
    hs.read_message(&msg1, &mut buf)
        .map_err(|e| e.to_string())?;

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
    hs.read_message(first_msg, &mut buf)
        .map_err(|e| e.to_string())?;

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
    hs.read_message(&msg1, &mut buf)
        .map_err(|e| e.to_string())?;

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
    hs.read_message(&msg2, &mut buf)
        .map_err(|e| e.to_string())?;

    finish(hs)
}

// ─── Transport session (encrypt/decrypt JSON frames) ──────────

pub struct Session {
    pub state: TransportState,
    pub chunked: bool,
}

impl Session {
    pub fn new(state: TransportState) -> Self {
        Self {
            state,
            chunked: false,
        }
    }

    fn encrypt_frames<T: Serialize>(&mut self, msg: &T) -> Result<Vec<Vec<u8>>, String> {
        let mut frames = Vec::new();
        for plaintext in encode_chunks(msg, self.chunked)? {
            let mut ct = vec![0u8; plaintext.len() + 16];
            let n = self
                .state
                .write_message(&plaintext, &mut ct)
                .map_err(|e| e.to_string())?;
            ct.truncate(n);
            frames.push(ct);
        }
        Ok(frames)
    }

    pub async fn send<T: Serialize>(
        &mut self,
        stream: &mut TcpStream,
        msg: &T,
    ) -> Result<(), String> {
        for frame in self.encrypt_frames(msg)? {
            write_frame(stream, &frame).await?;
        }
        Ok(())
    }

    /// Read while writing so two peers can exchange data larger than TCP buffers.
    pub async fn exchange<T: Serialize, R: DeserializeOwned>(
        &mut self,
        stream: &mut TcpStream,
        msg: &T,
    ) -> Result<R, String> {
        let frames = self.encrypt_frames(msg)?;
        let (mut reader, mut writer) = stream.split();
        let sending = async {
            for frame in frames {
                write_frame(&mut writer, &frame).await?;
            }
            Ok::<(), String>(())
        };
        let (_, reply) = tokio::try_join!(sending, self.recv(&mut reader))?;
        Ok(reply)
    }

    pub async fn recv<T: DeserializeOwned>(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<T, String> {
        let mut chunks = ChunkAssembler::default();
        loop {
            let ct = read_frame(stream).await?;
            let mut pt = vec![0u8; ct.len()];
            let n = self
                .state
                .read_message(&ct, &mut pt)
                .map_err(|e| e.to_string())?;
            if let Some(bytes) = chunks.push(&pt[..n], self.chunked)? {
                return serde_json::from_slice(&bytes).map_err(|e| e.to_string());
            }
        }
    }
}

pub struct MobileSession {
    pub key: [u8; 32],
    pub chunked: bool,
}

impl MobileSession {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            chunked: false,
        }
    }

    fn encrypt_frames<T: Serialize>(&mut self, msg: &T) -> Result<Vec<Vec<u8>>, String> {
        let mut frames = Vec::new();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        for plaintext in encode_chunks(msg, self.chunked)? {
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
                .map_err(|e| e.to_string())?;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            frames.push(out);
        }
        Ok(frames)
    }

    pub async fn send<T: Serialize>(
        &mut self,
        stream: &mut TcpStream,
        msg: &T,
    ) -> Result<(), String> {
        for frame in self.encrypt_frames(msg)? {
            write_frame(stream, &frame).await?;
        }
        Ok(())
    }

    /// Read while writing so two peers can exchange data larger than TCP buffers.
    pub async fn exchange<T: Serialize, R: DeserializeOwned>(
        &mut self,
        stream: &mut TcpStream,
        msg: &T,
    ) -> Result<R, String> {
        let frames = self.encrypt_frames(msg)?;
        let (mut reader, mut writer) = stream.split();
        let sending = async {
            for frame in frames {
                write_frame(&mut writer, &frame).await?;
            }
            Ok::<(), String>(())
        };
        let (_, reply) = tokio::try_join!(sending, self.recv(&mut reader))?;
        Ok(reply)
    }

    pub async fn recv<T: DeserializeOwned>(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<T, String> {
        let mut chunks = ChunkAssembler::default();
        loop {
            let data = read_frame(stream).await?;
            if data.len() < 28 {
                return Err("mobile frame too short".into());
            }
            let (nonce, ct) = data.split_at(12);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
            let pt = cipher
                .decrypt(Nonce::from_slice(nonce), ct)
                .map_err(|e| e.to_string())?;
            if let Some(bytes) = chunks.push(&pt, self.chunked)? {
                return serde_json::from_slice(&bytes).map_err(|e| e.to_string());
            }
        }
    }
}

const MAX_MESSAGE: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 40 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum Chunk {
    TransportChunk { data: String, last: bool },
}

fn encode_chunks<T: Serialize>(msg: &T, enabled: bool) -> Result<Vec<Vec<u8>>, String> {
    let bytes = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("Sync message exceeds 16 MiB limit".into());
    }
    if bytes.len() <= MAX_FRAME_PT {
        return Ok(vec![bytes]);
    }
    if !enabled {
        return Err(
            "Sync data exceeds this peer's frame limit. Update both apps to support chunked sync."
                .into(),
        );
    }
    let count = bytes.chunks(CHUNK_BYTES).len();
    bytes
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(i, data)| {
            serde_json::to_vec(&Chunk::TransportChunk {
                data: base64::engine::general_purpose::STANDARD.encode(data),
                last: i + 1 == count,
            })
            .map_err(|e| e.to_string())
        })
        .collect()
}

#[derive(Default)]
struct ChunkAssembler {
    bytes: Vec<u8>,
    started: bool,
}
impl ChunkAssembler {
    fn push(&mut self, frame: &[u8], enabled: bool) -> Result<Option<Vec<u8>>, String> {
        if let Ok(Chunk::TransportChunk { data, last }) = serde_json::from_slice(frame) {
            if !enabled {
                return Err("Unnegotiated chunked message".into());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| e.to_string())?;
            if bytes.is_empty() || self.bytes.len() + bytes.len() > MAX_MESSAGE {
                return Err("Invalid or oversized chunked message".into());
            }
            self.started = true;
            self.bytes.extend(bytes);
            return Ok(if last {
                Some(std::mem::take(&mut self.bytes))
            } else {
                None
            });
        }
        if self.started {
            return Err("Interrupted chunked message".into());
        }
        Ok(Some(frame.to_vec()))
    }
}

/// Derive the symmetric PSK used for steady-state KKpsk0 between two
/// devices. Same on both sides because we sort the two keys
/// lexicographically before hashing.
pub fn sync_psk(our_pk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"secureshell-sync-v1");
    let (a, b) = if our_pk <= their_pk {
        (our_pk, their_pk)
    } else {
        (their_pk, our_pk)
    };
    h.update(a);
    h.update(b);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_roundtrip_and_legacy_limit() {
        let message = serde_json::json!({"type":"Rows","content":"x".repeat(300_000)});
        assert!(encode_chunks(&message, false).is_err());
        let frames = encode_chunks(&message, true).unwrap();
        assert!(frames.len() > 1);
        assert!(frames.iter().all(|f| f.len() <= MAX_FRAME_PT));
        assert!(ChunkAssembler::default().push(&frames[0], false).is_err());
        let mut assembler = ChunkAssembler::default();
        let mut result = None;
        for frame in frames {
            result = assembler.push(&frame, true).unwrap();
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&result.unwrap()).unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn simultaneous_large_mobile_exchange_does_not_deadlock() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut session = MobileSession::new([7; 32]);
            session.chunked = true;
            let result: String = session
                .exchange(&mut stream, &"s".repeat(4 * 1024 * 1024))
                .await
                .unwrap();
            assert_eq!(result, "c".repeat(4 * 1024 * 1024));
        };
        let client = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut session = MobileSession::new([7; 32]);
            session.chunked = true;
            let result: String = session
                .exchange(&mut stream, &"c".repeat(4 * 1024 * 1024))
                .await
                .unwrap();
            assert_eq!(result, "s".repeat(4 * 1024 * 1024));
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn simultaneous_large_noise_exchange() {
        let server_sk = [3; 32];
        let client_sk = [4; 32];
        let server_pk =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(server_sk)).to_bytes();
        let client_pk =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_sk)).to_bytes();
        let psk = sync_psk(&server_pk, &client_pk);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let handshake = responder_handshake_kk(&mut stream, &server_sk, &client_pk, &psk)
                .await
                .unwrap();
            let mut session = Session::new(handshake.session);
            session.chunked = true;
            let response: String = session
                .exchange(&mut stream, &"s".repeat(2 * 1024 * 1024))
                .await
                .unwrap();
            assert_eq!(response, "c".repeat(2 * 1024 * 1024));
        };
        let client = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let handshake = initiator_handshake_kk(&mut stream, &client_sk, &server_pk, &psk)
                .await
                .unwrap();
            let mut session = Session::new(handshake.session);
            session.chunked = true;
            let response: String = session
                .exchange(&mut stream, &"c".repeat(2 * 1024 * 1024))
                .await
                .unwrap();
            assert_eq!(response, "s".repeat(2 * 1024 * 1024));
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }
}

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
/// Desktop-to-desktop pairing. Neither side knows the other's static key up
/// front — both are transmitted during the handshake and authenticated by the
/// psk derived from the pairing code the user types in.
pub const NOISE_XX: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";

/// Length of the XXpsk3 first message: a 32-byte ephemeral key plus the
/// 16-byte tag over its empty payload (a psk handshake mixes a key as soon as
/// `e` is sent, so even message one is encrypted). `pairing::run_responder`
/// uses this to tell a code-pairing dial from the other protocols it accepts,
/// and `xx_first_message_has_expected_length` keeps the two in step.
pub const XX_FIRST_MESSAGE_LEN: usize = 48;

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

/// Code-based pairing — initiator side (the device that types the code).
///
/// XXpsk3: `-> e` / `<- e, ee, s, es` / `-> s, se, psk`. Each side's `payload`
/// rides along in the message that carries its static key, so both learn the
/// other's device label as part of the handshake. Returns our peer's payload.
pub async fn initiator_handshake_xx(
    stream: &mut TcpStream,
    local_sk: &[u8; 32],
    psk: &[u8; 32],
    payload: &[u8],
) -> Result<(HandshakeResult, Vec<u8>), String> {
    let params = NOISE_XX.parse().map_err(|e: snow::Error| e.to_string())?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(local_sk)
        .psk(3, psk)
        .build_initiator()
        .map_err(|e| e.to_string())?;

    // -> e
    let mut out = vec![0u8; MAX_FRAME_CT];
    let n = hs.write_message(b"", &mut out).map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    // <- e, ee, s, es
    let msg2 = read_frame(stream).await?;
    let mut buf = vec![0u8; MAX_FRAME_PT];
    let n = hs
        .read_message(&msg2, &mut buf)
        .map_err(|_| BAD_CODE.to_string())?;
    let peer_payload = buf[..n].to_vec();

    // -> s, se, psk
    if payload.len() > MAX_FRAME_PT {
        return Err("pairing payload too large".into());
    }
    let n = hs
        .write_message(payload, &mut out)
        .map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    Ok((finish(hs)?, peer_payload))
}

/// Code-based pairing — responder side. The first message has already been
/// read off the stream by the protocol sniffer in `pairing::run_responder`.
/// Returns the handshake result plus the initiator's final-message payload.
pub async fn responder_handshake_xx_with_first_message(
    stream: &mut TcpStream,
    local_sk: &[u8; 32],
    psk: &[u8; 32],
    first_msg: &[u8],
    payload: &[u8],
) -> Result<(HandshakeResult, Vec<u8>), String> {
    let params = NOISE_XX.parse().map_err(|e: snow::Error| e.to_string())?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(local_sk)
        .psk(3, psk)
        .build_responder()
        .map_err(|e| e.to_string())?;

    // <- e (already read)
    let mut buf = vec![0u8; MAX_FRAME_PT];
    hs.read_message(first_msg, &mut buf)
        .map_err(|e| e.to_string())?;

    // -> e, ee, s, es
    if payload.len() > MAX_FRAME_PT {
        return Err("pairing payload too large".into());
    }
    let mut out = vec![0u8; MAX_FRAME_CT];
    let n = hs
        .write_message(payload, &mut out)
        .map_err(|e| e.to_string())?;
    write_frame(stream, &out[..n]).await?;

    // <- s, se, psk
    let msg3 = read_frame(stream).await?;
    let n = hs
        .read_message(&msg3, &mut buf)
        .map_err(|_| BAD_CODE.to_string())?;
    let payload = buf[..n].to_vec();

    Ok((finish(hs)?, payload))
}

/// A psk failure and a tampered handshake are indistinguishable on the wire,
/// and the overwhelmingly likely cause is a mistyped code.
const BAD_CODE: &str = "Pairing code did not match — check the code on the other device and try again";

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

/// Derive the pairing psk from the human-typed pairing code. Argon2id with a
/// fixed salt: the code is single-use and short-lived, but it is only ~60 bits
/// so we still make each guess expensive for anyone who captured the traffic.
pub fn pairing_psk(code: &str) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use sha2::{Digest, Sha256};

    let normalized = normalize_pairing_code(code)?;
    let salt = Sha256::digest(b"secureshell-pair-psk-v1");
    let params = Params::new(32 * 1024, 2, 1, Some(32)).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalized.as_bytes(), &salt, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Alphabet for pairing codes: no I, L, O, 0 or 1, so nothing is ambiguous
/// when read off one screen and typed into another.
pub const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
pub const CODE_LEN: usize = 12;

/// Generate a fresh pairing code, grouped for readability: `ABCD-EFGH-JKMN`.
pub fn generate_pairing_code() -> String {
    let mut raw = [0u8; CODE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);
    let chars: Vec<char> = raw
        .iter()
        .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
        .collect();
    chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Accept whatever the user typed — spaces, dashes, lower case — and reduce it
/// to the canonical form the psk is derived from.
pub fn normalize_pairing_code(code: &str) -> Result<String, String> {
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.len() != CODE_LEN {
        return Err(format!(
            "Pairing code must be {CODE_LEN} characters (got {})",
            cleaned.len()
        ));
    }
    if let Some(bad) = cleaned.chars().find(|c| !CODE_ALPHABET.contains(&(*c as u8))) {
        return Err(format!("'{bad}' is not a valid pairing code character"));
    }
    Ok(cleaned)
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
    #[test]
    fn pairing_code_normalizes_and_rejects_junk() {
        let code = generate_pairing_code();
        assert_eq!(code.len(), CODE_LEN + 2); // two separators
        let canonical = normalize_pairing_code(&code).unwrap();
        assert_eq!(canonical.len(), CODE_LEN);
        assert_eq!(
            normalize_pairing_code(&code.to_lowercase().replace('-', " ")).unwrap(),
            canonical
        );
        assert_eq!(pairing_psk(&code).unwrap(), pairing_psk(&canonical).unwrap());
        assert!(normalize_pairing_code("ABCD").is_err());
        assert!(normalize_pairing_code("ABCDEFGHJKM0").is_err());
    }

    #[tokio::test]
    async fn xx_pairing_handshake_agrees_on_keys_and_rejects_wrong_code() {
        let responder_sk = [11; 32];
        let initiator_sk = [12; 32];
        let responder_pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            responder_sk,
        ))
        .to_bytes();
        let initiator_pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            initiator_sk,
        ))
        .to_bytes();
        let psk = pairing_psk(&generate_pairing_code()).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_frame(&mut stream).await.unwrap();
            assert_eq!(first.len(), XX_FIRST_MESSAGE_LEN);
            let (handshake, payload) = responder_handshake_xx_with_first_message(
                &mut stream,
                &responder_sk,
                &psk,
                &first,
                b"desktop",
            )
            .await
            .unwrap();
            assert_eq!(handshake.peer_static, initiator_pk);
            assert_eq!(payload, b"laptop");
            handshake.handshake_hash
        };
        let client = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let (handshake, payload) =
                initiator_handshake_xx(&mut stream, &initiator_sk, &psk, b"laptop")
                    .await
                    .unwrap();
            assert_eq!(handshake.peer_static, responder_pk);
            assert_eq!(payload, b"desktop");
            handshake.handshake_hash
        };
        let (a, b) = tokio::join!(server, client);
        assert_eq!(a, b);

        // A mistyped code produces a different psk, which XXpsk3 rejects.
        let wrong = pairing_psk(&generate_pairing_code()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_frame(&mut stream).await.unwrap();
            responder_handshake_xx_with_first_message(
                &mut stream,
                &responder_sk,
                &wrong,
                &first,
                b"desktop",
            )
            .await
                .err()
                .expect("handshake with the wrong code must fail")
        };
        let client = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let _ = initiator_handshake_xx(&mut stream, &initiator_sk, &psk, b"laptop").await;
        };
        let (err, _) = tokio::join!(server, client);
        assert!(err.contains("Pairing code did not match"), "{err}");
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

// One-time QR-based pairing flow. See docs/sync-protocol.md.
//
// Lifecycle:
//
//   1. `PairingSession::start(identity, sync_listener_port)` — generates a one-shot
//      pairing code, derives the 32-byte PSK from it, binds a random TCP port,
//      starts mDNS advertisement, and returns a `PairingInvite` holding both the
//      QR payload (rendered to SVG, for the Android app) and the typable code
//      (for another desktop).
//   2. A background tokio task accepts the first incoming TCP connection.
//      Three protocols are supported, told apart by the first frame:
//      a. Desktop joining with the code: Noise XXpsk3 → SAS from handshake hash.
//      b. Desktop scanning the QR: Noise IKpsk2 → SAS from handshake hash.
//      c. Mobile pairing: AES-GCM(PSK) encrypted key exchange → SAS from shared inputs.
//   3. `confirm(accept)` either persists the peer in the trust store or
//      discards everything.
//
// The other half is `PairingSession::join(..)`: the desktop where the user types
// the code. It dials the host's sync listener, is routed to the host's waiting
// session, and runs the XXpsk3 handshake as initiator. From `confirm` onwards
// both sides behave identically.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::db::Database;
use crate::sync::discovery::{self, Advertiser};
use crate::sync::identity::DeviceIdentity;
use crate::sync::peer_store::{self, Peer};
use crate::sync::transport::{self, MobileSession, Session};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingInvite {
    pub qr_payload: String,
    pub qr_svg: String,
    pub ip:   String,
    pub port: u16,
    /// Human-typable pairing code, shown so it can be entered on another
    /// desktop. The PSK is derived from it, so it is as sensitive as the QR.
    pub code: String,
    /// False when the fixed sync port could not be bound, in which case another
    /// desktop has no well-known port to dial and only QR pairing works.
    pub code_pairing: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum PairingStatus {
    Idle,
    Listening { invite: PairingInvite },
    /// Join side: dialling the host and running the handshake.
    Connecting { host: String },
    AwaitingConfirmation {
        sas: String,
        peer_pk_hex: String,
        peer_label: String,
    },
    Done,
    Failed { reason: String },
}

pub struct PairingSession {
    /// Present on the hosting side only; the joining side has nothing to show.
    pub invite: Option<PairingInvite>,
    inner: Arc<Mutex<Inner>>,
    advertiser: Option<Advertiser>,
    cancel_tx: Option<oneshot::Sender<()>>,
    device_label: String,
}

enum PendingTransport {
    Noise(TcpStream, Session),
    Mobile(TcpStream, MobileSession),
}

struct Inner {
    status: Option<PairingStatus>,
    pending_peer: Option<PendingPeer>,
    pending_transport: Option<PendingTransport>,
}

impl Default for Inner {
    fn default() -> Self {
        Self { status: None, pending_peer: None, pending_transport: None }
    }
}

struct PendingPeer {
    pk_hex: String,
    label: String,
    shared_secret: Option<String>,
    psk: [u8; 32],
}

impl PairingSession {
    pub async fn start(
        identity: DeviceIdentity,
        sync_listener_port: Option<u16>,
        pair_rx: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<TcpStream>>>,
    ) -> Result<Self, String> {
        let code = transport::generate_pairing_code();
        let psk = transport::pairing_psk(&code)?;

        // Also bind a random port for desktop-to-desktop pairing (Noise IK).
        let listener = TcpListener::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
        let bound: SocketAddr = listener.local_addr().map_err(|e| e.to_string())?;
        let port = bound.port();
        let ip = discovery::local_ipv4()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "0.0.0.0".into());

        let mut payload_json = serde_json::json!({
            "v":    1,
            "ip":   ip,
            "port": port,
            "psk":  B64.encode(psk),
            "pk":   identity.pk_hex,
        });
        if let Some(sp) = sync_listener_port {
            payload_json["sync_port"] = serde_json::json!(sp);
        }
        let payload = payload_json.to_string();
        let qr_svg = render_qr_svg(&payload);

        let invite = PairingInvite {
            qr_payload: payload,
            qr_svg,
            ip: ip.clone(),
            port,
            code,
            code_pairing: sync_listener_port.is_some(),
        };

        let instance = format!("secureshell-{}", &identity.pk_hex[..8]);
        let advertiser = Advertiser::start(&discovery::Advertisement {
            instance,
            port,
            pk_hex: identity.pk_hex.clone(),
            label:  identity.label.clone(),
        })
        .ok();

        let inner = Arc::new(Mutex::new(Inner {
            status: Some(PairingStatus::Listening { invite: invite.clone() }),
            ..Default::default()
        }));
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let inner_task = inner.clone();
        let identity_task = identity.clone();
        let device_label = identity.label.clone();

        tauri::async_runtime::spawn(async move {
            tokio::select! {
                _ = cancel_rx => {
                    let mut g = inner_task.lock().unwrap();
                    g.status = Some(PairingStatus::Failed { reason: "cancelled".into() });
                }
                res = run_responder(listener, pair_rx, identity_task, psk) => {
                    let mut g = inner_task.lock().unwrap();
                    match res {
                        Ok(outcome) => {
                            g.pending_peer = Some(PendingPeer {
                                pk_hex: outcome.peer_pk_hex.clone(),
                                label:  outcome.peer_label.clone(),
                                shared_secret: outcome.shared_secret,
                                psk: outcome.psk,
                            });
                            g.pending_transport = Some(outcome.transport);
                            g.status = Some(PairingStatus::AwaitingConfirmation {
                                sas: outcome.sas,
                                peer_pk_hex: outcome.peer_pk_hex,
                                peer_label: outcome.peer_label,
                            });
                        }
                        Err(e) => g.status = Some(PairingStatus::Failed { reason: e }),
                    }
                }
            }
        });

        Ok(Self {
            invite: Some(invite),
            inner,
            advertiser,
            cancel_tx: Some(cancel_tx),
            device_label,
        })
    }

    /// The other half of code pairing: dial a desktop that is showing a pairing
    /// code and run the XXpsk3 handshake as initiator. Reaches the host's
    /// waiting session through its sync listener's `pair` route, so the user
    /// only has to type the host's address and the code.
    pub async fn join(
        identity: DeviceIdentity,
        host: String,
        port: u16,
        code: String,
    ) -> Result<Self, String> {
        // Fail fast on a typo before opening any connection.
        let psk = transport::pairing_psk(&code)?;
        let device_label = identity.label.clone();

        let inner = Arc::new(Mutex::new(Inner {
            status: Some(PairingStatus::Connecting { host: host.clone() }),
            ..Default::default()
        }));
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let inner_task = inner.clone();
        let identity_task = identity.clone();

        tauri::async_runtime::spawn(async move {
            tokio::select! {
                _ = cancel_rx => {
                    let mut g = inner_task.lock().unwrap();
                    g.status = Some(PairingStatus::Failed { reason: "cancelled".into() });
                }
                res = run_initiator(host, port, identity_task, psk) => {
                    let mut g = inner_task.lock().unwrap();
                    match res {
                        Ok(outcome) => {
                            g.pending_peer = Some(PendingPeer {
                                pk_hex: outcome.peer_pk_hex.clone(),
                                label:  outcome.peer_label.clone(),
                                shared_secret: outcome.shared_secret,
                                psk: outcome.psk,
                            });
                            g.pending_transport = Some(outcome.transport);
                            g.status = Some(PairingStatus::AwaitingConfirmation {
                                sas: outcome.sas,
                                peer_pk_hex: outcome.peer_pk_hex,
                                peer_label: outcome.peer_label,
                            });
                        }
                        Err(e) => g.status = Some(PairingStatus::Failed { reason: e }),
                    }
                }
            }
        });

        Ok(Self {
            invite: None,
            inner,
            advertiser: None,
            cancel_tx: Some(cancel_tx),
            device_label,
        })
    }

    pub fn status(&self) -> PairingStatus {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.status.clone())
            .unwrap_or(PairingStatus::Idle)
    }

    pub fn cancel(mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
        if let Some(a) = self.advertiser.take() {
            a.stop();
        }
    }

    pub async fn confirm(mut self, accept: bool, db: &Database) -> Result<(), String> {
        let (pending_peer, pending_transport) = {
            let mut g = self.inner.lock().map_err(|e| e.to_string())?;
            (g.pending_peer.take(), g.pending_transport.take())
        };

        if let Some(a) = self.advertiser.take() {
            a.stop();
        }
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }

        let Some(pending) = pending_peer else {
            return Err("pairing has no peer to confirm".into());
        };

        if !accept {
            return Ok(());
        }

        let transport = pending_transport
            .ok_or_else(|| "no live channel — pairing already consumed".to_string())?;

        // Run initial sync over the live channel.
        let stats = match transport {
            PendingTransport::Noise(mut stream, mut session) => {
                crate::sync::protocol::run_sync(
                    &mut stream, &mut session, db, &self.device_label,
                ).await
            }
            PendingTransport::Mobile(mut stream, mut session) => {
                // For mobile pairing, read Android's pair_confirm/reject first.
                read_mobile_confirm(&mut stream, &pending.psk).await?;
                crate::sync::protocol::run_sync_mobile(
                    &mut stream, &mut session, db, &self.device_label,
                ).await
            }
        };

        let now = chrono::Utc::now().to_rfc3339();
        let last_synced_at = stats.as_ref().ok().map(|_| now.clone());

        let peer = Peer {
            id: peer_store::peer_id_from_pk(&pending.pk_hex),
            pk_hex: pending.pk_hex,
            label: pending.label,
            paired_at: now,
            last_synced_at,
            shared_secret: pending.shared_secret,
        };
        peer_store::upsert(db, peer)?;

        stats.map(|_| ())
    }
}

struct ResponderOutcome {
    peer_pk_hex: String,
    peer_label: String,
    sas: String,
    transport: PendingTransport,
    shared_secret: Option<String>,
    psk: [u8; 32],
}

async fn run_responder(
    listener: TcpListener,
    pair_rx: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<TcpStream>>>,
    identity: DeviceIdentity,
    psk: [u8; 32],
) -> Result<ResponderOutcome, String> {
    // Accept from either:
    // - The random pairing port advertised in the QR (a QR scanner, Noise IK)
    // - The channel from the sync listener on port 43951, which carries both
    //   mobile pairing and a desktop joining with the typed code
    let mut stream = tokio::select! {
        res = listener.accept() => {
            res.map_err(|e| e.to_string())?.0
        }
        Some(s) = async { pair_rx.lock().await.recv().await } => s,
    };

    // Read first frame (both protocols start with a 4-byte BE length + payload).
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > 65535 {
        return Err(format!("bad pairing frame length {frame_len}"));
    }
    let mut frame = vec![0u8; frame_len];
    stream.read_exact(&mut frame).await.map_err(|e| e.to_string())?;

    // Detect protocol from the first frame by length. A code-pairing dial opens
    // with an ephemeral key and an empty payload, which nothing else we speak
    // can match: an IK first message carries a static key too (96 bytes), and a
    // mobile frame is a nonce plus the ciphertext of a JSON object holding a
    // 64-character hex secret.
    if frame.len() == transport::XX_FIRST_MESSAGE_LEN {
        return handle_code_pairing(stream, &identity, &psk, &frame).await;
    }

    // Otherwise try AES-GCM decrypt with PSK. If it succeeds and
    // contains a "mobile_pair" message, handle the mobile flow. Otherwise
    // treat the frame as a Noise IK first message.
    if frame.len() >= 28 {
        if let Some(mobile_json) = try_decrypt_mobile_frame(&psk, &frame) {
            if mobile_json.get("type").and_then(|v| v.as_str()) == Some("mobile_pair") {
                return handle_mobile_pairing(stream, &identity, &psk, &mobile_json).await;
            }
        }
    }

    // Noise IK (desktop-to-desktop pairing).
    let local_sk = identity.secret_bytes()?;
    let h = transport::responder_handshake_ik_with_first_message(&mut stream, &local_sk, &psk, &frame).await?;
    let peer_pk_hex = hex::encode(h.peer_static);
    let sas = derive_sas(&h.handshake_hash);
    Ok(ResponderOutcome {
        peer_pk_hex,
        peer_label: "Desktop".into(),
        sas,
        transport: PendingTransport::Noise(stream, Session::new(h.session)),
        shared_secret: None,
        psk,
    })
}

/// Responder side of code pairing. The label each side shows for the other is
/// carried inside the handshake, so it is authenticated rather than claimed in
/// the clear.
async fn handle_code_pairing(
    mut stream: TcpStream,
    identity: &DeviceIdentity,
    psk: &[u8; 32],
    first_msg: &[u8],
) -> Result<ResponderOutcome, String> {
    let local_sk = identity.secret_bytes()?;
    let (h, peer_payload) = transport::responder_handshake_xx_with_first_message(
        &mut stream,
        &local_sk,
        psk,
        first_msg,
        &encode_pair_payload(&identity.label),
    )
    .await?;

    // One encrypted frame so the joining side can tell a wrong code from a
    // network problem: with a mismatched psk it never arrives.
    let mut session = Session::new(h.session);
    session
        .send(&mut stream, &serde_json::json!({ "type": "pair_ready" }))
        .await?;

    Ok(ResponderOutcome {
        peer_pk_hex: hex::encode(h.peer_static),
        peer_label: decode_pair_payload(&peer_payload),
        sas: derive_sas(&h.handshake_hash),
        transport: PendingTransport::Noise(stream, session),
        shared_secret: None,
        psk: *psk,
    })
}

/// Initiator side of code pairing — see `PairingSession::join`.
async fn run_initiator(
    host: String,
    port: u16,
    identity: DeviceIdentity,
    psk: [u8; 32],
) -> Result<ResponderOutcome, String> {
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("Could not reach {addr} — check the address and that both devices are on the same Wi-Fi"))?
    .map_err(|e| format!("Could not connect to {addr}: {e}"))?;

    // Ask the host's sync listener to hand us to its waiting pairing session.
    let claim = b"pair";
    stream
        .write_all(&(claim.len() as u32).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(claim).await.map_err(|e| e.to_string())?;

    let local_sk = identity.secret_bytes()?;
    let (h, peer_payload) = transport::initiator_handshake_xx(
        &mut stream,
        &local_sk,
        &psk,
        &encode_pair_payload(&identity.label),
    )
    .await
    // The psk only enters an XXpsk3 handshake at the last message, so we never
    // see a code mismatch as such — the host just hangs up on us. Say so.
    .map_err(|e| format!("{e} — check the other device is showing a pairing code, and that the code matches"))?;

    // The psk only enters an XXpsk3 handshake in the final message, so a wrong
    // code fails on the host's side, not ours. This ack is how we find out.
    let mut session = Session::new(h.session);
    let ready: serde_json::Value = session
        .recv(&mut stream)
        .await
        .map_err(|_| "Pairing code did not match — check the code on the other device and try again".to_string())?;
    if ready.get("type").and_then(|v| v.as_str()) != Some("pair_ready") {
        return Err("Unexpected reply from the other device".into());
    }

    Ok(ResponderOutcome {
        peer_pk_hex: hex::encode(h.peer_static),
        peer_label: decode_pair_payload(&peer_payload),
        sas: derive_sas(&h.handshake_hash),
        transport: PendingTransport::Noise(stream, session),
        shared_secret: None,
        psk,
    })
}

fn encode_pair_payload(label: &str) -> Vec<u8> {
    serde_json::json!({ "label": label }).to_string().into_bytes()
}

fn decode_pair_payload(payload: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| v.get("label").and_then(|l| l.as_str()).map(str::to_string))
        .map(|l| l.chars().take(64).collect::<String>())
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| "Desktop".into())
}

fn try_decrypt_mobile_frame(psk: &[u8; 32], frame: &[u8]) -> Option<serde_json::Value> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
    if frame.len() < 28 { return None; }
    let (nonce_bytes, ct) = frame.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(psk));
    let pt = cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).ok()?;
    serde_json::from_slice(&pt).ok()
}

async fn handle_mobile_pairing(
    mut stream: TcpStream,
    identity: &DeviceIdentity,
    psk: &[u8; 32],
    json: &serde_json::Value,
) -> Result<ResponderOutcome, String> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};

    let device_secret_hex = json.get("device_secret")
        .and_then(|v| v.as_str())
        .ok_or("missing device_secret")?;
    let peer_label = json.get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("Android")
        .to_string();

    let device_secret: Vec<u8> = hex::decode(device_secret_hex).map_err(|e| e.to_string())?;
    if device_secret.len() != 32 {
        return Err("device_secret must be 32 bytes".into());
    }

    let peer_pk_hex = derive_mobile_peer_id(&device_secret);
    let our_pk = identity.public_bytes()?;
    let sas = derive_mobile_sas(psk, &device_secret, &our_pk);

    // Send ack with our pk + SAS (encrypted with PSK)
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(psk));
    let reply = serde_json::json!({
        "type": "pair_ack",
        "pk": identity.pk_hex,
        "sas": sas,
    });
    let reply_pt = serde_json::to_vec(&reply).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let reply_ct = cipher.encrypt(Nonce::from_slice(&nonce), reply_pt.as_slice())
        .map_err(|e: aes_gcm::Error| e.to_string())?;
    let mut out = Vec::with_capacity(12 + reply_ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&reply_ct);
    let len = out.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(&out).await.map_err(|e| e.to_string())?;

    // Return immediately — SAS will be shown on desktop. Android's pair_confirm/reject
    // will be read when the desktop user clicks confirm (in the `confirm()` method).
    // Build MobileSession keyed with device_secret for the initial sync.
    let mut ds = [0u8; 32];
    ds.copy_from_slice(&device_secret);
    let session = MobileSession::new(ds);

    Ok(ResponderOutcome {
        peer_pk_hex,
        peer_label,
        sas,
        transport: PendingTransport::Mobile(stream, session),
        shared_secret: Some(device_secret_hex.to_string()),
        psk: *psk,
    })
}

async fn read_mobile_confirm(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<(), String> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > 65535 {
        return Err("bad confirm frame".into());
    }
    let mut frame = vec![0u8; frame_len];
    stream.read_exact(&mut frame).await.map_err(|e| e.to_string())?;
    if frame.len() < 28 { return Err("confirm frame too short".into()); }
    let (nonce, ct) = frame.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(psk));
    let pt = cipher.decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "confirm decrypt failed".to_string())?;
    let json: serde_json::Value = serde_json::from_slice(&pt).map_err(|e| e.to_string())?;
    let msg_type = json.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if msg_type == "pair_reject" {
        return Err("Android user rejected pairing".into());
    }
    if msg_type != "pair_confirm" {
        return Err(format!("unexpected confirm type: {msg_type}"));
    }
    Ok(())
}

/// Render `data` as a square SVG QR code.
pub fn render_qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(data, EcLevel::M).expect("qr build");
    code.render::<svg::Color<'_>>()
        .min_dimensions(240, 240)
        .dark_color(svg::Color("#0a0a0c"))
        .light_color(svg::Color("#ffffff"))
        .build()
}

pub fn derive_sas(handshake_hash: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"secureshell-sas-v1");
    h.update(handshake_hash);
    let digest = h.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", n % 1_000_000)
}

pub fn derive_mobile_sas(psk: &[u8], device_secret: &[u8], desktop_pk: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"secureshell-mobile-sas-v1");
    h.update(psk);
    h.update(device_secret);
    h.update(desktop_pk);
    let digest = h.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", n % 1_000_000)
}

pub fn derive_mobile_peer_id(device_secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"secureshell-mobile-id-v1");
    h.update(device_secret);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(label: &str, seed: u8) -> DeviceIdentity {
        let sk = x25519_dalek::StaticSecret::from([seed; 32]);
        DeviceIdentity {
            sk_hex: hex::encode(sk.to_bytes()),
            pk_hex: hex::encode(x25519_dalek::PublicKey::from(&sk).to_bytes()),
            label: label.into(),
        }
    }

    /// Two desktops pair with nothing but a typed code: both end up with the
    /// other's real public key, the other's label, and the same SAS to compare.
    #[tokio::test]
    async fn desktop_code_pairing_meets_in_the_middle() {
        let host = identity("host-laptop", 21);
        let joiner = identity("kitchen-pc", 22);
        let code = transport::generate_pairing_code();
        let psk = transport::pairing_psk(&code).unwrap();

        // Stands in for listener.rs: reads the `pair` claim off the wire and
        // hands the stream to the waiting pairing session.
        let sync_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = sync_listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            let (mut stream, _) = sync_listener.accept().await.unwrap();
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).await.unwrap();
            let mut claim = vec![0u8; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut claim).await.unwrap();
            assert_eq!(claim, b"pair");
            tx.send(stream).await.unwrap();
        });

        // The host also keeps its own QR port open; it stays idle here.
        let qr_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let responding = run_responder(
            qr_listener,
            Arc::new(tokio::sync::Mutex::new(rx)),
            host.clone(),
            psk,
        );
        // A joiner is allowed to type the code in any shape.
        let joining = run_initiator(
            "127.0.0.1".into(),
            port,
            joiner.clone(),
            transport::pairing_psk(&code.to_lowercase()).unwrap(),
        );

        let (host_side, join_side) = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            async { tokio::join!(responding, joining) },
        )
        .await
        .unwrap();
        let host_side = host_side.unwrap();
        let join_side = join_side.unwrap();

        assert_eq!(host_side.sas, join_side.sas);
        assert_eq!(host_side.peer_pk_hex, joiner.pk_hex);
        assert_eq!(join_side.peer_pk_hex, host.pk_hex);
        assert_eq!(host_side.peer_label, "kitchen-pc");
        assert_eq!(join_side.peer_label, "host-laptop");
        // Desktop peers authenticate by key, so no shared secret is stored.
        assert!(host_side.shared_secret.is_none());
        assert!(join_side.shared_secret.is_none());
    }

    #[tokio::test]
    async fn joining_a_device_that_is_not_pairing_explains_itself() {
        let joiner = identity("kitchen-pc", 23);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Mimic listener.rs refusing the claim: close the connection.
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        let err = run_initiator(
            "127.0.0.1".into(),
            port,
            joiner,
            transport::pairing_psk(&transport::generate_pairing_code()).unwrap(),
        )
        .await
        .err()
        .expect("joining an idle device must fail");
        assert!(err.contains("pairing code"), "{err}");
    }
}

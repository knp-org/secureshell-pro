// One-time QR-based pairing flow. See docs/sync-protocol.md.
//
// Lifecycle:
//
//   1. `PairingSession::start(identity, sync_listener_port)` — generates a one-shot 32-byte PSK,
//      binds a random TCP port, starts mDNS advertisement, returns a
//      `PairingInvite` containing the QR payload (also rendered to SVG).
//   2. A background tokio task accepts the first incoming TCP connection.
//      Two protocols are supported:
//      a. Desktop-to-desktop: Noise IKpsk2 handshake → SAS from handshake hash.
//      b. Mobile pairing: AES-GCM(PSK) encrypted key exchange → SAS from shared inputs.
//   3. `confirm(accept)` either persists the peer in the trust store or
//      discards everything.

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
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum PairingStatus {
    Idle,
    Listening { invite: PairingInvite },
    AwaitingConfirmation {
        sas: String,
        peer_pk_hex: String,
        peer_label: String,
    },
    Done,
    Failed { reason: String },
}

pub struct PairingSession {
    pub invite: PairingInvite,
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
        let mut psk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut psk);

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
            invite,
            inner,
            advertiser,
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
    // - The random pairing port (desktop-to-desktop Noise IK)
    // - The channel from the sync listener (mobile pairing routed via port 43951)
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

    // Detect protocol: try AES-GCM decrypt with PSK. If it succeeds and
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

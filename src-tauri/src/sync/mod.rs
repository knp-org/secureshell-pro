// LAN peer-to-peer sync. See docs/sync-protocol.md for the wire spec.
//
// This module is split into:
//   - identity:   device static keypair (X25519) + persistence
//   - peer_store: trusted peers (their static pubkey + label)
//   - discovery:  mDNS advertise / browse for `_secureshellsync._tcp.local.`
//   - pairing:    one-time QR-based pairing flow with Noise IKpsk2
//   - transport:  framed Noise transport channel (used by pairing + sync)
//   - protocol:   message types & sync state machine (next phase)
//
// All Tauri commands exported at the bottom of the file.

pub mod discovery;
pub mod identity;
pub mod listener;
pub mod pairing;
pub mod peer_store;
pub mod protocol;
pub mod transport;

use std::sync::Mutex;
use tauri::State;

use crate::db::Database;

/// Tauri-managed sync state: owns the device identity, peer store, and any
/// in-flight pairing session.
pub struct SyncState {
    pub identity: Mutex<Option<identity::DeviceIdentity>>,
    pub pairing:  Mutex<Option<pairing::PairingSession>>,
    /// TCP port of the steady-state sync listener (`listener::run`). Filled once the listener binds.
    pub sync_listener_port: Mutex<Option<u16>>,
    /// Channel for forwarding incoming "pair" connections from the listener to
    /// the active PairingSession.
    pub pair_tx: tokio::sync::mpsc::Sender<tokio::net::TcpStream>,
    pub pair_rx: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<tokio::net::TcpStream>>>,
}

impl SyncState {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        Self {
            identity: Mutex::new(None),
            pairing:  Mutex::new(None),
            sync_listener_port: Mutex::new(None),
            pair_tx: tx,
            pair_rx: std::sync::Arc::new(tokio::sync::Mutex::new(rx)),
        }
    }

    /// Lazily load (or generate) the device identity from disk.
    pub fn ensure_identity(&self, db: &Database) -> Result<identity::DeviceIdentity, String> {
        let mut guard = self.identity.lock().map_err(|e| e.to_string())?;
        if let Some(id) = guard.as_ref() {
            return Ok(id.clone());
        }
        let id = identity::DeviceIdentity::load_or_create(db)?;
        *guard = Some(id.clone());
        Ok(id)
    }
}

// ─── Tauri commands ─────────────────────────────────────────

#[tauri::command]
pub async fn pairing_start(
    db: State<'_, Database>,
    state: State<'_, SyncState>,
) -> Result<pairing::PairingInvite, String> {
    let id = state.ensure_identity(&db)?;
    let sync_port = *state
        .sync_listener_port
        .lock()
        .map_err(|e| e.to_string())?;
    let pair_rx = state.pair_rx.clone();
    let session = pairing::PairingSession::start(id, sync_port, pair_rx).await?;
    let invite = session.invite.clone();
    {
        let mut guard = state.pairing.lock().map_err(|e| e.to_string())?;
        *guard = Some(session);
    }
    Ok(invite)
}

#[tauri::command]
pub fn pairing_cancel(state: State<'_, SyncState>) -> Result<(), String> {
    let mut guard = state.pairing.lock().map_err(|e| e.to_string())?;
    if let Some(s) = guard.take() {
        s.cancel();
    }
    Ok(())
}

#[tauri::command]
pub fn pairing_status(state: State<'_, SyncState>) -> Result<pairing::PairingStatus, String> {
    let guard = state.pairing.lock().map_err(|e| e.to_string())?;
    Ok(match guard.as_ref() {
        None => pairing::PairingStatus::Idle,
        Some(s) => s.status(),
    })
}

#[tauri::command]
pub async fn pairing_confirm(
    db: State<'_, Database>,
    state: State<'_, SyncState>,
    accept: bool,
) -> Result<(), String> {
    let session = {
        let mut guard = state.pairing.lock().map_err(|e| e.to_string())?;
        guard.take()
    };
    let Some(session) = session else {
        return Err("no pairing in progress".into());
    };
    session.confirm(accept, &db).await
}

#[tauri::command]
pub async fn sync_now(
    db: State<'_, Database>,
    state: State<'_, SyncState>,
    peer_id: String,
) -> Result<SyncReport, String> {
    let id = state.ensure_identity(&db)?;
    let peers = peer_store::list(&db)?;
    let peer = peers.into_iter().find(|p| p.id == peer_id)
        .ok_or_else(|| format!("unknown peer {}", peer_id))?;

    // Mobile peers can only be synced from the Android side (they connect to us).
    if peer.shared_secret.is_some() {
        return Err(
            "Mobile sync must be started from the Android app. Open Sync on Android and tap Sync.".to_string()
        );
    }

    let peer_pk: [u8; 32] = hex::decode(&peer.pk_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "bad peer pk length".to_string())?;
    let our_sk = id.secret_bytes()?;
    let our_pk = id.public_bytes()?;
    let psk = transport::sync_psk(&our_pk, &peer_pk);

    // Find peer on the LAN.
    let discovered = discovery::find_peer(&peer.pk_hex, std::time::Duration::from_secs(5))
        .await?
        .ok_or_else(|| "peer not found on LAN — make sure the device is on the same Wi-Fi and the app is open".to_string())?;

    let mut stream = tokio::net::TcpStream::connect(discovered.addr).await.map_err(|e| e.to_string())?;

    // Announce our pk so the listener picks the right peer record. Format:
    // 4-byte BE length + hex-encoded pk; server replies with 4-byte len + 1 byte ack.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let pk_bytes = id.pk_hex.as_bytes();
    stream.write_all(&(pk_bytes.len() as u32).to_be_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(pk_bytes).await.map_err(|e| e.to_string())?;
    let mut ack_len = [0u8; 4];
    stream.read_exact(&mut ack_len).await.map_err(|e| e.to_string())?;
    let n = u32::from_be_bytes(ack_len) as usize;
    if n == 0 || n > 16 { return Err(format!("bad ack length {n}")); }
    let mut ack = vec![0u8; n];
    stream.read_exact(&mut ack).await.map_err(|e| e.to_string())?;

    let h = transport::initiator_handshake_kk(&mut stream, &our_sk, &peer_pk, &psk).await?;
    let mut session = transport::Session::new(h.session);

    let stats = protocol::run_sync(&mut stream, &mut session, &db, &id.label).await?;

    // Update last_synced_at.
    let mut updated = peer.clone();
    updated.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    peer_store::upsert(&db, updated)?;

    Ok(SyncReport { pulled: stats.pulled, pushed: stats.pushed, peer_label: peer.label })
}

#[derive(serde::Serialize)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub peer_label: String,
}

#[tauri::command]
pub fn peers_list(
    db: State<'_, Database>,
) -> Result<Vec<peer_store::Peer>, String> {
    peer_store::list(&db)
}

#[tauri::command]
pub fn peer_remove(
    db: State<'_, Database>,
    id: String,
) -> Result<(), String> {
    peer_store::remove(&db, &id)
}

// Steady-state sync listener.
//
// Started once at app launch. Accepts incoming sync requests from paired peers.
// Mobile peers authenticate via HMAC challenge-response using the shared_secret
// established during pairing. Desktop peers use Noise KK.

use std::time::Duration;

use tauri::{AppHandle, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::db::Database;
use crate::sync::{
    discovery::{Advertisement, Advertiser},
    identity::DeviceIdentity,
    peer_store, protocol,
    transport,
    SyncState,
};

const MAX_PK_HEX: usize = 128;

pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        loop {
            if let Err(e) = run(&app).await {
                log::warn!("sync listener exited: {e}; restarting in 5s");
                eprintln!("[secureshell-pro] sync listener error: {e}; retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });
}

async fn run(app: &AppHandle) -> Result<(), String> {
    let db    = app.state::<Database>();
    let state = app.state::<SyncState>();
    let identity = state.ensure_identity(&db)?;

    const FIXED_SYNC_PORT: u16 = 43951;
    let listener = TcpListener::bind(("0.0.0.0", FIXED_SYNC_PORT))
        .await
        .map_err(|e| format!("could not bind sync listener on port {FIXED_SYNC_PORT}: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    {
        let Ok(mut g) = state.sync_listener_port.lock() else {
            return Err("sync_listener_port mutex poisoned".into());
        };
        *g = Some(port);
    }

    let instance = format!("secureshell-sync-{}", &identity.pk_hex[..8]);
    let _advertiser = Advertiser::start(&Advertisement {
        instance,
        port,
        pk_hex: identity.pk_hex.clone(),
        label:  identity.label.clone(),
    }).ok();

    log::info!("sync listener bound on :{port}");
    eprintln!("[secureshell-pro] LAN sync TCP listener: 0.0.0.0:{port}");

    loop {
        let (stream, peer_addr) = listener.accept().await.map_err(|e| e.to_string())?;
        let app2 = app.clone();
        let identity2 = identity.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) = handle_one(&app2, identity2, stream).await {
                log::info!("incoming sync from {peer_addr} failed: {e}");
            }
        });
    }
}

async fn handle_one(app: &AppHandle, identity: DeviceIdentity, mut stream: TcpStream) -> Result<(), String> {
    // 1. Read claimed pk hex (length-prefixed).
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PK_HEX {
        return Err(format!("bad claim length {len}"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    let claimed_pk = std::str::from_utf8(&buf).map_err(|e| e.to_string())?.to_string();

    // Route pairing requests to the active PairingSession.
    if claimed_pk == "pair" {
        let state = app.state::<crate::sync::SyncState>();
        state.pair_tx.send(stream).await.map_err(|_| "no active pairing session")?;
        return Ok(());
    }

    let db = app.state::<Database>();
    let our_pk = identity.public_bytes()?;

    // 2. Look up the peer in trust store.
    let peers = peer_store::list(&db)?;
    let peer = peers.into_iter().find(|p| p.pk_hex == claimed_pk)
        .ok_or_else(|| format!("untrusted peer pk {claimed_pk}"))?;

    // 3. Determine auth method based on whether peer has a shared_secret (mobile)
    //    or a real X25519 public key (desktop).
    if let Some(ref secret_hex) = peer.shared_secret {
        // Mobile peer — authenticate via HMAC challenge-response.
        let secret = hex::decode(secret_hex).map_err(|e| e.to_string())?;
        if secret.len() != 32 {
            return Err("stored shared_secret is not 32 bytes".into());
        }

        // Send a random 32-byte challenge.
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        stream.write_all(&(32u32).to_be_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&challenge).await.map_err(|e| e.to_string())?;

        // Expect HMAC-SHA256(shared_secret, challenge) back.
        let mut resp_len_buf = [0u8; 4];
        stream.read_exact(&mut resp_len_buf).await.map_err(|e| e.to_string())?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        if resp_len != 32 {
            return Err(format!("bad challenge response length {resp_len}"));
        }
        let mut response = [0u8; 32];
        stream.read_exact(&mut response).await.map_err(|e| e.to_string())?;

        let expected = hmac_sha256(&secret, &challenge);
        if !constant_time_eq(&response, &expected) {
            return Err("challenge-response authentication failed".into());
        }

        // Send ack
        stream.write_all(&(1u32).to_be_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&[1u8]).await.map_err(|e| e.to_string())?;

        // Run sync using MobileSession keyed with shared_secret
        let mut key = [0u8; 32];
        key.copy_from_slice(&secret);
        let mut session = transport::MobileSession::new(key);
        let stats = protocol::run_sync_mobile(&mut stream, &mut session, &db, &identity.label).await?;
        log::info!("incoming mobile sync from {} pulled={} pushed={}",
            peer.label, stats.pulled, stats.pushed);
    } else {
        // Desktop peer — Noise KK handshake.
        let our_sk = identity.secret_bytes()?;
        let peer_pk: [u8; 32] = hex::decode(&peer.pk_hex).map_err(|e| e.to_string())?
            .try_into().map_err(|_| "bad peer pk length".to_string())?;
        let psk = transport::sync_psk(&our_pk, &peer_pk);

        // Send ack (legacy format: 4-byte len + 1 byte)
        stream.write_all(&(1u32).to_be_bytes()).await.map_err(|e| e.to_string())?;
        stream.write_all(&[0u8]).await.map_err(|e| e.to_string())?;

        let h = transport::responder_handshake_kk(&mut stream, &our_sk, &peer_pk, &psk).await?;
        let mut session = transport::Session::new(h.session);
        let stats = protocol::run_sync(&mut stream, &mut session, &db, &identity.label).await?;
        log::info!("incoming sync from {} pulled={} pushed={}",
            peer.label, stats.pulled, stats.pushed);
    }

    // Update last_synced_at.
    let mut updated = peer.clone();
    updated.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    peer_store::upsert(&db, updated)?;
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    // HMAC: H((K ^ opad) || H((K ^ ipad) || message))
    let mut k = [0u8; 64];
    if key.len() <= 64 {
        k[..key.len()].copy_from_slice(key);
    } else {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

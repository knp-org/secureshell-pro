// mDNS service advertise / browse for `_secureshellsync._tcp.local.`.
// Wraps `mdns-sd` with the conventions from docs/sync-protocol.md.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

pub const SERVICE_TYPE: &str = "_secureshellsync._tcp.local.";

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DiscoveredPeer {
    pub pk_hex: String,
    pub label: String,
    pub addr: std::net::SocketAddr,
}

#[derive(Debug, Clone)]
pub struct Advertisement {
    pub instance: String,
    pub port: u16,
    pub pk_hex: String,
    pub label: String,
}

pub struct Advertiser {
    daemon: ServiceDaemon,
    full_name: String,
}

impl Advertiser {
    pub fn start(ad: &Advertisement) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;

        let mut props: HashMap<String, String> = HashMap::new();
        props.insert("v".into(), "1".into());
        props.insert("pk".into(), ad.pk_hex.clone());
        props.insert("host".into(), ad.label.clone());

        let host_ip = IpAddr::V4(local_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED));
        let hostname = format!("{}.local.", ad.instance);
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &ad.instance,
            &hostname,
            host_ip,
            ad.port,
            props,
        )
        .map_err(|e| e.to_string())?;

        let full_name = info.get_fullname().to_string();
        daemon.register(info).map_err(|e| e.to_string())?;

        Ok(Self { daemon, full_name })
    }

    pub fn stop(self) {
        let _ = self.daemon.unregister(&self.full_name);
        let _ = self.daemon.shutdown();
    }
}

/// Browse the LAN for `_secureshellsync._tcp` and return the first peer
/// matching `wanted_pk_hex`, or None if nothing shows up within `timeout`.
pub async fn find_peer(wanted_pk_hex: &str, timeout: Duration) -> Result<Option<DiscoveredPeer>, String> {
    let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
    let recv = daemon.browse(SERVICE_TYPE).map_err(|e| e.to_string())?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() { break; }
        let ev = match tokio::time::timeout(remaining, async {
            // mdns-sd's channel is sync; spin via blocking task.
            tokio::task::spawn_blocking({
                let recv = recv.clone();
                move || recv.recv()
            }).await
        }).await {
            Ok(Ok(Ok(ev))) => ev,
            _ => break,
        };

        if let ServiceEvent::ServiceResolved(info) = ev {
            let props = info.get_properties();
            let pk = props.get("pk").map(|p| p.val_str().to_string()).unwrap_or_default();
            let label = props.get("host").map(|p| p.val_str().to_string()).unwrap_or_default();
            if pk == wanted_pk_hex {
                if let Some(addr) = info.get_addresses().iter().next() {
                    let sock = std::net::SocketAddr::new(*addr, info.get_port());
                    let _ = daemon.shutdown();
                    return Ok(Some(DiscoveredPeer { pk_hex: pk, label, addr: sock }));
                }
            }
        }
    }
    let _ = daemon.shutdown();
    Ok(None)
}

/// Best-effort: pick a non-loopback IPv4 address of this machine. Prefer
/// non-link-local addresses (regular LAN ranges) so the QR embeds a real
/// IP the Android peer can reach.
pub fn local_ipv4() -> Option<Ipv4Addr> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    ifaces
        .into_iter()
        .filter_map(|iface| match iface.ip() {
            std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() => Some(ip),
            _ => None,
        })
        .next()
}

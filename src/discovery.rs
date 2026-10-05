//! Active host discovery: ARP sweep (raw on Linux, SendARP on Windows), or TCP ping
//! when ARP is not available.

use crate::net::LocalNet;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

/// Sends ARP who-has to every target (two rounds) and collects replies.
/// Fails if the process lacks CAP_NET_RAW.
#[cfg(not(windows))]
pub fn arp_sweep(net: &LocalNet, targets: &[Ipv4Addr], wait: Duration) -> Result<HashMap<Ipv4Addr, String>> {
    use anyhow::{Context, anyhow, bail};
    use pnet::datalink::{self, Channel, Config};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::{MutablePacket, Packet};
    use pnet::util::MacAddr;
    use std::time::Instant;

    let src_mac: MacAddr = net.mac.as_deref().ok_or_else(|| anyhow!("interface has no MAC"))?.parse()?;
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == net.iface)
        .ok_or_else(|| anyhow!("interface {} not found", net.iface))?;
    let config = Config { read_timeout: Some(Duration::from_millis(100)), ..Default::default() };
    let (mut tx, mut rx) = match datalink::channel(&iface, config).context("opening raw socket")? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => bail!("unsupported datalink channel"),
    };

    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found = HashMap::new();

    for round in 0..2 {
        for &ip in targets.iter().filter(|ip| !found.contains_key(*ip)) {
            let mut buf = [0u8; 42];
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_destination(MacAddr::broadcast());
            eth.set_source(src_mac);
            eth.set_ethertype(EtherTypes::Arp);
            let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_hw_addr(src_mac);
            arp.set_sender_proto_addr(net.ip);
            arp.set_target_hw_addr(MacAddr::zero());
            arp.set_target_proto_addr(ip);
            if let Some(Err(e)) = tx.send_to(&buf, None) {
                return Err(e).context("sending ARP request");
            }
        }

        let deadline = Instant::now() + if round == 0 { wait / 2 } else { wait };
        while Instant::now() < deadline {
            let Ok(frame) = rx.next() else { continue }; // read timeout
            let Some(eth) = EthernetPacket::new(frame) else { continue };
            if eth.get_ethertype() != EtherTypes::Arp {
                continue;
            }
            let Some(arp) = ArpPacket::new(eth.payload()) else { continue };
            let sender = arp.get_sender_proto_addr();
            if arp.get_operation() == ArpOperations::Reply && wanted.contains(&sender) {
                found.insert(sender, arp.get_sender_hw_addr().to_string());
            }
        }
    }
    Ok(found)
}

/// Asks the OS to ARP-resolve every target in parallel. No admin rights or packet driver
/// needed; the per-host timeout is the OS's own, so `wait` is unused.
#[cfg(windows)]
pub fn arp_sweep(_net: &LocalNet, targets: &[Ipv4Addr], _wait: Duration) -> Result<HashMap<Ipv4Addr, String>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;
    const ERROR_GEN_FAILURE: u32 = 31;
    const ERROR_BAD_NET_NAME: u32 = 67; // no reply

    let results: Vec<(Ipv4Addr, u32, [u8; 8], u32)> = std::thread::scope(|s| {
        let handles: Vec<_> = targets
            .iter()
            .map(|&ip| {
                s.spawn(move || {
                    let mut mac = [0u8; 8];
                    let mut len = mac.len() as u32;
                    // SAFETY: `mac` is a writable buffer of `len` bytes, which SendARP does not exceed.
                    let rc = unsafe { SendARP(u32::from_ne_bytes(ip.octets()), 0, mac.as_mut_ptr().cast(), &mut len) };
                    (ip, rc, mac, len)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("SendARP thread panicked")).collect()
    });

    let found: HashMap<_, _> = results
        .iter()
        .filter(|(_, rc, _, len)| *rc == 0 && *len == 6)
        .map(|(ip, _, mac, _)| (*ip, crate::cache::format_mac(&mac[..6])))
        .collect();

    // Every call failing for a reason other than "no reply" means SendARP itself is unusable.
    if found.is_empty()
        && let Some((_, rc, _, _)) = results.iter().find(|(_, rc, _, _)| ![ERROR_BAD_NET_NAME, ERROR_GEN_FAILURE].contains(rc))
    {
        anyhow::bail!("SendARP failed with error {rc}");
    }
    Ok(found)
}

/// Ports likely to be open or to answer with RST on common LAN devices.
const PING_PORTS: [u16; 8] = [80, 443, 22, 445, 139, 53, 8080, 62078];

/// A host is alive if any probe port accepts or actively refuses the connection.
/// As a side effect the kernel ARP-resolves every target, which `cache::arp_cache` picks up later.
pub async fn tcp_ping(targets: &[Ipv4Addr], timeout: Duration) -> HashSet<Ipv4Addr> {
    stream::iter(targets.iter().copied())
        .map(|ip| async move {
            let probes = PING_PORTS.iter().map(|&port| async move {
                let addr = SocketAddr::from((ip, port));
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => true,
                    Ok(Err(e)) => e.kind() == std::io::ErrorKind::ConnectionRefused,
                    Err(_) => false,
                }
            });
            futures::future::join_all(probes).await.into_iter().any(|a| a).then_some(ip)
        })
        .buffer_unordered(64)
        .filter_map(|ip| async move { ip })
        .collect()
        .await
}

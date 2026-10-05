//! Hostname resolution: system reverse DNS, mDNS (reverse PTR + DNS-SD browse) and NetBIOS.

use crate::model::MdnsService;
use futures::stream::{self, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Reverse lookup through the system resolver (DNS, /etc/hosts, nss-mdns if configured).
pub async fn reverse_dns(ips: &[Ipv4Addr], timeout: Duration) -> HashMap<Ipv4Addr, String> {
    stream::iter(ips.iter().copied())
        .map(|ip| async move {
            let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)));
            match tokio::time::timeout(timeout, lookup).await {
                Ok(Ok(Ok(name))) if name != ip.to_string() => Some((ip, name)),
                _ => None,
            }
        })
        .buffer_unordered(32)
        .filter_map(|r| async move { r })
        .collect()
        .await
}

const SERVICES_META: &str = "_services._dns-sd._udp.local.";

#[derive(Default)]
pub struct MdnsResult {
    pub names: HashMap<Ipv4Addr, Vec<String>>,
    /// Advertised DNS-SD services per responding IP, keyed by full instance name.
    pub services: HashMap<Ipv4Addr, BTreeMap<String, MdnsService>>,
}

impl MdnsResult {
    fn add_name(&mut self, ip: Ipv4Addr, name: &Name) {
        let name = name_str(name);
        let names = self.names.entry(ip).or_default();
        if !names.contains(&name) {
            names.push(name);
        }
    }

    fn service(&mut self, ip: Ipv4Addr, instance: &Name) -> &mut MdnsService {
        self.services.entry(ip).or_default().entry(instance.to_ascii()).or_insert_with(|| MdnsService {
            service: name_str(&instance.base_name()).trim_end_matches(".local").to_string(),
            instance: instance.iter().next().map(|l| String::from_utf8_lossy(l).into_owned()).unwrap_or_default(),
            port: None,
            target: None,
            txt: Vec::new(),
        })
    }
}

fn name_str(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_string()
}

fn query(name: Name, rtype: RecordType) -> Option<Vec<u8>> {
    let mut query = Query::query(name, rtype);
    query.set_mdns_unicast_response(true);
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.add_query(query);
    msg.to_vec().ok()
}

/// "16.1.168.192.in-addr.arpa." -> 192.168.1.16
fn ip_from_arpa(name: &Name) -> Option<Ipv4Addr> {
    let s = name.to_ascii().to_lowercase();
    let rev = s.trim_end_matches('.').strip_suffix(".in-addr.arpa")?;
    let mut octets: Vec<u8> = rev.split('.').map(|o| o.parse().ok()).collect::<Option<_>>()?;
    octets.reverse();
    let octets: [u8; 4] = octets.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// Sends a query to the mDNS group and unicast to every host, so devices that
/// ignore one of the two still get asked.
async fn send_all(sock: &UdpSocket, pkt: &[u8], ips: &[Ipv4Addr]) {
    let _ = sock.send_to(pkt, SocketAddr::from(([224, 0, 0, 251], 5353))).await;
    for &ip in ips {
        let _ = sock.send_to(pkt, SocketAddr::from((ip, 5353))).await;
    }
}

/// Collects responses until `wait` elapses. Service records are attributed to the responder's IP.
async fn listen(sock: &UdpSocket, wait: Duration, res: &mut MdnsResult, types: &mut BTreeSet<Name>) {
    let mut buf = vec![0u8; 9000];
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok((len, src))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        let IpAddr::V4(src) = src.ip() else { continue };
        let Ok(msg) = Message::from_vec(&buf[..len]) else { continue };
        let records: Vec<_> = msg.answers.iter().chain(&msg.additionals).collect();
        for rec in &records {
            match &rec.data {
                RData::PTR(ptr) => {
                    if let Some(ip) = ip_from_arpa(&rec.name) {
                        res.add_name(ip, &ptr.0);
                    } else if rec.name.to_ascii().eq_ignore_ascii_case(SERVICES_META) {
                        types.insert(ptr.0.clone());
                    } else {
                        res.service(src, &ptr.0);
                    }
                }
                RData::SRV(srv) => {
                    let svc = res.service(src, &rec.name);
                    svc.port = Some(srv.port);
                    svc.target = Some(name_str(&srv.target));
                    res.add_name(src, &srv.target);
                }
                RData::A(a) => res.add_name(a.0, &rec.name),
                _ => {}
            }
        }
        // TXT after PTR/SRV so it only attaches to instances we know about.
        for rec in &records {
            let RData::TXT(txt) = &rec.data else { continue };
            let Some(svc) = res.services.get_mut(&src).and_then(|s| s.get_mut(&rec.name.to_ascii())) else {
                continue;
            };
            svc.txt = txt
                .txt_data
                .iter()
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .filter(|t| !t.is_empty())
                .collect();
        }
    }
}

/// Bound to an ephemeral port, so responders answer unicast to us (RFC 6762 §6.7).
/// Round 1 asks reverse PTRs and the DNS-SD service-type list; round 2 browses each type found.
pub async fn mdns(ips: &[Ipv4Addr], wait: Duration) -> MdnsResult {
    let mut res = MdnsResult::default();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return res;
    };
    let _ = sock.set_multicast_ttl_v4(255);
    let mut types = BTreeSet::new();

    for &ip in ips {
        if let Some(pkt) = query(Name::from(ip), RecordType::PTR) {
            send_all(&sock, &pkt, &[ip]).await;
        }
    }
    if let Some(pkt) = query(Name::from_ascii(SERVICES_META).unwrap(), RecordType::PTR) {
        send_all(&sock, &pkt, ips).await;
    }
    listen(&sock, wait, &mut res, &mut types).await;

    for t in &types {
        if let Some(pkt) = query(t.clone(), RecordType::PTR) {
            send_all(&sock, &pkt, ips).await;
        }
    }
    listen(&sock, wait, &mut res, &mut types).await;
    res
}

/// NetBIOS node status (NBSTAT) request for the wildcard name "*".
fn nbstat_query() -> Vec<u8> {
    let mut q = vec![0x4e, 0x53, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
    q.extend(b"CK"); // '*' in first-level encoding
    q.extend([b'A'; 30]); // 15 NUL padding bytes
    q.extend([0, 0, 0x21, 0, 1]); // end of name, type NBSTAT, class IN
    q
}

/// Returns the unique workstation name (suffix 0x00, not a group name) from an NBSTAT response.
fn parse_nbstat(b: &[u8]) -> Option<String> {
    let mut i = 12;
    if *b.get(i)? & 0xC0 == 0xC0 {
        i += 2;
    } else {
        while *b.get(i)? != 0 {
            i += 1 + b[i] as usize;
        }
        i += 1;
    }
    i += 10; // type, class, TTL, rdlength
    let count = *b.get(i)? as usize;
    i += 1;
    (0..count)
        .find_map(|k| {
            let e = b.get(i + k * 18..i + k * 18 + 18)?;
            let group = u16::from_be_bytes([e[16], e[17]]) & 0x8000 != 0;
            (e[15] == 0x00 && !group).then(|| String::from_utf8_lossy(&e[..15]).trim_end().to_string())
        })
        .filter(|n| !n.is_empty())
}

pub async fn netbios(ips: &[Ipv4Addr], wait: Duration) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return out;
    };
    let pkt = nbstat_query();
    for &ip in ips {
        let _ = sock.send_to(&pkt, SocketAddr::from((ip, 137))).await;
    }
    let mut buf = vec![0u8; 1500];
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok((len, src))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        if let (IpAddr::V4(ip), Some(name)) = (src.ip(), parse_nbstat(&buf[..len])) {
            out.insert(ip, name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbstat() {
        let mut r = vec![0x4e, 0x53, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        r.extend(&nbstat_query()[12..12 + 34]); // echoed name
        r.extend([0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41, 2]);
        r.extend(b"WORKGROUP      \x00\x84\x00"); // group name first
        r.extend(b"DESKTOP-ABC    \x00\x04\x00");
        assert_eq!(parse_nbstat(&r).as_deref(), Some("DESKTOP-ABC"));
    }

    #[test]
    fn arpa() {
        assert_eq!(ip_from_arpa(&Name::from(Ipv4Addr::new(192, 168, 1, 16))), Some(Ipv4Addr::new(192, 168, 1, 16)));
    }
}

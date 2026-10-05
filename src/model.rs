use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostnames: BTreeSet<String>,
    /// Where this host was learned from (arp_cache, dhcp_lease, arp_scan, tcp_ping, mdns, ...).
    pub sources: BTreeSet<&'static str>,
    pub online: bool,
    pub is_gateway: bool,
    pub is_self: bool,
    pub ports: Vec<PortInfo>,
    pub mdns_services: Vec<MdnsService>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: &'static str,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub tls: bool,
    /// Extra detail, e.g. HTTP page title.
    pub info: Option<String>,
    pub banner: Option<String>,
    /// Server certificate, when the port speaks TLS.
    pub cert: Option<CertInfo>,
    /// "probe" when identified from the wire, "port-table" when guessed from the port number.
    pub detection: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub subject_cn: Option<String>,
    /// DNS names from the Subject Alternative Name extension.
    pub sans: Vec<String>,
}

impl CertInfo {
    /// CN and SANs that look like FQDNs. Bare words are skipped: on self-signed device
    /// certificates they are usually vendor strings (e.g. "ZyXELcert"), not hostnames.
    pub fn hostnames(&self) -> Vec<String> {
        self.subject_cn
            .iter()
            .chain(&self.sans)
            .filter(|n| {
                n.contains('.')
                    && n.parse::<std::net::IpAddr>().is_err()
                    && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            })
            .cloned()
            .collect()
    }
}

/// A DNS-SD service advertised over mDNS.
#[derive(Debug, Clone, Serialize)]
pub struct MdnsService {
    /// Service type, e.g. "_googlecast._tcp".
    pub service: String,
    /// Instance label, e.g. "Living Room TV".
    pub instance: String,
    pub port: Option<u16>,
    pub target: Option<String>,
    pub txt: Vec<String>,
}

/// All hosts known so far, keyed by IP.
#[derive(Default)]
pub struct Inventory(pub BTreeMap<Ipv4Addr, Host>);

impl Inventory {
    pub fn entry(&mut self, ip: Ipv4Addr, source: &'static str) -> &mut Host {
        let host = self.0.entry(ip).or_insert_with(|| Host {
            ip,
            mac: None,
            vendor: None,
            hostnames: BTreeSet::new(),
            sources: BTreeSet::new(),
            online: false,
            is_gateway: false,
            is_self: false,
            ports: Vec::new(),
            mdns_services: Vec::new(),
        });
        host.sources.insert(source);
        host
    }
}

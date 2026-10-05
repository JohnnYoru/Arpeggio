//! Port list and TCP connect scan.
//!
//! The "most common ports" ranking is nmap's frequency data, read at runtime from the user's
//! own nmap installation; Arpeggio does not ship it. Without nmap, a built-in list is used.

use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;

/// Common TCP services, roughly most likely first. Scanned before the rest of 1-1024
/// when nmap's data is unavailable.
const BUILTIN: &[(u16, &str)] = &[
    (80, "http"), (443, "https"), (22, "ssh"), (21, "ftp"), (23, "telnet"), (25, "smtp"),
    (53, "domain"), (445, "microsoft-ds"), (139, "netbios-ssn"), (135, "msrpc"),
    (3389, "ms-wbt-server"), (8080, "http-alt"), (8443, "https-alt"), (110, "pop3"),
    (143, "imap"), (993, "imaps"), (995, "pop3s"), (587, "submission"), (465, "smtps"),
    (3306, "mysql"), (5432, "postgresql"), (5900, "vnc"), (111, "rpcbind"), (631, "ipp"),
    (9100, "jetdirect"), (515, "printer"), (548, "afp"), (2049, "nfs"), (1723, "pptp"),
    (1080, "socks"), (8000, "http-alt"), (8008, "http-alt"), (8081, "http-alt"),
    (8888, "http-alt"), (3000, "http-alt"), (3001, "http-alt"), (5000, "upnp"),
    (5001, "http-alt"), (1900, "upnp"), (49152, "upnp"), (49153, "upnp"), (62078, "iphone-sync"),
    (7000, "airplay"), (8009, "ajp13"), (8060, "roku-ecp"), (1400, "sonos"), (5555, "adb"),
    (554, "rtsp"), (8554, "rtsp-alt"), (1935, "rtmp"), (5060, "sip"), (5061, "sips"),
    (3478, "stun"), (389, "ldap"), (636, "ldaps"), (88, "kerberos"), (3268, "globalcatldap"),
    (5985, "wsman"), (5986, "wsmans"), (1433, "ms-sql-s"), (1521, "oracle"),
    (27017, "mongodb"), (6379, "redis"), (11211, "memcached"), (9200, "elasticsearch"),
    (5601, "kibana"), (5672, "amqp"), (15672, "rabbitmq-mgmt"), (1883, "mqtt"),
    (8883, "secure-mqtt"), (2375, "docker"), (2376, "docker-tls"), (6443, "kubernetes-api"),
    (10250, "kubelet"), (8086, "influxdb"), (8123, "home-assistant"), (32400, "plex"),
    (8096, "jellyfin"), (9000, "http-alt"), (9090, "http-alt"), (9443, "https-alt"),
    (10000, "webmin"), (3128, "http-proxy"), (8291, "winbox"), (8728, "mikrotik-api"),
    (9091, "transmission"), (6881, "bittorrent"), (6667, "irc"), (6000, "x11"),
    (4369, "epmd"), (25565, "minecraft"),
];

struct PortTable {
    /// Most likely open first.
    ranked: Vec<u16>,
    names: HashMap<u16, String>,
    /// "nmap" or "builtin", reported in the scan output.
    kind: &'static str,
    /// Human-readable origin, for the log.
    origin: String,
}

/// nmap-services from the local nmap install: $NMAPDIR first, then the usual install paths.
fn find_nmap_services() -> Option<(PathBuf, String)> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("NMAPDIR").map(PathBuf::from).into_iter().collect();
    #[cfg(windows)]
    dirs.extend(
        ["ProgramFiles(x86)", "ProgramFiles"]
            .iter()
            .filter_map(std::env::var_os)
            .map(|p| PathBuf::from(p).join("Nmap")),
    );
    #[cfg(not(windows))]
    dirs.extend(["/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap"].map(PathBuf::from));
    dirs.into_iter()
        .map(|d| d.join("nmap-services"))
        .find_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
}

/// TCP entries of an nmap-services file, ranked by open frequency.
fn parse_nmap_services(text: &str) -> (Vec<u16>, HashMap<u16, String>) {
    let mut entries: Vec<(u16, f64, &str)> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut cols = l.split_whitespace();
            let name = cols.next()?;
            let (port, proto) = cols.next()?.split_once('/')?;
            let freq = cols.next()?.parse().ok()?;
            (proto == "tcp").then_some((port.parse().ok()?, freq, name))
        })
        .collect();
    entries.sort_by(|a, b| b.1.total_cmp(&a.1));
    let names = entries
        .iter()
        .filter(|(_, _, n)| *n != "unknown")
        .map(|(p, _, n)| (*p, n.to_string()))
        .collect();
    (entries.into_iter().map(|(p, _, _)| p).collect(), names)
}

fn builtin() -> (Vec<u16>, HashMap<u16, String>) {
    let curated: HashSet<u16> = BUILTIN.iter().map(|(p, _)| *p).collect();
    let ranked = BUILTIN.iter().map(|(p, _)| *p).chain((1..=1024).filter(|p| !curated.contains(p))).collect();
    (ranked, BUILTIN.iter().map(|(p, n)| (*p, n.to_string())).collect())
}

fn table() -> &'static PortTable {
    static CELL: OnceLock<PortTable> = OnceLock::new();
    CELL.get_or_init(|| {
        if let Some((path, text)) = find_nmap_services() {
            let (ranked, names) = parse_nmap_services(&text);
            if !ranked.is_empty() {
                return PortTable { ranked, names, kind: "nmap", origin: path.display().to_string() };
            }
        }
        let (ranked, names) = builtin();
        PortTable { ranked, names, kind: "builtin", origin: "built-in list (nmap not found)".into() }
    })
}

/// ("nmap" | "builtin", where the list came from).
pub fn port_list_source() -> (&'static str, &'static str) {
    (table().kind, &table().origin)
}

/// The `n` most likely open TCP ports.
pub fn top_ports(n: usize) -> Vec<u16> {
    table().ranked.iter().take(n).copied().collect()
}

/// Conventional service name for a TCP port, if known.
pub fn service_name(port: u16) -> Option<&'static str> {
    table().names.get(&port).map(String::as_str)
}

/// TCP connect scan of every (host, port) pair; returns the open ones.
pub async fn scan(
    hosts: &[Ipv4Addr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
) -> Vec<(Ipv4Addr, u16)> {
    let total = hosts.len() * ports.len();
    let pairs = hosts.iter().flat_map(|&h| ports.iter().map(move |&p| (h, p)));
    let mut done = 0usize;
    let mut open = Vec::new();

    let mut results = stream::iter(pairs)
        .map(|(ip, port)| async move {
            let addr = SocketAddr::from((ip, port));
            let ok = matches!(tokio::time::timeout(timeout, TcpStream::connect(addr)).await, Ok(Ok(_)));
            (ip, port, ok)
        })
        .buffer_unordered(concurrency);

    while let Some((ip, port, ok)) = results.next().await {
        done += 1;
        if ok {
            eprintln!("    open {ip}:{port}");
            open.push((ip, port));
        }
        if done.is_multiple_of((total / 10).max(1)) {
            eprintln!("  .. {}% ({done}/{total})", done * 100 / total);
        }
    }
    open.sort();
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_services_ranked_by_frequency() {
        let text = "# comment\nssh\t22/tcp\t0.18\nhttp\t80/tcp\t0.48\nunknown\t9/tcp\t0.01\ndomain\t53/udp\t0.5\n";
        let (ranked, names) = parse_nmap_services(text);
        assert_eq!(ranked, [80, 22, 9]);
        assert_eq!(names.get(&22).map(String::as_str), Some("ssh"));
        assert!(!names.contains_key(&9));
    }

    #[test]
    fn builtin_has_no_duplicates() {
        let (ranked, _) = builtin();
        let unique: HashSet<_> = ranked.iter().collect();
        assert_eq!(unique.len(), ranked.len());
        assert_eq!(ranked[0], 80);
        assert!(ranked.contains(&1024) && ranked.contains(&62078));
    }
}

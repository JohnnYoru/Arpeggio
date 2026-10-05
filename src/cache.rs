//! Passive sources read before any packet is sent: ARP cache, DHCP leases, hosts file.

use regex::Regex;
use std::net::Ipv4Addr;
use std::path::PathBuf;

pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    /// ATF_COM flag: the kernel has a resolved MAC for this entry.
    pub complete: bool,
}

pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// "dhcp_lease" for leases handed out by this machine, "dhcp_client_lease" for
    /// router/server/DNS addresses learned from this machine's own lease.
    pub source: &'static str,
}

#[cfg(not(windows))]
pub fn arp_cache() -> Vec<ArpEntry> {
    let Ok(table) = std::fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let ip = cols.first()?.parse().ok()?;
            let flags = u32::from_str_radix(cols.get(2)?.trim_start_matches("0x"), 16).ok()?;
            let mac = cols.get(3)?.to_lowercase();
            (mac != "00:00:00:00:00:00").then_some(ArpEntry { ip, mac, complete: flags & 0x2 != 0 })
        })
        .collect()
}

#[cfg(windows)]
pub fn format_mac(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Windows neighbor table (the `arp -a` data) via GetIpNetTable2.
#[cfg(windows)]
pub fn arp_cache() -> Vec<ArpEntry> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, NlnsIncomplete, NlnsUnreachable};

    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: on success GetIpNetTable2 stores a table we own until FreeMibTable.
    if unsafe { GetIpNetTable2(AF_INET, &mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    // SAFETY: the table holds NumEntries rows laid out contiguously starting at `Table`.
    let rows = unsafe {
        let first = std::ptr::addr_of!((*table).Table).cast::<MIB_IPNET_ROW2>();
        std::slice::from_raw_parts(first, (*table).NumEntries as usize)
    };
    let out = rows
        .iter()
        .filter_map(|row| {
            let mac = row.PhysicalAddress.get(..row.PhysicalAddressLength as usize)?;
            // Skip unresolved entries and broadcast/multicast addresses.
            if mac.len() != 6 || mac.iter().all(|b| *b == 0) || mac[0] & 1 != 0 {
                return None;
            }
            // SAFETY: the table was requested for AF_INET, so every address is IPv4.
            let ip = Ipv4Addr::from(unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes());
            Some(ArpEntry { ip, mac: format_mac(mac), complete: row.State != NlnsUnreachable && row.State != NlnsIncomplete })
        })
        .collect();
    // SAFETY: `table` came from GetIpNetTable2 and is not used afterwards.
    unsafe { FreeMibTable(table.cast()) };
    out
}

pub fn hosts_file() -> Vec<(Ipv4Addr, Vec<String>)> {
    #[cfg(not(windows))]
    let path = "/etc/hosts".to_string();
    #[cfg(windows)]
    let path = format!(
        r"{}\System32\drivers\etc\hosts",
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
    );
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut words = line.split('#').next()?.split_whitespace();
            let ip = words.next()?.parse().ok()?;
            Some((ip, words.map(str::to_string).collect()))
        })
        .collect()
}

fn read_glob(dir: &str, pred: impl Fn(&str) -> bool) -> Vec<(PathBuf, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(&pred))
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
        .collect()
}

fn ipv4s(text: &str) -> impl Iterator<Item = Ipv4Addr> + '_ {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.')).filter_map(|s| s.parse().ok())
}

/// Collects leases from common DHCP servers and clients. Unreadable files are skipped silently.
pub fn dhcp_leases() -> Vec<Lease> {
    let mut out = Vec::new();

    // dnsmasq: "<expiry> <mac> <ip> <hostname> <client-id>"
    for path in ["/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases"] {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        for line in text.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let Some(ip) = cols.get(2).and_then(|s| s.parse().ok()) else { continue };
            out.push(Lease {
                ip,
                mac: cols.get(1).map(|s| s.to_lowercase()),
                hostname: cols.get(3).filter(|h| **h != "*").map(|s| s.to_string()),
                source: "dhcp_lease",
            });
        }
    }

    // ISC dhcpd: "lease <ip> { ... hardware ethernet <mac>; client-hostname "<name>"; }"
    let block = Regex::new(r"(?s)lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}").unwrap();
    let hw = Regex::new(r"hardware ethernet\s+([0-9a-fA-F:]+);").unwrap();
    let name = Regex::new(r#"client-hostname\s+"([^"]+)";"#).unwrap();
    for path in ["/var/lib/dhcp/dhcpd.leases", "/var/lib/dhcpd/dhcpd.leases"] {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        for cap in block.captures_iter(&text) {
            let Ok(ip) = cap[1].parse() else { continue };
            out.push(Lease {
                ip,
                mac: hw.captures(&cap[2]).map(|c| c[1].to_lowercase()),
                hostname: name.captures(&cap[2]).map(|c| c[1].to_string()),
                source: "dhcp_lease",
            });
        }
    }

    // Kea: CSV with a header naming the columns.
    if let Ok(text) = std::fs::read_to_string("/var/lib/kea/kea-leases4.csv") {
        let mut lines = text.lines();
        let header: Vec<&str> = lines.next().unwrap_or("").split(',').collect();
        let col = |n: &str| header.iter().position(|h| *h == n);
        let (ia, im, ih) = (col("address"), col("hwaddr"), col("hostname"));
        for line in lines {
            let cols: Vec<&str> = line.split(',').collect();
            let get = |i: Option<usize>| i.and_then(|i| cols.get(i)).filter(|s| !s.is_empty());
            let Some(ip) = get(ia).and_then(|s| s.parse().ok()) else { continue };
            out.push(Lease {
                ip,
                mac: get(im).map(|s| s.to_lowercase()),
                hostname: get(ih).map(|s| s.trim_end_matches('.').to_string()),
                source: "dhcp_lease",
            });
        }
    }

    // Client leases (NetworkManager internal client / systemd-networkd): KEY=VALUE.
    let mut client = read_glob("/var/lib/NetworkManager", |n| n.ends_with(".lease"));
    client.extend(read_glob("/run/systemd/netif/leases", |_| true));
    for (_, text) in &client {
        for line in text.lines() {
            let Some((key, val)) = line.split_once('=') else { continue };
            if matches!(key, "ROUTER" | "SERVER_ADDRESS" | "DNS" | "NTP") {
                out.extend(ipv4s(val).map(client_lease));
            }
        }
    }

    // dhclient: "option routers ...;", "option dhcp-server-identifier ...;", ...
    let mut dhclient = read_glob("/var/lib/dhcp", |n| n.starts_with("dhclient"));
    dhclient.extend(read_glob("/var/lib/dhclient", |_| true));
    dhclient.extend(read_glob("/var/lib/NetworkManager", |n| n.starts_with("dhclient")));
    for (_, text) in &dhclient {
        for line in text.lines().map(str::trim) {
            if ["option routers", "option dhcp-server-identifier", "option domain-name-servers"]
                .iter()
                .any(|p| line.starts_with(p))
            {
                out.extend(ipv4s(line).map(client_lease));
            }
        }
    }

    // Windows keeps no lease files; for DHCP-configured adapters, the gateway and DNS
    // servers are what the client lease handed out.
    #[cfg(windows)]
    for iface in netdev::get_interfaces().into_iter().filter(|i| i.dhcp_v4_enabled == Some(true)) {
        let gateways = iface.gateway.map(|g| g.ipv4).unwrap_or_default();
        let dns = iface.dns_servers.into_iter().filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        });
        out.extend(gateways.into_iter().chain(dns).map(client_lease));
    }

    out
}

fn client_lease(ip: Ipv4Addr) -> Lease {
    Lease { ip, mac: None, hostname: None, source: "dhcp_client_lease" }
}

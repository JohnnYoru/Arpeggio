use anyhow::{Context, Result, anyhow};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

pub struct LocalNet {
    /// Interface name (on Windows, the friendly name such as "Ethernet").
    pub iface: String,
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub cidr: Ipv4Network,
    pub gateway: Option<Ipv4Addr>,
}

impl LocalNet {
    /// Every usable host address in the target network.
    pub fn targets(&self) -> Vec<Ipv4Addr> {
        let (net, bcast) = (self.cidr.network(), self.cidr.broadcast());
        self.cidr.iter().filter(|ip| *ip != net && *ip != bcast).collect()
    }
}

/// The interface as found by one of the lookup methods, before the target network is chosen.
struct Found {
    name: String,
    addr: Ipv4Network,
    mac: Option<String>,
    gateway: Option<Ipv4Addr>,
}

/// Default route as (interface name, gateway) from the /proc/net/route table.
#[cfg(not(windows))]
fn default_route(table: &str) -> Option<(String, Ipv4Addr)> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[1] != "00000000" {
            return None;
        }
        // Gateway is a little-endian hex u32.
        let gw = u32::from_str_radix(cols[2], 16).ok()?;
        Some((cols[0].to_string(), Ipv4Addr::from(gw.to_le_bytes())))
    })
}

/// Linux: default route from /proc/net/route, interface details from pnet.
#[cfg(not(windows))]
fn from_proc(iface_name: Option<&str>, table: &str) -> Result<Found> {
    use pnet::datalink;
    use pnet::ipnetwork::IpNetwork;

    let route = default_route(table);
    let name = iface_name
        .map(str::to_string)
        .or_else(|| route.as_ref().map(|(n, _)| n.clone()))
        .ok_or_else(|| anyhow!("no default route; pass --iface"))?;

    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .with_context(|| format!("interface {name} not found"))?;

    let v4 = iface
        .ips
        .iter()
        .find_map(|n| match n {
            IpNetwork::V4(v4) => Some(*v4),
            _ => None,
        })
        .with_context(|| format!("interface {name} has no IPv4 address"))?;

    Ok(Found {
        addr: Ipv4Network::new(v4.ip(), v4.prefix())?,
        mac: iface.mac.map(|m| m.to_string()),
        gateway: route.filter(|(n, _)| *n == name).map(|(_, gw)| gw),
        name,
    })
}

/// Fallback when /proc/net/route is unavailable (Windows, macOS): the OS routing APIs via netdev.
/// `--iface` matches either the system name (adapter GUID on Windows) or the friendly name.
fn from_netdev(iface_name: Option<&str>) -> Result<Found> {
    let iface = match iface_name {
        Some(n) => netdev::get_interfaces()
            .into_iter()
            .find(|i| i.name == n || i.friendly_name.as_deref() == Some(n))
            .with_context(|| format!("interface {n} not found"))?,
        None => netdev::get_default_interface().map_err(|e| anyhow!("no default interface ({e}); pass --iface"))?,
    };
    let name = iface.friendly_name.clone().unwrap_or_else(|| iface.name.clone());
    let v4 = iface.ipv4.first().with_context(|| format!("interface {name} has no IPv4 address"))?;

    Ok(Found {
        addr: Ipv4Network::new(v4.addr(), v4.prefix_len())?,
        mac: iface.mac_addr.map(|m| m.to_string()),
        gateway: iface.gateway.and_then(|g| g.ipv4.first().copied()),
        name,
    })
}

/// Picks the interface (explicit or the default-route one) and the network to scan.
/// Without an explicit CIDR, the interface's network is used, narrowed to a /24 if larger.
pub fn detect(iface_name: Option<&str>, cidr: Option<Ipv4Network>) -> Result<LocalNet> {
    #[cfg(not(windows))]
    let found = match std::fs::read_to_string("/proc/net/route") {
        Ok(table) => from_proc(iface_name, &table)?,
        Err(_) => from_netdev(iface_name)?,
    };
    #[cfg(windows)]
    let found = from_netdev(iface_name)?;

    let cidr = match cidr {
        Some(c) => c,
        None => {
            let prefix = found.addr.prefix().max(24);
            Ipv4Network::new(Ipv4Network::new(found.addr.ip(), prefix)?.network(), prefix)?
        }
    };

    Ok(LocalNet {
        iface: found.name,
        ip: found.addr.ip(),
        mac: found.mac,
        gateway: found.gateway.filter(|gw| cidr.contains(*gw)),
        cidr,
    })
}

mod cache;
mod discovery;
mod model;
mod names;
mod net;
mod oui;
mod ports;
mod service;
mod topology;

use anyhow::Result;
use clap::Parser;
use futures::stream::{self, StreamExt};
use model::Inventory;
use ipnetwork::Ipv4Network;
use serde_json::json;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Discovers hosts on the local subnet, scans their top TCP ports, fingerprints services,
/// and writes a Cytoscape.js topology as JSON.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Interface to use (default: the one holding the default route).
    #[arg(short, long)]
    iface: Option<String>,
    /// Network to scan (default: the interface's network, narrowed to /24).
    #[arg(short, long)]
    cidr: Option<Ipv4Network>,
    /// How many of the most common TCP ports to scan (ranked by the local nmap install's
    /// frequency data; without nmap, a built-in list of ~1100 ports).
    #[arg(short = 'p', long, default_value_t = 5000)]
    top_ports: usize,
    /// TCP connect timeout in milliseconds.
    #[arg(short, long, default_value_t = 1000)]
    timeout_ms: u64,
    /// Maximum simultaneous connection attempts during the port scan.
    #[arg(long, default_value_t = 1000)]
    concurrency: usize,
    /// Output file (default: stdout).
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let timeout = Duration::from_millis(args.timeout_ms);
    let started_at = now();
    let _ = rlimit::increase_nofile_limit(args.concurrency as u64 + 1024);

    let net = net::detect(args.iface.as_deref(), args.cidr)?;
    let targets = net.targets();
    eprintln!(
        "[*] {} {} -> {} ({} addresses), gateway {}",
        net.iface,
        net.ip,
        net.cidr,
        targets.len(),
        net.gateway.map_or("none".into(), |g| g.to_string())
    );

    // 1. Passive sources.
    let mut inv = Inventory::default();
    let arp_before = cache::arp_cache();
    for e in arp_before.iter().filter(|e| net.cidr.contains(e.ip)) {
        inv.entry(e.ip, "arp_cache").mac = Some(e.mac.clone());
    }
    for lease in cache::dhcp_leases().into_iter().filter(|l| net.cidr.contains(l.ip)) {
        let host = inv.entry(lease.ip, lease.source);
        if lease.mac.is_some() {
            host.mac = lease.mac;
        }
        host.hostnames.extend(lease.hostname);
    }
    for (ip, names) in cache::hosts_file().into_iter().filter(|(ip, _)| net.cidr.contains(*ip)) {
        inv.entry(ip, "hosts_file").hostnames.extend(names);
    }
    eprintln!("[*] caches: {} known hosts before scanning", inv.0.len());

    // 2. Active discovery.
    let sweep = {
        let (net_ref, targets) = (&net, targets.clone());
        tokio::task::block_in_place(|| discovery::arp_sweep(net_ref, &targets, Duration::from_secs(2)))
    };
    let mode = match sweep {
        Ok(found) => {
            eprintln!("[*] ARP sweep: {} hosts replied", found.len());
            for (ip, mac) in found {
                let host = inv.entry(ip, "arp_scan");
                host.mac = Some(mac);
                host.online = true;
            }
            "arp"
        }
        Err(e) => {
            eprintln!("[!] ARP sweep unavailable ({e:#}); falling back to TCP ping");
            for ip in discovery::tcp_ping(&targets, timeout).await {
                let host = inv.entry(ip, "tcp_ping");
                host.online = true;
            }
            // Hosts that answered the kernel's ARP during the TCP ping, even if every port was filtered.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let was_complete = |ip| arp_before.iter().any(|e| e.ip == ip && e.complete);
            for e in cache::arp_cache().into_iter().filter(|e| net.cidr.contains(e.ip)) {
                let fresh = e.complete && !was_complete(e.ip);
                let host = inv.entry(e.ip, if fresh { "arp_resolve" } else { "arp_cache" });
                host.mac = Some(e.mac);
                host.online |= fresh;
            }
            "tcp"
        }
    };

    let me = inv.entry(net.ip, "self");
    me.is_self = true;
    me.online = true;
    me.mac = net.mac.clone();
    if let Some(gw) = net.gateway {
        inv.entry(gw, "route").is_gateway = true;
    }
    for host in inv.0.values_mut() {
        host.vendor = host.mac.as_deref().and_then(oui::vendor);
    }
    let online = inv.0.values().filter(|h| h.online).count();
    eprintln!("[*] {} hosts ({} online, {} cached only)", inv.0.len(), online, inv.0.len() - online);

    // 3. Hostnames.
    let ips: Vec<_> = inv.0.keys().copied().collect();
    let (rdns, mdns, netbios) = tokio::join!(
        names::reverse_dns(&ips, Duration::from_secs(3)),
        names::mdns(&ips, Duration::from_secs(2)),
        names::netbios(&ips, Duration::from_secs(2))
    );
    for (ip, name) in rdns {
        inv.entry(ip, "rdns").hostnames.insert(name);
    }
    for (ip, names) in mdns.names.into_iter().filter(|(ip, _)| net.cidr.contains(*ip)) {
        let host = inv.entry(ip, "mdns");
        host.hostnames.extend(names);
        host.online = true; // it just answered us
    }
    for (ip, services) in mdns.services.into_iter().filter(|(ip, _)| net.cidr.contains(*ip)) {
        let host = inv.entry(ip, "mdns_browse");
        host.mdns_services.extend(services.into_values());
        host.online = true;
    }
    for (ip, name) in netbios.into_iter().filter(|(ip, _)| net.cidr.contains(*ip)) {
        let host = inv.entry(ip, "netbios");
        host.hostnames.insert(name);
        host.online = true;
    }

    // 4. Port scan (online and cached hosts alike, including any found by name resolution).
    let ips: Vec<_> = inv.0.keys().copied().collect();
    let port_list = ports::top_ports(args.top_ports);
    let (port_kind, port_origin) = ports::port_list_source();
    eprintln!("[*] port list: {port_origin}");
    eprintln!("[*] scanning {} TCP ports on {} hosts", port_list.len(), ips.len());
    let open = ports::scan(&ips, &port_list, timeout, args.concurrency).await;

    // 5. Service detection.
    eprintln!("[*] fingerprinting {} open ports", open.len());
    let services: Vec<_> = stream::iter(open)
        .map(|(ip, port)| async move { (ip, service::detect(ip, port, timeout).await) })
        .buffer_unordered(64)
        .collect()
        .await;
    for (ip, info) in services {
        let host = inv.entry(ip, "port_scan");
        host.online = true;
        let cert_names = info.cert.as_ref().map(|c| c.hostnames()).unwrap_or_default();
        if !cert_names.is_empty() {
            host.hostnames.extend(cert_names);
            host.sources.insert("tls_cert");
        }
        host.ports.push(info);
    }
    for host in inv.0.values_mut() {
        host.ports.sort_by_key(|p| p.port);
    }

    // 6. Output.
    let scan = json!({
        "started_at": started_at,
        "finished_at": now(),
        "interface": net.iface,
        "local_ip": net.ip,
        "cidr": net.cidr.to_string(),
        "gateway": net.gateway,
        "discovery": mode,
        "top_ports": port_list.len(),
        "port_list": port_kind,
    });
    let out = serde_json::to_string_pretty(&topology::build(&inv, &net.cidr.to_string(), scan))?;
    match args.output {
        Some(path) => {
            std::fs::write(&path, out)?;
            eprintln!("[*] wrote {}", path.display());
        }
        None => println!("{out}"),
    }
    Ok(())
}

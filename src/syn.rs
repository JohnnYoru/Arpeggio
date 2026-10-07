//! Half-open (SYN) port scan over a raw socket.

use anyhow::{Context, Result, bail};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{TransportReceiver, tcp_packet_iter, transport_channel};
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HEADER_LEN: usize = 20;

const MAX_RETRIES: u32 = 3;

const LINGER_MAX: Duration = Duration::from_millis(1500);

/// Ends a round early once replies stop arriving.
const LINGER_QUIET: Duration = Duration::from_millis(350);

/// Large enough to hold the replies to a full burst.
const RCVBUF: libc::c_int = 8 << 20;

#[derive(Default)]
struct Replies {
    open: HashSet<(Ipv4Addr, u16)>,
    answered: HashSet<(Ipv4Addr, u16)>,
    last: Option<Instant>,
}

fn cookie(key: u32, ip: Ipv4Addr, port: u16) -> u32 {
    let mut h = u64::from(key) ^ (u64::from(u32::from(ip)) << 16) ^ u64::from(port);
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (h ^ (h >> 31)) as u32
}

/// Sets a read timeout, so the reader can stop, and a larger receive buffer.
fn configure(rx: &TransportReceiver, wakeup: Duration) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: wakeup.as_secs() as libc::time_t,
        tv_usec: wakeup.subsec_micros() as libc::suseconds_t,
    };
    let rcvbuf = RCVBUF;
    let opts: [(libc::c_int, *const libc::c_void, usize); 2] = [
        (libc::SO_RCVTIMEO, std::ptr::addr_of!(tv).cast(), size_of::<libc::timeval>()),
        (libc::SO_RCVBUF, std::ptr::addr_of!(rcvbuf).cast(), size_of::<libc::c_int>()),
    ];
    for (name, value, len) in opts {
        // SAFETY: fd is owned by `rx`; each value matches its option's type and size.
        let rc = unsafe { libc::setsockopt(rx.socket.fd, libc::SOL_SOCKET, name, value, len as libc::socklen_t) };
        if rc != 0 {
            bail!("setting socket option {name}: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Waits for in-flight replies until the network goes quiet.
fn linger(replies: &Mutex<Replies>) {
    let deadline = Instant::now() + LINGER_MAX;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        let last = replies.lock().expect("reply lock poisoned").last;
        if last.is_none_or(|t| t.elapsed() >= LINGER_QUIET) {
            return;
        }
    }
}

/// Records replies that match our cookie until `stop` is set.
fn receive(rx: &mut TransportReceiver, src_port: u16, key: u32, replies: &Mutex<Replies>, stop: &AtomicBool) {
    let mut iter = tcp_packet_iter(rx);
    while !stop.load(Ordering::Relaxed) {
        let Ok((packet, addr)) = iter.next() else { continue };
        let IpAddr::V4(ip) = addr else { continue };
        if packet.get_destination() != src_port {
            continue;
        }
        let port = packet.get_source();
        if packet.get_acknowledgement() != cookie(key, ip, port).wrapping_add(1) {
            continue;
        }
        let flags = packet.get_flags();
        let (syn, ack, rst) = (flags & TcpFlags::SYN != 0, flags & TcpFlags::ACK != 0, flags & TcpFlags::RST != 0);
        if !ack {
            continue;
        }
        let mut replies = replies.lock().expect("reply lock poisoned");
        replies.last = Some(Instant::now());
        if syn {
            if replies.open.insert((ip, port)) {
                eprintln!("    open {ip}:{port}");
            }
        } else if !rst {
            continue;
        }
        replies.answered.insert((ip, port));
    }
}

fn send_round(
    tx: &mut pnet::transport::TransportSender,
    pairs: &[(Ipv4Addr, u16)],
    local_ip: Ipv4Addr,
    src_port: u16,
    key: u32,
    rate: u32,
    round: u32,
) -> Result<()> {
    let mut buf = [0u8; HEADER_LEN];
    let start = Instant::now();

    for (sent, &(ip, port)) in pairs.iter().enumerate() {
        {
            let mut tcp = MutableTcpPacket::new(&mut buf).expect("buffer fits a TCP header");
            tcp.set_source(src_port);
            tcp.set_destination(port);
            tcp.set_sequence(cookie(key, ip, port));
            tcp.set_data_offset((HEADER_LEN / 4) as u8);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(64240);
            tcp.set_checksum(0);
            let sum = ipv4_checksum(&tcp.to_immutable(), &local_ip, &ip);
            tcp.set_checksum(sum);
        }

        // ENOBUFS: transmit queue full. Back off and resend.
        for attempt in 0.. {
            let tcp = TcpPacket::new(&buf).expect("packet was just built");
            match tx.send_to(tcp, IpAddr::V4(ip)) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NetworkUnreachable => break,
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) && attempt < 1000 => {
                    std::thread::sleep(Duration::from_micros(200));
                }
                Err(e) => return Err(e).with_context(|| format!("sending SYN to {ip}:{port}")),
            }
        }

        let due = Duration::from_secs_f64((sent + 1) as f64 / f64::from(rate));
        match due.checked_sub(start.elapsed()) {
            Some(wait) if wait >= Duration::from_millis(1) => std::thread::sleep(wait),
            _ => {}
        }
        if (sent + 1).is_multiple_of((pairs.len() / 10).max(1)) {
            let label = if round == 0 { "sent" } else { "resent" };
            eprintln!("  .. {label} {}% ({}/{})", (sent + 1) * 100 / pairs.len(), sent + 1, pairs.len());
        }
    }
    Ok(())
}

/// SYN-scans every (host, port) pair and returns the open ones.
pub fn scan(
    local_ip: Ipv4Addr,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    rate: u32,
) -> Result<Vec<(Ipv4Addr, u16)>> {
    let (mut tx, mut rx) = transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp)))
        .context("opening raw TCP socket")?;
    configure(&rx, Duration::from_millis(100))?;

    let key = rand_u32();
    let src_port = 40000 + (rand_u32() % 20000) as u16;

    let replies = Arc::new(Mutex::new(Replies::default()));
    let stop = Arc::new(AtomicBool::new(false));

    let result = std::thread::scope(|scope| {
        let reader = {
            let (replies, stop) = (Arc::clone(&replies), Arc::clone(&stop));
            scope.spawn(move || receive(&mut rx, src_port, key, &replies, &stop))
        };

        let mut send_all = || -> Result<()> {
            let mut pending: Vec<_> = hosts.iter().flat_map(|&h| ports.iter().map(move |&p| (h, p))).collect();

            for round in 0..=MAX_RETRIES {
                // Each retry halves the rate; slower rounds recover dropped replies.
                let rate = rate >> round;
                send_round(&mut tx, &pending, local_ip, src_port, key, rate.max(1), round)?;
                linger(&replies);

                // Only retry hosts that answered at least once.
                let unanswered: Vec<_> = {
                    let answered = &replies.lock().expect("reply lock poisoned").answered;
                    let live: HashSet<Ipv4Addr> = answered.iter().map(|(ip, _)| *ip).collect();
                    pending
                        .iter()
                        .copied()
                        .filter(|pair| live.contains(&pair.0) && !answered.contains(pair))
                        .collect()
                };
                // Stop when nothing is left or a round recovers nothing.
                if unanswered.is_empty() || unanswered.len() == pending.len() {
                    break;
                }
                pending = unanswered;
                if round < MAX_RETRIES {
                    eprintln!("  .. retrying {} unanswered ports", pending.len());
                }
            }
            Ok(())
        };

        let result = send_all();
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader thread panicked");
        result
    });
    result?;

    let mut open: Vec<_> = replies.lock().expect("reply lock poisoned").open.iter().copied().collect();
    open.sort();
    Ok(open)
}

/// Random seed from std's hasher; not cryptographic.
fn rand_u32() -> u32 {
    std::hash::RandomState::new().hash_one(0u8) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_differ_per_target_and_key() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        assert_ne!(cookie(1, ip, 80), cookie(1, ip, 443));
        assert_ne!(cookie(1, ip, 80), cookie(1, Ipv4Addr::new(10, 0, 0, 2), 80));
        assert_ne!(cookie(1, ip, 80), cookie(2, ip, 80));
        assert_eq!(cookie(7, ip, 80), cookie(7, ip, 80));
    }
}

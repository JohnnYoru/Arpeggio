//! Lightweight service detection: passive banner, HTTP probe, TLS handshake.

use crate::model::{CertInfo, PortInfo};
use crate::ports::service_name;
use regex::bytes::Regex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{CryptoProvider, ring};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use x509_parser::extensions::GeneralName;
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Ports where the server waits for a TLS ClientHello, so TLS is tried before plain HTTP.
const TLS_HINT: [u16; 10] = [443, 465, 636, 853, 993, 995, 5986, 8443, 9443, 10443];

struct Found {
    service: String,
    product: Option<String>,
    version: Option<String>,
    info: Option<String>,
}

pub async fn detect(ip: Ipv4Addr, port: u16, timeout: Duration) -> PortInfo {
    let addr = SocketAddr::from((ip, port));
    let banner_wait = timeout * 2;

    let mut tls = false;
    let mut cert = None;
    let mut raw = passive(addr, timeout, banner_wait).await;
    let mut found = raw.as_deref().and_then(classify_banner);

    if found.is_none() {
        let order: [bool; 2] = if TLS_HINT.contains(&port) { [true, false] } else { [false, true] };
        for use_tls in order {
            let resp = if use_tls {
                http_over_tls(ip, addr, timeout, banner_wait).await.map(|(resp, c)| {
                    cert = c;
                    resp
                })
            } else {
                http_plain(ip, addr, timeout, banner_wait).await
            };
            let Some(resp) = resp else { continue };
            if let Some(f) = classify_http(&resp, use_tls) {
                (found, raw, tls) = (Some(f), Some(resp), use_tls);
                break;
            }
            // A TLS handshake succeeded but the payload isn't HTTP: still worth reporting.
            if use_tls {
                tls = true;
                found = Some(Found {
                    service: format!("ssl/{}", service_name(port).unwrap_or("unknown")),
                    product: None,
                    version: None,
                    info: None,
                });
                break;
            }
            // Some services only talk after receiving data; the HTTP request may provoke a banner.
            if raw.is_none() && !resp.is_empty() {
                found = classify_banner(&resp);
                raw = Some(resp);
                if found.is_some() {
                    break;
                }
            }
        }
    }

    let banner = raw.as_deref().map(printable).filter(|b| !b.is_empty());
    match found {
        Some(f) => PortInfo {
            port,
            protocol: "tcp",
            service: f.service,
            product: f.product,
            version: f.version,
            tls,
            info: f.info,
            banner,
            cert,
            detection: "probe",
        },
        None => PortInfo {
            port,
            protocol: "tcp",
            service: service_name(port).unwrap_or("unknown").to_string(),
            product: None,
            version: None,
            tls,
            info: None,
            banner,
            cert,
            detection: "port-table",
        },
    }
}

async fn connect(addr: SocketAddr, timeout: Duration) -> Option<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()
}

/// Reads until the peer stops sending, the buffer fills, or `wait` elapses.
async fn read_some<S: AsyncRead + Unpin>(s: &mut S, wait: Duration) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let mut len = 0;
    let deadline = tokio::time::Instant::now() + wait;
    while len < buf.len() {
        match tokio::time::timeout_at(deadline, s.read(&mut buf[len..])).await {
            Ok(Ok(n)) if n > 0 => len += n,
            _ => break,
        }
    }
    buf.truncate(len);
    buf
}

/// Services that speak first (SSH, FTP, SMTP, ...).
async fn passive(addr: SocketAddr, timeout: Duration, wait: Duration) -> Option<Vec<u8>> {
    let mut s = connect(addr, timeout).await?;
    Some(read_some(&mut s, wait).await).filter(|b| !b.is_empty())
}

async fn http_exchange<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, ip: Ipv4Addr, wait: Duration) -> Vec<u8> {
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: arpeggio\r\nAccept: */*\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return Vec::new();
    }
    read_some(s, wait).await
}

async fn http_plain(ip: Ipv4Addr, addr: SocketAddr, timeout: Duration, wait: Duration) -> Option<Vec<u8>> {
    let mut s = connect(addr, timeout).await?;
    Some(http_exchange(&mut s, ip, wait).await)
}

/// Returns None if the TLS handshake fails; otherwise the (possibly empty) HTTP response
/// and the server certificate.
async fn http_over_tls(
    ip: Ipv4Addr,
    addr: SocketAddr,
    timeout: Duration,
    wait: Duration,
) -> Option<(Vec<u8>, Option<CertInfo>)> {
    let tcp = connect(addr, timeout).await?;
    let name = ServerName::IpAddress(IpAddr::V4(ip).into());
    let mut s = tokio::time::timeout(timeout * 2, tls_connector().connect(name, tcp)).await.ok()?.ok()?;
    let cert = s.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(|c| cert_info(c));
    Some((http_exchange(&mut s, ip, wait).await, cert))
}

fn cert_info(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let subject_cn = cert.subject().iter_common_name().next().and_then(|cn| cn.as_str().ok()).map(str::to_string);
    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|g| match g {
                GeneralName::DNSName(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some(CertInfo { subject_cn, sans })
}

fn regex(pat: &'static str) -> Regex {
    Regex::new(pat).unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim().to_string()
}

fn classify_banner(b: &[u8]) -> Option<Found> {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let rules = RULES.get_or_init(|| {
        vec![
            (regex(r"^SSH-[\d.]+-([^_\s-]+)[_-]?(\S*)"), "ssh"),
            (regex(r"(?i)^220[ -].*?(Postfix|Exim|Sendmail|Microsoft ESMTP)"), "smtp"),
            (regex(r"(?i)^220[ -].*E?SMTP"), "smtp"),
            (regex(r"(?i)^220[ -].*?(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|FTP)[ ]?([\d.]*)"), "ftp"),
            (regex(r"^\+OK ?(.*)"), "pop3"),
            (regex(r"^\* OK ?(.*)"), "imap"),
            (regex(r"^RFB (\d{3}\.\d{3})"), "vnc"),
            (regex(r"(?s-u)^.{4}\x0a(\d[\w.\-]*)\x00"), "mysql"),
            (regex(r"(?-u)^\xff[\xfb-\xfe]"), "telnet"),
            (regex(r"^AMQP"), "amqp"),
            (regex(r"^-ERR|^-NOAUTH|^\$\d+\r\n"), "redis"),
        ]
    });

    for (re, service) in rules {
        let Some(c) = re.captures(b) else { continue };
        let g = |i: usize| c.get(i).map(|m| text(m.as_bytes())).filter(|s| !s.is_empty());
        let (product, version) = match *service {
            "ssh" => (g(1), g(2)),
            "smtp" => (g(1), None),
            "ftp" => (g(1).filter(|p| !p.eq_ignore_ascii_case("ftp")), g(2)),
            "vnc" => (None, g(1)),
            "mysql" => {
                let v = g(1);
                let product = if v.as_deref().is_some_and(|v| v.contains("MariaDB")) { "MariaDB" } else { "MySQL" };
                (Some(product.to_string()), v)
            }
            _ => (None, None),
        };
        let info = matches!(*service, "pop3" | "imap").then(|| g(1)).flatten();
        return Some(Found { service: service.to_string(), product, version, info });
    }
    None
}

fn classify_http(b: &[u8], tls: bool) -> Option<Found> {
    if !b.starts_with(b"HTTP/") {
        return None;
    }
    static SERVER: OnceLock<Regex> = OnceLock::new();
    static TITLE: OnceLock<Regex> = OnceLock::new();
    let server = SERVER.get_or_init(|| regex(r"(?im)^server:[ \t]*([^\r\n]+)"));
    let title = TITLE.get_or_init(|| regex(r"(?is)<title[^>]*>\s*([^<]*?)\s*</title>"));

    let (product, version) = match server.captures(b).map(|c| text(&c[1])) {
        Some(s) => match s.split_once('/') {
            Some((p, v)) => (Some(p.to_string()), Some(v.split_whitespace().next().unwrap_or(v).trim_end_matches([',', ';']).to_string())),
            None => (Some(s), None),
        },
        None => (None, None),
    };
    let status = text(b.split(|&c| c == b'\n').next().unwrap_or_default());
    let info = match title.captures(b).map(|c| text(&c[1])).filter(|t| !t.is_empty()) {
        Some(t) => format!("{status} | title: {t}"),
        None => status,
    };
    Some(Found {
        service: if tls { "https" } else { "http" }.to_string(),
        product,
        version,
        info: Some(info),
    })
}

/// First line-ish of a banner, with control bytes escaped and length capped.
fn printable(b: &[u8]) -> String {
    let s: String = String::from_utf8_lossy(&b[..b.len().min(160)])
        .chars()
        .map(|c| if c.is_control() && c != ' ' { '.' } else { c })
        .collect();
    s.trim().to_string()
}

fn tls_connector() -> TlsConnector {
    static CELL: OnceLock<TlsConnector> = OnceLock::new();
    CELL.get_or_init(|| {
        let provider = Arc::new(ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
    .clone()
}

/// We only fingerprint the service, so any certificate is accepted.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banners() {
        let f = classify_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n").unwrap();
        assert_eq!((f.service.as_str(), f.product.as_deref(), f.version.as_deref()), ("ssh", Some("OpenSSH"), Some("9.6p1")));
        let f = classify_banner(b"SSH-2.0-dropbear_2022.83\r\n").unwrap();
        assert_eq!((f.product.as_deref(), f.version.as_deref()), (Some("dropbear"), Some("2022.83")));
        assert_eq!(classify_banner(b"220 mail.example.com ESMTP Postfix\r\n").unwrap().product.as_deref(), Some("Postfix"));
        let f = classify_banner(b"220 (vsFTPd 3.0.5)\r\n").unwrap();
        assert_eq!((f.service.as_str(), f.product.as_deref(), f.version.as_deref()), ("ftp", Some("vsFTPd"), Some("3.0.5")));
        assert_eq!(classify_banner(b"RFB 003.008\n").unwrap().service, "vnc");
        let f = classify_banner(b"J\x00\x00\x00\x0a10.11.6-MariaDB\x00abc").unwrap();
        assert_eq!((f.service.as_str(), f.product.as_deref()), ("mysql", Some("MariaDB")));
        assert!(classify_banner(b"hello").is_none());
    }

    #[test]
    fn http() {
        let r = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n\r\n<html><title> Router </title>";
        let f = classify_http(r, false).unwrap();
        assert_eq!((f.product.as_deref(), f.version.as_deref()), (Some("nginx"), Some("1.24.0")));
        assert_eq!(f.info.as_deref(), Some("HTTP/1.1 200 OK | title: Router"));
        let f = classify_http(b"HTTP/1.0 404 Not Found\r\nServer: Linux/4.4.115, UPnP/1.0\r\n\r\n", false).unwrap();
        assert_eq!(f.version.as_deref(), Some("4.4.115"));
    }
}

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::decode::{DecodedPacket, DnsRdata, Layer};

/// Where a name came from, used to resolve conflicts when several sources map
/// to the same IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameSource {
    Dns,
    TlsSni,
    QuicSni,
    HttpHost,
}

impl NameSource {
    fn priority(self) -> u8 {
        match self {
            NameSource::Dns | NameSource::TlsSni | NameSource::QuicSni => 2,
            NameSource::HttpHost => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameEntry {
    pub name: String,
    pub source: NameSource,
    pub last_seen: DateTime<Utc>,
}

/// Passive IP→name map learned from observed DNS answers and TLS SNI (no
/// decryption). Snapshot-persistable so a daemon can save/restore it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameResolver {
    by_ip: HashMap<IpAddr, NameEntry>,
}

impl NameResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Learn everything available from one decoded packet. Returns true if any
    /// mapping was added or changed.
    pub fn observe_packet(&mut self, pkt: &DecodedPacket) -> bool {
        self.observe_layers(&pkt.layers, pkt.timestamp)
    }

    pub fn observe_layers(&mut self, layers: &[Layer], ts: DateTime<Utc>) -> bool {
        let mut dst_ip: Option<IpAddr> = None;
        let mut changed = false;

        for layer in layers {
            match layer {
                Layer::Ipv4(ip) => dst_ip = Some(IpAddr::V4(ip.dst_ip)),
                Layer::Ipv6(ip) => dst_ip = Some(IpAddr::V6(ip.dst_ip)),
                Layer::Dns(dns) if dns.is_response => {
                    // Map every answered address to the originally queried name
                    // (which already collapses any CNAME chain to the user-facing host).
                    if let Some(q) = dns.questions.first() {
                        let qname = q.qname.clone();
                        for ans in &dns.answers {
                            let ip = match &ans.rdata {
                                DnsRdata::A(ip) => Some(IpAddr::V4(*ip)),
                                DnsRdata::Aaaa(ip) => Some(IpAddr::V6(*ip)),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                changed |= self.insert(ip, qname.clone(), NameSource::Dns, ts);
                            }
                        }
                    }
                }
                Layer::TlsClientHello(tls) => {
                    if let (Some(sni), Some(ip)) = (&tls.sni, dst_ip) {
                        changed |= self.insert(ip, sni.clone(), NameSource::TlsSni, ts);
                    }
                }
                _ => {}
            }
        }
        changed
    }

    fn insert(&mut self, ip: IpAddr, name: String, source: NameSource, ts: DateTime<Utc>) -> bool {
        if let Some(existing) = self.by_ip.get(&ip) {
            // Don't downgrade to a lower-priority source.
            if existing.source.priority() > source.priority() {
                return false;
            }
        }
        let changed = self.by_ip.get(&ip).map(|e| e.name != name).unwrap_or(true);
        self.by_ip.insert(
            ip,
            NameEntry {
                name,
                source,
                last_seen: ts,
            },
        );
        changed
    }

    pub fn name_for(&self, ip: IpAddr) -> Option<&str> {
        self.by_ip.get(&ip).map(|e| e.name.as_str())
    }

    pub fn entry(&self, ip: IpAddr) -> Option<&NameEntry> {
        self.by_ip.get(&ip)
    }

    /// Best-effort registrable domain ("api.github.com" → "github.com"). Uses a
    /// tiny multi-part-TLD allowlist; not a full Public Suffix List.
    pub fn registrable_domain(&self, ip: IpAddr) -> Option<String> {
        self.name_for(ip).map(registrable_domain_of)
    }

    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

const MULTI_PART_TLDS: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br",
    "co.in", "com.cn",
];

pub fn registrable_domain_of(name: &str) -> String {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return labels.join(".");
    }
    let last_two = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if n >= 3 && MULTI_PART_TLDS.contains(&last_two.as_str()) {
        format!("{}.{}", labels[n - 3], last_two)
    } else {
        last_two
    }
}

/// Thread-safe wrapper around [`NameResolver`] for use across the daemon's
/// capture/correlate threads.
#[derive(Clone, Default)]
pub struct SharedNameResolver {
    inner: Arc<Mutex<NameResolver>>,
}

impl SharedNameResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&self, pkt: &DecodedPacket) -> bool {
        self.inner.lock().unwrap().observe_packet(pkt)
    }

    pub fn resolve(&self, ip: IpAddr) -> Option<NameEntry> {
        self.inner.lock().unwrap().entry(ip).cloned()
    }

    pub fn registrable_domain(&self, ip: IpAddr) -> Option<String> {
        self.inner.lock().unwrap().registrable_domain(ip)
    }

    /// Take a serializable snapshot (for persistence).
    pub fn snapshot(&self) -> NameResolver {
        self.inner.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use std::net::Ipv4Addr;

    fn dns_response_packet(qname: &str, ip: Ipv4Addr) -> DecodedPacket {
        DecodedPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: 0,
            data: vec![],
            layers: vec![
                Layer::Ipv4(Ipv4Header {
                    version: 4,
                    ihl: 5,
                    dscp: 0,
                    ecn: 0,
                    total_length: 0,
                    identification: 0,
                    flags: 0,
                    fragment_offset: 0,
                    ttl: 64,
                    protocol: 17,
                    checksum: 0,
                    src_ip: Ipv4Addr::new(1, 1, 1, 1),
                    dst_ip: Ipv4Addr::new(10, 0, 0, 1),
                    header_range: (0, 0),
                }),
                Layer::Dns(DnsInfo {
                    transaction_id: 1,
                    is_response: true,
                    rcode: 0,
                    questions: vec![DnsQuestion {
                        qname: qname.into(),
                        qtype: 1,
                        qclass: 1,
                    }],
                    answers: vec![DnsRecord {
                        name: qname.into(),
                        rtype: 1,
                        rclass: 1,
                        ttl: 300,
                        rdata: DnsRdata::A(ip),
                    }],
                    authorities: vec![],
                    additionals: vec![],
                    header_range: (0, 0),
                }),
            ],
            summary: PacketSummary {
                source: String::new(),
                destination: String::new(),
                protocol: "DNS".into(),
                length: 0,
                info: String::new(),
                color_hint: ColorHint::Dns,
            },
            process: None,
            retransmission: false,
        }
    }

    #[test]
    fn test_dns_answer_maps_ip_to_name() {
        let mut r = NameResolver::new();
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        assert!(r.observe_packet(&dns_response_packet("example.com", ip)));
        assert_eq!(r.name_for(IpAddr::V4(ip)), Some("example.com"));
    }

    #[test]
    fn test_sni_maps_dst_ip_to_name() {
        let mut r = NameResolver::new();
        let dst = Ipv4Addr::new(140, 82, 121, 4);
        let mut pkt = dns_response_packet("placeholder", Ipv4Addr::new(9, 9, 9, 9));
        // Replace layers with IP(dst) + TLS ClientHello(sni).
        pkt.layers = vec![
            Layer::Ipv4(Ipv4Header {
                version: 4,
                ihl: 5,
                dscp: 0,
                ecn: 0,
                total_length: 0,
                identification: 0,
                flags: 0,
                fragment_offset: 0,
                ttl: 64,
                protocol: 6,
                checksum: 0,
                src_ip: Ipv4Addr::new(10, 0, 0, 1),
                dst_ip: dst,
                header_range: (0, 0),
            }),
            Layer::TlsClientHello(TlsClientHelloInfo {
                sni: Some("github.com".into()),
                alpn: vec![],
                cipher_suites: vec![],
                extensions: vec![],
                supported_groups: vec![],
                ec_point_formats: vec![],
                signature_algorithms: vec![],
                supported_versions: vec![],
                legacy_version: 0x0303,
                ja3: None,
                ja4: None,
                header_range: (0, 0),
            }),
        ];
        r.observe_packet(&pkt);
        assert_eq!(r.name_for(IpAddr::V4(dst)), Some("github.com"));
    }

    #[test]
    fn test_registrable_domain() {
        assert_eq!(registrable_domain_of("api.github.com"), "github.com");
        assert_eq!(registrable_domain_of("github.com"), "github.com");
        assert_eq!(registrable_domain_of("a.b.co.uk"), "b.co.uk");
        assert_eq!(registrable_domain_of("localhost"), "localhost");
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut r = NameResolver::new();
        r.observe_packet(&dns_response_packet(
            "example.com",
            Ipv4Addr::new(1, 2, 3, 4),
        ));
        let json = serde_json::to_string(&r).unwrap();
        let back: NameResolver = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.name_for(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            Some("example.com")
        );
    }
}

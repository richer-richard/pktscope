pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod ja;
pub mod tcp;
pub mod tls;
pub mod udp;

use crate::capture::{Linktype, RawPacket};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColorHint {
    Tcp,
    Udp,
    Arp,
    Icmp,
    Dns,
    Tls,
    Retransmission,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
    pub color_hint: ColorHint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedPacket {
    pub number: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub wire_len: u32,
    pub data: Vec<u8>,
    pub layers: Vec<Layer>,
    pub summary: PacketSummary,
    pub process: Option<ProcessInfo>,
    pub retransmission: bool,
}

// ---------------------------------------------------------------------------
// Layer types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Layer {
    Ethernet(EthernetHeader),
    Arp(ArpHeader),
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Icmpv6(Icmpv6Header),
    Dns(DnsInfo),
    TlsClientHello(TlsClientHelloInfo),
    TlsHandshake(TlsHandshakeInfo),
    Payload { offset: usize, len: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ethertype: u16,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpHeader {
    pub hw_type: u16,
    pub proto_type: u16,
    pub operation: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_bits(bits: u8) -> Self {
        Self {
            fin: bits & 0x01 != 0,
            syn: bits & 0x02 != 0,
            rst: bits & 0x04 != 0,
            psh: bits & 0x08 != 0,
            ack: bits & 0x10 != 0,
            urg: bits & 0x20 != 0,
            ece: bits & 0x40 != 0,
            cwr: bits & 0x80 != 0,
        }
    }

    pub fn display(&self) -> String {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.urg {
            flags.push("URG");
        }
        if self.ece {
            flags.push("ECE");
        }
        if self.cwr {
            flags.push("CWR");
        }
        format!("[{}]", flags.join(", "))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub payload_len: usize,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Unknown {
        rtype: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientHelloInfo {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub legacy_version: u16,
    /// JA3 fingerprint (MD5 hex of the canonical JA3 string).
    pub ja3: Option<String>,
    /// JA4 fingerprint.
    pub ja4: Option<String>,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshakeInfo {
    pub messages: Vec<TlsHandshakeMessage>,
    pub header_range: (usize, usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsHandshakeMessage {
    ServerHello {
        version: u16,
        cipher_suite: u16,
        alpn: Vec<String>,
    },
    Certificate {
        cert_count: usize,
    },
    Other {
        msg_type: u8,
    },
}

// ---------------------------------------------------------------------------
// Decoder chain types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct DecodeResult {
    pub layer: Layer,
    pub next: Option<NextDecode>,
    pub next_offset: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum NextDecode {
    Ethernet,
    Ipv4,
    Ipv6,
    Arp,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    ApplicationPayload { transport: TransportHint },
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TransportHint {
    pub src_port: u16,
    pub dst_port: u16,
    pub is_tcp: bool,
}

// ---------------------------------------------------------------------------
// Decoder chain driver
// ---------------------------------------------------------------------------

pub fn decode_packet(raw: &RawPacket) -> DecodedPacket {
    let layers = decode_layers(&raw.data, raw.linktype);
    let summary = compute_summary(&layers, raw.wire_len);
    DecodedPacket {
        number: raw.number,
        timestamp: raw.timestamp,
        wire_len: raw.wire_len,
        data: raw.data.clone(),
        layers,
        summary,
        process: None,
        retransmission: false,
    }
}

fn decode_layers(data: &[u8], linktype: Linktype) -> Vec<Layer> {
    let mut layers = Vec::with_capacity(4);

    let initial = match linktype {
        Linktype::Ethernet => Some(NextDecode::Ethernet),
        Linktype::RawIp => {
            if data.first().is_some_and(|b| b >> 4 == 4) {
                Some(NextDecode::Ipv4)
            } else if data.first().is_some_and(|b| b >> 4 == 6) {
                Some(NextDecode::Ipv6)
            } else {
                None
            }
        }
        Linktype::Other(_) => None,
    };

    let mut next_decode = initial;
    let mut offset = 0;

    while let Some(what) = next_decode {
        match what {
            NextDecode::ApplicationPayload { transport } => {
                let app_offset = offset;
                if app_offset < data.len() {
                    if transport.src_port == 53 || transport.dst_port == 53 {
                        if let Some(dns) = dns::try_decode_dns(data, app_offset) {
                            layers.push(Layer::Dns(dns));
                        }
                    } else if let Some(tls) = tls::try_decode_tls_client_hello(data, app_offset) {
                        layers.push(Layer::TlsClientHello(tls));
                    } else if let Some(hs) = tls::try_decode_tls_handshake(data, app_offset) {
                        layers.push(Layer::TlsHandshake(hs));
                    }
                    if app_offset < data.len() {
                        layers.push(Layer::Payload {
                            offset: app_offset,
                            len: data.len() - app_offset,
                        });
                    }
                }
                break;
            }
            _ => {
                let result = match what {
                    NextDecode::Ethernet => ethernet::decode_ethernet(data, offset),
                    NextDecode::Ipv4 => ipv4::decode_ipv4(data, offset),
                    NextDecode::Ipv6 => ipv6::decode_ipv6(data, offset),
                    NextDecode::Arp => arp::decode_arp(data, offset),
                    NextDecode::Tcp => tcp::decode_tcp(data, offset),
                    NextDecode::Udp => udp::decode_udp(data, offset),
                    NextDecode::Icmp => icmp::decode_icmp(data, offset),
                    NextDecode::Icmpv6 => icmpv6::decode_icmpv6(data, offset),
                    NextDecode::ApplicationPayload { .. } => unreachable!(),
                };
                match result {
                    Some(dr) => {
                        layers.push(dr.layer);
                        offset = dr.next_offset;
                        next_decode = dr.next;
                    }
                    None => break,
                }
            }
        }
    }

    layers
}

fn compute_summary(layers: &[Layer], wire_len: u32) -> PacketSummary {
    let mut source = String::new();
    let mut destination = String::new();
    let mut protocol = "???".to_string();
    let mut info = String::new();
    let mut color_hint = ColorHint::Other;

    for layer in layers {
        match layer {
            Layer::Ethernet(eth) => {
                if source.is_empty() {
                    source = eth.src_mac.to_string();
                    destination = eth.dst_mac.to_string();
                }
            }
            Layer::Arp(a) => {
                source = a.sender_ip.to_string();
                destination = a.target_ip.to_string();
                protocol = "ARP".into();
                color_hint = ColorHint::Arp;
                info = match a.operation {
                    1 => format!("Who has {}? Tell {}", a.target_ip, a.sender_ip),
                    2 => format!("{} is at {}", a.sender_ip, a.sender_mac),
                    _ => format!("op={}", a.operation),
                };
            }
            Layer::Ipv4(ip) => {
                source = ip.src_ip.to_string();
                destination = ip.dst_ip.to_string();
                protocol = "IPv4".into();
            }
            Layer::Ipv6(ip) => {
                source = ip.src_ip.to_string();
                destination = ip.dst_ip.to_string();
                protocol = "IPv6".into();
            }
            Layer::Tcp(t) => {
                protocol = "TCP".into();
                color_hint = ColorHint::Tcp;
                info = format!(
                    "{} → {} {} Seq={} Ack={} Len={}",
                    t.src_port,
                    t.dst_port,
                    t.flags.display(),
                    t.seq_num,
                    t.ack_num,
                    t.payload_len
                );
            }
            Layer::Udp(u) => {
                protocol = "UDP".into();
                color_hint = ColorHint::Udp;
                info = format!("{} → {} Len={}", u.src_port, u.dst_port, u.length);
            }
            Layer::Icmp(ic) => {
                protocol = "ICMP".into();
                color_hint = ColorHint::Icmp;
                info = icmp_info(ic.icmp_type, ic.code);
            }
            Layer::Icmpv6(ic) => {
                protocol = "ICMPv6".into();
                color_hint = ColorHint::Icmp;
                info = format!("Type={} Code={}", ic.icmp_type, ic.code);
            }
            Layer::Dns(dns) => {
                protocol = "DNS".into();
                color_hint = ColorHint::Dns;
                let qnames: Vec<&str> = dns.questions.iter().map(|q| q.qname.as_str()).collect();
                let names = qnames.join(", ");
                info = if dns.is_response {
                    let answers: Vec<String> = dns
                        .answers
                        .iter()
                        .filter_map(|r| match &r.rdata {
                            DnsRdata::A(ip) => Some(ip.to_string()),
                            DnsRdata::Aaaa(ip) => Some(ip.to_string()),
                            DnsRdata::Cname(c) => Some(format!("CNAME {c}")),
                            _ => None,
                        })
                        .collect();
                    if answers.is_empty() {
                        format!("DNS A {names}")
                    } else {
                        format!("DNS A {names} → {}", answers.join(", "))
                    }
                } else {
                    format!("DNS Q {names}")
                };
            }
            Layer::TlsClientHello(tls) => {
                protocol = "TLS".into();
                color_hint = ColorHint::Tls;
                info = match &tls.sni {
                    Some(sni) => format!("TLS → {}", sni),
                    None => "TLS Client Hello".into(),
                };
            }
            Layer::TlsHandshake(hs) => {
                protocol = "TLS".into();
                color_hint = ColorHint::Tls;
                info = match hs.messages.first() {
                    Some(TlsHandshakeMessage::ServerHello { alpn, .. }) if !alpn.is_empty() => {
                        format!("TLS Server Hello (alpn: {})", alpn.join(","))
                    }
                    Some(TlsHandshakeMessage::ServerHello { .. }) => "TLS Server Hello".into(),
                    Some(TlsHandshakeMessage::Certificate { cert_count }) => {
                        format!("TLS Certificate ({cert_count})")
                    }
                    Some(TlsHandshakeMessage::Other { msg_type }) => {
                        format!("TLS Handshake (type {msg_type})")
                    }
                    None => "TLS Handshake".into(),
                };
            }
            Layer::Payload { .. } => {}
        }
    }

    PacketSummary {
        source,
        destination,
        protocol,
        length: wire_len,
        info,
        color_hint,
    }
}

fn icmp_info(icmp_type: u8, code: u8) -> String {
    match (icmp_type, code) {
        (0, _) => "Echo Reply".into(),
        (3, 0) => "Destination Net Unreachable".into(),
        (3, 1) => "Destination Host Unreachable".into(),
        (3, 3) => "Destination Port Unreachable".into(),
        (3, _) => format!("Destination Unreachable (code={})", code),
        (8, _) => "Echo Request".into(),
        (11, _) => "Time Exceeded".into(),
        _ => format!("Type={} Code={}", icmp_type, code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Linktype;
    use chrono::Utc;

    fn make_raw(data: Vec<u8>, linktype: Linktype) -> RawPacket {
        RawPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: data.len() as u32,
            data,
            linktype,
        }
    }

    #[test]
    fn test_decode_ethernet_ipv4_tcp() {
        // Ethernet(IPv4(TCP)) minimal packet
        let mut pkt = Vec::new();
        // Ethernet: dst=ff:ff:ff:ff:ff:ff, src=00:11:22:33:44:55, type=0x0800
        pkt.extend_from_slice(&[0xff; 6]);
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        // IPv4: version=4, ihl=5, total_len=40, protocol=6(TCP), src=10.0.0.1, dst=10.0.0.2
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, // ver/ihl, dscp/ecn, total_len
            0x00, 0x01, 0x00, 0x00, // id, flags/frag
            0x40, 0x06, 0x00, 0x00, // ttl, proto=TCP, checksum
            10, 0, 0, 1, // src
            10, 0, 0, 2, // dst
        ]);
        // TCP: src=80, dst=12345, seq=1000, ack=0, data_offset=5, flags=SYN(0x02)
        pkt.extend_from_slice(&[
            0x00, 0x50, 0x30, 0x39, // src=80, dst=12345
            0x00, 0x00, 0x03, 0xe8, // seq=1000
            0x00, 0x00, 0x00, 0x00, // ack=0
            0x50, 0x02, 0xff, 0xff, // data_offset=5, flags=SYN, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ]);

        let decoded = decode_packet(&make_raw(pkt, Linktype::Ethernet));
        assert!(decoded.layers.len() >= 3);
        assert!(matches!(decoded.layers[0], Layer::Ethernet(_)));
        assert!(matches!(decoded.layers[1], Layer::Ipv4(_)));
        assert!(matches!(decoded.layers[2], Layer::Tcp(_)));
        assert_eq!(decoded.summary.protocol, "TCP");
        assert_eq!(decoded.summary.source, "10.0.0.1");
        assert_eq!(decoded.summary.destination, "10.0.0.2");
    }
}

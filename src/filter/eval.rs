use std::net::IpAddr;

use super::ast::*;
use crate::decode::{DecodedPacket, Layer};

pub fn eval_filter(expr: &FilterExpr, pkt: &DecodedPacket) -> bool {
    match expr {
        FilterExpr::ProtocolPresent(proto) => has_protocol(*proto, &pkt.layers),
        FilterExpr::Comparison { field, op, value } => {
            let field_str = field.as_str();
            // Special handling for tcp.port and udp.port (match either src or dst)
            if field_str == "tcp.port" {
                return match_port_either(&pkt.layers, *op, value, true);
            }
            if field_str == "udp.port" {
                return match_port_either(&pkt.layers, *op, value, false);
            }
            match extract_field(field, &pkt.layers) {
                Some(field_val) => compare_values(&field_val, *op, value),
                None => false,
            }
        }
        FilterExpr::Contains { field, pattern } => match extract_field(field, &pkt.layers) {
            Some(FilterValue::Str(s)) => s.contains(pattern.as_str()),
            _ => false,
        },
        FilterExpr::And(a, b) => eval_filter(a, pkt) && eval_filter(b, pkt),
        FilterExpr::Or(a, b) => eval_filter(a, pkt) || eval_filter(b, pkt),
        FilterExpr::Not(e) => !eval_filter(e, pkt),
    }
}

fn has_protocol(proto: ProtocolAtom, layers: &[Layer]) -> bool {
    layers.iter().any(|l| match (proto, l) {
        (ProtocolAtom::Ethernet, Layer::Ethernet(_)) => true,
        (ProtocolAtom::Arp, Layer::Arp(_)) => true,
        (ProtocolAtom::Ip, Layer::Ipv4(_)) | (ProtocolAtom::Ip, Layer::Ipv6(_)) => true,
        (ProtocolAtom::Ipv4, Layer::Ipv4(_)) => true,
        (ProtocolAtom::Ipv6, Layer::Ipv6(_)) => true,
        (ProtocolAtom::Tcp, Layer::Tcp(_)) => true,
        (ProtocolAtom::Udp, Layer::Udp(_)) => true,
        (ProtocolAtom::Icmp, Layer::Icmp(_)) => true,
        (ProtocolAtom::Icmpv6, Layer::Icmpv6(_)) => true,
        (ProtocolAtom::Dns, Layer::Dns(_)) => true,
        (ProtocolAtom::Tls, Layer::TlsClientHello(_)) => true,
        _ => false,
    })
}

fn extract_field(field: &FieldPath, layers: &[Layer]) -> Option<FilterValue> {
    let path = field.as_str();
    for layer in layers {
        match layer {
            Layer::Ipv4(ip) => match path.as_str() {
                "ip.src" => return Some(FilterValue::IpAddr(IpAddr::V4(ip.src_ip))),
                "ip.dst" => return Some(FilterValue::IpAddr(IpAddr::V4(ip.dst_ip))),
                _ => {}
            },
            Layer::Ipv6(ip) => match path.as_str() {
                "ip.src" => return Some(FilterValue::IpAddr(IpAddr::V6(ip.src_ip))),
                "ip.dst" => return Some(FilterValue::IpAddr(IpAddr::V6(ip.dst_ip))),
                _ => {}
            },
            Layer::Tcp(tcp) => match path.as_str() {
                "tcp.srcport" => return Some(FilterValue::Integer(tcp.src_port as i64)),
                "tcp.dstport" => return Some(FilterValue::Integer(tcp.dst_port as i64)),
                _ => {}
            },
            Layer::Udp(udp) => match path.as_str() {
                "udp.srcport" => return Some(FilterValue::Integer(udp.src_port as i64)),
                "udp.dstport" => return Some(FilterValue::Integer(udp.dst_port as i64)),
                _ => {}
            },
            Layer::Dns(dns) => match path.as_str() {
                "dns.qname" => {
                    return dns
                        .questions
                        .first()
                        .map(|q| FilterValue::Str(q.qname.clone()));
                }
                _ => {}
            },
            Layer::TlsClientHello(tls) => match path.as_str() {
                "tls.sni" => {
                    return tls.sni.as_ref().map(|s| FilterValue::Str(s.clone()));
                }
                _ => {}
            },
            Layer::Icmp(icmp) => match path.as_str() {
                "icmp.type" => return Some(FilterValue::Integer(icmp.icmp_type as i64)),
                "icmp.code" => return Some(FilterValue::Integer(icmp.code as i64)),
                _ => {}
            },
            Layer::Arp(arp) => match path.as_str() {
                "arp.sender.ip" => {
                    return Some(FilterValue::IpAddr(IpAddr::V4(arp.sender_ip)));
                }
                "arp.target.ip" => {
                    return Some(FilterValue::IpAddr(IpAddr::V4(arp.target_ip)));
                }
                _ => {}
            },
            _ => {}
        }
    }
    None
}

fn match_port_either(layers: &[Layer], op: CompareOp, value: &FilterValue, is_tcp: bool) -> bool {
    for layer in layers {
        match (is_tcp, layer) {
            (true, Layer::Tcp(tcp)) => {
                let src = FilterValue::Integer(tcp.src_port as i64);
                let dst = FilterValue::Integer(tcp.dst_port as i64);
                if compare_values(&src, op, value) || compare_values(&dst, op, value) {
                    return true;
                }
            }
            (false, Layer::Udp(udp)) => {
                let src = FilterValue::Integer(udp.src_port as i64);
                let dst = FilterValue::Integer(udp.dst_port as i64);
                if compare_values(&src, op, value) || compare_values(&dst, op, value) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn compare_values(left: &FilterValue, op: CompareOp, right: &FilterValue) -> bool {
    match op {
        CompareOp::Eq => left == right,
        CompareOp::Ne => left != right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use crate::filter::parser::parse_filter;
    use std::net::Ipv4Addr;

    fn make_tcp_packet() -> DecodedPacket {
        DecodedPacket {
            number: 1,
            timestamp: chrono::Utc::now(),
            wire_len: 100,
            data: vec![0u8; 100],
            layers: vec![
                Layer::Ethernet(EthernetHeader {
                    src_mac: MacAddr([0; 6]),
                    dst_mac: MacAddr([0; 6]),
                    ethertype: 0x0800,
                    header_range: (0, 14),
                }),
                Layer::Ipv4(Ipv4Header {
                    version: 4,
                    ihl: 5,
                    dscp: 0,
                    ecn: 0,
                    total_length: 60,
                    identification: 0,
                    flags: 0,
                    fragment_offset: 0,
                    ttl: 64,
                    protocol: 6,
                    checksum: 0,
                    src_ip: Ipv4Addr::new(10, 0, 0, 1),
                    dst_ip: Ipv4Addr::new(10, 0, 0, 2),
                    header_range: (14, 34),
                }),
                Layer::Tcp(TcpHeader {
                    src_port: 443,
                    dst_port: 50000,
                    seq_num: 0,
                    ack_num: 0,
                    data_offset: 5,
                    flags: TcpFlags::from_bits(0x02),
                    window_size: 65535,
                    checksum: 0,
                    urgent_pointer: 0,
                    payload_len: 0,
                    header_range: (34, 54),
                }),
            ],
            summary: PacketSummary {
                source: "10.0.0.1".into(),
                destination: "10.0.0.2".into(),
                protocol: "TCP".into(),
                length: 100,
                info: "443 → 50000 [SYN]".into(),
                color_hint: ColorHint::Tcp,
            },
            process: None,
            retransmission: false,
        }
    }

    fn make_dns_packet() -> DecodedPacket {
        DecodedPacket {
            number: 2,
            timestamp: chrono::Utc::now(),
            wire_len: 80,
            data: vec![0u8; 80],
            layers: vec![
                Layer::Udp(UdpHeader {
                    src_port: 12345,
                    dst_port: 53,
                    length: 40,
                    checksum: 0,
                    header_range: (34, 42),
                }),
                Layer::Dns(DnsInfo {
                    transaction_id: 0xABCD,
                    is_response: false,
                    questions: vec![DnsQuestion {
                        qname: "example.com".into(),
                        qtype: 1,
                        qclass: 1,
                    }],
                    header_range: (42, 70),
                }),
            ],
            summary: PacketSummary {
                source: "10.0.0.1".into(),
                destination: "10.0.0.2".into(),
                protocol: "DNS".into(),
                length: 80,
                info: "DNS Q example.com".into(),
                color_hint: ColorHint::Dns,
            },
            process: None,
            retransmission: false,
        }
    }

    #[test]
    fn test_protocol_present() {
        let pkt = make_tcp_packet();
        assert!(eval_filter(&parse_filter("tcp").unwrap(), &pkt));
        assert!(!eval_filter(&parse_filter("udp").unwrap(), &pkt));
        assert!(eval_filter(&parse_filter("ip").unwrap(), &pkt));
    }

    #[test]
    fn test_port_comparison() {
        let pkt = make_tcp_packet();
        assert!(eval_filter(&parse_filter("tcp.port == 443").unwrap(), &pkt));
        assert!(eval_filter(
            &parse_filter("tcp.port == 50000").unwrap(),
            &pkt
        ));
        assert!(!eval_filter(&parse_filter("tcp.port == 80").unwrap(), &pkt));
    }

    #[test]
    fn test_ip_comparison() {
        let pkt = make_tcp_packet();
        assert!(eval_filter(
            &parse_filter("ip.src == 10.0.0.1").unwrap(),
            &pkt
        ));
        assert!(!eval_filter(
            &parse_filter("ip.src == 10.0.0.3").unwrap(),
            &pkt
        ));
    }

    #[test]
    fn test_dns_qname_contains() {
        let pkt = make_dns_packet();
        assert!(eval_filter(
            &parse_filter("dns.qname contains example").unwrap(),
            &pkt
        ));
        assert!(!eval_filter(
            &parse_filter("dns.qname contains google").unwrap(),
            &pkt
        ));
    }

    #[test]
    fn test_boolean_operators() {
        let pkt = make_tcp_packet();
        assert!(eval_filter(
            &parse_filter("tcp and ip.src == 10.0.0.1").unwrap(),
            &pkt
        ));
        assert!(!eval_filter(&parse_filter("udp or arp").unwrap(), &pkt));
        assert!(eval_filter(&parse_filter("not udp").unwrap(), &pkt));
    }

    #[test]
    fn test_tls_sni_contains() {
        let mut pkt = make_tcp_packet();
        pkt.layers.push(Layer::TlsClientHello(TlsClientHelloInfo {
            sni: Some("github.com".into()),
            header_range: (54, 100),
        }));
        assert!(eval_filter(
            &parse_filter("tls.sni contains github").unwrap(),
            &pkt
        ));
        assert!(!eval_filter(
            &parse_filter("tls.sni contains google").unwrap(),
            &pkt
        ));
    }
}

//! Conservative, on-demand anomaly heuristics over a decoded packet. Computed
//! lazily (not stored on the packet) and only flags plaintext/cleartext cases —
//! never encrypted traffic, to keep the false-positive rate low.

use crate::decode::{DecodedPacket, Layer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    PlaintextCredential,
    UnusualPort,
    KnownBadIp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalySeverity {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyAnnotation {
    pub kind: AnomalyKind,
    pub detail: String,
    pub severity: AnomalySeverity,
}

const COMMON_HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8888, 3000];

/// Inspect a packet for cheap, high-signal anomalies. Returns `None` for
/// encrypted or unremarkable traffic.
pub fn analyze(pkt: &DecodedPacket) -> Option<AnomalyAnnotation> {
    // Never flag encrypted traffic.
    if pkt.layers.iter().any(|l| {
        matches!(
            l,
            Layer::TlsClientHello(_) | Layer::TlsHandshake(_) | Layer::Quic(_)
        )
    }) {
        return None;
    }

    let ports = tcp_udp_ports(&pkt.layers);

    // HTTP Basic credentials in cleartext.
    if let Some(http) = pkt.layers.iter().find_map(|l| match l {
        Layer::Http(h) => Some(h),
        _ => None,
    }) {
        for (k, v) in &http.headers {
            if k.eq_ignore_ascii_case("authorization")
                && v.to_ascii_lowercase().starts_with("basic")
            {
                return Some(AnomalyAnnotation {
                    kind: AnomalyKind::PlaintextCredential,
                    detail: "HTTP Basic credentials sent in cleartext".into(),
                    severity: AnomalySeverity::Warning,
                });
            }
        }
        // Cleartext HTTP on an unusual port.
        if let Some((sp, dp)) = ports {
            if !COMMON_HTTP_PORTS.contains(&sp) && !COMMON_HTTP_PORTS.contains(&dp) {
                return Some(AnomalyAnnotation {
                    kind: AnomalyKind::UnusualPort,
                    detail: format!("cleartext HTTP on unusual port {dp}"),
                    severity: AnomalySeverity::Info,
                });
            }
        }
    }

    // FTP password sent in cleartext (port 21).
    if let Some((sp, dp)) = ports {
        if sp == 21 || dp == 21 {
            if let Some(payload) = app_payload(pkt) {
                if payload.windows(5).any(|w| w.eq_ignore_ascii_case(b"PASS ")) {
                    return Some(AnomalyAnnotation {
                        kind: AnomalyKind::PlaintextCredential,
                        detail: "FTP password sent in cleartext".into(),
                        severity: AnomalySeverity::Warning,
                    });
                }
            }
        }
    }

    None
}

fn tcp_udp_ports(layers: &[Layer]) -> Option<(u16, u16)> {
    for l in layers {
        match l {
            Layer::Tcp(t) => return Some((t.src_port, t.dst_port)),
            Layer::Udp(u) => return Some((u.src_port, u.dst_port)),
            _ => {}
        }
    }
    None
}

fn app_payload(pkt: &DecodedPacket) -> Option<&[u8]> {
    for l in &pkt.layers {
        if let Layer::Payload { offset, len } = l {
            let end = (offset + len).min(pkt.data.len());
            return pkt.data.get(*offset..end);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use chrono::Utc;

    fn pkt(layers: Vec<Layer>, data: Vec<u8>) -> DecodedPacket {
        DecodedPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: data.len() as u32,
            data,
            layers,
            summary: PacketSummary {
                source: String::new(),
                destination: String::new(),
                protocol: String::new(),
                length: 0,
                info: String::new(),
                color_hint: ColorHint::Other,
            },
            process: None,
            retransmission: false,
        }
    }

    fn tcp(sp: u16, dp: u16) -> Layer {
        Layer::Tcp(TcpHeader {
            src_port: sp,
            dst_port: dp,
            seq_num: 0,
            ack_num: 0,
            data_offset: 5,
            flags: TcpFlags::from_bits(0),
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            payload_len: 0,
            header_range: (0, 0),
        })
    }

    fn http(headers: Vec<(&str, &str)>) -> Layer {
        Layer::Http(HttpInfo {
            is_request: true,
            method: Some("GET".into()),
            uri: Some("/".into()),
            version: Some("HTTP/1.1".into()),
            status_code: None,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            host: None,
            content_length: None,
            chunked: false,
            header_range: (0, 0),
        })
    }

    #[test]
    fn test_http_basic_creds() {
        let p = pkt(
            vec![
                tcp(40000, 80),
                http(vec![("Authorization", "Basic dXNlcjpwYXNz")]),
            ],
            vec![],
        );
        let a = analyze(&p).unwrap();
        assert_eq!(a.kind, AnomalyKind::PlaintextCredential);
    }

    #[test]
    fn test_encrypted_not_flagged() {
        let tls = Layer::TlsClientHello(TlsClientHelloInfo {
            sni: Some("x.com".into()),
            alpn: vec![],
            cipher_suites: vec![],
            extensions: vec![],
            supported_groups: vec![],
            ec_point_formats: vec![],
            signature_algorithms: vec![],
            supported_versions: vec![],
            legacy_version: 0,
            ja3: None,
            ja4: None,
            header_range: (0, 0),
        });
        let p = pkt(vec![tcp(40000, 443), tls], vec![]);
        assert!(analyze(&p).is_none());
    }

    #[test]
    fn test_unusual_http_port() {
        let p = pkt(vec![tcp(40000, 1337), http(vec![])], vec![]);
        let a = analyze(&p).unwrap();
        assert_eq!(a.kind, AnomalyKind::UnusualPort);
    }

    #[test]
    fn test_clean_packet() {
        let p = pkt(vec![tcp(40000, 80), http(vec![("Host", "x.com")])], vec![]);
        assert!(analyze(&p).is_none());
    }
}

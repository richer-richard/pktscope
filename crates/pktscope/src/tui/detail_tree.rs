use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use pktscope_core::decode::{DnsRdata, Layer, TlsHandshakeMessage};

use super::App;

pub fn render_detail_tree(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let lines = match app.selected_packet() {
        Some(pkt) => {
            let mut all_lines = Vec::new();
            for layer in &pkt.layers {
                let detail = detail_lines(layer);
                all_lines.extend(detail);
            }
            if pkt.retransmission {
                all_lines.insert(
                    0,
                    Line::from(Span::styled(
                        "⚠ TCP Retransmission",
                        Style::default().fg(Color::Red).bold(),
                    )),
                );
            }
            all_lines
        }
        None => vec![Line::from(Span::styled(
            "No packet selected",
            Style::default().fg(Color::DarkGray),
        ))],
    };

    let visible_height = area.height.saturating_sub(2) as usize;
    let scroll = app
        .detail_scroll
        .min(lines.len().saturating_sub(visible_height));
    let visible_lines: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(visible_height)
        .collect();

    let paragraph = Paragraph::new(visible_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Packet Details "),
    );
    frame.render_widget(paragraph, area);
}

fn detail_lines(layer: &Layer) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let header_style = Style::default().fg(Color::White).bold();
    let field_style = Style::default().fg(Color::Gray);

    match layer {
        Layer::Ethernet(eth) => {
            lines.push(Line::from(Span::styled(
                format!("▸ Ethernet II, Src: {}, Dst: {}", eth.src_mac, eth.dst_mac),
                header_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Source: {}", eth.src_mac),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Destination: {}", eth.dst_mac),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Type: 0x{:04x}", eth.ethertype),
                field_style,
            )));
        }
        Layer::Arp(arp) => {
            let op_str = match arp.operation {
                1 => "Request",
                2 => "Reply",
                _ => "Unknown",
            };
            lines.push(Line::from(Span::styled(
                format!("▸ ARP ({})", op_str),
                header_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Sender MAC: {}", arp.sender_mac),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Sender IP: {}", arp.sender_ip),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Target MAC: {}", arp.target_mac),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Target IP: {}", arp.target_ip),
                field_style,
            )));
        }
        Layer::Ipv4(ip) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "▸ Internet Protocol Version 4, Src: {}, Dst: {}",
                    ip.src_ip, ip.dst_ip
                ),
                header_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Version: {}", ip.version),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Header Length: {} bytes ({})", ip.ihl * 4, ip.ihl),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Total Length: {}", ip.total_length),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    TTL: {}", ip.ttl),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!(
                    "    Protocol: {} ({})",
                    protocol_name(ip.protocol),
                    ip.protocol
                ),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Source: {}", ip.src_ip),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Destination: {}", ip.dst_ip),
                field_style,
            )));
        }
        Layer::Ipv6(ip) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "▸ Internet Protocol Version 6, Src: {}, Dst: {}",
                    ip.src_ip, ip.dst_ip
                ),
                header_style,
            )));
            lines.push(Line::from(Span::styled(
                format!(
                    "    Next Header: {} ({})",
                    protocol_name(ip.next_header),
                    ip.next_header
                ),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Hop Limit: {}", ip.hop_limit),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Payload Length: {}", ip.payload_length),
                field_style,
            )));
        }
        Layer::Tcp(tcp) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "▸ TCP, Src Port: {}, Dst Port: {}",
                    tcp.src_port, tcp.dst_port
                ),
                header_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Source Port: {}", tcp.src_port),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Destination Port: {}", tcp.dst_port),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Sequence Number: {}", tcp.seq_num),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Acknowledgment Number: {}", tcp.ack_num),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Flags: {}", tcp.flags.display()),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Window Size: {}", tcp.window_size),
                field_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Payload Length: {}", tcp.payload_len),
                field_style,
            )));
        }
        Layer::Udp(udp) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "▸ UDP, Src Port: {}, Dst Port: {}",
                    udp.src_port, udp.dst_port
                ),
                header_style,
            )));
            lines.push(Line::from(Span::styled(
                format!("    Length: {}", udp.length),
                field_style,
            )));
        }
        Layer::Icmp(icmp) => {
            lines.push(Line::from(Span::styled(
                format!("▸ ICMP, Type: {}, Code: {}", icmp.icmp_type, icmp.code),
                header_style,
            )));
        }
        Layer::Icmpv6(icmp) => {
            lines.push(Line::from(Span::styled(
                format!("▸ ICMPv6, Type: {}, Code: {}", icmp.icmp_type, icmp.code),
                header_style,
            )));
        }
        Layer::Dns(dns) => {
            let dir = if dns.is_response { "Response" } else { "Query" };
            lines.push(Line::from(Span::styled(
                format!("▸ DNS {} (0x{:04x})", dir, dns.transaction_id),
                header_style,
            )));
            for q in &dns.questions {
                lines.push(Line::from(Span::styled(
                    format!(
                        "    Question: {} (type={})",
                        q.qname,
                        dns_type_name(q.qtype)
                    ),
                    field_style,
                )));
            }
            for ans in &dns.answers {
                let rd = match &ans.rdata {
                    DnsRdata::A(ip) => format!("A {ip}"),
                    DnsRdata::Aaaa(ip) => format!("AAAA {ip}"),
                    DnsRdata::Cname(c) => format!("CNAME {c}"),
                    DnsRdata::Ns(n) => format!("NS {n}"),
                    DnsRdata::Ptr(p) => format!("PTR {p}"),
                    DnsRdata::Mx {
                        preference,
                        exchange,
                    } => format!("MX {preference} {exchange}"),
                    DnsRdata::Txt(t) => format!("TXT {}", t.join(" ")),
                    DnsRdata::Srv { target, port, .. } => format!("SRV {target}:{port}"),
                    DnsRdata::Soa { mname, .. } => format!("SOA {mname}"),
                    DnsRdata::Unknown { rtype, .. } => format!("type{rtype}"),
                };
                lines.push(Line::from(Span::styled(
                    format!("    Answer: {} → {}", ans.name, rd),
                    field_style,
                )));
            }
        }
        Layer::TlsClientHello(tls) => {
            lines.push(Line::from(Span::styled(
                "▸ TLS Client Hello".to_string(),
                header_style,
            )));
            if let Some(ref sni) = tls.sni {
                lines.push(Line::from(Span::styled(
                    format!("    Server Name: {}", sni),
                    field_style,
                )));
            }
            if !tls.alpn.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("    ALPN: {}", tls.alpn.join(", ")),
                    field_style,
                )));
            }
            if let Some(ref ja3) = tls.ja3 {
                lines.push(Line::from(Span::styled(
                    format!("    JA3: {ja3}"),
                    field_style,
                )));
            }
            if let Some(ref ja4) = tls.ja4 {
                lines.push(Line::from(Span::styled(
                    format!("    JA4: {ja4}"),
                    field_style,
                )));
            }
        }
        Layer::TlsHandshake(hs) => {
            lines.push(Line::from(Span::styled(
                "▸ TLS Handshake".to_string(),
                header_style,
            )));
            for m in &hs.messages {
                let s = match m {
                    TlsHandshakeMessage::ServerHello {
                        version,
                        cipher_suite,
                        alpn,
                    } => format!(
                        "    Server Hello (version=0x{version:04x}, cipher=0x{cipher_suite:04x}, alpn={})",
                        alpn.join(",")
                    ),
                    TlsHandshakeMessage::Certificate { cert_count } => {
                        format!("    Certificate ({cert_count} certs)")
                    }
                    TlsHandshakeMessage::Other { msg_type } => {
                        format!("    Handshake type {msg_type}")
                    }
                };
                lines.push(Line::from(Span::styled(s, field_style)));
            }
        }
        Layer::Payload { offset, len } => {
            lines.push(Line::from(Span::styled(
                format!("▸ Data ({} bytes at offset {})", len, offset),
                field_style,
            )));
        }
    }

    lines
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "Unknown",
    }
}

fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        255 => "ANY",
        _ => "?",
    }
}

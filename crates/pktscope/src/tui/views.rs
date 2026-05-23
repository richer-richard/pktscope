//! Phase-4 statistics overlays and the follow-stream view, all computed on
//! demand from the in-memory packet ring (no extra live state).

use std::collections::BTreeMap;
use std::net::IpAddr;

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Sparkline, Table};

use pktscope_core::decode::{DecodedPacket, Layer};
use pktscope_core::flow::ReassemblyBuffer;
use pktscope_core::flow::StreamData;

use super::{App, OverlayKind};

pub fn render_overlay(f: &mut Frame, area: Rect, app: &App, kind: OverlayKind) {
    match kind {
        OverlayKind::TopTalkers => render_top_talkers(f, area, app),
        OverlayKind::ProtocolDist => render_protocol_dist(f, area, app),
        OverlayKind::Flows => render_flows(f, area, app),
        OverlayKind::Timeline => render_timeline(f, area, app),
        OverlayKind::Stream => render_stream(f, area, app),
        OverlayKind::Bookmarks => render_bookmarks(f, area, app),
    }
}

pub fn render_bookmarks(f: &mut Frame, area: Rect, app: &App) {
    let rows: Vec<Row> = app
        .packets
        .iter()
        .filter(|p| app.bookmarks.contains(&p.number))
        .skip(app.overlay_scroll)
        .map(|p| {
            Row::new(vec![
                p.number.to_string(),
                p.timestamp.format("%H:%M:%S%.3f").to_string(),
                format!("{} → {}", p.summary.source, p.summary.destination),
                p.summary.info.chars().take(50).collect::<String>(),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Min(24),
            Constraint::Min(20),
        ],
    )
    .header(header(&["#", "Time", "Endpoints", "Info"]))
    .block(block(&format!(
        "Bookmarks ({}) — m to toggle, Esc to close",
        app.bookmarks.len()
    )));
    f.render_widget(table, area);
}

pub fn fmt_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.1}G", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.1}M", f / (K * K))
    } else if f >= K {
        format!("{:.1}K", f / K)
    } else {
        format!("{b}B")
    }
}

pub fn render_throughput(f: &mut Frame, area: Rect, app: &App) {
    let data: Vec<u64> = app.throughput_pps.iter().copied().collect();
    let cur = data.last().copied().unwrap_or(0);
    let bps = app.throughput_bps.back().copied().unwrap_or(0);
    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(format!(
            "Throughput — {cur} pkt/s, {}/s (last {}s)",
            fmt_bytes(bps),
            data.len()
        )))
        .data(&data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(spark, area);
}

fn five_tuple(pkt: &DecodedPacket) -> Option<(IpAddr, u16, IpAddr, u16, u8, &'static str)> {
    let mut src = None;
    let mut dst = None;
    let mut proto = 0u8;
    for l in &pkt.layers {
        match l {
            Layer::Ipv4(ip) => {
                src = Some(IpAddr::V4(ip.src_ip));
                dst = Some(IpAddr::V4(ip.dst_ip));
                proto = ip.protocol;
            }
            Layer::Ipv6(ip) => {
                src = Some(IpAddr::V6(ip.src_ip));
                dst = Some(IpAddr::V6(ip.dst_ip));
                proto = ip.next_header;
            }
            Layer::Tcp(t) => return Some((src?, t.src_port, dst?, t.dst_port, proto, "TCP")),
            Layer::Udp(u) => return Some((src?, u.src_port, dst?, u.dst_port, proto, "UDP")),
            _ => {}
        }
    }
    None
}

struct FlowRow {
    label: String,
    proto: &'static str,
    packets: u64,
    bytes: u64,
    first_ms: i64,
    last_ms: i64,
}

fn aggregate_flows(app: &App) -> Vec<FlowRow> {
    let mut map: BTreeMap<String, FlowRow> = BTreeMap::new();
    for pkt in app.packets.iter() {
        let Some((sa, sp, da, dp, _proto, label)) = five_tuple(pkt) else {
            continue;
        };
        // Normalize endpoints so both directions share a key.
        let (a, b) = if (sa, sp) <= (da, dp) {
            (format!("{sa}:{sp}"), format!("{da}:{dp}"))
        } else {
            (format!("{da}:{dp}"), format!("{sa}:{sp}"))
        };
        let key = format!("{a} <-> {b} {label}");
        let ts = pkt.timestamp.timestamp_millis();
        let e = map.entry(key.clone()).or_insert(FlowRow {
            label: format!("{a} <-> {b}"),
            proto: label,
            packets: 0,
            bytes: 0,
            first_ms: ts,
            last_ms: ts,
        });
        e.packets += 1;
        e.bytes += pkt.wire_len as u64;
        e.first_ms = e.first_ms.min(ts);
        e.last_ms = e.last_ms.max(ts);
    }
    let mut v: Vec<FlowRow> = map.into_values().collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.bytes));
    v
}

fn block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(title.to_string())
}

fn header(cols: &[&str]) -> Row<'static> {
    Row::new(cols.iter().map(|c| c.to_string()).collect::<Vec<_>>())
        .style(Style::default().fg(Color::Yellow))
}

pub fn render_top_talkers(f: &mut Frame, area: Rect, app: &App) {
    let mut map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for pkt in app.packets.iter() {
        for ep in [&pkt.summary.source, &pkt.summary.destination] {
            if ep.is_empty() {
                continue;
            }
            let e = map.entry(ep.clone()).or_insert((0, 0));
            e.0 += 1;
            e.1 += pkt.wire_len as u64;
        }
    }
    let mut rows: Vec<(String, u64, u64)> = map.into_iter().map(|(k, (p, b))| (k, p, b)).collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.2));
    let table = Table::new(
        rows.iter()
            .skip(app.overlay_scroll)
            .map(|(ep, p, b)| Row::new(vec![ep.clone(), p.to_string(), fmt_bytes(*b)])),
        [
            Constraint::Min(20),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(header(&["Endpoint", "Packets", "Bytes"]))
    .block(block("Top talkers (Esc to close, j/k scroll)"));
    f.render_widget(table, area);
}

pub fn render_protocol_dist(f: &mut Frame, area: Rect, app: &App) {
    let total: u64 = app.proto_counts.values().sum();
    let mut rows: Vec<(String, u64)> = app.proto_counts.clone().into_iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    let table = Table::new(
        rows.iter().skip(app.overlay_scroll).map(|(proto, count)| {
            let pct = if total > 0 {
                *count as f64 * 100.0 / total as f64
            } else {
                0.0
            };
            let bars = "█".repeat((pct / 2.0) as usize);
            Row::new(vec![
                proto.clone(),
                count.to_string(),
                format!("{pct:.1}%"),
                bars,
            ])
        }),
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header(&["Protocol", "Count", "Pct", ""]))
    .block(block(&format!("Protocol distribution ({total} packets)")));
    f.render_widget(table, area);
}

pub fn render_flows(f: &mut Frame, area: Rect, app: &App) {
    let flows = aggregate_flows(app);
    let table = Table::new(
        flows.iter().skip(app.overlay_scroll).map(|r| {
            let dur = (r.last_ms - r.first_ms) as f64 / 1000.0;
            Row::new(vec![
                r.label.clone(),
                r.proto.to_string(),
                r.packets.to_string(),
                fmt_bytes(r.bytes),
                format!("{dur:.1}s"),
            ])
        }),
        [
            Constraint::Min(28),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(header(&["Flow", "Proto", "Packets", "Bytes", "Duration"]))
    .block(block(&format!("Flows ({}) — Esc to close", flows.len())));
    f.render_widget(table, area);
}

pub fn render_timeline(f: &mut Frame, area: Rect, app: &App) {
    let mut flows = aggregate_flows(app);
    flows.sort_by_key(|r| r.first_ms);
    let min = flows.iter().map(|r| r.first_ms).min().unwrap_or(0);
    let max = flows.iter().map(|r| r.last_ms).max().unwrap_or(1);
    let span = (max - min).max(1) as f64;
    const WIDTH: usize = 40;
    let lines: Vec<Line> = flows
        .iter()
        .skip(app.overlay_scroll)
        .map(|r| {
            let start = (((r.first_ms - min) as f64 / span) * WIDTH as f64) as usize;
            let end = (((r.last_ms - min) as f64 / span) * WIDTH as f64).ceil() as usize;
            let len = end.saturating_sub(start).max(1);
            let bar = format!(
                "{}{}",
                " ".repeat(start.min(WIDTH)),
                "▇".repeat(len.min(WIDTH))
            );
            Line::from(format!("{bar:<width$} {}", r.label, width = WIDTH + 1))
        })
        .collect();
    let p = Paragraph::new(lines).block(block("Connection timeline (Esc to close)"));
    f.render_widget(p, area);
}

pub fn render_stream(f: &mut Frame, area: Rect, app: &App) {
    let Some((title, data)) = &app.stream else {
        f.render_widget(block("No stream"), area);
        return;
    };
    let mut lines: Vec<Line> = Vec::new();
    for chunk in printable(&data.client_to_server).split('\n') {
        lines.push(Line::from(Span::styled(
            format!("» {chunk}"),
            Style::default().fg(Color::Cyan),
        )));
    }
    for chunk in printable(&data.server_to_client).split('\n') {
        lines.push(Line::from(Span::styled(
            format!("« {chunk}"),
            Style::default().fg(Color::Green),
        )));
    }
    let visible: Vec<Line> = lines.into_iter().skip(app.overlay_scroll).collect();
    let p =
        Paragraph::new(visible).block(block(&format!("{title} (» client, « server, Esc close)")));
    f.render_widget(p, area);
}

fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b) {
                b as char
            } else if b == b'\r' {
                ' '
            } else {
                '.'
            }
        })
        .collect()
}

/// Reassemble the selected packet's TCP flow from the ring (both directions).
pub fn build_stream(app: &App) -> Option<(String, StreamData)> {
    let selected = app.selected_packet()?;
    let (sa, sp, da, dp, proto, _) = five_tuple(selected)?;
    if proto != 6 {
        return None;
    }
    // Client = the lower (ip, port) endpoint.
    let (client, server) = if (sa, sp) <= (da, dp) {
        ((sa, sp), (da, dp))
    } else {
        ((da, dp), (sa, sp))
    };

    let mut c2s = ReassemblyBuffer::new();
    let mut s2c = ReassemblyBuffer::new();
    for pkt in app.packets.iter() {
        let Some((psa, psp, pda, pdp, pproto, _)) = five_tuple(pkt) else {
            continue;
        };
        if pproto != 6 {
            continue;
        }
        let same = ((psa, psp), (pda, pdp)) == (client, server)
            || ((pda, pdp), (psa, psp)) == (client, server);
        if !same {
            continue;
        }
        let (seq, payload) = match tcp_payload(pkt) {
            Some(v) => v,
            None => continue,
        };
        if payload.is_empty() {
            continue;
        }
        if (psa, psp) == client {
            c2s.insert_segment(seq, payload);
        } else {
            s2c.insert_segment(seq, payload);
        }
    }
    let data = StreamData {
        client_to_server: c2s.try_drain().unwrap_or_default(),
        server_to_client: s2c.try_drain().unwrap_or_default(),
    };
    let title = format!(
        "Follow TCP: {}:{} <-> {}:{}",
        client.0, client.1, server.0, server.1
    );
    Some((title, data))
}

fn tcp_payload(pkt: &DecodedPacket) -> Option<(u32, &[u8])> {
    let mut seq = None;
    for l in &pkt.layers {
        match l {
            Layer::Tcp(t) => seq = Some(t.seq_num),
            Layer::Payload { offset, len } => {
                let s = seq?;
                let end = (offset + len).min(pkt.data.len());
                return Some((s, pkt.data.get(*offset..end)?));
            }
            _ => {}
        }
    }
    None
}

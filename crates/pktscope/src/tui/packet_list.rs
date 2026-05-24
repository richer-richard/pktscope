use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Row, Table};

use pktscope_core::analysis::analyze;
use pktscope_core::decode::ColorHint;

use super::App;

pub fn render_packet_list(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let header = Row::new(vec![
        "#",
        "Time",
        "Source",
        "Destination",
        "Proto",
        "Len",
        "Info",
    ])
    .style(Style::default().fg(Color::White).bold())
    .bottom_margin(0);

    let visible_count = app.visible_count();
    let table_height = area.height.saturating_sub(3) as usize; // borders + header

    // Virtual scrolling: compute visible range
    let scroll_offset = if app.selected >= table_height {
        app.selected - table_height + 1
    } else {
        0
    };

    let visible_range_start = scroll_offset;
    let visible_range_end = (scroll_offset + table_height).min(visible_count);

    let rows: Vec<Row> = (visible_range_start..visible_range_end)
        .filter_map(|i| {
            let pkt = app.visible_packet(i)?;
            let elapsed = pkt.timestamp.format("%H:%M:%S%.3f").to_string();
            let anomaly = analyze(pkt);
            let matches_search = app.search_re.as_ref().is_some_and(|re| {
                re.is_match(&pkt.summary.info)
                    || re.is_match(&pkt.summary.source)
                    || re.is_match(&pkt.summary.destination)
            });

            let style = if i == app.selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if matches_search {
                Style::default().bg(Color::Yellow).fg(Color::Black)
            } else if anomaly.is_some() {
                Style::default().fg(Color::LightRed).bold()
            } else if pkt.retransmission {
                Style::default().fg(Color::Red)
            } else {
                match pkt.summary.color_hint {
                    ColorHint::Tcp => Style::default().fg(Color::Cyan),
                    ColorHint::Udp => Style::default().fg(Color::Green),
                    ColorHint::Arp => Style::default().fg(Color::Yellow),
                    ColorHint::Icmp => Style::default().fg(Color::Magenta),
                    ColorHint::Dns => Style::default().fg(Color::Yellow),
                    ColorHint::Tls => Style::default().fg(Color::Blue),
                    ColorHint::Retransmission => Style::default().fg(Color::Red),
                    ColorHint::Other => Style::default(),
                }
            };

            let bookmark = if app.bookmarks.contains(&pkt.number) {
                "★"
            } else {
                " "
            };
            let info_full = match &anomaly {
                Some(a) => format!("⚠ {} [{}]", pkt.summary.info, a.detail),
                None => pkt.summary.info.clone(),
            };
            // Char-safe truncation (info may contain multi-byte glyphs).
            let info: String = info_full.chars().take(70).collect();

            Some(
                Row::new(vec![
                    format!("{bookmark}{}", pkt.number),
                    elapsed,
                    pkt.summary.source.clone(),
                    pkt.summary.destination.clone(),
                    pkt.summary.protocol.clone(),
                    pkt.summary.length.to_string(),
                    info,
                ])
                .style(style),
            )
        })
        .collect();

    let widths = [
        Constraint::Length(7),
        Constraint::Length(14),
        Constraint::Length(16),
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Packets ({}) ", visible_count)),
    );

    frame.render_widget(table, area);
}

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Row, Table};

use crate::decode::ColorHint;

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

            let style = if i == app.selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
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

            // Truncate info to fit
            let info = if pkt.summary.info.len() > 60 {
                format!("{}…", &pkt.summary.info[..59])
            } else {
                pkt.summary.info.clone()
            };

            Some(
                Row::new(vec![
                    pkt.number.to_string(),
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

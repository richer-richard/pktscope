use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use super::{App, InputMode};

pub fn render_filter_bar(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let (text, style, border_style) = match app.mode {
        InputMode::FilterInput => {
            let mut display = app.filter_input.clone();
            // Show cursor position
            if app.filter_cursor <= display.len() {
                display.insert(app.filter_cursor, '│');
            }
            (
                format!("Filter: {}", display),
                Style::default().fg(Color::Yellow),
                Style::default().fg(Color::Yellow),
            )
        }
        InputMode::Search => (
            "Filter: (Ctrl-F search active — see status bar)".to_string(),
            Style::default().fg(Color::DarkGray),
            Style::default().fg(Color::DarkGray),
        ),
        InputMode::Normal => {
            if let Some(ref filter) = app.active_filter {
                let _ = filter; // used to check presence
                (
                    format!("Filter: {} [Applied]", app.filter_input),
                    Style::default().fg(Color::Green),
                    Style::default().fg(Color::Green),
                )
            } else {
                (
                    "Filter: (press '/' to filter)".to_string(),
                    Style::default().fg(Color::DarkGray),
                    Style::default().fg(Color::DarkGray),
                )
            }
        }
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Filter ");

    let paragraph = Paragraph::new(text).style(style).block(block);
    frame.render_widget(paragraph, area);
}

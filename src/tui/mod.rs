pub mod detail_tree;
pub mod filter_bar;
pub mod hex_view;
pub mod packet_list;

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, cursor};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Paragraph};
use ratatui::Terminal;

use crate::decode::DecodedPacket;
use crate::filter::ast::FilterExpr;
use crate::filter::eval::eval_filter;
use crate::filter::parser::parse_filter;
use crate::output::pcap_writer::PcapWriter;
use crate::storage::ring::PacketRing;

const FRAME_INTERVAL: Duration = Duration::from_millis(33);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    FilterInput,
}

#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
}

pub struct App {
    pub packets: PacketRing,
    pub filtered_indices: Option<Vec<usize>>,
    pub active_filter: Option<FilterExpr>,
    pub mode: InputMode,
    pub selected: usize,
    pub paused: bool,
    pub status_message: Option<StatusMessage>,
    pub detail_scroll: usize,
    pub hex_scroll: usize,
    pub total_received: u64,
    pub total_dropped: u64,
    pub filter_input: String,
    pub filter_cursor: usize,
    pub pcap_writer: Option<PcapWriter<std::io::BufWriter<std::fs::File>>>,
}

impl App {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            packets: PacketRing::new(buffer_size),
            filtered_indices: None,
            active_filter: None,
            mode: InputMode::Normal,
            selected: 0,
            paused: false,
            status_message: None,
            detail_scroll: 0,
            hex_scroll: 0,
            total_received: 0,
            total_dropped: 0,
            filter_input: String::new(),
            filter_cursor: 0,
            pcap_writer: None,
        }
    }

    pub fn visible_count(&self) -> usize {
        match &self.filtered_indices {
            Some(indices) => indices.len(),
            None => self.packets.len(),
        }
    }

    pub fn visible_packet(&self, visible_idx: usize) -> Option<&DecodedPacket> {
        match &self.filtered_indices {
            Some(indices) => indices
                .get(visible_idx)
                .and_then(|&ring_idx| self.packets.get(ring_idx)),
            None => self.packets.get(visible_idx),
        }
    }

    pub fn selected_packet(&self) -> Option<&DecodedPacket> {
        self.visible_packet(self.selected)
    }
}

pub fn run_tui(
    rx: Receiver<DecodedPacket>,
    buffer_size: usize,
    save_path: Option<&Path>,
) -> anyhow::Result<()> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Set up panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, cursor::Show);
        original_hook(panic_info);
    }));

    let mut app = App::new(buffer_size);

    if let Some(path) = save_path {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        app.pcap_writer = Some(PcapWriter::new(
            writer,
            crate::capture::Linktype::Ethernet,
            65535,
        )?);
    }

    loop {
        let frame_start = Instant::now();

        terminal.draw(|frame| render_frame(frame, &app))?;

        let timeout = FRAME_INTERVAL.saturating_sub(frame_start.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if !handle_key_event(&mut app, key) {
                    break;
                }
            }
        }

        if !app.paused {
            drain_packets(&mut app, &rx);
        }
    }

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        cursor::Show
    )?;

    if let Some(ref mut writer) = app.pcap_writer {
        writer.flush()?;
    }

    Ok(())
}

fn handle_key_event(app: &mut App, key: event::KeyEvent) -> bool {
    // Ctrl-C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return false;
    }

    match app.mode {
        InputMode::Normal => match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('j') | KeyCode::Down => {
                let count = app.visible_count();
                if count > 0 && app.selected < count - 1 {
                    app.selected += 1;
                    app.detail_scroll = 0;
                    app.hex_scroll = 0;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if app.selected > 0 {
                    app.selected -= 1;
                    app.detail_scroll = 0;
                    app.hex_scroll = 0;
                }
            }
            KeyCode::Char('G') | KeyCode::End => {
                let count = app.visible_count();
                if count > 0 {
                    app.selected = count - 1;
                    app.detail_scroll = 0;
                    app.hex_scroll = 0;
                }
            }
            KeyCode::Char('g') | KeyCode::Home => {
                app.selected = 0;
                app.detail_scroll = 0;
                app.hex_scroll = 0;
            }
            KeyCode::PageDown => {
                let count = app.visible_count();
                app.selected = (app.selected + 20).min(count.saturating_sub(1));
            }
            KeyCode::PageUp => {
                app.selected = app.selected.saturating_sub(20);
            }
            KeyCode::Char(' ') => {
                app.paused = !app.paused;
                app.status_message = Some(StatusMessage {
                    text: if app.paused {
                        "Paused".into()
                    } else {
                        "Resumed".into()
                    },
                    is_error: false,
                });
            }
            KeyCode::Char('/') => {
                app.mode = InputMode::FilterInput;
                app.filter_input.clear();
                app.filter_cursor = 0;
            }
            KeyCode::Char('s') => {
                app.status_message = Some(StatusMessage {
                    text: if app.pcap_writer.is_some() {
                        "Saving to pcap file...".into()
                    } else {
                        "No save path specified (use -w)".into()
                    },
                    is_error: app.pcap_writer.is_none(),
                });
            }
            _ => {}
        },
        InputMode::FilterInput => match key.code {
            KeyCode::Enter => {
                if app.filter_input.is_empty() {
                    app.active_filter = None;
                    app.filtered_indices = None;
                    app.selected = 0;
                    app.status_message = Some(StatusMessage {
                        text: "Filter cleared".into(),
                        is_error: false,
                    });
                } else {
                    match parse_filter(&app.filter_input) {
                        Ok(filter) => {
                            app.active_filter = Some(filter);
                            rebuild_filter_indices(app);
                            app.selected = 0;
                            app.status_message = Some(StatusMessage {
                                text: format!("Filter applied: {}", app.filter_input),
                                is_error: false,
                            });
                        }
                        Err(e) => {
                            app.status_message = Some(StatusMessage {
                                text: format!("Filter error: {}", e),
                                is_error: true,
                            });
                        }
                    }
                }
                app.mode = InputMode::Normal;
            }
            KeyCode::Esc => {
                app.mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                if app.filter_cursor > 0 {
                    app.filter_cursor -= 1;
                    app.filter_input.remove(app.filter_cursor);
                }
            }
            KeyCode::Left => {
                if app.filter_cursor > 0 {
                    app.filter_cursor -= 1;
                }
            }
            KeyCode::Right => {
                if app.filter_cursor < app.filter_input.len() {
                    app.filter_cursor += 1;
                }
            }
            KeyCode::Char(c) => {
                app.filter_input.insert(app.filter_cursor, c);
                app.filter_cursor += 1;
            }
            _ => {}
        },
    }
    true
}

fn drain_packets(app: &mut App, rx: &Receiver<DecodedPacket>) {
    let mut new_count = 0u64;
    while let Ok(pkt) = rx.try_recv() {
        app.total_received += 1;

        // Write to pcap if saving
        if let Some(ref mut writer) = app.pcap_writer {
            let _ = writer.write_packet(pkt.timestamp, &pkt.data, pkt.wire_len);
        }

        let matches_filter = match &app.active_filter {
            Some(filter) => eval_filter(filter, &pkt),
            None => true,
        };

        let ring_idx = app.packets.len();
        let evicted = app.packets.push(pkt);

        if evicted.is_some() {
            // An old packet was evicted; adjust filtered indices
            if let Some(ref mut indices) = app.filtered_indices {
                indices.retain_mut(|idx| {
                    if *idx == 0 {
                        false
                    } else {
                        *idx -= 1;
                        true
                    }
                });
            }
        }

        if matches_filter {
            if let Some(ref mut indices) = app.filtered_indices {
                let actual_idx = if evicted.is_some() {
                    ring_idx.min(app.packets.len() - 1)
                } else {
                    ring_idx
                };
                indices.push(actual_idx);
            }
            new_count += 1;
        }
    }

    // Auto-scroll to bottom if near the end
    if new_count > 0 {
        let count = app.visible_count();
        if count > 0 && app.selected >= count.saturating_sub(new_count as usize + 5) {
            app.selected = count - 1;
        }
    }
}

fn rebuild_filter_indices(app: &mut App) {
    match &app.active_filter {
        Some(filter) => {
            let mut indices = Vec::new();
            for i in 0..app.packets.len() {
                if let Some(pkt) = app.packets.get(i) {
                    if eval_filter(filter, pkt) {
                        indices.push(i);
                    }
                }
            }
            app.filtered_indices = Some(indices);
        }
        None => {
            app.filtered_indices = None;
        }
    }
}

fn render_frame(frame: &mut ratatui::Frame, app: &App) {
    let area = frame.area();

    // Layout: filter bar (3), main area (flexible), hex view (10), status bar (1)
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // filter bar
            Constraint::Min(10),   // main area
            Constraint::Length(10), // hex view
            Constraint::Length(1), // status bar
        ])
        .split(area);

    // Filter bar
    filter_bar::render_filter_bar(frame, main_layout[0], app);

    // Main area: packet list (60%) | detail tree (40%)
    let main_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(main_layout[1]);

    packet_list::render_packet_list(frame, main_split[0], app);
    detail_tree::render_detail_tree(frame, main_split[1], app);

    // Hex view
    hex_view::render_hex_view(frame, main_layout[2], app);

    // Status bar
    render_status_bar(frame, main_layout[3], app);
}

fn render_status_bar(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let displayed = app.visible_count();
    let state = if app.paused { "PAUSED" } else { "CAPTURING" };

    let status_text = match &app.status_message {
        Some(msg) => format!(
            " {} │ Packets: {} │ Displayed: {} │ Dropped: {} │ {} ",
            state, app.total_received, displayed, app.total_dropped, msg.text
        ),
        None => format!(
            " {} │ Packets: {} │ Displayed: {} │ Dropped: {} ",
            state, app.total_received, displayed, app.total_dropped
        ),
    };

    let style = if app.status_message.as_ref().is_some_and(|m| m.is_error) {
        Style::default().fg(Color::Red).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White).bg(Color::DarkGray)
    };

    let paragraph = Paragraph::new(status_text)
        .style(style)
        .block(Block::default());
    frame.render_widget(paragraph, area);
}

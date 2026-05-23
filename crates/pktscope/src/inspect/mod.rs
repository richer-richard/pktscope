//! The inspector TUI: attaches to a running daemon over its Unix socket and
//! shows live connections, per-process / per-domain breakdowns, the alerts
//! feed, and recent history. Mirrors the capture TUI's terminal lifecycle.

use std::io::stdout;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use crossbeam_channel::{Receiver, unbounded};
use crossterm::event::{self, Event as CEvent, KeyCode, KeyModifiers};
use crossterm::{cursor, execute, terminal};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table, Tabs};

use pktscope_core::alert::Alert;
use pktscope_core::inspector::InspectorApp;
use pktscope_core::ipc::protocol::Event as IpcEvent;
use pktscope_core::ipc::{IpcClient, Request, Response};
use pktscope_core::store::models::ConnectionRow;

const FRAME: Duration = Duration::from_millis(100);

enum Msg {
    Event(IpcEvent),
    Disconnected(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TabId {
    Connections,
    Processes,
    Domains,
    Alerts,
    History,
}

impl TabId {
    const ALL: [TabId; 5] = [
        TabId::Connections,
        TabId::Processes,
        TabId::Domains,
        TabId::Alerts,
        TabId::History,
    ];
    fn index(self) -> usize {
        TabId::ALL.iter().position(|t| *t == self).unwrap()
    }
    fn title(self) -> &'static str {
        match self {
            TabId::Connections => "Connections",
            TabId::Processes => "Processes",
            TabId::Domains => "Domains",
            TabId::Alerts => "Alerts",
            TabId::History => "History",
        }
    }
    fn from_index(i: usize) -> TabId {
        TabId::ALL[i % TabId::ALL.len()]
    }
}

enum Mode {
    Normal,
    Search,
}

struct Ui {
    app: InspectorApp,
    tab: TabId,
    mode: Mode,
    selected: usize,
    search: String,
    history: Vec<ConnectionRow>,
    query: IpcClient,
}

pub fn run_inspector(socket_path: &Path) -> Result<()> {
    let mut query = IpcClient::connect(socket_path)
        .map_err(|e| anyhow!("cannot connect to daemon at {}: {e}", socket_path.display()))?;

    let mut app = InspectorApp::new();
    if let Ok(Response::Status(s)) = query.request(&Request::Status) {
        app.set_status(s);
    }
    if let Ok(Response::Connections(c)) = query.request(&Request::LiveConnections) {
        app.set_snapshot(c);
    }
    if let Ok(Response::Alerts(a)) = query.request(&Request::RecentAlerts { limit: 200 }) {
        app.set_recent_alerts(a);
    }

    // Subscribe on a second connection; a reader thread forwards events.
    let mut sub = IpcClient::connect(socket_path)?;
    let _ = sub.request(&Request::Subscribe);
    let (tx, rx) = unbounded::<Msg>();
    std::thread::spawn(move || {
        loop {
            match sub.next_event() {
                Ok(ev) => {
                    if tx.send(Msg::Event(ev)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Msg::Disconnected(e.to_string()));
                    break;
                }
            }
        }
    });

    let mut ui = Ui {
        app,
        tab: TabId::Connections,
        mode: Mode::Normal,
        selected: 0,
        search: String::new(),
        history: Vec::new(),
        query,
    };

    run_loop(&mut ui, &rx)
}

fn run_loop(ui: &mut Ui, rx: &Receiver<Msg>) -> Result<()> {
    terminal::enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, terminal::EnterAlternateScreen, cursor::Hide)?;

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(stdout(), terminal::LeaveAlternateScreen, cursor::Show);
        prev(info);
    }));

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let result = (|| -> Result<()> {
        loop {
            let frame_start = Instant::now();
            terminal.draw(|f| render(f, ui))?;

            let timeout = FRAME.saturating_sub(frame_start.elapsed());
            if event::poll(timeout)? {
                if let CEvent::Key(key) = event::read()? {
                    if !handle_key(ui, key) {
                        break;
                    }
                }
            }
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Event(ev) => ui.app.apply(ev),
                    Msg::Disconnected(m) => ui.app.set_disconnected(m),
                }
            }
        }
        Ok(())
    })();

    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
        cursor::Show
    )?;
    result
}

/// Returns false to quit.
fn handle_key(ui: &mut Ui, key: event::KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return false;
    }
    match ui.mode {
        Mode::Search => match key.code {
            KeyCode::Enter => ui.mode = Mode::Normal,
            KeyCode::Esc => {
                ui.search.clear();
                ui.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                ui.search.pop();
            }
            KeyCode::Char(c) => ui.search.push(c),
            _ => {}
        },
        Mode::Normal => match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Tab | KeyCode::Right => ui.set_tab(TabId::from_index(ui.tab.index() + 1)),
            KeyCode::BackTab | KeyCode::Left => {
                ui.set_tab(TabId::from_index(ui.tab.index() + TabId::ALL.len() - 1))
            }
            KeyCode::Char(d @ '1'..='5') => {
                ui.set_tab(TabId::from_index(d as usize - '1' as usize))
            }
            KeyCode::Char('j') | KeyCode::Down => ui.selected = ui.selected.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => ui.selected = ui.selected.saturating_sub(1),
            KeyCode::Char('/') => ui.mode = Mode::Search,
            KeyCode::Char('r') => ui.refresh(),
            _ => {}
        },
    }
    true
}

impl Ui {
    fn set_tab(&mut self, tab: TabId) {
        self.tab = tab;
        self.selected = 0;
        if tab == TabId::History {
            self.refresh_history();
        }
    }

    fn refresh(&mut self) {
        if let Ok(Response::Status(s)) = self.query.request(&Request::Status) {
            self.app.set_status(s);
        }
        if let Ok(Response::Connections(c)) = self.query.request(&Request::LiveConnections) {
            self.app.set_snapshot(c);
        }
        if self.tab == TabId::History {
            self.refresh_history();
        }
    }

    fn refresh_history(&mut self) {
        if let Ok(Response::History(h)) = self
            .query
            .request(&Request::RecentConnections { limit: 200 })
        {
            self.history = h;
        }
    }
}

fn render(f: &mut Frame, ui: &Ui) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    let titles: Vec<Line> = TabId::ALL.iter().map(|t| Line::from(t.title())).collect();
    let tabs = Tabs::new(titles)
        .select(ui.tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("pktscope inspect"),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(tabs, chunks[0]);

    match ui.tab {
        TabId::Connections => render_connections(f, chunks[1], ui),
        TabId::Processes => render_processes(f, chunks[1], ui),
        TabId::Domains => render_domains(f, chunks[1], ui),
        TabId::Alerts => render_alerts(f, chunks[1], ui),
        TabId::History => render_history(f, chunks[1], ui),
    }
    render_status(f, chunks[2], ui);
}

fn sel_style(selected: bool) -> Style {
    if selected {
        Style::default().fg(Color::Black).bg(Color::White)
    } else {
        Style::default()
    }
}

fn render_connections(f: &mut Frame, area: Rect, ui: &Ui) {
    let conns = ui.app.matching(&ui.search);
    let rows = conns.iter().enumerate().map(|(i, c)| {
        let geo = match (&c.country, c.asn) {
            (Some(cc), Some(asn)) => format!("{cc} AS{asn}"),
            (Some(cc), None) => cc.clone(),
            _ => "-".into(),
        };
        Row::new(vec![
            c.process.clone(),
            c.dest_name.clone(),
            geo,
            format!("↑{}", fmt_bytes(c.bytes_up)),
            format!("↓{}", fmt_bytes(c.bytes_down)),
            proto_name(c.protocol).into(),
        ])
        .style(sel_style(i == ui.selected))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Min(20),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(5),
        ],
    )
    .header(
        Row::new(vec!["Process", "Destination", "Geo", "Up", "Down", "Proto"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Live connections ({})", conns.len())),
    );
    f.render_widget(table, area);
}

fn render_processes(f: &mut Frame, area: Rect, ui: &Ui) {
    let aggs = ui.app.process_aggs();
    let rows = aggs.iter().enumerate().map(|(i, a)| {
        Row::new(vec![
            a.process.clone(),
            a.conns.to_string(),
            format!("↑{}", fmt_bytes(a.bytes_up)),
            format!("↓{}", fmt_bytes(a.bytes_down)),
        ])
        .style(sel_style(i == ui.selected))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Process", "Conns", "Up", "Down"]).style(Style::default().fg(Color::Yellow)),
    )
    .block(Block::default().borders(Borders::ALL).title("Per-process"));
    f.render_widget(table, area);
}

fn render_domains(f: &mut Frame, area: Rect, ui: &Ui) {
    let aggs = ui.app.domain_aggs();
    let rows = aggs.iter().enumerate().map(|(i, a)| {
        Row::new(vec![
            a.domain.clone(),
            a.conns.to_string(),
            format!("↑{}", fmt_bytes(a.bytes_up)),
            format!("↓{}", fmt_bytes(a.bytes_down)),
        ])
        .style(sel_style(i == ui.selected))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Domain / Org", "Conns", "Up", "Down"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .block(Block::default().borders(Borders::ALL).title("Per-domain"));
    f.render_widget(table, area);
}

fn render_alerts(f: &mut Frame, area: Rect, ui: &Ui) {
    let items: Vec<ListItem> = ui
        .app
        .alerts
        .iter()
        .enumerate()
        .map(|(i, a)| ListItem::new(alert_line(a)).style(sel_style(i == ui.selected)))
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Alerts ({})", ui.app.alerts.len())),
    );
    f.render_widget(list, area);
}

fn render_history(f: &mut Frame, area: Rect, ui: &Ui) {
    let rows = ui.history.iter().enumerate().map(|(i, c)| {
        Row::new(vec![
            c.name.clone().unwrap_or_else(|| "-".into()),
            format!("{}:{}", proto_name(c.proto), c.remote_port),
            format!("↑{}", fmt_bytes(c.bytes_up)),
            format!("↓{}", fmt_bytes(c.bytes_down)),
            fmt_ts(c.ts_start_ms),
        ])
        .style(sel_style(i == ui.selected))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Min(20),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(20),
        ],
    )
    .header(
        Row::new(vec!["Destination", "Proto:Port", "Up", "Down", "Started"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("History ({})", ui.history.len())),
    );
    f.render_widget(table, area);
}

fn render_status(f: &mut Frame, area: Rect, ui: &Ui) {
    let text = if let Mode::Search = ui.mode {
        format!("/{}", ui.search)
    } else if !ui.app.connected {
        format!(
            "DISCONNECTED: {} — last state retained. q quit",
            ui.app.disconnect_msg.as_deref().unwrap_or("")
        )
    } else {
        let st = ui
            .app
            .status
            .as_ref()
            .map(|s| {
                format!(
                    "{} • {} live • {} alerts",
                    s.baseline,
                    ui.app.live_count(),
                    s.alerts
                )
            })
            .unwrap_or_else(|| format!("{} live", ui.app.live_count()));
        format!("{st}  |  Tab/1-5 view  j/k move  / search  r refresh  q quit")
    };
    let style = if !ui.app.connected {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    f.render_widget(Paragraph::new(text).style(style), area);
}

fn alert_line(a: &Alert) -> Line<'static> {
    let color = match a.severity {
        pktscope_core::alert::Severity::Critical => Color::Red,
        pktscope_core::alert::Severity::Warning => Color::LightRed,
        pktscope_core::alert::Severity::Notice => Color::Yellow,
        pktscope_core::alert::Severity::Info => Color::Gray,
    };
    Line::from(vec![
        Span::styled(format!("[{}] ", a.kind.label()), Style::default().fg(color)),
        Span::raw(a.title.clone()),
    ])
}

fn proto_name(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "?",
    }
}

fn fmt_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let b = b as f64;
    if b >= K * K * K {
        format!("{:.1}G", b / (K * K * K))
    } else if b >= K * K {
        format!("{:.1}M", b / (K * K))
    } else if b >= K {
        format!("{:.1}K", b / K)
    } else {
        format!("{}B", b as u64)
    }
}

fn fmt_ts(ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

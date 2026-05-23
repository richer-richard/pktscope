use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use super::protocol::{ConnectionDto, DaemonStatus, Event, Request, Response};
use crate::flow::FlowKey;
use crate::store::Store;
use crate::store::models::BaselineState;

/// Live (currently active) connection table, shared between the daemon worker
/// (writer) and the IPC server (reader).
#[derive(Default)]
pub struct LiveState {
    pub conns: HashMap<FlowKey, ConnectionDto>,
}

impl LiveState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<ConnectionDto> {
        let mut v: Vec<ConnectionDto> = self.conns.values().cloned().collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.last_seen_ms));
        v
    }
}

/// Fan-out bus for live events to subscribed connections. Slow subscribers drop
/// events (best-effort); disconnected subscribers are pruned.
#[derive(Default)]
pub struct Bus {
    subs: Mutex<Vec<Sender<Event>>>,
}

impl Bus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = bounded(1024);
        self.subs.lock().unwrap().push(tx);
        rx
    }

    pub fn broadcast(&self, ev: &Event) {
        let mut subs = self.subs.lock().unwrap();
        subs.retain(|tx| !matches!(tx.try_send(ev.clone()), Err(TrySendError::Disconnected(_))));
    }
}

/// Shared context for the IPC server.
pub struct ServerCtx {
    pub store: Arc<Mutex<Store>>,
    pub live: Arc<Mutex<LiveState>>,
    pub bus: Arc<Bus>,
    pub interface: String,
    pub started: Instant,
    pub stop: Arc<AtomicBool>,
}

/// Accept loop. Polls `stop` so the daemon can shut down cleanly.
pub fn run_server(listener: UnixListener, ctx: Arc<ServerCtx>) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !ctx.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets can inherit the listener's non-blocking flag
                // (notably on macOS/BSD); per-connection I/O must be blocking.
                let _ = stream.set_nonblocking(false);
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, ctx) {
                        eprintln!("pktscope ipc: connection handler error: {e}");
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn handle_conn(stream: UnixStream, ctx: Arc<ServerCtx>) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let req: Request = match serde_json::from_str(line.trim_end()) {
            Ok(r) => r,
            Err(e) => {
                write_resp(
                    &mut writer,
                    &Response::Error {
                        message: e.to_string(),
                    },
                )?;
                continue;
            }
        };

        match req {
            Request::Subscribe => {
                // Subscribe before acking so no events are missed after the ack.
                let rx = ctx.bus.subscribe();
                write_resp(&mut writer, &Response::Subscribed)?;
                while let Ok(ev) = rx.recv() {
                    if write_line(&mut writer, &ev).is_err() {
                        break;
                    }
                }
                break;
            }
            Request::Stop => {
                ctx.stop.store(true, Ordering::Relaxed);
                write_resp(&mut writer, &Response::Stopping)?;
                break;
            }
            other => {
                let resp = handle_query(&ctx, other);
                write_resp(&mut writer, &resp)?;
            }
        }
    }
    Ok(())
}

fn handle_query(ctx: &ServerCtx, req: Request) -> Response {
    let store = ctx.store.lock().unwrap();
    match req {
        Request::Status => {
            let (processes, destinations, alerts) = store.counts().unwrap_or((0, 0, 0));
            let baseline = match store.baseline_state() {
                Ok(BaselineState::Active) => "active",
                _ => "learning",
            }
            .to_string();
            Response::Status(DaemonStatus {
                pid: std::process::id(),
                uptime_secs: ctx.started.elapsed().as_secs(),
                interface: ctx.interface.clone(),
                baseline,
                learning_ends_ms: store.meta_get_i64("learning_ends_ms").ok().flatten(),
                processes,
                destinations,
                alerts,
                schema_version: crate::store::schema::SCHEMA_VERSION,
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
        }
        Request::LiveConnections => Response::Connections(ctx.live.lock().unwrap().snapshot()),
        Request::ListProcesses => match store.list_processes() {
            Ok(v) => Response::Processes(v),
            Err(e) => err(e),
        },
        Request::ListDestinations { process_id } => {
            match store.list_destinations_for_process(process_id) {
                Ok(v) => Response::Destinations(v),
                Err(e) => err(e),
            }
        }
        Request::ProcessHistory {
            process_id,
            since_ms,
            until_ms,
        } => match store.query_process_history(process_id, since_ms, until_ms) {
            Ok(v) => Response::History(v),
            Err(e) => err(e),
        },
        Request::RecentAlerts { limit } => match store.query_recent_alerts(limit) {
            Ok(v) => Response::Alerts(v),
            Err(e) => err(e),
        },
        Request::Subscribe | Request::Stop => Response::Error {
            message: "handled out of band".into(),
        },
    }
}

fn err(e: crate::store::StoreError) -> Response {
    Response::Error {
        message: e.to_string(),
    }
}

fn write_resp(w: &mut UnixStream, resp: &Response) -> io::Result<()> {
    write_line(w, resp)
}

fn write_line<T: serde::Serialize>(w: &mut UnixStream, value: &T) -> io::Result<()> {
    let mut line = serde_json::to_string(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    line.push('\n');
    w.write_all(line.as_bytes())?;
    w.flush()
}

//! The always-on egress monitor daemon: capture → correlate → detect → persist,
//! with a Unix-socket IPC server for the inspector and `--json` consumers.

pub mod correlate;
pub mod daemonize;
pub mod paths;

use std::collections::HashSet;
use std::net::IpAddr;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, anyhow};
use crossbeam_channel::bounded;

use crate::alert::{AlertConfig, AlertEngine};
use crate::enrich::{Enricher, GeoIpEnricher};
use crate::ipc::client::IpcClient;
use crate::ipc::protocol::{DaemonStatus, Request, Response};
use crate::ipc::server::{Bus, LiveState, ServerCtx, run_server};
use crate::store::Store;

pub use correlate::{WorkerCtx, run_worker};

const CHANNEL_CAPACITY: usize = 10_000;

pub struct MonitorConfig {
    pub interface: String,
    pub bpf: Option<String>,
    pub snaplen: i32,
    pub db_path: PathBuf,
    pub socket_path: PathBuf,
    pub geoip_country: Option<PathBuf>,
    pub geoip_asn: Option<PathBuf>,
    pub alert: AlertConfig,
    pub notify: bool,
}

/// Run the daemon until `stop` is set. Spawns capture + IPC-server threads and
/// runs the correlate/detect worker on the calling thread.
pub fn run_monitor(cfg: MonitorConfig, stop: Arc<AtomicBool>) -> anyhow::Result<()> {
    let store = Arc::new(Mutex::new(
        Store::open(&cfg.db_path).context("opening store")?,
    ));
    let enricher: Arc<dyn Enricher> = Arc::new(GeoIpEnricher::open(
        cfg.geoip_country.as_deref(),
        cfg.geoip_asn.as_deref(),
    ));
    let local_addrs = interface_addrs(&cfg.interface);

    let (raw_tx, raw_rx) = bounded(CHANNEL_CAPACITY);
    let capture = crate::capture::live::start_live_capture(
        &cfg.interface,
        cfg.bpf.as_deref(),
        cfg.snaplen,
        raw_tx,
        stop.clone(),
    )?;

    if let Some(parent) = cfg.socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path).context("binding IPC socket")?;

    let live = Arc::new(Mutex::new(LiveState::new()));
    let bus = Bus::new();
    let notifier = Arc::from(crate::notify::make_notifier(cfg.notify));

    let server_ctx = Arc::new(ServerCtx {
        store: store.clone(),
        live: live.clone(),
        bus: bus.clone(),
        interface: cfg.interface.clone(),
        started: Instant::now(),
        stop: stop.clone(),
    });
    let server = std::thread::Builder::new()
        .name("ipc-server".into())
        .spawn(move || {
            let _ = run_server(listener, server_ctx);
        })?;

    let worker_ctx = WorkerCtx {
        store,
        engine: AlertEngine::new(cfg.alert),
        enricher,
        live,
        bus,
        notifier,
        local_addrs,
    };
    run_worker(raw_rx, worker_ctx, stop.clone());

    let _ = capture.join();
    let _ = server.join();
    let _ = std::fs::remove_file(&cfg.socket_path);
    Ok(())
}

/// Query a running daemon's status over its socket.
pub fn monitor_status(socket_path: &Path) -> anyhow::Result<DaemonStatus> {
    let mut client = IpcClient::connect(socket_path).context("connecting to daemon")?;
    match client.request(&Request::Status)? {
        Response::Status(s) => Ok(s),
        Response::Error { message } => Err(anyhow!("daemon error: {message}")),
        _ => Err(anyhow!("unexpected response")),
    }
}

/// Ask a running daemon to stop.
pub fn monitor_stop(socket_path: &Path) -> anyhow::Result<()> {
    let mut client = IpcClient::connect(socket_path).context("connecting to daemon")?;
    match client.request(&Request::Stop)? {
        Response::Stopping => Ok(()),
        Response::Error { message } => Err(anyhow!("daemon error: {message}")),
        _ => Err(anyhow!("unexpected response")),
    }
}

fn interface_addrs(name: &str) -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    if let Ok(devices) = pcap::Device::list() {
        for dev in devices {
            if dev.name == name {
                for addr in dev.addresses {
                    set.insert(addr.addr);
                }
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Alert;
    use crate::alert::{AlertKind, Severity};
    use crate::capture::{Linktype, RawPacket};
    use crate::ipc::protocol::Event;
    use chrono::Utc;
    use serde_json::json;
    use std::sync::atomic::Ordering;

    fn eth_ipv4_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0xff; 6]); // dst mac
        p.extend_from_slice(&[0, 1, 2, 3, 4, 5]); // src mac
        p.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header (20 bytes)
        p.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0, 0,
        ]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        // TCP header (20 bytes)
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]); // ack
        p.push(0x50); // data offset 5
        p.push(flags);
        p.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, checksum, urgent
        p
    }

    fn raw(data: Vec<u8>) -> RawPacket {
        RawPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: data.len() as u32,
            data,
            linktype: Linktype::Ethernet,
        }
    }

    #[test]
    fn test_worker_records_flow_and_connection() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let live = Arc::new(Mutex::new(LiveState::new()));
        let bus = Bus::new();
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let ctx = WorkerCtx {
            store: store.clone(),
            engine: AlertEngine::new(AlertConfig::demo()),
            enricher: Arc::new(crate::enrich::NullEnricher),
            live,
            bus,
            notifier: Arc::new(crate::notify::LogNotifier),
            local_addrs: HashSet::from([local]),
        };
        let (tx, rx) = bounded(64);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn(move || run_worker(rx, ctx, stop));

        let lan = [10, 0, 0, 1];
        let remote = [93, 184, 216, 34];
        tx.send(raw(eth_ipv4_tcp(lan, remote, 50000, 443, 1000, 0x02)))
            .unwrap(); // SYN
        tx.send(raw(eth_ipv4_tcp(lan, remote, 50000, 443, 1001, 0x11)))
            .unwrap(); // FIN
        tx.send(raw(eth_ipv4_tcp(remote, lan, 443, 50000, 2000, 0x11)))
            .unwrap(); // FIN back
        drop(tx); // worker drains, flushes closed flow, then exits
        handle.join().unwrap();

        let store = store.lock().unwrap();
        let (_p, dests, _a) = store.counts().unwrap();
        assert!(dests >= 1, "destination should be recorded");
        assert_eq!(store.recent_connections(10).unwrap().len(), 1);
    }

    #[test]
    fn test_ipc_roundtrip_and_subscribe() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("t.sock");

        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        store
            .lock()
            .unwrap()
            .insert_alert(
                &Alert {
                    id: None,
                    kind: AlertKind::NewProcessEgress,
                    severity: Severity::Warning,
                    ts: 1,
                    process_id: None,
                    dest_id: None,
                    dedup_key: "x".into(),
                    title: "t".into(),
                    detail: json!({}),
                },
                3_600_000,
            )
            .unwrap();

        let bus = Bus::new();
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(ServerCtx {
            store,
            live: Arc::new(Mutex::new(LiveState::new())),
            bus: bus.clone(),
            interface: "lo".into(),
            started: Instant::now(),
            stop: stop.clone(),
        });
        let listener = UnixListener::bind(&sock).unwrap();
        let srv = std::thread::spawn(move || {
            let _ = run_server(listener, ctx);
        });

        let mut client = IpcClient::connect(&sock).unwrap();
        match client.request(&Request::Status).unwrap() {
            Response::Status(s) => assert_eq!(s.alerts, 1),
            other => panic!("expected status, got {other:?}"),
        }
        match client
            .request(&Request::RecentAlerts { limit: 10 })
            .unwrap()
        {
            Response::Alerts(a) => assert_eq!(a.len(), 1),
            other => panic!("expected alerts, got {other:?}"),
        }

        // Subscribe on a second connection, then broadcast an event.
        let mut sub = IpcClient::connect(&sock).unwrap();
        assert!(matches!(
            sub.request(&Request::Subscribe).unwrap(),
            Response::Subscribed
        ));
        bus.broadcast(&Event::Heartbeat { ts_ms: 99 });
        assert!(matches!(
            sub.next_event().unwrap(),
            Event::Heartbeat { ts_ms: 99 }
        ));

        stop.store(true, Ordering::Relaxed);
        drop(client);
        drop(sub);
        let _ = srv.join();
    }
}

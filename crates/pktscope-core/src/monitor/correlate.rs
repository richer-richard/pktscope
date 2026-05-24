use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use crossbeam_channel::{Receiver, RecvTimeoutError, unbounded};

use crate::alert::{AlertEngine, FlowEvent};
use crate::capture::RawPacket;
use crate::decode::decode_packet;
use crate::enrich::Enricher;
use crate::enrich::names::NameResolver;
use crate::flow::tracker::FlowTracker;
use crate::flow::{Dir, FlowKey, FlowStatsSnapshot, FlowUpdate};
use crate::identity::BinaryIdentity;
use crate::ipc::protocol::{ConnectionDto, Event};
use crate::ipc::server::{Bus, LiveState};
use crate::notify::Notifier;
use crate::process::lookup_socket_proc;
use crate::store::Store;
use crate::store::models::ConnectionRow;

/// Everything the worker thread needs. The worker is the only writer of the
/// store and the live-connection table.
pub struct WorkerCtx {
    pub store: Arc<Mutex<Store>>,
    pub engine: AlertEngine,
    pub enricher: Arc<dyn Enricher>,
    pub live: Arc<Mutex<LiveState>>,
    pub bus: Arc<Bus>,
    pub notifier: Arc<dyn Notifier>,
    pub local_addrs: HashSet<IpAddr>,
}

/// Internal per-flow bookkeeping (id + resolved row ids) for connection-history
/// insertion on close.
struct FlowMeta {
    id: u64,
    outbound: bool,
    process_id: Option<i64>,
    dest_id: Option<i64>,
}

/// The daemon pipeline: decode → flow-track → correlate (pid/identity/name/geo)
/// → detect → persist → broadcast. Runs until `stop` is set or the capture
/// channel disconnects.
pub fn run_worker(raw_rx: Receiver<RawPacket>, ctx: WorkerCtx, stop: Arc<AtomicBool>) {
    let (done_tx, done_rx) = unbounded();
    let mut tracker = FlowTracker::new().with_completion_sink(done_tx);
    tracker.set_local_addrs(ctx.local_addrs.clone());
    let mut resolver = NameResolver::new();
    let mut metas: HashMap<FlowKey, FlowMeta> = HashMap::new();
    let mut next_id: u64 = 1;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match raw_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(raw) => {
                let mut decoded = decode_packet(&raw);
                resolver.observe_packet(&decoded);
                let ts_ms = decoded.timestamp.timestamp_millis();
                if let Some(upd) = tracker.update(&mut decoded) {
                    handle_update(&ctx, &resolver, &mut metas, &mut next_id, upd, ts_ms);
                }
                while let Ok(snap) = done_rx.try_recv() {
                    persist_closed(&ctx, &mut metas, snap);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                ctx.bus.broadcast(&Event::Heartbeat {
                    ts_ms: Utc::now().timestamp_millis(),
                });
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    while let Ok(snap) = done_rx.try_recv() {
        persist_closed(&ctx, &mut metas, snap);
    }
}

fn handle_update(
    ctx: &WorkerCtx,
    resolver: &NameResolver,
    metas: &mut HashMap<FlowKey, FlowMeta>,
    next_id: &mut u64,
    upd: FlowUpdate,
    ts_ms: i64,
) {
    let key = upd.key.clone();
    // Reconstruct this packet's endpoints from the normalized key + direction.
    let (src_addr, src_port, dst_addr, dst_port) = match upd.dir {
        Dir::LowToHigh => (key.addr_low, key.port_low, key.addr_high, key.port_high),
        Dir::HighToLow => (key.addr_high, key.port_high, key.addr_low, key.port_low),
    };
    let dst_local = ctx.local_addrs.contains(&dst_addr);
    let src_local = ctx.local_addrs.contains(&src_addr);
    // The local side is the source unless only the destination is local.
    let (local_addr, local_port, remote_addr, remote_port, pkt_outbound) =
        if dst_local && !src_local {
            (dst_addr, dst_port, src_addr, src_port, false)
        } else {
            (src_addr, src_port, dst_addr, dst_port, true)
        };

    let bytes = upd.bytes as u64;
    let (up_delta, down_delta) = if pkt_outbound { (bytes, 0) } else { (0, bytes) };

    let (id, outbound) = {
        let meta = metas.entry(key.clone()).or_insert_with(|| {
            let id = *next_id;
            *next_id += 1;
            FlowMeta {
                id,
                outbound: pkt_outbound,
                process_id: None,
                dest_id: None,
            }
        });
        (meta.id, meta.outbound)
    };

    let socketproc = lookup_socket_proc(key.protocol, local_addr, local_port);
    let identity = socketproc
        .as_ref()
        .and_then(|p| p.exe_path.as_ref())
        .map(|exe| BinaryIdentity::identify(exe));
    let name = resolver.name_for(remote_addr).map(|s| s.to_string());
    let geo = ctx.enricher.lookup(remote_addr);

    let ev = FlowEvent {
        ts: ts_ms,
        key: key.clone(),
        proc_: socketproc.clone(),
        identity,
        dest_ip: remote_addr,
        dest_port: remote_port,
        local_port,
        protocol: key.protocol,
        name: name.clone(),
        geo: geo.clone(),
        bytes_up: up_delta,
        bytes_down: down_delta,
        flow_first_seen: upd.first_seen,
        outbound,
    };

    let outcome = {
        let store = ctx.store.lock().unwrap();
        ctx.engine.evaluate_full(&store, &ev)
    };
    if let Ok(o) = outcome {
        if let Some(meta) = metas.get_mut(&key) {
            meta.process_id = o.process_id;
            meta.dest_id = Some(o.dest_id);
        }
        for a in &o.alerts {
            ctx.bus.broadcast(&Event::Alert(a.clone()));
            ctx.notifier.notify(a);
        }
    }

    let dto = {
        let mut live = ctx.live.lock().unwrap();
        let dto = live.conns.entry(key).or_insert_with(|| ConnectionDto {
            id,
            process: socketproc
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "?".into()),
            pid: socketproc.as_ref().map(|p| p.pid),
            dest_name: name.clone().unwrap_or_else(|| remote_addr.to_string()),
            remote_ip: remote_addr.to_string(),
            remote_port,
            local_port,
            protocol: key_protocol(&ev),
            country: geo.country.clone(),
            asn: geo.asn,
            as_org: geo.as_org.clone(),
            bytes_up: 0,
            bytes_down: 0,
            first_seen_ms: ts_ms,
            last_seen_ms: ts_ms,
            outbound,
        });
        dto.bytes_up += up_delta;
        dto.bytes_down += down_delta;
        dto.last_seen_ms = ts_ms;
        if let Some(n) = &name {
            dto.dest_name = n.clone();
        }
        if geo.country.is_some() {
            dto.country = geo.country.clone();
        }
        if geo.asn.is_some() {
            dto.asn = geo.asn;
            dto.as_org = geo.as_org.clone();
        }
        if let Some(p) = &socketproc {
            dto.process = p.name.clone();
            dto.pid = Some(p.pid);
        }
        dto.clone()
    };
    ctx.bus.broadcast(&Event::Flow(dto));
}

fn key_protocol(ev: &FlowEvent) -> u8 {
    ev.protocol
}

fn persist_closed(
    ctx: &WorkerCtx,
    metas: &mut HashMap<FlowKey, FlowMeta>,
    snap: FlowStatsSnapshot,
) {
    let meta = metas.remove(&snap.key);
    let name = {
        let mut live = ctx.live.lock().unwrap();
        let n = live.conns.get(&snap.key).map(|d| d.dest_name.clone());
        live.conns.remove(&snap.key);
        n
    };
    if let Some(m) = &meta {
        ctx.bus.broadcast(&Event::Closed { id: m.id });
    }
    let row = ConnectionRow {
        id: 0,
        process_id: meta.as_ref().and_then(|m| m.process_id),
        dest_id: meta.as_ref().and_then(|m| m.dest_id),
        proto: snap.protocol,
        local_port: snap.local_port.unwrap_or(0),
        remote_port: snap.remote_port.unwrap_or(0),
        bytes_up: snap.bytes_up,
        bytes_down: snap.bytes_down,
        name,
        ts_start_ms: snap.first_seen.timestamp_millis(),
        ts_end_ms: snap.last_seen.timestamp_millis(),
    };
    let _ = ctx.store.lock().unwrap().insert_connection(&row);
}

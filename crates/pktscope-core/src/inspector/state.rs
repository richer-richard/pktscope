use std::collections::{BTreeMap, VecDeque};

use crate::alert::Alert;
use crate::enrich::names::registrable_domain_of;
use crate::ipc::protocol::{ConnectionDto, DaemonStatus, Event};

const MAX_ALERTS: usize = 500;

/// Per-process rollup of live connections.
#[derive(Debug, Clone)]
pub struct ProcessAgg {
    pub process: String,
    pub pid: Option<u32>,
    pub conns: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Per-domain rollup of live connections.
#[derive(Debug, Clone)]
pub struct DomainAgg {
    pub domain: String,
    pub conns: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// UI-agnostic inspector state: a reducer over IPC events plus query results.
/// Holds live connections, the alert feed, and daemon status; survives a
/// daemon disconnect by retaining the last-known state and a banner message.
#[derive(Default)]
pub struct InspectorApp {
    conns: BTreeMap<u64, ConnectionDto>,
    pub alerts: VecDeque<Alert>,
    pub status: Option<DaemonStatus>,
    pub connected: bool,
    pub disconnect_msg: Option<String>,
}

impl InspectorApp {
    pub fn new() -> Self {
        Self {
            connected: true,
            ..Default::default()
        }
    }

    /// Apply a streamed event from the daemon.
    pub fn apply(&mut self, ev: Event) {
        match ev {
            Event::Flow(dto) => {
                self.conns.insert(dto.id, dto);
            }
            Event::Closed { id } => {
                self.conns.remove(&id);
            }
            Event::Alert(a) => {
                self.alerts.push_front(a);
                while self.alerts.len() > MAX_ALERTS {
                    self.alerts.pop_back();
                }
            }
            Event::Heartbeat { .. } => {}
        }
    }

    pub fn set_snapshot(&mut self, conns: Vec<ConnectionDto>) {
        self.conns.clear();
        for c in conns {
            self.conns.insert(c.id, c);
        }
    }

    pub fn set_recent_alerts(&mut self, alerts: Vec<Alert>) {
        self.alerts = alerts.into_iter().collect();
    }

    pub fn set_status(&mut self, status: DaemonStatus) {
        self.status = Some(status);
    }

    pub fn set_disconnected(&mut self, msg: impl Into<String>) {
        self.connected = false;
        self.disconnect_msg = Some(msg.into());
    }

    /// Live connections, most-recently-active first.
    pub fn connections(&self) -> Vec<&ConnectionDto> {
        let mut v: Vec<&ConnectionDto> = self.conns.values().collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.last_seen_ms));
        v
    }

    /// Live connections matching a case-insensitive substring across process,
    /// destination name, IP, org, and country.
    pub fn matching(&self, query: &str) -> Vec<&ConnectionDto> {
        if query.is_empty() {
            return self.connections();
        }
        let q = query.to_lowercase();
        self.connections()
            .into_iter()
            .filter(|c| {
                c.process.to_lowercase().contains(&q)
                    || c.dest_name.to_lowercase().contains(&q)
                    || c.remote_ip.contains(&q)
                    || c.as_org
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || c.country
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
            })
            .collect()
    }

    pub fn process_aggs(&self) -> Vec<ProcessAgg> {
        let mut map: BTreeMap<String, ProcessAgg> = BTreeMap::new();
        for c in self.conns.values() {
            let e = map.entry(c.process.clone()).or_insert(ProcessAgg {
                process: c.process.clone(),
                pid: c.pid,
                conns: 0,
                bytes_up: 0,
                bytes_down: 0,
            });
            e.conns += 1;
            e.bytes_up += c.bytes_up;
            e.bytes_down += c.bytes_down;
        }
        let mut v: Vec<ProcessAgg> = map.into_values().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.bytes_up + a.bytes_down));
        v
    }

    pub fn domain_aggs(&self) -> Vec<DomainAgg> {
        let mut map: BTreeMap<String, DomainAgg> = BTreeMap::new();
        for c in self.conns.values() {
            let domain = c
                .as_org
                .clone()
                .unwrap_or_else(|| registrable_domain_of(&c.dest_name));
            let e = map.entry(domain.clone()).or_insert(DomainAgg {
                domain,
                conns: 0,
                bytes_up: 0,
                bytes_down: 0,
            });
            e.conns += 1;
            e.bytes_up += c.bytes_up;
            e.bytes_down += c.bytes_down;
        }
        let mut v: Vec<DomainAgg> = map.into_values().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.bytes_up + a.bytes_down));
        v
    }

    pub fn live_count(&self) -> usize {
        self.conns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: u64, process: &str, dest: &str, up: u64) -> ConnectionDto {
        ConnectionDto {
            id,
            process: process.into(),
            pid: Some(1),
            dest_name: dest.into(),
            remote_ip: "1.2.3.4".into(),
            remote_port: 443,
            local_port: 5000,
            protocol: 6,
            country: Some("US".into()),
            asn: Some(1),
            as_org: None,
            bytes_up: up,
            bytes_down: 0,
            first_seen_ms: 0,
            last_seen_ms: id as i64,
            outbound: true,
        }
    }

    #[test]
    fn test_apply_flow_and_close() {
        let mut app = InspectorApp::new();
        app.apply(Event::Flow(conn(1, "curl", "example.com", 10)));
        app.apply(Event::Flow(conn(2, "ssh", "github.com", 20)));
        assert_eq!(app.live_count(), 2);
        app.apply(Event::Closed { id: 1 });
        assert_eq!(app.live_count(), 1);
        // Most-recently-active first.
        assert_eq!(app.connections()[0].id, 2);
    }

    #[test]
    fn test_matching() {
        let mut app = InspectorApp::new();
        app.apply(Event::Flow(conn(1, "curl", "example.com", 10)));
        app.apply(Event::Flow(conn(2, "ssh", "github.com", 20)));
        assert_eq!(app.matching("github").len(), 1);
        assert_eq!(app.matching("").len(), 2);
        assert_eq!(app.matching("us").len(), 2); // country US
    }

    #[test]
    fn test_aggs() {
        let mut app = InspectorApp::new();
        app.apply(Event::Flow(conn(1, "curl", "a.example.com", 100)));
        app.apply(Event::Flow(conn(2, "curl", "b.example.com", 50)));
        let procs = app.process_aggs();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].conns, 2);
        assert_eq!(procs[0].bytes_up, 150);
        let domains = app.domain_aggs();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].domain, "example.com");
    }

    #[test]
    fn test_disconnect_retains_state() {
        let mut app = InspectorApp::new();
        app.apply(Event::Flow(conn(1, "curl", "example.com", 10)));
        app.set_disconnected("daemon closed");
        assert!(!app.connected);
        assert_eq!(app.live_count(), 1);
    }
}

//! Newline-delimited JSON protocol spoken over the daemon's Unix socket.
//! Each request and response is a single JSON object on its own line. After a
//! `Subscribe` request the connection becomes a one-way stream of `Event`s.

use serde::{Deserialize, Serialize};

use crate::alert::Alert;
use crate::store::models::{ConnectionRow, DestRow, ProcessRow};

/// A live (or recently active) outbound connection, as shown by the inspector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionDto {
    pub id: u64,
    pub process: String,
    pub pid: Option<u32>,
    pub dest_name: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub protocol: u8,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub outbound: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonStatus {
    pub pid: u32,
    pub uptime_secs: u64,
    pub interface: String,
    /// "learning" or "active".
    pub baseline: String,
    pub learning_ends_ms: Option<i64>,
    pub processes: u64,
    pub destinations: u64,
    pub alerts: u64,
    pub schema_version: u32,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Status,
    LiveConnections,
    ListProcesses,
    ListDestinations {
        process_id: i64,
    },
    ProcessHistory {
        process_id: i64,
        since_ms: i64,
        until_ms: i64,
    },
    RecentAlerts {
        limit: usize,
    },
    /// Upgrade this connection to a live event stream.
    Subscribe,
    /// Ask the daemon to shut down.
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Response {
    Status(DaemonStatus),
    Connections(Vec<ConnectionDto>),
    Processes(Vec<ProcessRow>),
    Destinations(Vec<DestRow>),
    History(Vec<ConnectionRow>),
    Alerts(Vec<Alert>),
    Subscribed,
    Stopping,
    Error { message: String },
}

/// Pushed to a subscribed connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Flow(ConnectionDto),
    Closed { id: u64 },
    Alert(Alert),
    Heartbeat { ts_ms: i64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let r = Request::ProcessHistory {
            process_id: 5,
            since_ms: 0,
            until_ms: 100,
        };
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("\"type\":\"process_history\""));
        let back: Request = serde_json::from_str(&line).unwrap();
        matches!(back, Request::ProcessHistory { process_id: 5, .. });
    }

    #[test]
    fn test_event_roundtrip() {
        let e = Event::Heartbeat { ts_ms: 42 };
        let line = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&line).unwrap();
        assert!(matches!(back, Event::Heartbeat { ts_ms: 42 }));
    }
}

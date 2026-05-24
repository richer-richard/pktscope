use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::FlowKey;

/// A point-in-time, serializable view of one flow's accounting. "up" is
/// local→remote (egress) and "down" is remote→local, oriented using the set of
/// local host addresses registered via
/// [`super::tracker::FlowTracker::set_local_addrs`]. When the local side cannot
/// be determined the low endpoint is treated as local.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStatsSnapshot {
    pub key: FlowKey,
    pub protocol: u8,
    pub local_addr: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub pkts_up: u64,
    pub pkts_down: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub srtt_ms: Option<f64>,
    pub handshake_rtt_ms: Option<f64>,
}

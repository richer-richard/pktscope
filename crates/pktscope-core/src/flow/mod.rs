pub mod dns_tracker;
pub mod stats;
pub mod tracker;

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use stats::FlowStatsSnapshot;

/// A normalized (direction-independent) connection key. The endpoint that sorts
/// lower by `(ip, port)` is stored as `*_low`, the other as `*_high`, so both
/// directions of a conversation map to the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub addr_low: IpAddr,
    pub port_low: u16,
    pub addr_high: IpAddr,
    pub port_high: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, protocol: u8) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                addr_low: src_ip,
                port_low: src_port,
                addr_high: dst_ip,
                port_high: dst_port,
                protocol,
            }
        } else {
            Self {
                addr_low: dst_ip,
                port_low: dst_port,
                addr_high: src_ip,
                port_high: src_port,
                protocol,
            }
        }
    }
}

/// Direction of a packet relative to a flow's normalized `(low, high)` endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Dir {
    LowToHigh,
    HighToLow,
}

/// Mutable per-flow state: retransmission detection (TCP), byte/packet
/// accounting (both directions), and RTT estimation.
#[derive(Debug, Clone)]
pub struct FlowState {
    // Retransmission detection (TCP only).
    pub max_seq_low: Option<u64>,
    pub max_seq_high: Option<u64>,
    pub fin_low: bool,
    pub fin_high: bool,
    pub rst_seen: bool,

    // Accounting.
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub pkts_low_to_high: u64,
    pub pkts_high_to_low: u64,
    pub bytes_low_to_high: u64,
    pub bytes_high_to_low: u64,

    // RTT estimation.
    pub syn_ts: Option<DateTime<Utc>>,
    pub synack_ts: Option<DateTime<Utc>>,
    pub handshake_rtt_ms: Option<f64>,
    pub srtt_ms: Option<f64>,
    /// In-flight data send-times keyed by the segment's end sequence number,
    /// used to derive data/ACK RTT samples. One map per direction.
    pub unacked_low: BTreeMap<u32, DateTime<Utc>>,
    pub unacked_high: BTreeMap<u32, DateTime<Utc>>,
}

impl FlowState {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            max_seq_low: None,
            max_seq_high: None,
            fin_low: false,
            fin_high: false,
            rst_seen: false,
            first_seen: now,
            last_seen: now,
            pkts_low_to_high: 0,
            pkts_high_to_low: 0,
            bytes_low_to_high: 0,
            bytes_high_to_low: 0,
            syn_ts: None,
            synack_ts: None,
            handshake_rtt_ms: None,
            srtt_ms: None,
            unacked_low: BTreeMap::new(),
            unacked_high: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FlowAnnotation {
    pub is_retransmission: bool,
}

/// Result of [`tracker::FlowTracker::update`] for a single packet. Carries the
/// per-packet contribution (direction + bytes) plus the optional TCP
/// retransmission annotation, so downstream consumers (the daemon) get the
/// 5-tuple, direction, byte delta, and whether the flow was first seen.
#[derive(Debug, Clone)]
pub struct FlowUpdate {
    pub annotation: Option<FlowAnnotation>,
    pub key: FlowKey,
    pub dir: Dir,
    pub bytes: u32,
    pub first_seen: bool,
}

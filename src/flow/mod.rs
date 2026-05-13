pub mod tracker;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

#[derive(Debug, Clone)]
pub struct FlowState {
    pub max_seq_low: Option<u64>,
    pub max_seq_high: Option<u64>,
    pub fin_low: bool,
    pub fin_high: bool,
    pub rst_seen: bool,
}

impl FlowState {
    pub fn new() -> Self {
        Self {
            max_seq_low: None,
            max_seq_high: None,
            fin_low: false,
            fin_high: false,
            rst_seen: false,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FlowAnnotation {
    pub is_retransmission: bool,
}

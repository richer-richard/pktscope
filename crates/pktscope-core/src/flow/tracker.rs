use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;

use super::{FlowAnnotation, FlowKey, FlowState};
use crate::decode::{DecodedPacket, Layer};

const MAX_FLOWS: usize = 10_000;

pub struct FlowTracker {
    flows: LruCache<FlowKey, FlowState>,
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: LruCache::new(NonZeroUsize::new(MAX_FLOWS).unwrap()),
        }
    }

    pub fn update(&mut self, pkt: &mut DecodedPacket) -> Option<FlowAnnotation> {
        let (src_ip, dst_ip, src_port, dst_port, protocol, seq, payload_len, _flags) =
            extract_flow_info(&pkt.layers)?;

        if protocol != 6 {
            return None; // only track TCP
        }

        let key = FlowKey::new(src_ip, src_port, dst_ip, dst_port, protocol);
        let is_low_side = (src_ip, src_port) <= (dst_ip, dst_port);

        let state = self.flows.get_or_insert_mut(key.clone(), FlowState::new);

        let mut is_retransmission = false;

        // Compute effective sequence end = seq + payload_len (as u64 to avoid wrapping complexity)
        let seq_end = seq as u64 + payload_len as u64;

        if payload_len > 0 {
            let max_seq = if is_low_side {
                &mut state.max_seq_low
            } else {
                &mut state.max_seq_high
            };

            match *max_seq {
                Some(prev_max) if seq_end <= prev_max => {
                    is_retransmission = true;
                }
                _ => {
                    *max_seq = Some(seq_end);
                }
            }
        }

        // Track FIN/RST for cleanup
        if let Some((fin, rst)) = extract_tcp_flags(&pkt.layers) {
            if rst {
                state.rst_seen = true;
            }
            if fin {
                if is_low_side {
                    state.fin_low = true;
                } else {
                    state.fin_high = true;
                }
            }
            if state.rst_seen || (state.fin_low && state.fin_high) {
                self.flows.pop(&key);
            }
        }

        if is_retransmission {
            pkt.retransmission = true;
            pkt.summary.info = format!("[Retransmission] {}", pkt.summary.info);
            pkt.summary.color_hint = crate::decode::ColorHint::Retransmission;
        }

        Some(FlowAnnotation { is_retransmission })
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

type FlowInfo = (IpAddr, IpAddr, u16, u16, u8, u32, usize, u8);

fn extract_flow_info(layers: &[Layer]) -> Option<FlowInfo> {
    let mut src_ip: Option<IpAddr> = None;
    let mut dst_ip: Option<IpAddr> = None;
    let mut protocol: Option<u8> = None;

    for layer in layers {
        match layer {
            Layer::Ipv4(ip) => {
                src_ip = Some(IpAddr::V4(ip.src_ip));
                dst_ip = Some(IpAddr::V4(ip.dst_ip));
                protocol = Some(ip.protocol);
            }
            Layer::Ipv6(ip) => {
                src_ip = Some(IpAddr::V6(ip.src_ip));
                dst_ip = Some(IpAddr::V6(ip.dst_ip));
                protocol = Some(ip.next_header);
            }
            Layer::Tcp(tcp) => {
                let flags_byte = if tcp.flags.syn { 0x02 } else { 0 }
                    | if tcp.flags.fin { 0x01 } else { 0 }
                    | if tcp.flags.rst { 0x04 } else { 0 }
                    | if tcp.flags.ack { 0x10 } else { 0 };
                return Some((
                    src_ip?,
                    dst_ip?,
                    tcp.src_port,
                    tcp.dst_port,
                    protocol?,
                    tcp.seq_num,
                    tcp.payload_len,
                    flags_byte,
                ));
            }
            _ => {}
        }
    }
    None
}

fn extract_tcp_flags(layers: &[Layer]) -> Option<(bool, bool)> {
    for layer in layers {
        if let Layer::Tcp(tcp) = layer {
            return Some((tcp.flags.fin, tcp.flags.rst));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use chrono::Utc;
    use std::net::Ipv4Addr;

    #[allow(clippy::too_many_arguments)]
    fn make_tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        payload_len: usize,
        syn: bool,
        fin: bool,
        rst: bool,
    ) -> DecodedPacket {
        DecodedPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: 100,
            data: vec![0u8; 100],
            layers: vec![
                Layer::Ipv4(Ipv4Header {
                    version: 4,
                    ihl: 5,
                    dscp: 0,
                    ecn: 0,
                    total_length: 60,
                    identification: 0,
                    flags: 0,
                    fragment_offset: 0,
                    ttl: 64,
                    protocol: 6,
                    checksum: 0,
                    src_ip,
                    dst_ip,
                    header_range: (14, 34),
                }),
                Layer::Tcp(TcpHeader {
                    src_port,
                    dst_port,
                    seq_num: seq,
                    ack_num: 0,
                    data_offset: 5,
                    flags: TcpFlags {
                        fin,
                        syn,
                        rst,
                        psh: false,
                        ack: !syn,
                        urg: false,
                        ece: false,
                        cwr: false,
                    },
                    window_size: 65535,
                    checksum: 0,
                    urgent_pointer: 0,
                    payload_len,
                    header_range: (34, 54),
                }),
            ],
            summary: PacketSummary {
                source: src_ip.to_string(),
                destination: dst_ip.to_string(),
                protocol: "TCP".into(),
                length: 100,
                info: "test".into(),
                color_hint: ColorHint::Tcp,
            },
            process: None,
            retransmission: false,
        }
    }

    #[test]
    fn test_no_retransmission() {
        let mut tracker = FlowTracker::new();
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        let mut p1 = make_tcp_packet(src, dst, 80, 12345, 1000, 100, false, false, false);
        let a1 = tracker.update(&mut p1);
        assert!(!a1.unwrap().is_retransmission);

        let mut p2 = make_tcp_packet(src, dst, 80, 12345, 1100, 100, false, false, false);
        let a2 = tracker.update(&mut p2);
        assert!(!a2.unwrap().is_retransmission);
    }

    #[test]
    fn test_retransmission_detected() {
        let mut tracker = FlowTracker::new();
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        let mut p1 = make_tcp_packet(src, dst, 80, 12345, 1000, 100, false, false, false);
        tracker.update(&mut p1);

        let mut p2 = make_tcp_packet(src, dst, 80, 12345, 1100, 200, false, false, false);
        tracker.update(&mut p2);

        // Retransmit of first packet
        let mut p3 = make_tcp_packet(src, dst, 80, 12345, 1000, 100, false, false, false);
        let a3 = tracker.update(&mut p3);
        assert!(a3.unwrap().is_retransmission);
        assert!(p3.retransmission);
    }

    #[test]
    fn test_flow_key_normalization() {
        let k1 = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            12345,
            6,
        );
        let k2 = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
            6,
        );
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_fin_cleanup() {
        let mut tracker = FlowTracker::new();
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        let mut p1 = make_tcp_packet(src, dst, 80, 12345, 1000, 100, false, false, false);
        tracker.update(&mut p1);
        assert_eq!(tracker.len(), 1);

        let mut p2 = make_tcp_packet(src, dst, 80, 12345, 1100, 0, false, true, false);
        tracker.update(&mut p2);
        // FIN from one side only
        assert_eq!(tracker.len(), 1);

        let mut p3 = make_tcp_packet(dst, src, 12345, 80, 2000, 0, false, true, false);
        tracker.update(&mut p3);
        // FIN from both sides → evicted
        assert_eq!(tracker.len(), 0);
    }
}

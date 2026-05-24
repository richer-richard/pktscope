use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroUsize;

use chrono::{DateTime, Utc};
use crossbeam_channel::Sender;
use lru::LruCache;

use super::stats::FlowStatsSnapshot;
use super::{Dir, FlowAnnotation, FlowKey, FlowState, FlowUpdate};
use crate::decode::{DecodedPacket, Layer};

const MAX_FLOWS: usize = 10_000;
const MAX_UNACKED: usize = 256;

/// Tracks live TCP/UDP flows: byte/packet accounting per direction, TCP
/// retransmission detection, and RTT estimation. Flows are evicted on
/// FIN/FIN/RST; when a completion sink is registered the final
/// [`FlowStatsSnapshot`] is emitted before eviction so the daemon never loses a
/// closed connection's totals.
pub struct FlowTracker {
    flows: LruCache<FlowKey, FlowState>,
    local_addrs: HashSet<IpAddr>,
    completed_tx: Option<Sender<FlowStatsSnapshot>>,
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
            local_addrs: HashSet::new(),
            completed_tx: None,
        }
    }

    /// Register a channel that receives the final snapshot of each flow as it
    /// closes (FIN/FIN or RST). Used by the daemon to capture completed flows.
    pub fn with_completion_sink(mut self, tx: Sender<FlowStatsSnapshot>) -> Self {
        self.completed_tx = Some(tx);
        self
    }

    /// Register the set of local host addresses so up/down can be oriented as
    /// local→remote / remote→local.
    pub fn set_local_addrs(&mut self, addrs: HashSet<IpAddr>) {
        self.local_addrs = addrs;
    }

    pub fn update(&mut self, pkt: &mut DecodedPacket) -> Option<FlowUpdate> {
        let info = extract_pkt_flow_info(&pkt.layers)?;
        let key = FlowKey::new(
            info.src_ip,
            info.src_port,
            info.dst_ip,
            info.dst_port,
            info.protocol,
        );
        let is_low = (info.src_ip, info.src_port) <= (info.dst_ip, info.dst_port);
        let dir = if is_low {
            Dir::LowToHigh
        } else {
            Dir::HighToLow
        };
        let ts = pkt.timestamp;
        let wire = pkt.wire_len;
        let first_seen = !self.flows.contains(&key);

        let (annotation, should_close) = {
            let state = self
                .flows
                .get_or_insert_mut(key.clone(), || FlowState::new(ts));
            state.last_seen = ts;
            match dir {
                Dir::LowToHigh => {
                    state.pkts_low_to_high += 1;
                    state.bytes_low_to_high += wire as u64;
                }
                Dir::HighToLow => {
                    state.pkts_high_to_low += 1;
                    state.bytes_high_to_low += wire as u64;
                }
            }

            if let Some(tcp) = info.tcp {
                let mut is_retransmission = false;
                if tcp.payload_len > 0 {
                    let seq_end = tcp.seq as u64 + tcp.payload_len as u64;
                    let max_seq = if is_low {
                        &mut state.max_seq_low
                    } else {
                        &mut state.max_seq_high
                    };
                    match *max_seq {
                        Some(prev) if seq_end <= prev => is_retransmission = true,
                        _ => *max_seq = Some(seq_end),
                    }
                }

                record_rtt(state, is_low, &tcp, ts);

                if tcp.rst {
                    state.rst_seen = true;
                }
                if tcp.fin {
                    if is_low {
                        state.fin_low = true;
                    } else {
                        state.fin_high = true;
                    }
                }
                let should_close = state.rst_seen || (state.fin_low && state.fin_high);

                if is_retransmission {
                    pkt.retransmission = true;
                    pkt.summary.info = format!("[Retransmission] {}", pkt.summary.info);
                    pkt.summary.color_hint = crate::decode::ColorHint::Retransmission;
                }
                (Some(FlowAnnotation { is_retransmission }), should_close)
            } else {
                (None, false)
            }
        };

        if should_close {
            if let (Some(tx), Some(snap)) = (self.completed_tx.clone(), self.stats_for(&key)) {
                let _ = tx.send(snap);
            }
            self.flows.pop(&key);
        }

        Some(FlowUpdate {
            annotation,
            key,
            dir,
            bytes: wire,
            first_seen,
        })
    }

    /// Snapshot every live flow (allocates). Suitable for periodic UI/daemon polling.
    pub fn snapshot(&self) -> Vec<FlowStatsSnapshot> {
        self.flows
            .iter()
            .map(|(k, s)| self.make_snapshot(k, s))
            .collect()
    }

    /// Snapshot a single live flow by key.
    pub fn stats_for(&self, key: &FlowKey) -> Option<FlowStatsSnapshot> {
        self.flows.peek(key).map(|s| self.make_snapshot(key, s))
    }

    fn make_snapshot(&self, key: &FlowKey, state: &FlowState) -> FlowStatsSnapshot {
        let local_is_low = self.local_addrs.contains(&key.addr_low);
        let local_is_high = self.local_addrs.contains(&key.addr_high);
        // Treat low as local unless only high is local.
        let local_low = !matches!((local_is_low, local_is_high), (false, true));

        let (bytes_up, bytes_down, pkts_up, pkts_down, la, lp, ra, rp) = if local_low {
            (
                state.bytes_low_to_high,
                state.bytes_high_to_low,
                state.pkts_low_to_high,
                state.pkts_high_to_low,
                key.addr_low,
                key.port_low,
                key.addr_high,
                key.port_high,
            )
        } else {
            (
                state.bytes_high_to_low,
                state.bytes_low_to_high,
                state.pkts_high_to_low,
                state.pkts_low_to_high,
                key.addr_high,
                key.port_high,
                key.addr_low,
                key.port_low,
            )
        };

        FlowStatsSnapshot {
            key: key.clone(),
            protocol: key.protocol,
            local_addr: Some(la),
            local_port: Some(lp),
            remote_addr: Some(ra),
            remote_port: Some(rp),
            bytes_up,
            bytes_down,
            pkts_up,
            pkts_down,
            first_seen: state.first_seen,
            last_seen: state.last_seen,
            srtt_ms: state.srtt_ms,
            handshake_rtt_ms: state.handshake_rtt_ms,
        }
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

#[derive(Debug, Clone, Copy)]
struct TcpBits {
    seq: u32,
    ack: u32,
    payload_len: usize,
    syn: bool,
    ack_flag: bool,
    fin: bool,
    rst: bool,
}

struct PktFlowInfo {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    tcp: Option<TcpBits>,
}

/// Extract IP + transport identity for TCP and UDP packets (the flows we
/// account). Returns `None` for non-TCP/UDP traffic (ARP/ICMP), which is not
/// connection-oriented.
fn extract_pkt_flow_info(layers: &[Layer]) -> Option<PktFlowInfo> {
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
                return Some(PktFlowInfo {
                    src_ip: src_ip?,
                    dst_ip: dst_ip?,
                    src_port: tcp.src_port,
                    dst_port: tcp.dst_port,
                    protocol: protocol?,
                    tcp: Some(TcpBits {
                        seq: tcp.seq_num,
                        ack: tcp.ack_num,
                        payload_len: tcp.payload_len,
                        syn: tcp.flags.syn,
                        ack_flag: tcp.flags.ack,
                        fin: tcp.flags.fin,
                        rst: tcp.flags.rst,
                    }),
                });
            }
            Layer::Udp(udp) => {
                return Some(PktFlowInfo {
                    src_ip: src_ip?,
                    dst_ip: dst_ip?,
                    src_port: udp.src_port,
                    dst_port: udp.dst_port,
                    protocol: protocol?,
                    tcp: None,
                });
            }
            _ => {}
        }
    }
    None
}

/// Update RTT estimates from one TCP segment: handshake RTT (SYN→SYN/ACK) and
/// smoothed data RTT (payload send time → ACK).
fn record_rtt(state: &mut FlowState, is_low: bool, tcp: &TcpBits, ts: DateTime<Utc>) {
    if tcp.syn && !tcp.ack_flag {
        state.syn_ts.get_or_insert(ts);
    } else if tcp.syn && tcp.ack_flag {
        state.synack_ts.get_or_insert(ts);
        if state.handshake_rtt_ms.is_none() {
            if let Some(syn) = state.syn_ts {
                if let Some(us) = (ts - syn).num_microseconds() {
                    if us >= 0 {
                        state.handshake_rtt_ms = Some(us as f64 / 1000.0);
                    }
                }
            }
        }
    }

    // Record our own outgoing data so the peer's ACK can be timed.
    if tcp.payload_len > 0 {
        let seq_end = tcp.seq.wrapping_add(tcp.payload_len as u32);
        let map = if is_low {
            &mut state.unacked_low
        } else {
            &mut state.unacked_high
        };
        map.entry(seq_end).or_insert(ts);
        while map.len() > MAX_UNACKED {
            let oldest = map.keys().next().copied();
            match oldest {
                Some(k) => {
                    map.remove(&k);
                }
                None => break,
            }
        }
    }

    // An ACK from this side acknowledges data the other side sent.
    if tcp.ack_flag {
        let ack = tcp.ack;
        let acked_keys: Vec<u32> = {
            let other = if is_low {
                &state.unacked_high
            } else {
                &state.unacked_low
            };
            other.range(..=ack).map(|(&k, _)| k).collect()
        };
        for k in acked_keys {
            let send_ts = if is_low {
                state.unacked_high.remove(&k)
            } else {
                state.unacked_low.remove(&k)
            };
            if let Some(send_ts) = send_ts {
                if let Some(us) = (ts - send_ts).num_microseconds() {
                    if us >= 0 {
                        let sample = us as f64 / 1000.0;
                        state.srtt_ms = Some(match state.srtt_ms {
                            Some(prev) => prev * 0.875 + sample * 0.125,
                            None => sample,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use chrono::{Duration, Utc};
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

    fn make_udp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> DecodedPacket {
        DecodedPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: 80,
            data: vec![0u8; 80],
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
                    protocol: 17,
                    checksum: 0,
                    src_ip,
                    dst_ip,
                    header_range: (14, 34),
                }),
                Layer::Udp(UdpHeader {
                    src_port,
                    dst_port,
                    length: 60,
                    checksum: 0,
                    header_range: (34, 42),
                }),
            ],
            summary: PacketSummary {
                source: src_ip.to_string(),
                destination: dst_ip.to_string(),
                protocol: "UDP".into(),
                length: 80,
                info: "test".into(),
                color_hint: ColorHint::Udp,
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
        let u1 = tracker.update(&mut p1).unwrap();
        assert!(!u1.annotation.unwrap().is_retransmission);
        assert!(u1.first_seen);

        let mut p2 = make_tcp_packet(src, dst, 80, 12345, 1100, 100, false, false, false);
        let u2 = tracker.update(&mut p2).unwrap();
        assert!(!u2.annotation.unwrap().is_retransmission);
        assert!(!u2.first_seen);
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
        let u3 = tracker.update(&mut p3).unwrap();
        assert!(u3.annotation.unwrap().is_retransmission);
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

    #[test]
    fn test_byte_accounting() {
        let mut tracker = FlowTracker::new();
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(93, 184, 216, 34);
        tracker.set_local_addrs(HashSet::from([IpAddr::V4(local)]));

        // 2 packets local→remote, 1 packet remote→local
        let mut up1 = make_tcp_packet(local, remote, 50000, 443, 1, 100, false, false, false);
        tracker.update(&mut up1);
        let mut up2 = make_tcp_packet(local, remote, 50000, 443, 101, 100, false, false, false);
        tracker.update(&mut up2);
        let mut down1 = make_tcp_packet(remote, local, 443, 50000, 1, 100, false, false, false);
        tracker.update(&mut down1);

        let snaps = tracker.snapshot();
        assert_eq!(snaps.len(), 1);
        let s = &snaps[0];
        assert_eq!(s.local_addr, Some(IpAddr::V4(local)));
        assert_eq!(s.remote_addr, Some(IpAddr::V4(remote)));
        assert_eq!(s.pkts_up, 2);
        assert_eq!(s.pkts_down, 1);
        assert_eq!(s.bytes_up, 200);
        assert_eq!(s.bytes_down, 100);
    }

    #[test]
    fn test_udp_tracked() {
        let mut tracker = FlowTracker::new();
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let dns = Ipv4Addr::new(1, 1, 1, 1);
        let mut p = make_udp_packet(local, dns, 50000, 53);
        let u = tracker.update(&mut p).unwrap();
        assert!(u.annotation.is_none()); // UDP has no retransmission annotation
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.snapshot()[0].protocol, 17);
    }

    #[test]
    fn test_completion_sink() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut tracker = FlowTracker::new().with_completion_sink(tx);
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        let mut p1 = make_tcp_packet(src, dst, 80, 12345, 1000, 100, false, false, false);
        tracker.update(&mut p1);
        let mut fin1 = make_tcp_packet(src, dst, 80, 12345, 1100, 0, false, true, false);
        tracker.update(&mut fin1);
        let mut fin2 = make_tcp_packet(dst, src, 12345, 80, 2000, 0, false, true, false);
        tracker.update(&mut fin2);

        // Flow evicted, and a final snapshot was emitted with the byte total.
        assert_eq!(tracker.len(), 0);
        let snap = rx.try_recv().expect("completed flow snapshot");
        assert_eq!(snap.bytes_up + snap.bytes_down, 300);
    }

    #[test]
    fn test_handshake_rtt() {
        let mut tracker = FlowTracker::new();
        let client = Ipv4Addr::new(10, 0, 0, 1);
        let server = Ipv4Addr::new(10, 0, 0, 2);

        let base = Utc::now();
        let mut syn = make_tcp_packet(client, server, 50000, 443, 0, 0, true, false, false);
        syn.timestamp = base;
        tracker.update(&mut syn);

        // SYN-ACK 20ms later (syn=true forces ack=false in builder, so set ack manually)
        let mut synack = make_tcp_packet(server, client, 443, 50000, 0, 0, true, false, false);
        synack.timestamp = base + Duration::milliseconds(20);
        if let Layer::Tcp(t) = &mut synack.layers[1] {
            t.flags.ack = true;
        }
        tracker.update(&mut synack);

        let key = FlowKey::new(IpAddr::V4(client), 50000, IpAddr::V4(server), 443, 6);
        let rtt = tracker.stats_for(&key).unwrap().handshake_rtt_ms.unwrap();
        assert!((rtt - 20.0).abs() < 0.5, "handshake rtt = {rtt}");
    }
}

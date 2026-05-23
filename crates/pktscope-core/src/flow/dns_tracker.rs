use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::decode::{DnsInfo, DnsRdata};

struct PendingQuery {
    packet_number: u64,
    timestamp: DateTime<Utc>,
    #[allow(dead_code)]
    qname: String,
}

/// A correlated DNS query/response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPairing {
    /// Packet number of the originating query.
    pub query_packet: u64,
    pub rtt_ms: f64,
    /// Short human-readable summary of the answer records (e.g. "93.184.216.34").
    pub answer_summary: String,
}

/// Correlates DNS queries with responses by transaction id, using packet
/// capture timestamps (not wall-clock) so it works for offline pcap replay.
pub struct DnsTracker {
    pending: HashMap<u16, PendingQuery>,
    cap: usize,
}

impl Default for DnsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            cap: 4096,
        }
    }

    /// Observe a decoded DNS message. Records queries; on a matching response
    /// returns the pairing (with RTT and an answer summary).
    pub fn observe(
        &mut self,
        dns: &DnsInfo,
        packet_number: u64,
        timestamp: DateTime<Utc>,
    ) -> Option<DnsPairing> {
        if !dns.is_response {
            if self.pending.len() >= self.cap {
                if let Some(&k) = self.pending.keys().next() {
                    self.pending.remove(&k);
                }
            }
            let qname = dns
                .questions
                .first()
                .map(|q| q.qname.clone())
                .unwrap_or_default();
            self.pending.insert(
                dns.transaction_id,
                PendingQuery {
                    packet_number,
                    timestamp,
                    qname,
                },
            );
            None
        } else {
            let q = self.pending.remove(&dns.transaction_id)?;
            let rtt_ms = (timestamp - q.timestamp)
                .num_microseconds()
                .map(|us| (us as f64 / 1000.0).max(0.0))
                .unwrap_or(0.0);
            Some(DnsPairing {
                query_packet: q.packet_number,
                rtt_ms,
                answer_summary: summarize_answers(dns),
            })
        }
    }
}

fn summarize_answers(dns: &DnsInfo) -> String {
    let parts: Vec<String> = dns
        .answers
        .iter()
        .filter_map(|r| match &r.rdata {
            DnsRdata::A(ip) => Some(ip.to_string()),
            DnsRdata::Aaaa(ip) => Some(ip.to_string()),
            DnsRdata::Cname(c) => Some(format!("CNAME {c}")),
            _ => None,
        })
        .collect();
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{DnsInfo, DnsQuestion, DnsRdata, DnsRecord};
    use chrono::Duration;

    fn query(txid: u16, qname: &str) -> DnsInfo {
        DnsInfo {
            transaction_id: txid,
            is_response: false,
            rcode: 0,
            questions: vec![DnsQuestion {
                qname: qname.into(),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            header_range: (0, 0),
        }
    }

    fn response(txid: u16, qname: &str, ip: [u8; 4]) -> DnsInfo {
        let mut info = query(txid, qname);
        info.is_response = true;
        info.answers = vec![DnsRecord {
            name: qname.into(),
            rtype: 1,
            rclass: 1,
            ttl: 300,
            rdata: DnsRdata::A(ip.into()),
        }];
        info
    }

    #[test]
    fn test_pairing_rtt() {
        let mut tracker = DnsTracker::new();
        let base = Utc::now();
        assert!(
            tracker
                .observe(&query(0x1234, "example.com"), 1, base)
                .is_none()
        );
        let pairing = tracker
            .observe(
                &response(0x1234, "example.com", [93, 184, 216, 34]),
                2,
                base + Duration::milliseconds(5),
            )
            .expect("pairing");
        assert_eq!(pairing.query_packet, 1);
        assert!((pairing.rtt_ms - 5.0).abs() < 0.5);
        assert_eq!(pairing.answer_summary, "93.184.216.34");
    }

    #[test]
    fn test_mismatched_txid() {
        let mut tracker = DnsTracker::new();
        let base = Utc::now();
        tracker.observe(&query(0x1111, "a.com"), 1, base);
        assert!(
            tracker
                .observe(&response(0x2222, "b.com", [1, 1, 1, 1]), 2, base)
                .is_none()
        );
    }

    #[test]
    fn test_response_without_query() {
        let mut tracker = DnsTracker::new();
        assert!(
            tracker
                .observe(&response(0x9999, "x.com", [1, 1, 1, 1]), 1, Utc::now())
                .is_none()
        );
    }
}

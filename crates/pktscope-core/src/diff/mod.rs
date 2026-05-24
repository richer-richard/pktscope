//! Diff two captures by packet content (a multiset comparison of raw bytes).

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::decode::DecodedPacket;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffResult {
    /// Indices into `a` of packets with no match in `b`.
    pub only_a: Vec<usize>,
    /// Indices into `b` of packets with no match in `a`.
    pub only_b: Vec<usize>,
    /// Number of packets present in both (matched as a multiset).
    pub common: usize,
}

fn content_hash(pkt: &DecodedPacket) -> u64 {
    let mut h = DefaultHasher::new();
    pkt.data.hash(&mut h);
    h.finish()
}

/// Compare two captures by raw packet content, treating duplicates as a multiset.
pub fn diff_by_content(a: &[DecodedPacket], b: &[DecodedPacket]) -> DiffResult {
    let mut b_counts: HashMap<u64, usize> = HashMap::new();
    for p in b {
        *b_counts.entry(content_hash(p)).or_insert(0) += 1;
    }
    let mut a_counts: HashMap<u64, usize> = HashMap::new();
    for p in a {
        *a_counts.entry(content_hash(p)).or_insert(0) += 1;
    }

    let mut remaining_b = b_counts.clone();
    let mut only_a = Vec::new();
    let mut common = 0;
    for (i, p) in a.iter().enumerate() {
        let h = content_hash(p);
        match remaining_b.get_mut(&h) {
            Some(c) if *c > 0 => {
                *c -= 1;
                common += 1;
            }
            _ => only_a.push(i),
        }
    }

    let mut remaining_a = a_counts;
    let mut only_b = Vec::new();
    for (i, p) in b.iter().enumerate() {
        let h = content_hash(p);
        match remaining_a.get_mut(&h) {
            Some(c) if *c > 0 => *c -= 1,
            _ => only_b.push(i),
        }
    }

    DiffResult {
        only_a,
        only_b,
        common,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::*;
    use chrono::Utc;

    fn pkt(data: Vec<u8>) -> DecodedPacket {
        DecodedPacket {
            number: 0,
            timestamp: Utc::now(),
            wire_len: data.len() as u32,
            data,
            layers: vec![],
            summary: PacketSummary {
                source: String::new(),
                destination: String::new(),
                protocol: String::new(),
                length: 0,
                info: String::new(),
                color_hint: ColorHint::Other,
            },
            process: None,
            retransmission: false,
        }
    }

    #[test]
    fn test_diff() {
        let a = vec![pkt(vec![1]), pkt(vec![2]), pkt(vec![3])];
        let b = vec![pkt(vec![2]), pkt(vec![3]), pkt(vec![4])];
        let d = diff_by_content(&a, &b);
        assert_eq!(d.common, 2);
        assert_eq!(d.only_a.len(), 1); // [1]
        assert_eq!(d.only_b.len(), 1); // [4]
    }
}

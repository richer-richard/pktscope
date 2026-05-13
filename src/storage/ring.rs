use std::collections::VecDeque;

use crate::decode::DecodedPacket;

pub struct PacketRing {
    packets: VecDeque<DecodedPacket>,
    capacity: usize,
}

impl PacketRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            packets: VecDeque::with_capacity(capacity.min(8192)),
            capacity,
        }
    }

    pub fn push(&mut self, pkt: DecodedPacket) -> Option<DecodedPacket> {
        let evicted = if self.packets.len() >= self.capacity {
            self.packets.pop_front()
        } else {
            None
        };
        self.packets.push_back(pkt);
        evicted
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&DecodedPacket> {
        self.packets.get(index)
    }

    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = &DecodedPacket> {
        self.packets.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{ColorHint, DecodedPacket, PacketSummary};

    fn dummy_packet(num: u64) -> DecodedPacket {
        DecodedPacket {
            number: num,
            timestamp: chrono::Utc::now(),
            wire_len: 64,
            data: vec![0u8; 64],
            layers: vec![],
            summary: PacketSummary {
                source: "0.0.0.0".into(),
                destination: "0.0.0.0".into(),
                protocol: "TEST".into(),
                length: 64,
                info: String::new(),
                color_hint: ColorHint::Other,
            },
            process: None,
            retransmission: false,
        }
    }

    #[test]
    fn test_push_and_get() {
        let mut ring = PacketRing::new(10);
        ring.push(dummy_packet(0));
        ring.push(dummy_packet(1));
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.get(0).unwrap().number, 0);
        assert_eq!(ring.get(1).unwrap().number, 1);
    }

    #[test]
    fn test_capacity_eviction() {
        let mut ring = PacketRing::new(3);
        for i in 0..5 {
            ring.push(dummy_packet(i));
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.get(0).unwrap().number, 2);
        assert_eq!(ring.get(1).unwrap().number, 3);
        assert_eq!(ring.get(2).unwrap().number, 4);
    }

    #[test]
    fn test_empty() {
        let ring = PacketRing::new(10);
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert!(ring.get(0).is_none());
    }
}

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

const MAX_STREAM_BUFFER: usize = 1024 * 1024;

/// Outcome of inserting a TCP segment into a [`ReassemblyBuffer`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReassemblyResult {
    /// Stored in order at the head (drainable now).
    Contiguous,
    /// Stored ahead of a gap (out of order).
    Gap,
    /// Stored, but neither contiguous nor a clean gap (overlap/partial).
    Buffered,
    /// Already-seen data; ignored.
    Duplicate,
    /// Buffer cap reached; not stored.
    Capped,
}

/// Reassembles one direction of a TCP byte stream from segments that may arrive
/// out of order, duplicated, or overlapping. Sequence comparisons use wrapping
/// (serial-number) arithmetic so the 2^32 wrap is handled correctly.
#[derive(Debug, Default)]
pub struct ReassemblyBuffer {
    /// Contiguous bytes received but not yet drained.
    pending: Vec<u8>,
    /// Out-of-order future segments, keyed by sequence number.
    segments: BTreeMap<u32, Vec<u8>>,
    base_seq: Option<u32>,
    /// Next contiguous sequence number expected (one past `pending`).
    next_seq: u32,
    total_buffered: usize,
    fin: bool,
    capped: bool,
}

/// `a < b` under TCP serial-number arithmetic.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

impl ReassemblyBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_segment(&mut self, seq: u32, data: &[u8]) -> ReassemblyResult {
        if data.is_empty() {
            return ReassemblyResult::Buffered;
        }
        if self.base_seq.is_none() {
            self.base_seq = Some(seq);
            self.next_seq = seq;
        }

        let mut seq = seq;
        let mut data = data;

        // Entirely before next_seq → already consumed.
        let end = seq.wrapping_add(data.len() as u32);
        if !seq_lt(self.next_seq, end) {
            return ReassemblyResult::Duplicate;
        }
        // Overlaps the consumed region → trim the front.
        if seq_lt(seq, self.next_seq) {
            let skip = self.next_seq.wrapping_sub(seq) as usize;
            if skip >= data.len() {
                return ReassemblyResult::Duplicate;
            }
            data = &data[skip..];
            seq = self.next_seq;
        }

        if self.capped {
            return ReassemblyResult::Capped;
        }
        if self.total_buffered + data.len() > MAX_STREAM_BUFFER {
            self.capped = true;
            return ReassemblyResult::Capped;
        }

        if seq == self.next_seq {
            // Contiguous: append and pull in any now-adjacent buffered segments.
            self.pending.extend_from_slice(data);
            self.next_seq = self.next_seq.wrapping_add(data.len() as u32);
            self.total_buffered += data.len();
            while let Some(seg) = self.segments.remove(&self.next_seq) {
                self.next_seq = self.next_seq.wrapping_add(seg.len() as u32);
                self.pending.extend_from_slice(&seg);
            }
            ReassemblyResult::Contiguous
        } else {
            // Future, out-of-order segment.
            match self.segments.entry(seq) {
                Entry::Vacant(v) => {
                    v.insert(data.to_vec());
                    self.total_buffered += data.len();
                }
                Entry::Occupied(_) => return ReassemblyResult::Duplicate,
            }
            ReassemblyResult::Gap
        }
    }

    /// Remove and return the contiguous bytes received so far.
    pub fn try_drain(&mut self) -> Option<Vec<u8>> {
        if self.pending.is_empty() {
            return None;
        }
        self.total_buffered -= self.pending.len();
        Some(std::mem::take(&mut self.pending))
    }

    pub fn mark_fin(&mut self) {
        self.fin = true;
    }

    /// FIN seen and no buffered gaps remain.
    pub fn is_complete(&self) -> bool {
        self.fin && self.segments.is_empty()
    }

    pub fn buffered_len(&self) -> usize {
        self.total_buffered
    }

    pub fn capped(&self) -> bool {
        self.capped
    }
}

/// Both directions of a reassembled TCP conversation.
#[derive(Debug, Clone, Default)]
pub struct StreamData {
    pub client_to_server: Vec<u8>,
    pub server_to_client: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order() {
        let mut b = ReassemblyBuffer::new();
        assert_eq!(
            b.insert_segment(1000, b"hello"),
            ReassemblyResult::Contiguous
        );
        assert_eq!(
            b.insert_segment(1005, b"world"),
            ReassemblyResult::Contiguous
        );
        assert_eq!(b.try_drain().unwrap(), b"helloworld");
        assert!(b.try_drain().is_none());
    }

    #[test]
    fn test_out_of_order() {
        let mut b = ReassemblyBuffer::new();
        assert_eq!(b.insert_segment(1000, b"AAA"), ReassemblyResult::Contiguous);
        // Gap: 1006 arrives before 1003.
        assert_eq!(b.insert_segment(1006, b"CCC"), ReassemblyResult::Gap);
        // Only the contiguous prefix drains.
        assert_eq!(b.try_drain().unwrap(), b"AAA");
        assert!(b.try_drain().is_none());
        // Fill the gap → the rest becomes contiguous.
        assert_eq!(b.insert_segment(1003, b"BBB"), ReassemblyResult::Contiguous);
        assert_eq!(b.try_drain().unwrap(), b"BBBCCC");
    }

    #[test]
    fn test_duplicate_and_overlap() {
        let mut b = ReassemblyBuffer::new();
        b.insert_segment(1000, b"hello");
        assert_eq!(b.try_drain().unwrap(), b"hello");
        // Full retransmit of consumed data.
        assert_eq!(
            b.insert_segment(1000, b"hello"),
            ReassemblyResult::Duplicate
        );
        // Overlapping retransmit: trims to the new tail "p".
        assert_eq!(b.insert_segment(1003, b"lop"), ReassemblyResult::Contiguous);
        assert_eq!(b.try_drain().unwrap(), b"p");
    }

    #[test]
    fn test_seq_wrap() {
        let mut b = ReassemblyBuffer::new();
        let base = 0xFFFF_FFFEu32; // straddles the wrap
        assert_eq!(b.insert_segment(base, b"AB"), ReassemblyResult::Contiguous);
        assert_eq!(
            b.insert_segment(base.wrapping_add(2), b"CD"),
            ReassemblyResult::Contiguous
        );
        assert_eq!(b.try_drain().unwrap(), b"ABCD");
    }

    #[test]
    fn test_cap() {
        let mut b = ReassemblyBuffer::new();
        // First segment anchors; then a giant one trips the cap.
        b.insert_segment(0, b"x");
        b.try_drain();
        let big = vec![0u8; MAX_STREAM_BUFFER + 1];
        assert_eq!(b.insert_segment(1, &big), ReassemblyResult::Capped);
        assert!(b.capped());
    }

    #[test]
    fn test_fin_completion() {
        let mut b = ReassemblyBuffer::new();
        b.insert_segment(1, b"hi");
        b.try_drain();
        assert!(!b.is_complete());
        b.mark_fin();
        assert!(b.is_complete());
    }
}

use super::{QuicInfo, QuicPacketType};

/// Detect and parse a QUIC long-header packet (Initial / 0-RTT / Handshake /
/// Retry / Version Negotiation). Short-header packets are not identified
/// (ambiguous without connection state). SNI extraction would require deriving
/// the Initial keys and decrypting the CRYPTO frame — deferred behind a future
/// `quic-decrypt` feature — so `sni` is always `None` here.
pub fn try_decode_quic(data: &[u8], offset: usize) -> Option<QuicInfo> {
    let d = data.get(offset..)?;
    if d.len() < 6 {
        return None;
    }
    let b0 = d[0];
    // Long header: high bit set. (Fixed bit 0x40 is set for v1 but cleared on
    // version-negotiation packets, so we don't require it.)
    if b0 & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
    let packet_type = if version == 0 {
        QuicPacketType::VersionNegotiation
    } else {
        match (b0 & 0x30) >> 4 {
            0 => QuicPacketType::Initial,
            1 => QuicPacketType::ZeroRtt,
            2 => QuicPacketType::Handshake,
            _ => QuicPacketType::Retry,
        }
    };

    let mut pos = 5;
    let dcid = read_cid(d, &mut pos)?;
    let scid = read_cid(d, &mut pos)?;

    Some(QuicInfo {
        long_header: true,
        version: Some(version),
        packet_type,
        dcid,
        scid,
        sni: None,
        header_range: (offset, offset + pos.min(d.len())),
    })
}

/// Read an 8-bit-length-prefixed connection id.
fn read_cid(d: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = *d.get(*pos)? as usize;
    *pos += 1;
    if len > 20 || *pos + len > d.len() {
        return None;
    }
    let cid = d[*pos..*pos + len].to_vec();
    *pos += len;
    Some(cid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_packet() {
        // Long header (0xC0=long+fixed, type Initial=0), version 1, dcid len 4, scid len 0.
        let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x04, 1, 2, 3, 4, 0x00];
        pkt.extend_from_slice(&[0xAA; 8]); // (token/length/payload — ignored)
        let q = try_decode_quic(&pkt, 0).unwrap();
        assert!(q.long_header);
        assert_eq!(q.version, Some(1));
        assert_eq!(q.packet_type, QuicPacketType::Initial);
        assert_eq!(q.dcid, vec![1, 2, 3, 4]);
        assert!(q.scid.is_empty());
        assert!(q.sni.is_none());
    }

    #[test]
    fn test_version_negotiation() {
        let pkt = vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let q = try_decode_quic(&pkt, 0).unwrap();
        assert_eq!(q.packet_type, QuicPacketType::VersionNegotiation);
        assert_eq!(q.version, Some(0));
    }

    #[test]
    fn test_short_header_ignored() {
        let pkt = vec![0x40, 1, 2, 3, 4, 5];
        assert!(try_decode_quic(&pkt, 0).is_none());
    }
}

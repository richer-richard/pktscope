use super::{DecodeResult, EthernetHeader, Layer, MacAddr, NextDecode};

pub fn decode_ethernet(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 14 {
        return None;
    }

    let dst_mac = MacAddr([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
    ]);
    let src_mac = MacAddr([
        data[offset + 6],
        data[offset + 7],
        data[offset + 8],
        data[offset + 9],
        data[offset + 10],
        data[offset + 11],
    ]);
    let ethertype = u16::from_be_bytes([data[offset + 12], data[offset + 13]]);

    let next = match ethertype {
        0x0800 => Some(NextDecode::Ipv4),
        0x0806 => Some(NextDecode::Arp),
        0x86DD => Some(NextDecode::Ipv6),
        _ => None,
    };

    Some(DecodeResult {
        layer: Layer::Ethernet(EthernetHeader {
            src_mac,
            dst_mac,
            ethertype,
            header_range: (offset, offset + 14),
        }),
        next,
        next_offset: offset + 14,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ethernet_ipv4() {
        let frame = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // src
            0x08, 0x00, // ethertype IPv4
        ];
        let result = decode_ethernet(&frame, 0).unwrap();
        if let Layer::Ethernet(eth) = &result.layer {
            assert_eq!(eth.dst_mac, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
            assert_eq!(eth.src_mac, MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
            assert_eq!(eth.ethertype, 0x0800);
            assert_eq!(eth.header_range, (0, 14));
        } else {
            panic!("Expected Ethernet layer");
        }
        assert!(matches!(result.next, Some(NextDecode::Ipv4)));
        assert_eq!(result.next_offset, 14);
    }

    #[test]
    fn test_decode_ethernet_arp() {
        let mut frame = [0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x06;
        let result = decode_ethernet(&frame, 0).unwrap();
        assert!(matches!(result.next, Some(NextDecode::Arp)));
    }

    #[test]
    fn test_decode_ethernet_ipv6() {
        let mut frame = [0u8; 14];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        let result = decode_ethernet(&frame, 0).unwrap();
        assert!(matches!(result.next, Some(NextDecode::Ipv6)));
    }

    #[test]
    fn test_decode_ethernet_too_short() {
        let frame = [0u8; 13];
        assert!(decode_ethernet(&frame, 0).is_none());
    }

    #[test]
    fn test_decode_ethernet_unknown_type() {
        let mut frame = [0u8; 14];
        frame[12] = 0xFF;
        frame[13] = 0xFF;
        let result = decode_ethernet(&frame, 0).unwrap();
        assert!(result.next.is_none());
    }
}

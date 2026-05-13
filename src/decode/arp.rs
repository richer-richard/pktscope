use std::net::Ipv4Addr;

use super::{ArpHeader, DecodeResult, Layer, MacAddr};

pub fn decode_arp(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 28 {
        return None;
    }

    let o = offset;
    let hw_type = u16::from_be_bytes([data[o], data[o + 1]]);
    let proto_type = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let _hw_len = data[o + 4];
    let _proto_len = data[o + 5];
    let operation = u16::from_be_bytes([data[o + 6], data[o + 7]]);

    let sender_mac = MacAddr([
        data[o + 8],
        data[o + 9],
        data[o + 10],
        data[o + 11],
        data[o + 12],
        data[o + 13],
    ]);
    let sender_ip = Ipv4Addr::new(data[o + 14], data[o + 15], data[o + 16], data[o + 17]);
    let target_mac = MacAddr([
        data[o + 18],
        data[o + 19],
        data[o + 20],
        data[o + 21],
        data[o + 22],
        data[o + 23],
    ]);
    let target_ip = Ipv4Addr::new(data[o + 24], data[o + 25], data[o + 26], data[o + 27]);

    Some(DecodeResult {
        layer: Layer::Arp(ArpHeader {
            hw_type,
            proto_type,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
            header_range: (offset, offset + 28),
        }),
        next: None,
        next_offset: offset + 28,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_arp_request() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x00;
        pkt[1] = 0x01; // hw_type = Ethernet
        pkt[2] = 0x08;
        pkt[3] = 0x00; // proto_type = IPv4
        pkt[4] = 6; // hw_len
        pkt[5] = 4; // proto_len
        pkt[6] = 0x00;
        pkt[7] = 0x01; // operation = request
        // sender mac
        pkt[8..14].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // sender ip = 192.168.1.1
        pkt[14..18].copy_from_slice(&[192, 168, 1, 1]);
        // target mac = 00:00:00:00:00:00
        // target ip = 192.168.1.2
        pkt[24..28].copy_from_slice(&[192, 168, 1, 2]);

        let result = decode_arp(&pkt, 0).unwrap();
        if let Layer::Arp(arp) = &result.layer {
            assert_eq!(arp.operation, 1);
            assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 2));
            assert_eq!(
                arp.sender_mac,
                MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            );
        } else {
            panic!("Expected ARP layer");
        }
        assert!(result.next.is_none());
    }

    #[test]
    fn test_decode_arp_too_short() {
        assert!(decode_arp(&[0u8; 27], 0).is_none());
    }
}

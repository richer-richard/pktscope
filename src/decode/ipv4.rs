use std::net::Ipv4Addr;

use super::{DecodeResult, Ipv4Header, Layer, NextDecode};

pub fn decode_ipv4(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 20 {
        return None;
    }

    let o = offset;
    let ver_ihl = data[o];
    let version = ver_ihl >> 4;
    let ihl = ver_ihl & 0x0F;

    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = (ihl as usize) * 4;
    if remaining < header_len {
        return None;
    }

    let dscp_ecn = data[o + 1];
    let dscp = dscp_ecn >> 2;
    let ecn = dscp_ecn & 0x03;
    let total_length = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let identification = u16::from_be_bytes([data[o + 4], data[o + 5]]);
    let flags_frag = u16::from_be_bytes([data[o + 6], data[o + 7]]);
    let flags = (flags_frag >> 13) as u8;
    let fragment_offset = flags_frag & 0x1FFF;
    let ttl = data[o + 8];
    let protocol = data[o + 9];
    let checksum = u16::from_be_bytes([data[o + 10], data[o + 11]]);
    let src_ip = Ipv4Addr::new(data[o + 12], data[o + 13], data[o + 14], data[o + 15]);
    let dst_ip = Ipv4Addr::new(data[o + 16], data[o + 17], data[o + 18], data[o + 19]);

    let next = match protocol {
        1 => Some(NextDecode::Icmp),
        6 => Some(NextDecode::Tcp),
        17 => Some(NextDecode::Udp),
        _ => None,
    };

    Some(DecodeResult {
        layer: Layer::Ipv4(Ipv4Header {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
            header_range: (offset, offset + header_len),
        }),
        next,
        next_offset: offset + header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_header() -> Vec<u8> {
        vec![
            0x45, 0x00, // ver=4, ihl=5, dscp=0, ecn=0
            0x00, 0x3c, // total_len=60
            0xab, 0xcd, // id
            0x40, 0x00, // flags=DF, frag=0
            0x40, 0x06, // ttl=64, proto=TCP
            0x00, 0x00, // checksum
            0x0a, 0x00, 0x00, 0x01, // src=10.0.0.1
            0xc0, 0xa8, 0x01, 0x01, // dst=192.168.1.1
        ]
    }

    #[test]
    fn test_decode_ipv4_tcp() {
        let data = make_ipv4_header();
        let result = decode_ipv4(&data, 0).unwrap();
        if let Layer::Ipv4(ip) = &result.layer {
            assert_eq!(ip.version, 4);
            assert_eq!(ip.ihl, 5);
            assert_eq!(ip.ttl, 64);
            assert_eq!(ip.protocol, 6);
            assert_eq!(ip.src_ip, Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(ip.dst_ip, Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(ip.total_length, 60);
            assert_eq!(ip.header_range, (0, 20));
        } else {
            panic!("Expected IPv4 layer");
        }
        assert!(matches!(result.next, Some(NextDecode::Tcp)));
        assert_eq!(result.next_offset, 20);
    }

    #[test]
    fn test_decode_ipv4_udp() {
        let mut data = make_ipv4_header();
        data[9] = 17; // UDP
        let result = decode_ipv4(&data, 0).unwrap();
        assert!(matches!(result.next, Some(NextDecode::Udp)));
    }

    #[test]
    fn test_decode_ipv4_icmp() {
        let mut data = make_ipv4_header();
        data[9] = 1; // ICMP
        let result = decode_ipv4(&data, 0).unwrap();
        assert!(matches!(result.next, Some(NextDecode::Icmp)));
    }

    #[test]
    fn test_decode_ipv4_too_short() {
        assert!(decode_ipv4(&[0x45; 19], 0).is_none());
    }

    #[test]
    fn test_decode_ipv4_bad_version() {
        let mut data = make_ipv4_header();
        data[0] = 0x65; // version 6
        assert!(decode_ipv4(&data, 0).is_none());
    }
}

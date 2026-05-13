use std::net::Ipv6Addr;

use super::{DecodeResult, Ipv6Header, Layer, NextDecode};

pub fn decode_ipv6(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 40 {
        return None;
    }

    let o = offset;
    let ver_tc_fl = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let version = (ver_tc_fl >> 28) as u8;
    if version != 6 {
        return None;
    }
    let traffic_class = ((ver_tc_fl >> 20) & 0xFF) as u8;
    let flow_label = ver_tc_fl & 0x000F_FFFF;

    let payload_length = u16::from_be_bytes([data[o + 4], data[o + 5]]);
    let next_header = data[o + 6];
    let hop_limit = data[o + 7];

    let src_bytes: [u8; 16] = data[o + 8..o + 24].try_into().ok()?;
    let dst_bytes: [u8; 16] = data[o + 24..o + 40].try_into().ok()?;
    let src_ip = Ipv6Addr::from(src_bytes);
    let dst_ip = Ipv6Addr::from(dst_bytes);

    let next = match next_header {
        6 => Some(NextDecode::Tcp),
        17 => Some(NextDecode::Udp),
        58 => Some(NextDecode::Icmpv6),
        _ => None,
    };

    Some(DecodeResult {
        layer: Layer::Ipv6(Ipv6Header {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src_ip,
            dst_ip,
            header_range: (offset, offset + 40),
        }),
        next,
        next_offset: offset + 40,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv6_header(next_header: u8) -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[0] = 0x60; // version=6, tc=0
        h[4] = 0x00;
        h[5] = 0x14; // payload_length=20
        h[6] = next_header;
        h[7] = 64; // hop_limit
        // src = ::1
        h[23] = 1;
        // dst = ::2
        h[39] = 2;
        h
    }

    #[test]
    fn test_decode_ipv6_tcp() {
        let data = make_ipv6_header(6);
        let result = decode_ipv6(&data, 0).unwrap();
        if let Layer::Ipv6(ip) = &result.layer {
            assert_eq!(ip.version, 6);
            assert_eq!(ip.next_header, 6);
            assert_eq!(ip.hop_limit, 64);
            assert_eq!(ip.src_ip, "::1".parse::<Ipv6Addr>().unwrap());
            assert_eq!(ip.dst_ip, "::2".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("Expected IPv6 layer");
        }
        assert!(matches!(result.next, Some(NextDecode::Tcp)));
    }

    #[test]
    fn test_decode_ipv6_udp() {
        let data = make_ipv6_header(17);
        let result = decode_ipv6(&data, 0).unwrap();
        assert!(matches!(result.next, Some(NextDecode::Udp)));
    }

    #[test]
    fn test_decode_ipv6_icmpv6() {
        let data = make_ipv6_header(58);
        let result = decode_ipv6(&data, 0).unwrap();
        assert!(matches!(result.next, Some(NextDecode::Icmpv6)));
    }

    #[test]
    fn test_decode_ipv6_too_short() {
        assert!(decode_ipv6(&[0x60; 39], 0).is_none());
    }
}

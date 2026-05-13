use super::{DecodeResult, Icmpv6Header, Layer};

pub fn decode_icmpv6(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 8 {
        return None;
    }

    let o = offset;
    let icmp_type = data[o];
    let code = data[o + 1];
    let checksum = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let rest = u32::from_be_bytes([data[o + 4], data[o + 5], data[o + 6], data[o + 7]]);

    Some(DecodeResult {
        layer: Layer::Icmpv6(Icmpv6Header {
            icmp_type,
            code,
            checksum,
            rest,
            header_range: (offset, offset + 8),
        }),
        next: None,
        next_offset: offset + 8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_icmpv6_echo_request() {
        let mut data = vec![0u8; 8];
        data[0] = 128; // ICMPv6 Echo Request
        data[1] = 0;
        let result = decode_icmpv6(&data, 0).unwrap();
        if let Layer::Icmpv6(icmp) = &result.layer {
            assert_eq!(icmp.icmp_type, 128);
            assert_eq!(icmp.code, 0);
        } else {
            panic!("Expected ICMPv6 layer");
        }
        assert!(result.next.is_none());
    }

    #[test]
    fn test_decode_icmpv6_too_short() {
        assert!(decode_icmpv6(&[0u8; 7], 0).is_none());
    }
}

use super::{DecodeResult, IcmpHeader, Layer};

pub fn decode_icmp(data: &[u8], offset: usize) -> Option<DecodeResult> {
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
        layer: Layer::Icmp(IcmpHeader {
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
    fn test_decode_icmp_echo_request() {
        let mut data = vec![0u8; 8];
        data[0] = 8; // Echo Request
        data[1] = 0; // Code 0
        let result = decode_icmp(&data, 0).unwrap();
        if let Layer::Icmp(icmp) = &result.layer {
            assert_eq!(icmp.icmp_type, 8);
            assert_eq!(icmp.code, 0);
        } else {
            panic!("Expected ICMP layer");
        }
        assert!(result.next.is_none());
    }

    #[test]
    fn test_decode_icmp_echo_reply() {
        let mut data = vec![0u8; 8];
        data[0] = 0; // Echo Reply
        let result = decode_icmp(&data, 0).unwrap();
        if let Layer::Icmp(icmp) = &result.layer {
            assert_eq!(icmp.icmp_type, 0);
        } else {
            panic!("Expected ICMP layer");
        }
    }

    #[test]
    fn test_decode_icmp_too_short() {
        assert!(decode_icmp(&[0u8; 7], 0).is_none());
    }
}

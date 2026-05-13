use super::{DecodeResult, Layer, NextDecode, TransportHint, UdpHeader};

pub fn decode_udp(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 8 {
        return None;
    }

    let o = offset;
    let src_port = u16::from_be_bytes([data[o], data[o + 1]]);
    let dst_port = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let length = u16::from_be_bytes([data[o + 4], data[o + 5]]);
    let checksum = u16::from_be_bytes([data[o + 6], data[o + 7]]);

    let payload_len = remaining.saturating_sub(8);

    Some(DecodeResult {
        layer: Layer::Udp(UdpHeader {
            src_port,
            dst_port,
            length,
            checksum,
            header_range: (offset, offset + 8),
        }),
        next: if payload_len > 0 {
            Some(NextDecode::ApplicationPayload {
                transport: TransportHint {
                    src_port,
                    dst_port,
                    is_tcp: false,
                },
            })
        } else {
            None
        },
        next_offset: offset + 8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_udp() {
        let mut data = vec![0u8; 12];
        data[0..2].copy_from_slice(&53u16.to_be_bytes()); // src=53
        data[2..4].copy_from_slice(&12345u16.to_be_bytes()); // dst=12345
        data[4..6].copy_from_slice(&12u16.to_be_bytes()); // length=12
        let result = decode_udp(&data, 0).unwrap();
        if let Layer::Udp(udp) = &result.layer {
            assert_eq!(udp.src_port, 53);
            assert_eq!(udp.dst_port, 12345);
            assert_eq!(udp.length, 12);
        } else {
            panic!("Expected UDP layer");
        }
        assert!(matches!(
            result.next,
            Some(NextDecode::ApplicationPayload { .. })
        ));
    }

    #[test]
    fn test_decode_udp_too_short() {
        assert!(decode_udp(&[0u8; 7], 0).is_none());
    }

    #[test]
    fn test_decode_udp_no_payload() {
        let mut data = vec![0u8; 8];
        data[0..2].copy_from_slice(&1234u16.to_be_bytes());
        data[2..4].copy_from_slice(&5678u16.to_be_bytes());
        data[4..6].copy_from_slice(&8u16.to_be_bytes());
        let result = decode_udp(&data, 0).unwrap();
        assert!(result.next.is_none());
    }
}

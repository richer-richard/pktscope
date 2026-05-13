use super::{DecodeResult, Layer, NextDecode, TcpFlags, TcpHeader, TransportHint};

pub fn decode_tcp(data: &[u8], offset: usize) -> Option<DecodeResult> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 20 {
        return None;
    }

    let o = offset;
    let src_port = u16::from_be_bytes([data[o], data[o + 1]]);
    let dst_port = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let seq_num = u32::from_be_bytes([data[o + 4], data[o + 5], data[o + 6], data[o + 7]]);
    let ack_num = u32::from_be_bytes([data[o + 8], data[o + 9], data[o + 10], data[o + 11]]);
    let data_offset = data[o + 12] >> 4;

    if data_offset < 5 {
        return None;
    }
    let header_len = (data_offset as usize) * 4;
    if remaining < header_len {
        return None;
    }

    let flag_bits = data[o + 13];
    let flags = TcpFlags::from_bits(flag_bits);
    let window_size = u16::from_be_bytes([data[o + 14], data[o + 15]]);
    let checksum = u16::from_be_bytes([data[o + 16], data[o + 17]]);
    let urgent_pointer = u16::from_be_bytes([data[o + 18], data[o + 19]]);

    let payload_len = remaining.saturating_sub(header_len);

    Some(DecodeResult {
        layer: Layer::Tcp(TcpHeader {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            payload_len,
            header_range: (offset, offset + header_len),
        }),
        next: if payload_len > 0 {
            Some(NextDecode::ApplicationPayload {
                transport: TransportHint {
                    src_port,
                    dst_port,
                    is_tcp: true,
                },
            })
        } else {
            None
        },
        next_offset: offset + header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_header(src: u16, dst: u16, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0..2].copy_from_slice(&src.to_be_bytes());
        h[2..4].copy_from_slice(&dst.to_be_bytes());
        h[4..8].copy_from_slice(&1000u32.to_be_bytes()); // seq
        h[8..12].copy_from_slice(&500u32.to_be_bytes()); // ack
        h[12] = 0x50; // data_offset=5
        h[13] = flags;
        h[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
        h
    }

    #[test]
    fn test_decode_tcp_syn() {
        let data = make_tcp_header(80, 12345, 0x02);
        let result = decode_tcp(&data, 0).unwrap();
        if let Layer::Tcp(tcp) = &result.layer {
            assert_eq!(tcp.src_port, 80);
            assert_eq!(tcp.dst_port, 12345);
            assert_eq!(tcp.seq_num, 1000);
            assert_eq!(tcp.ack_num, 500);
            assert!(tcp.flags.syn);
            assert!(!tcp.flags.ack);
            assert_eq!(tcp.payload_len, 0);
        } else {
            panic!("Expected TCP layer");
        }
        assert!(result.next.is_none()); // no payload
    }

    #[test]
    fn test_decode_tcp_with_payload() {
        let mut data = make_tcp_header(443, 50000, 0x18); // PSH+ACK
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // 4 bytes payload
        let result = decode_tcp(&data, 0).unwrap();
        if let Layer::Tcp(tcp) = &result.layer {
            assert!(tcp.flags.psh);
            assert!(tcp.flags.ack);
            assert_eq!(tcp.payload_len, 4);
        } else {
            panic!("Expected TCP layer");
        }
        assert!(matches!(
            result.next,
            Some(NextDecode::ApplicationPayload { .. })
        ));
    }

    #[test]
    fn test_decode_tcp_flags() {
        let f = TcpFlags::from_bits(0x12); // SYN+ACK
        assert!(f.syn);
        assert!(f.ack);
        assert!(!f.fin);
        assert_eq!(f.display(), "[SYN, ACK]");
    }

    #[test]
    fn test_decode_tcp_too_short() {
        assert!(decode_tcp(&[0u8; 19], 0).is_none());
    }
}

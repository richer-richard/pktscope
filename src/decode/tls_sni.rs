use super::TlsClientHelloInfo;

pub fn try_decode_tls_client_hello(data: &[u8], offset: usize) -> Option<TlsClientHelloInfo> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 6 {
        return None;
    }

    let o = offset;

    // TLS record: content_type=0x16 (Handshake)
    if data[o] != 0x16 {
        return None;
    }

    // TLS version (major.minor) — we accept any
    // Record length
    let record_len = u16::from_be_bytes([data[o + 3], data[o + 4]]) as usize;
    if remaining < 5 + record_len || record_len < 4 {
        return None;
    }

    let hs_offset = o + 5;

    // Handshake type: 0x01 = Client Hello
    if data[hs_offset] != 0x01 {
        return None;
    }

    // Handshake length (3 bytes)
    let hs_len = ((data[hs_offset + 1] as usize) << 16)
        | ((data[hs_offset + 2] as usize) << 8)
        | (data[hs_offset + 3] as usize);

    let ch_start = hs_offset + 4;
    let ch_end = ch_start + hs_len;
    if ch_end > data.len() {
        return None;
    }

    // Client Hello:
    //   2 bytes client version
    //   32 bytes random
    //   1 byte session_id_len + session_id
    //   2 bytes cipher_suites_len + cipher_suites
    //   1 byte compression_methods_len + compression_methods
    //   2 bytes extensions_len + extensions

    let mut pos = ch_start;
    pos += 2; // client version
    pos += 32; // random
    if pos >= ch_end {
        return Some(TlsClientHelloInfo {
            sni: None,
            header_range: (offset, ch_end.min(data.len())),
        });
    }

    // Session ID
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > ch_end {
        return Some(TlsClientHelloInfo {
            sni: None,
            header_range: (offset, ch_end.min(data.len())),
        });
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= ch_end {
        return Some(TlsClientHelloInfo {
            sni: None,
            header_range: (offset, ch_end.min(data.len())),
        });
    }

    // Compression methods
    let cm_len = data[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > ch_end {
        return Some(TlsClientHelloInfo {
            sni: None,
            header_range: (offset, ch_end.min(data.len())),
        });
    }

    // Extensions
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > ch_end {
        return Some(TlsClientHelloInfo {
            sni: None,
            header_range: (offset, ch_end.min(data.len())),
        });
    }

    // Walk extensions to find SNI (type 0x0000)
    let sni = parse_sni_extension(data, pos, ext_end);

    Some(TlsClientHelloInfo {
        sni,
        header_range: (offset, ch_end.min(data.len())),
    })
}

fn parse_sni_extension(data: &[u8], mut pos: usize, ext_end: usize) -> Option<String> {
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            // SNI list length (2 bytes)
            if pos + 2 > ext_end || pos + 2 > data.len() {
                return None;
            }
            let _sni_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;

            // SNI type (1 byte, 0x00 = hostname)
            if pos >= ext_end || pos >= data.len() {
                return None;
            }
            let sni_type = data[pos];
            pos += 1;

            if sni_type != 0x00 {
                return None;
            }

            // Hostname length (2 bytes)
            if pos + 2 > ext_end || pos + 2 > data.len() {
                return None;
            }
            let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + name_len > data.len() {
                return None;
            }

            return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
        }

        pos += ext_data_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: &str) -> Vec<u8> {
        // Build a minimal TLS Client Hello with SNI extension
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len(); // list_len + type + name_len + name
        let sni_ext_len = 4 + sni_ext_data_len; // ext_type(2) + ext_data_len(2) + data
        let extensions_len = sni_ext_len;

        let session_id_len: usize = 0;
        let cipher_suites_len: usize = 2; // one cipher suite
        let compression_len: usize = 1; // one compression method

        let ch_body_len = 2 + 32 + 1 + session_id_len + 2 + cipher_suites_len + 1
            + compression_len
            + 2
            + extensions_len;

        let mut pkt = Vec::new();

        // TLS record header
        pkt.push(0x16); // content type: Handshake
        pkt.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        let record_len = (4 + ch_body_len) as u16;
        pkt.extend_from_slice(&record_len.to_be_bytes());

        // Handshake header
        pkt.push(0x01); // Client Hello
        let hs_len = ch_body_len as u32;
        pkt.push((hs_len >> 16) as u8);
        pkt.push((hs_len >> 8) as u8);
        pkt.push(hs_len as u8);

        // Client Hello body
        pkt.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        pkt.extend_from_slice(&[0u8; 32]); // random

        pkt.push(0); // session_id_len = 0

        pkt.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA

        pkt.push(compression_len as u8);
        pkt.push(0x00); // null compression

        // Extensions
        pkt.extend_from_slice(&(extensions_len as u16).to_be_bytes());

        // SNI extension
        pkt.extend_from_slice(&[0x00, 0x00]); // extension type = SNI
        pkt.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let sni_list_len = (1 + 2 + sni_bytes.len()) as u16;
        pkt.extend_from_slice(&sni_list_len.to_be_bytes());
        pkt.push(0x00); // host_name type
        pkt.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(sni_bytes);

        pkt
    }

    #[test]
    fn test_extract_sni() {
        let data = build_client_hello("example.com");
        let result = try_decode_tls_client_hello(&data, 0).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_extract_sni_github() {
        let data = build_client_hello("github.com");
        let result = try_decode_tls_client_hello(&data, 0).unwrap();
        assert_eq!(result.sni.as_deref(), Some("github.com"));
    }

    #[test]
    fn test_not_handshake() {
        let data = [0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(try_decode_tls_client_hello(&data, 0).is_none());
    }

    #[test]
    fn test_too_short() {
        assert!(try_decode_tls_client_hello(&[0x16, 0x03], 0).is_none());
    }
}

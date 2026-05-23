use super::ja;
use super::{TlsClientHelloInfo, TlsHandshakeInfo, TlsHandshakeMessage};

struct TlsRecord<'a> {
    handshake_type: u8,
    body: &'a [u8],
    end: usize,
}

/// Parse the outer TLS record + handshake header, returning the handshake
/// message body slice. Only handles a single handshake record starting at
/// `offset` (content type 0x16).
fn parse_tls_record(data: &[u8], offset: usize) -> Option<TlsRecord<'_>> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 6 || data[offset] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
    if remaining < 5 + record_len || record_len < 4 {
        return None;
    }
    let hs = offset + 5;
    let handshake_type = data[hs];
    let hs_len =
        ((data[hs + 1] as usize) << 16) | ((data[hs + 2] as usize) << 8) | (data[hs + 3] as usize);
    let body_start = hs + 4;
    let body_end = body_start + hs_len;
    if body_end > data.len() {
        return None;
    }
    Some(TlsRecord {
        handshake_type,
        body: &data[body_start..body_end],
        end: body_end,
    })
}

#[derive(Default)]
struct ExtData {
    types: Vec<u16>,
    sni: Option<String>,
    alpn: Vec<String>,
    groups: Vec<u16>,
    formats: Vec<u8>,
    sig_algs: Vec<u16>,
    versions: Vec<u16>,
}

/// Decode a TLS ClientHello, extracting SNI, ALPN, cipher suites, extensions,
/// curves, signature algorithms, and computing JA3/JA4 fingerprints.
pub fn try_decode_tls_client_hello(data: &[u8], offset: usize) -> Option<TlsClientHelloInfo> {
    let rec = parse_tls_record(data, offset)?;
    if rec.handshake_type != 0x01 {
        return None;
    }
    let body = rec.body;
    let end = rec.end;
    let minimal = |legacy: u16| TlsClientHelloInfo {
        sni: None,
        alpn: vec![],
        cipher_suites: vec![],
        extensions: vec![],
        supported_groups: vec![],
        ec_point_formats: vec![],
        signature_algorithms: vec![],
        supported_versions: vec![],
        legacy_version: legacy,
        ja3: None,
        ja4: None,
        header_range: (offset, end.min(data.len())),
    };

    if body.len() < 34 {
        return Some(minimal(0));
    }
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut p = 34; // version(2) + random(32)

    // Session id.
    if p >= body.len() {
        return Some(minimal(legacy_version));
    }
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    if p + 2 > body.len() {
        return Some(minimal(legacy_version));
    }

    // Cipher suites.
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if p + cs_len > body.len() {
        return Some(minimal(legacy_version));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    let mut i = 0;
    while i + 1 < cs_len {
        cipher_suites.push(u16::from_be_bytes([body[p + i], body[p + i + 1]]));
        i += 2;
    }
    p += cs_len;

    // Compression methods.
    if p >= body.len() {
        return Some(minimal(legacy_version));
    }
    let cm_len = body[p] as usize;
    p += 1 + cm_len;

    // Extensions.
    let mut exts = ExtData::default();
    if p + 2 <= body.len() {
        let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let ext_end = (p + ext_len).min(body.len());
        parse_extensions(&body[p..ext_end], &mut exts);
    }

    let best_version = exts
        .versions
        .iter()
        .copied()
        .filter(|&v| !ja::is_grease(v))
        .max()
        .unwrap_or(legacy_version);
    let ja3s = ja::ja3_string(
        legacy_version,
        &cipher_suites,
        &exts.types,
        &exts.groups,
        &exts.formats,
    );
    let ja3 = Some(ja::ja3_hash(&ja3s));
    let ja4 = Some(ja::ja4(
        best_version,
        false,
        exts.sni.is_some(),
        &cipher_suites,
        &exts.types,
        &exts.sig_algs,
        exts.alpn.first().map(|s| s.as_str()),
    ));

    Some(TlsClientHelloInfo {
        sni: exts.sni,
        alpn: exts.alpn,
        cipher_suites,
        extensions: exts.types,
        supported_groups: exts.groups,
        ec_point_formats: exts.formats,
        signature_algorithms: exts.sig_algs,
        supported_versions: exts.versions,
        legacy_version,
        ja3,
        ja4,
        header_range: (offset, end.min(data.len())),
    })
}

/// Decode a non-ClientHello TLS handshake record (ServerHello, Certificate, …).
pub fn try_decode_tls_handshake(data: &[u8], offset: usize) -> Option<TlsHandshakeInfo> {
    let rec = parse_tls_record(data, offset)?;
    let message = match rec.handshake_type {
        0x01 => return None, // ClientHello handled separately.
        0x02 => parse_server_hello(rec.body),
        0x0b => TlsHandshakeMessage::Certificate {
            cert_count: count_certs(rec.body),
        },
        other => TlsHandshakeMessage::Other { msg_type: other },
    };
    Some(TlsHandshakeInfo {
        messages: vec![message],
        header_range: (offset, rec.end.min(data.len())),
    })
}

fn parse_server_hello(body: &[u8]) -> TlsHandshakeMessage {
    let mut alpn = Vec::new();
    let mut version = 0u16;
    let mut cipher_suite = 0u16;
    if body.len() >= 34 {
        version = u16::from_be_bytes([body[0], body[1]]);
        let mut p = 34;
        if p < body.len() {
            let sid_len = body[p] as usize;
            p += 1 + sid_len;
            if p + 2 <= body.len() {
                cipher_suite = u16::from_be_bytes([body[p], body[p + 1]]);
                p += 2 + 1; // cipher + compression method
                if p + 2 <= body.len() {
                    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
                    p += 2;
                    let ext_end = (p + ext_len).min(body.len());
                    let mut exts = ExtData::default();
                    parse_extensions(&body[p..ext_end], &mut exts);
                    alpn = exts.alpn;
                    if let Some(v) = exts.versions.iter().copied().find(|&v| !ja::is_grease(v)) {
                        version = v;
                    }
                }
            }
        }
    }
    TlsHandshakeMessage::ServerHello {
        version,
        cipher_suite,
        alpn,
    }
}

fn count_certs(body: &[u8]) -> usize {
    // TLS 1.2 Certificate: 3-byte total length, then 3-byte-len entries.
    if body.len() < 3 {
        return 0;
    }
    let total = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | (body[2] as usize);
    let end = (3 + total).min(body.len());
    let mut p = 3;
    let mut count = 0;
    while p + 3 <= end {
        let len =
            ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | (body[p + 2] as usize);
        p += 3 + len;
        if p > end {
            break;
        }
        count += 1;
    }
    count
}

fn parse_extensions(ext: &[u8], out: &mut ExtData) {
    let mut p = 0;
    while p + 4 <= ext.len() {
        let etype = u16::from_be_bytes([ext[p], ext[p + 1]]);
        let elen = u16::from_be_bytes([ext[p + 2], ext[p + 3]]) as usize;
        p += 4;
        if p + elen > ext.len() {
            break;
        }
        let edata = &ext[p..p + elen];
        out.types.push(etype);
        match etype {
            0x0000 => out.sni = parse_sni(edata),
            0x000a => out.groups = parse_u16_list_2(edata),
            0x000b => out.formats = parse_u8_list_1(edata),
            0x000d => out.sig_algs = parse_u16_list_2(edata),
            0x0010 => out.alpn = parse_alpn(edata),
            0x002b => out.versions = parse_u16_list_1(edata),
            _ => {}
        }
        p += elen;
    }
}

fn parse_sni(edata: &[u8]) -> Option<String> {
    if edata.len() < 5 {
        return None;
    }
    // server_name_list length (2), then entries: type(1) + name_len(2) + name.
    let mut p = 2;
    while p + 3 <= edata.len() {
        let name_type = edata[p];
        let name_len = u16::from_be_bytes([edata[p + 1], edata[p + 2]]) as usize;
        p += 3;
        if p + name_len > edata.len() {
            return None;
        }
        if name_type == 0 {
            return String::from_utf8(edata[p..p + name_len].to_vec()).ok();
        }
        p += name_len;
    }
    None
}

fn parse_alpn(edata: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if edata.len() < 2 {
        return out;
    }
    let mut p = 2; // ALPN protocol list length.
    while p < edata.len() {
        let len = edata[p] as usize;
        p += 1;
        if p + len > edata.len() {
            break;
        }
        out.push(String::from_utf8_lossy(&edata[p..p + len]).to_string());
        p += len;
    }
    out
}

fn parse_u16_list_2(edata: &[u8]) -> Vec<u16> {
    // 2-byte byte-length prefix, then u16 entries.
    if edata.len() < 2 {
        return vec![];
    }
    let len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
    parse_u16s(&edata[2..], len)
}

fn parse_u16_list_1(edata: &[u8]) -> Vec<u16> {
    // 1-byte byte-length prefix, then u16 entries (supported_versions).
    if edata.is_empty() {
        return vec![];
    }
    let len = edata[0] as usize;
    parse_u16s(&edata[1..], len)
}

fn parse_u16s(data: &[u8], byte_len: usize) -> Vec<u16> {
    let end = byte_len.min(data.len());
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < end {
        out.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    out
}

fn parse_u8_list_1(edata: &[u8]) -> Vec<u8> {
    if edata.is_empty() {
        return vec![];
    }
    let len = (edata[0] as usize).min(edata.len() - 1);
    edata[1..1 + len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(sni: &str, with_alpn: bool) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
        let sni_ext_len = 4 + sni_ext_data_len;

        // Optional ALPN extension advertising "h2".
        let alpn_proto = b"h2";
        let alpn_ext_data_len = 2 + 1 + alpn_proto.len();
        let alpn_ext_len = 4 + alpn_ext_data_len;

        let extensions_len = sni_ext_len + if with_alpn { alpn_ext_len } else { 0 };

        let cipher_suites_len: usize = 2;
        let compression_len: usize = 1;
        let ch_body_len =
            2 + 32 + 1 + 2 + cipher_suites_len + 1 + compression_len + 2 + extensions_len;

        let mut pkt = Vec::new();
        pkt.push(0x16);
        pkt.extend_from_slice(&[0x03, 0x01]);
        let record_len = (4 + ch_body_len) as u16;
        pkt.extend_from_slice(&record_len.to_be_bytes());

        pkt.push(0x01); // ClientHello
        let hs_len = ch_body_len as u32;
        pkt.push((hs_len >> 16) as u8);
        pkt.push((hs_len >> 8) as u8);
        pkt.push(hs_len as u8);

        pkt.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0); // session id len
        pkt.extend_from_slice(&(cipher_suites_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x2F]); // one cipher suite
        pkt.push(compression_len as u8);
        pkt.push(0x00);

        pkt.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // SNI extension.
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        let sni_list_len = (1 + 2 + sni_bytes.len()) as u16;
        pkt.extend_from_slice(&sni_list_len.to_be_bytes());
        pkt.push(0x00);
        pkt.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(sni_bytes);
        // ALPN extension.
        if with_alpn {
            pkt.extend_from_slice(&[0x00, 0x10]);
            pkt.extend_from_slice(&(alpn_ext_data_len as u16).to_be_bytes());
            pkt.extend_from_slice(&((1 + alpn_proto.len()) as u16).to_be_bytes());
            pkt.push(alpn_proto.len() as u8);
            pkt.extend_from_slice(alpn_proto);
        }
        pkt
    }

    #[test]
    fn test_extract_sni() {
        let data = build_client_hello("example.com", false);
        let result = try_decode_tls_client_hello(&data, 0).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_extract_sni_github() {
        let data = build_client_hello("github.com", false);
        let result = try_decode_tls_client_hello(&data, 0).unwrap();
        assert_eq!(result.sni.as_deref(), Some("github.com"));
    }

    #[test]
    fn test_ja3_present_and_stable() {
        let data = build_client_hello("example.com", false);
        let r1 = try_decode_tls_client_hello(&data, 0).unwrap();
        let r2 = try_decode_tls_client_hello(&data, 0).unwrap();
        let ja3 = r1.ja3.unwrap();
        assert_eq!(ja3.len(), 32);
        assert_eq!(ja3, r2.ja3.unwrap());
        assert_eq!(r1.cipher_suites, vec![0x002f]);
    }

    #[test]
    fn test_alpn_extracted_and_ja4() {
        let data = build_client_hello("example.com", true);
        let r = try_decode_tls_client_hello(&data, 0).unwrap();
        assert_eq!(r.alpn, vec!["h2".to_string()]);
        let ja4 = r.ja4.unwrap();
        assert!(ja4.starts_with('t'), "ja4 = {ja4}");
        assert_eq!(ja4.split('_').count(), 3);
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

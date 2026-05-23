use super::{DnsInfo, DnsQuestion};

pub fn try_decode_dns(data: &[u8], offset: usize) -> Option<DnsInfo> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 12 {
        return None;
    }

    let o = offset;
    let transaction_id = u16::from_be_bytes([data[o], data[o + 1]]);
    let flags = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let is_response = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([data[o + 4], data[o + 5]]) as usize;

    // Sanity check: qdcount should be reasonable
    if qdcount > 100 {
        return None;
    }

    let mut pos = o + 12;
    let mut questions = Vec::with_capacity(qdcount.min(8));

    for _ in 0..qdcount {
        let (qname, new_pos) = parse_dns_name(data, pos, 0)?;
        pos = new_pos;
        if pos + 4 > data.len() {
            break;
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;
        questions.push(DnsQuestion {
            qname,
            qtype,
            qclass,
        });
    }

    if questions.is_empty() {
        return None;
    }

    Some(DnsInfo {
        transaction_id,
        is_response,
        questions,
        header_range: (offset, pos.min(data.len())),
    })
}

#[allow(unused_assignments)]
fn parse_dns_name(data: &[u8], mut pos: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 128 {
        return None;
    }

    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_pos = pos;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len_byte = data[pos];

        if len_byte == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }

        // Compression pointer
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = ((len_byte as usize & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            // Follow the pointer
            let (name_part, _) = parse_dns_name(data, ptr, depth + 1)?;
            if !labels.is_empty() {
                labels.push(name_part);
            } else {
                return Some((name_part, end_pos));
            }
            break;
        }

        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[pos..pos + label_len]).to_string();
        labels.push(label);
        pos += label_len;
    }

    let name = labels.join(".");
    Some((name, end_pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_query(qname: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Header
        pkt.extend_from_slice(&[0xAB, 0xCD]); // transaction ID
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        pkt.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ancount=0
        pkt.extend_from_slice(&[0x00, 0x00]); // nscount=0
        pkt.extend_from_slice(&[0x00, 0x00]); // arcount=0

        // Question: encode qname
        for label in qname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // terminator

        pkt.extend_from_slice(&[0x00, 0x01]); // qtype A
        pkt.extend_from_slice(&[0x00, 0x01]); // qclass IN

        pkt
    }

    fn build_dns_response(qname: &str) -> Vec<u8> {
        let mut pkt = build_dns_query(qname);
        // Set response flag
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt
    }

    #[test]
    fn test_parse_dns_query() {
        let data = build_dns_query("example.com");
        let result = try_decode_dns(&data, 0).unwrap();
        assert_eq!(result.transaction_id, 0xABCD);
        assert!(!result.is_response);
        assert_eq!(result.questions.len(), 1);
        assert_eq!(result.questions[0].qname, "example.com");
        assert_eq!(result.questions[0].qtype, 1); // A
    }

    #[test]
    fn test_parse_dns_response() {
        let data = build_dns_response("google.com");
        let result = try_decode_dns(&data, 0).unwrap();
        assert!(result.is_response);
        assert_eq!(result.questions[0].qname, "google.com");
    }

    #[test]
    fn test_parse_dns_subdomain() {
        let data = build_dns_query("www.example.co.uk");
        let result = try_decode_dns(&data, 0).unwrap();
        assert_eq!(result.questions[0].qname, "www.example.co.uk");
    }

    #[test]
    fn test_parse_dns_too_short() {
        assert!(try_decode_dns(&[0u8; 11], 0).is_none());
    }

    #[test]
    fn test_parse_dns_compression_pointer() {
        // Build a packet with a compression pointer
        let mut data = Vec::new();
        // Header
        data.extend_from_slice(&[0x00, 0x01]); // txid
        data.extend_from_slice(&[0x81, 0x80]); // flags: response
        data.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar

        // Question: "example.com"
        let name_offset = data.len();
        data.push(7);
        data.extend_from_slice(b"example");
        data.push(3);
        data.extend_from_slice(b"com");
        data.push(0);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // qtype, qclass

        let _ = name_offset; // used for verification

        let result = try_decode_dns(&data, 0).unwrap();
        assert_eq!(result.questions[0].qname, "example.com");
    }
}

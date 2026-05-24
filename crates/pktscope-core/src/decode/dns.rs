use std::net::{Ipv4Addr, Ipv6Addr};

use super::{DnsInfo, DnsQuestion, DnsRdata, DnsRecord};

/// Decode a DNS message starting at `offset` within `data`. Parses the question
/// section plus the answer/authority/additional resource records. Compression
/// pointers are resolved relative to the DNS message start (`offset`).
pub fn try_decode_dns(data: &[u8], offset: usize) -> Option<DnsInfo> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 12 {
        return None;
    }

    let base = offset; // DNS message start; compression pointers are relative to this.
    let o = offset;
    let transaction_id = u16::from_be_bytes([data[o], data[o + 1]]);
    let flags = u16::from_be_bytes([data[o + 2], data[o + 3]]);
    let is_response = (flags & 0x8000) != 0;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([data[o + 4], data[o + 5]]) as usize;
    let ancount = u16::from_be_bytes([data[o + 6], data[o + 7]]) as usize;
    let nscount = u16::from_be_bytes([data[o + 8], data[o + 9]]) as usize;
    let arcount = u16::from_be_bytes([data[o + 10], data[o + 11]]) as usize;

    // Sanity bounds.
    if qdcount > 100 || ancount > 4096 || nscount > 4096 || arcount > 4096 {
        return None;
    }

    let mut pos = o + 12;
    let mut questions = Vec::with_capacity(qdcount.min(8));

    for _ in 0..qdcount {
        let (qname, new_pos) = parse_dns_name(data, pos, base, 0)?;
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

    let mut answers = Vec::new();
    let mut authorities = Vec::new();
    let mut additionals = Vec::new();
    parse_records(data, &mut pos, base, ancount, &mut answers);
    parse_records(data, &mut pos, base, nscount, &mut authorities);
    parse_records(data, &mut pos, base, arcount, &mut additionals);

    Some(DnsInfo {
        transaction_id,
        is_response,
        rcode,
        questions,
        answers,
        authorities,
        additionals,
        header_range: (offset, pos.min(data.len())),
    })
}

fn parse_records(
    data: &[u8],
    pos: &mut usize,
    base: usize,
    count: usize,
    out: &mut Vec<DnsRecord>,
) {
    for _ in 0..count {
        match parse_rr(data, *pos, base) {
            Some((rec, new_pos)) => {
                *pos = new_pos;
                out.push(rec);
            }
            None => break,
        }
    }
}

fn parse_rr(data: &[u8], start: usize, base: usize) -> Option<(DnsRecord, usize)> {
    let (name, mut pos) = parse_dns_name(data, start, base, 0)?;
    if pos + 10 > data.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    pos += 10;
    if pos + rdlen > data.len() {
        return None;
    }
    let rdata = parse_rdata(data, pos, rdlen, base, rtype);
    Some((
        DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        pos + rdlen,
    ))
}

fn parse_rdata(data: &[u8], pos: usize, rdlen: usize, base: usize, rtype: u16) -> DnsRdata {
    let unknown = || DnsRdata::Unknown {
        rtype,
        data: data[pos..pos + rdlen].to_vec(),
    };
    match rtype {
        1 if rdlen == 4 => DnsRdata::A(Ipv4Addr::new(
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        )),
        28 if rdlen == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[pos..pos + 16]);
            DnsRdata::Aaaa(Ipv6Addr::from(octets))
        }
        5 => parse_dns_name(data, pos, base, 0)
            .map(|(n, _)| DnsRdata::Cname(n))
            .unwrap_or_else(unknown),
        2 => parse_dns_name(data, pos, base, 0)
            .map(|(n, _)| DnsRdata::Ns(n))
            .unwrap_or_else(unknown),
        12 => parse_dns_name(data, pos, base, 0)
            .map(|(n, _)| DnsRdata::Ptr(n))
            .unwrap_or_else(unknown),
        15 if rdlen >= 3 => {
            let preference = u16::from_be_bytes([data[pos], data[pos + 1]]);
            match parse_dns_name(data, pos + 2, base, 0) {
                Some((exchange, _)) => DnsRdata::Mx {
                    preference,
                    exchange,
                },
                None => unknown(),
            }
        }
        16 => {
            let mut strings = Vec::new();
            let mut p = pos;
            let end = pos + rdlen;
            while p < end {
                let len = data[p] as usize;
                p += 1;
                if p + len > end {
                    break;
                }
                strings.push(String::from_utf8_lossy(&data[p..p + len]).to_string());
                p += len;
            }
            DnsRdata::Txt(strings)
        }
        33 if rdlen >= 6 => {
            let priority = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let weight = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let port = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
            match parse_dns_name(data, pos + 6, base, 0) {
                Some((target, _)) => DnsRdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                },
                None => unknown(),
            }
        }
        6 => {
            let parsed = (|| {
                let (mname, p) = parse_dns_name(data, pos, base, 0)?;
                let (rname, p) = parse_dns_name(data, p, base, 0)?;
                if p + 20 > data.len() {
                    return None;
                }
                let u = |i: usize| {
                    u32::from_be_bytes([
                        data[p + i],
                        data[p + i + 1],
                        data[p + i + 2],
                        data[p + i + 3],
                    ])
                };
                Some(DnsRdata::Soa {
                    mname,
                    rname,
                    serial: u(0),
                    refresh: u(4),
                    retry: u(8),
                    expire: u(12),
                    minimum: u(16),
                })
            })();
            parsed.unwrap_or_else(unknown)
        }
        _ => unknown(),
    }
}

/// Parse a (possibly compressed) DNS name. `base` is the offset of the DNS
/// message start within `data`; compression pointers are interpreted relative
/// to it. Returns the decoded name and the position immediately after the name
/// in the linear stream (for compressed names, after the 2-byte pointer).
#[allow(unused_assignments)]
fn parse_dns_name(
    data: &[u8],
    mut pos: usize,
    base: usize,
    depth: usize,
) -> Option<(String, usize)> {
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

        // Compression pointer.
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let ptr = ((len_byte as usize & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            // Pointer is relative to the DNS message start.
            let (name_part, _) = parse_dns_name(data, base + ptr, base, depth + 1)?;
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
        pkt.extend_from_slice(&[0xAB, 0xCD]); // transaction ID
        pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        pkt.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ancount=0
        pkt.extend_from_slice(&[0x00, 0x00]); // nscount=0
        pkt.extend_from_slice(&[0x00, 0x00]); // arcount=0
        for label in qname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01]); // qtype A
        pkt.extend_from_slice(&[0x00, 0x01]); // qclass IN
        pkt
    }

    /// Build a response with one A answer that uses a compression pointer back
    /// to the question name (offset 12).
    fn build_dns_response_a(qname: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut pkt = build_dns_query(qname);
        pkt[2] = 0x81;
        pkt[3] = 0x80; // response flags
        pkt[7] = 0x01; // ancount = 1
        // Answer: name = pointer to 0x000C (question name)
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&[0x00, 0x01]); // type A
        pkt.extend_from_slice(&[0x00, 0x01]); // class IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // ttl 300
        pkt.extend_from_slice(&[0x00, 0x04]); // rdlen 4
        pkt.extend_from_slice(&ip.octets());
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
        assert_eq!(result.questions[0].qtype, 1);
        assert!(result.answers.is_empty());
    }

    #[test]
    fn test_parse_dns_response_a_record() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let data = build_dns_response_a("example.com", ip);
        let result = try_decode_dns(&data, 0).unwrap();
        assert!(result.is_response);
        assert_eq!(result.answers.len(), 1);
        assert_eq!(result.answers[0].name, "example.com");
        match &result.answers[0].rdata {
            DnsRdata::A(a) => assert_eq!(*a, ip),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_dns_answer_with_offset() {
        // DNS message NOT at offset 0: compression pointers must resolve
        // relative to the message start, not the buffer start.
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let inner = build_dns_response_a("test.local", ip);
        let mut data = vec![0xEE; 42]; // simulate Eth+IP+UDP headers
        data.extend_from_slice(&inner);
        let result = try_decode_dns(&data, 42).unwrap();
        assert_eq!(result.answers.len(), 1);
        assert_eq!(result.answers[0].name, "test.local");
        match &result.answers[0].rdata {
            DnsRdata::A(a) => assert_eq!(*a, ip),
            other => panic!("expected A, got {other:?}"),
        }
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
}

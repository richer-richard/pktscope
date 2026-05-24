//! JA3 (MD5) and JA4 (SHA-256) TLS client fingerprints, computed from the
//! parsed ClientHello fields. GREASE values (RFC 8701) are excluded.

use md5::Md5;
use sha2::{Digest, Sha256};

/// True for RFC 8701 GREASE values (high byte == low byte, low nibble == 0xa).
pub fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0x00ff) && (v & 0x000f) == 0x000a
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Build the canonical JA3 string:
/// `version,ciphers,extensions,curves,point_formats` (GREASE-filtered).
pub fn ja3_string(
    version: u16,
    ciphers: &[u16],
    exts: &[u16],
    groups: &[u16],
    formats: &[u8],
) -> String {
    let join_u16 = |xs: &[u16]| {
        xs.iter()
            .filter(|&&v| !is_grease(v))
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let join_u8 = |xs: &[u8]| {
        xs.iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    format!(
        "{},{},{},{},{}",
        version,
        join_u16(ciphers),
        join_u16(exts),
        join_u16(groups),
        join_u8(formats)
    )
}

/// MD5 hash (hex) of a JA3 string.
pub fn ja3_hash(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

/// Compute the JA4 fingerprint (`ja4_a_ja4_b_ja4_c`). `version` should be the
/// negotiated/highest offered TLS version; `over_quic` selects the q/t prefix.
#[allow(clippy::too_many_arguments)]
pub fn ja4(
    version: u16,
    over_quic: bool,
    sni_present: bool,
    ciphers: &[u16],
    exts: &[u16],
    sig_algs: &[u16],
    alpn_first: Option<&str>,
) -> String {
    let proto = if over_quic { 'q' } else { 't' };
    let ver = ja4_version_code(version);
    let sni = if sni_present { 'd' } else { 'i' };
    let nciph = ciphers.iter().filter(|&&v| !is_grease(v)).count().min(99);
    let next = exts.iter().filter(|&&v| !is_grease(v)).count().min(99);
    let alpn = ja4_alpn(alpn_first);
    let ja4_a = format!("{proto}{ver}{sni}{nciph:02}{next:02}{alpn}");

    let mut c: Vec<u16> = ciphers.iter().copied().filter(|&v| !is_grease(v)).collect();
    c.sort_unstable();
    let cstr = c
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ja4_b = sha12(&cstr, c.is_empty());

    // JA4_c: sorted extensions (excluding SNI/ALPN/GREASE) "_" sig algs in order.
    let mut e: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|&v| !is_grease(v) && v != 0x0000 && v != 0x0010)
        .collect();
    e.sort_unstable();
    let estr = e
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sstr = sig_algs
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ja4_c = sha12(
        &format!("{estr}_{sstr}"),
        e.is_empty() && sig_algs.is_empty(),
    );

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

fn sha12(s: &str, empty: bool) -> String {
    if empty {
        return "000000000000".to_string();
    }
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())[..12].to_string()
}

fn ja4_version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0xfeff => "d1",
        0xfefd => "d2",
        _ => "00",
    }
}

fn ja4_alpn(first: Option<&str>) -> String {
    match first {
        Some(s) if !s.is_empty() => {
            let b = s.as_bytes();
            format!("{}{}", b[0] as char, b[b.len() - 1] as char)
        }
        _ => "00".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_grease() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x002f));
    }

    #[test]
    fn test_ja3_string() {
        let s = ja3_string(771, &[47, 53], &[0, 11], &[23], &[0]);
        assert_eq!(s, "771,47-53,0-11,23,0");
    }

    #[test]
    fn test_ja3_string_excludes_grease() {
        let s = ja3_string(771, &[0x0a0a, 47], &[0x1a1a, 0], &[23], &[0]);
        assert_eq!(s, "771,47,0,23,0");
    }

    #[test]
    fn test_ja3_hash_known_vector() {
        // MD5 of the empty string — verifies the MD5 + hex pipeline.
        assert_eq!(ja3_hash(""), "d41d8cd98f00b204e9800998ecf8427e");
        // Deterministic.
        assert_eq!(ja3_hash("771,47-53,0,23,0"), ja3_hash("771,47-53,0,23,0"));
    }

    #[test]
    fn test_ja4_structure() {
        let f = ja4(
            0x0304,
            false,
            true,
            &[0x1301, 0x1302],
            &[0, 43, 16],
            &[0x0403],
            Some("h2"),
        );
        // t13d<2ciph><3ext>h2_<12hex>_<12hex>
        assert!(f.starts_with("t13d0203h2_"), "ja4 = {f}");
        let parts: Vec<&str> = f.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn test_ja4_no_alpn_no_sni() {
        let f = ja4(0x0303, false, false, &[0x002f], &[0], &[], None);
        assert!(f.starts_with("t12i0101"), "ja4 = {f}");
    }
}

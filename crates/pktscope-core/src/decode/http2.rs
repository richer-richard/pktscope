//! HTTP/2 (cleartext "h2c") frame parsing + HPACK header decompression.
//!
//! Note: HTTP/2 over TLS ("h2") is encrypted and not visible to a passive
//! sniffer; this decodes prior-knowledge cleartext h2c only. HPACK Huffman
//! literals are not expanded (shown as a placeholder); indexed and non-Huffman
//! literals decode fully.

use std::collections::VecDeque;

use super::{Http2Frame, Http2FrameInfo};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Parse an h2c stream that begins with the connection preface.
pub fn try_decode_http2(stream: &[u8]) -> Option<Http2FrameInfo> {
    if !stream.starts_with(PREFACE) {
        return None;
    }
    let mut pos = PREFACE.len();
    let mut hpack = Hpack::new();
    let mut frames = Vec::new();

    while pos + 9 <= stream.len() && frames.len() < 128 {
        let length = ((stream[pos] as usize) << 16)
            | ((stream[pos + 1] as usize) << 8)
            | (stream[pos + 2] as usize);
        let frame_type = stream[pos + 3];
        let flags = stream[pos + 4];
        let stream_id = u32::from_be_bytes([
            stream[pos + 5] & 0x7f,
            stream[pos + 6],
            stream[pos + 7],
            stream[pos + 8],
        ]);
        pos += 9;
        let Some(payload) = stream.get(pos..pos + length) else {
            break;
        };

        // HEADERS frame without PADDED (0x08) / PRIORITY (0x20) → header block is the payload.
        let headers = if frame_type == 0x1 && flags & 0x08 == 0 && flags & 0x20 == 0 {
            hpack.decode(payload)
        } else {
            Vec::new()
        };

        frames.push(Http2Frame {
            stream_id,
            frame_type,
            flags,
            length: length as u32,
            headers,
        });
        pos += length;
    }

    Some(Http2FrameInfo { frames })
}

/// Minimal HPACK decoder (RFC 7541): static table + dynamic table + integer and
/// string literals. Huffman-coded strings are not expanded.
pub struct Hpack {
    dynamic: VecDeque<(String, String)>,
    max_size: usize,
    size: usize,
}

impl Default for Hpack {
    fn default() -> Self {
        Self::new()
    }
}

impl Hpack {
    pub fn new() -> Self {
        Self {
            dynamic: VecDeque::new(),
            max_size: 4096,
            size: 0,
        }
    }

    pub fn decode(&mut self, block: &[u8]) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        let mut i = 0;
        while i < block.len() {
            let b = block[i];
            if b & 0x80 != 0 {
                // 6.1 Indexed Header Field
                let Some((idx, ni)) = decode_int(block, i, 7) else {
                    break;
                };
                i = ni;
                if idx == 0 {
                    break;
                }
                if let Some(h) = self.indexed(idx) {
                    headers.push(h);
                }
            } else if b & 0x40 != 0 {
                // 6.2.1 Literal with incremental indexing (6-bit prefix)
                let Some((name, value, ni)) = self.literal(block, i, 6) else {
                    break;
                };
                i = ni;
                self.insert(name.clone(), value.clone());
                headers.push((name, value));
            } else if b & 0x20 != 0 {
                // 6.3 Dynamic table size update (5-bit prefix)
                let Some((sz, ni)) = decode_int(block, i, 5) else {
                    break;
                };
                i = ni;
                self.max_size = sz;
                self.evict();
            } else {
                // 6.2.2 / 6.2.3 Literal without / never indexed (4-bit prefix)
                let Some((name, value, ni)) = self.literal(block, i, 4) else {
                    break;
                };
                i = ni;
                headers.push((name, value));
            }
        }
        headers
    }

    fn literal(&self, block: &[u8], pos: usize, prefix: u32) -> Option<(String, String, usize)> {
        let (idx, mut p) = decode_int(block, pos, prefix)?;
        let name = if idx == 0 {
            let (s, np) = decode_str(block, p)?;
            p = np;
            s
        } else {
            self.indexed(idx)?.0
        };
        let (value, np) = decode_str(block, p)?;
        Some((name, value, np))
    }

    fn indexed(&self, idx: usize) -> Option<(String, String)> {
        if idx == 0 {
            return None;
        }
        if idx <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[idx - 1];
            Some((n.to_string(), v.to_string()))
        } else {
            self.dynamic.get(idx - STATIC_TABLE.len() - 1).cloned()
        }
    }

    fn insert(&mut self, name: String, value: String) {
        self.size += name.len() + value.len() + 32;
        self.dynamic.push_front((name, value));
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.size -= n.len() + v.len() + 32,
                None => break,
            }
        }
    }
}

fn decode_int(buf: &[u8], mut pos: usize, prefix: u32) -> Option<(usize, usize)> {
    let mask = ((1u32 << prefix) - 1) as usize;
    let mut value = (*buf.get(pos)? as usize) & mask;
    pos += 1;
    if value < mask {
        return Some((value, pos));
    }
    let mut shift = 0;
    loop {
        let b = *buf.get(pos)?;
        pos += 1;
        value += ((b & 0x7f) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 28 {
            return None;
        }
    }
    Some((value, pos))
}

fn decode_str(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let huffman = (*buf.get(pos)? & 0x80) != 0;
    let (len, p) = decode_int(buf, pos, 7)?;
    let bytes = buf.get(p..p + len)?;
    let s = if huffman {
        format!("<huffman:{}b>", bytes.len())
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    Some((s, p + len))
}

/// RFC 7541 Appendix A static table (1-indexed).
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_int() {
        // RFC 7541 C.1.1: value 10, 5-bit prefix.
        assert_eq!(decode_int(&[0x0a], 0, 5), Some((10, 1)));
        // C.1.2: value 1337, 5-bit prefix → 31, 154, 10.
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], 0, 5), Some((1337, 3)));
    }

    #[test]
    fn test_hpack_indexed_and_literal() {
        let mut h = Hpack::new();
        // 0x82 = indexed field, index 2 (:method GET).
        // Then literal with incremental indexing, new name (0x40), name "x" value "y".
        let block = [0x82, 0x40, 0x01, b'x', 0x01, b'y'];
        let headers = h.decode(&block);
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(headers[1], ("x".to_string(), "y".to_string()));
        // The literal was added to the dynamic table (index 62).
        assert_eq!(h.indexed(62), Some(("x".to_string(), "y".to_string())));
    }

    #[test]
    fn test_preface_and_headers_frame() {
        let mut stream = PREFACE.to_vec();
        // HEADERS frame: length=1, type=1, flags=END_HEADERS(0x04), stream 1, payload [0x82].
        stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x82]);
        let info = try_decode_http2(&stream).unwrap();
        assert_eq!(info.frames.len(), 1);
        assert_eq!(info.frames[0].frame_type, 1);
        assert_eq!(
            info.frames[0].headers[0],
            (":method".to_string(), "GET".to_string())
        );
    }

    #[test]
    fn test_not_h2() {
        assert!(try_decode_http2(b"GET / HTTP/1.1\r\n").is_none());
    }
}

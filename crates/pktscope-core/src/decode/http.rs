use super::HttpInfo;

/// Decode an HTTP/1.x request or response head from the start of a (possibly
/// reassembled) byte stream. Only the header block is parsed; the body may be
/// binary and is ignored. Returns `None` if the start does not look like HTTP/1.x.
pub fn try_decode_http(stream: &[u8]) -> Option<HttpInfo> {
    let head_end = find_subslice(stream, b"\r\n\r\n")
        .map(|i| i + 2)
        .unwrap_or_else(|| stream.len().min(8192));
    let head = &stream[..head_end];
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    if first.is_empty() {
        return None;
    }

    let mut info = HttpInfo {
        is_request: false,
        method: None,
        uri: None,
        version: None,
        status_code: None,
        headers: Vec::new(),
        host: None,
        content_length: None,
        chunked: false,
        header_range: (0, head_end),
    };

    if let Some(rest) = first.strip_prefix("HTTP/") {
        // Status line: "HTTP/x.y CODE reason"
        let mut p = rest.splitn(2, ' ');
        info.version = Some(format!("HTTP/{}", p.next()?));
        info.status_code = p.next().and_then(|s| s.split(' ').next()?.parse().ok());
        info.status_code?; // must have a numeric code
    } else {
        // Request line: "METHOD URI HTTP/x.y"
        let mut p = first.splitn(3, ' ');
        let method = p.next()?;
        if !is_http_method(method) {
            return None;
        }
        let uri = p.next()?;
        let version = p.next()?;
        if !version.starts_with("HTTP/") {
            return None;
        }
        info.is_request = true;
        info.method = Some(method.to_string());
        info.uri = Some(uri.to_string());
        info.version = Some(version.to_string());
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            match k.to_ascii_lowercase().as_str() {
                "host" => info.host = Some(v.to_string()),
                "content-length" => info.content_length = v.parse().ok(),
                "transfer-encoding" if v.eq_ignore_ascii_case("chunked") => info.chunked = true,
                _ => {}
            }
            info.headers.push((k.to_string(), v.to_string()));
        }
    }
    Some(info)
}

fn is_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request() {
        let info = try_decode_http(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert!(info.is_request);
        assert_eq!(info.method.as_deref(), Some("GET"));
        assert_eq!(info.uri.as_deref(), Some("/index.html"));
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_response_chunked() {
        let info = try_decode_http(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert!(!info.is_request);
        assert_eq!(info.status_code, Some(200));
        assert!(info.chunked);
    }

    #[test]
    fn test_not_http() {
        assert!(try_decode_http(b"\x16\x03\x01\x00\x05hello").is_none());
        assert!(try_decode_http(b"random text\r\n\r\n").is_none());
    }
}

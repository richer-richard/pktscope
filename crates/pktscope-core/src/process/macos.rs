use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::SocketProc;

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

struct Cache {
    /// (protocol, local_addr, local_port) -> (pid, command name)
    entries: HashMap<(u8, IpAddr, u16), (u32, String)>,
    last_refresh: Instant,
}

pub fn lookup_socket_proc_macos(
    protocol: u8,
    local_addr: IpAddr,
    local_port: u16,
) -> Option<SocketProc> {
    let (pid, name) = {
        let mut guard = CACHE.lock().ok()?;
        let cache = guard.get_or_insert_with(|| Cache {
            entries: HashMap::new(),
            last_refresh: Instant::now() - REFRESH_INTERVAL * 2,
        });
        if cache.last_refresh.elapsed() > REFRESH_INTERVAL {
            cache.entries = build_table();
            cache.last_refresh = Instant::now();
        }
        cache
            .entries
            .get(&(protocol, local_addr, local_port))
            .cloned()?
    };

    Some(SocketProc {
        pid,
        name,
        exe_path: exe_path_for_pid_macos(pid),
    })
}

pub fn exe_path_for_pid_macos(pid: u32) -> Option<PathBuf> {
    const MAXSIZE: usize = 4096;
    let mut buf = vec![0u8; MAXSIZE];
    // SAFETY: proc_pidpath fills `buf` with up to `MAXSIZE` bytes and returns
    // the number written (<= MAXSIZE), or <= 0 on error.
    let ret = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut libc::c_void,
            MAXSIZE as u32,
        )
    };
    if ret <= 0 {
        return None;
    }
    buf.truncate(ret as usize);
    Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
}

/// Build the full (proto, local addr, local port) -> (pid, command) table by
/// parsing one `lsof -i` invocation. `+c 0` disables command-name truncation.
fn build_table() -> HashMap<(u8, IpAddr, u16), (u32, String)> {
    let mut map = HashMap::new();
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P", "+c", "0", "-FpcPn"])
        .output();
    if let Ok(out) = output {
        // lsof can exit non-zero when some handles are inaccessible; still parse stdout.
        parse_lsof(&String::from_utf8_lossy(&out.stdout), &mut map);
    }
    map
}

fn parse_lsof(text: &str, map: &mut HashMap<(u8, IpAddr, u16), (u32, String)>) {
    let mut pid: u32 = 0;
    let mut cmd = String::new();
    let mut proto: Option<u8> = None;

    for line in text.lines() {
        let Some(&tag) = line.as_bytes().first() else {
            continue;
        };
        let rest = &line[1..];
        match tag {
            b'p' => {
                pid = rest.parse().unwrap_or(0);
                cmd.clear();
                proto = None;
            }
            b'c' => cmd = rest.to_string(),
            b'f' => proto = None, // new file record
            b'P' => {
                proto = match rest {
                    "TCP" => Some(6),
                    "UDP" => Some(17),
                    _ => None,
                }
            }
            b'n' => {
                if let Some(pr) = proto {
                    let local = rest.split("->").next().unwrap_or(rest);
                    if let Some((addr, port)) = parse_endpoint(local) {
                        map.insert((pr, addr, port), (pid, cmd.clone()));
                    }
                }
            }
            _ => {}
        }
    }
}

fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6: [addr]:port
        let (addr, port) = rest.split_once("]:")?;
        Some((addr.parse().ok()?, port.parse().ok()?))
    } else {
        let (addr, port) = s.rsplit_once(':')?;
        if addr == "*" {
            return None;
        }
        Some((addr.parse().ok()?, port.parse().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_lsof_connected() {
        let sample = "\
p501
cfirefox
f12
PTCP
n192.168.1.5:50000->93.184.216.34:443
f13
PUDP
n10.0.0.2:53battle
";
        // (the malformed UDP line should be ignored)
        let mut map = HashMap::new();
        parse_lsof(sample, &mut map);
        let key = (6u8, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 50000u16);
        assert_eq!(map.get(&key), Some(&(501u32, "firefox".to_string())));
    }

    #[test]
    fn test_parse_endpoint() {
        assert_eq!(
            parse_endpoint("1.2.3.4:443"),
            Some((IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443))
        );
        assert_eq!(parse_endpoint("*:8080"), None);
        assert!(parse_endpoint("[2001:db8::1]:443").is_some());
    }

    #[test]
    #[ignore = "requires a live socket and lsof; run manually"]
    fn test_self_lookup() {
        use std::io::Write;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _ = std::io::stdout().flush();
        let sp = lookup_socket_proc_macos(6, IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        assert!(sp.is_some(), "should attribute our own listening socket");
        assert_eq!(sp.unwrap().pid, std::process::id());
    }
}

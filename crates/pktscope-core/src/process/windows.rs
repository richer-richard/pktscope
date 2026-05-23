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
    entries: HashMap<(u8, IpAddr, u16), u32>,
    names: HashMap<u32, String>,
    last_refresh: Instant,
}

pub fn lookup_socket_proc_windows(
    protocol: u8,
    local_addr: IpAddr,
    local_port: u16,
) -> Option<SocketProc> {
    let (pid, name) = {
        let mut guard = CACHE.lock().ok()?;
        let cache = guard.get_or_insert_with(|| Cache {
            entries: HashMap::new(),
            names: HashMap::new(),
            last_refresh: Instant::now() - REFRESH_INTERVAL * 2,
        });
        if cache.last_refresh.elapsed() > REFRESH_INTERVAL {
            cache.entries = build_table();
            cache.names = build_names();
            cache.last_refresh = Instant::now();
        }
        let pid = *cache.entries.get(&(protocol, local_addr, local_port))?;
        let name = cache
            .names
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| format!("pid {pid}"));
        (pid, name)
    };
    Some(SocketProc {
        pid,
        name,
        exe_path: exe_path_for_pid_windows(pid),
    })
}

/// Resolving the full image path on Windows requires OpenProcess +
/// QueryFullProcessImageName; left unimplemented for now (identity falls back
/// gracefully to "unreadable" without it).
pub fn exe_path_for_pid_windows(_pid: u32) -> Option<PathBuf> {
    None
}

fn build_table() -> HashMap<(u8, IpAddr, u16), u32> {
    let mut map = HashMap::new();
    if let Ok(out) = Command::new("netstat").args(["-ano"]).output() {
        parse_netstat(&String::from_utf8_lossy(&out.stdout), &mut map);
    }
    map
}

fn build_names() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(out) = Command::new("tasklist")
        .args(["/NH", "/FO", "CSV"])
        .output()
    {
        parse_tasklist(&String::from_utf8_lossy(&out.stdout), &mut map);
    }
    map
}

fn parse_netstat(text: &str, map: &mut HashMap<(u8, IpAddr, u16), u32>) {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let proto = match fields[0] {
            "TCP" => 6u8,
            "UDP" => 17u8,
            _ => continue,
        };
        let pid: u32 = match fields.last().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if let Some((addr, port)) = parse_endpoint(fields[1]) {
            map.insert((proto, addr, port), pid);
        }
    }
}

fn parse_tasklist(text: &str, map: &mut HashMap<u32, String>) {
    for line in text.lines() {
        // CSV: "Image Name","PID","Session Name","Session#","Mem Usage"
        let cols: Vec<&str> = line.split("\",\"").collect();
        if cols.len() < 2 {
            continue;
        }
        let name = cols[0].trim_start_matches('"').to_string();
        if let Ok(pid) = cols[1].trim_matches('"').parse::<u32>() {
            map.insert(pid, name);
        }
    }
}

fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        let addr = addr.split('%').next().unwrap_or(addr); // strip zone id
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
    fn test_parse_netstat() {
        let sample = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    192.168.1.5:50000      93.184.216.34:443      ESTABLISHED     1234
  UDP    0.0.0.0:53             *:*                                    4567
";
        let mut map = HashMap::new();
        parse_netstat(sample, &mut map);
        assert_eq!(
            map.get(&(6, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 50000)),
            Some(&1234)
        );
        assert_eq!(
            map.get(&(17, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 53)),
            Some(&4567)
        );
    }

    #[test]
    fn test_parse_tasklist() {
        let sample = "\"firefox.exe\",\"1234\",\"Console\",\"1\",\"100,000 K\"\n";
        let mut map = HashMap::new();
        parse_tasklist(sample, &mut map);
        assert_eq!(map.get(&1234), Some(&"firefox.exe".to_string()));
    }
}

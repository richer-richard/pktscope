use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::SocketProc;

static CACHE: Mutex<Option<ProcNetCache>> = Mutex::new(None);

struct ProcNetCache {
    entries: HashMap<(IpAddr, u16), u64>, // (addr, port) -> inode
    last_refresh: Instant,
}

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);

pub fn lookup_socket_proc_linux(
    protocol: u8,
    local_addr: IpAddr,
    local_port: u16,
) -> Option<SocketProc> {
    let inode = {
        let mut cache_guard = CACHE.lock().ok()?;
        let cache = cache_guard.get_or_insert_with(|| ProcNetCache {
            entries: HashMap::new(),
            last_refresh: Instant::now() - REFRESH_INTERVAL * 2,
        });

        if cache.last_refresh.elapsed() > REFRESH_INTERVAL {
            cache.entries.clear();
            let files = match protocol {
                6 => vec!["/proc/net/tcp", "/proc/net/tcp6"],
                17 => vec!["/proc/net/udp", "/proc/net/udp6"],
                _ => return None,
            };
            for file in files {
                if let Ok(contents) = fs::read_to_string(file) {
                    parse_proc_net(&contents, &mut cache.entries);
                }
            }
            cache.last_refresh = Instant::now();
        }

        cache.entries.get(&(local_addr, local_port)).copied()
    };

    find_pid_for_inode(inode?)
}

pub fn exe_path_for_pid_linux(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

fn parse_proc_net(contents: &str, entries: &mut HashMap<(IpAddr, u16), u64>) {
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if let (Some((addr, port)), Some(inode)) =
            (parse_addr_port(fields[1]), fields[9].parse::<u64>().ok())
        {
            if inode != 0 {
                entries.insert((addr, port), inode);
            }
        }
    }
}

fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let addr_hex = parts[0];
    let addr = match addr_hex.len() {
        8 => {
            let n = u32::from_str_radix(addr_hex, 16).ok()?;
            IpAddr::V4(std::net::Ipv4Addr::from(n.to_be()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16).ok()?;
                let be = word.to_be_bytes();
                bytes[i * 4] = be[3];
                bytes[i * 4 + 1] = be[2];
                bytes[i * 4 + 2] = be[1];
                bytes[i * 4 + 3] = be[0];
            }
            IpAddr::V6(std::net::Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((addr, port))
}

fn find_pid_for_inode(inode: u64) -> Option<SocketProc> {
    let inode_str = format!("socket:[{inode}]");
    let proc_dir = fs::read_dir("/proc").ok()?;

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_str()?;
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let fd_dir = format!("/proc/{name_str}/fd");
        if let Ok(fds) = fs::read_dir(&fd_dir) {
            for fd_entry in fds.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    if link.to_str() == Some(&inode_str) {
                        let pid: u32 = name_str.parse().ok()?;
                        let name = fs::read_to_string(format!("/proc/{pid}/comm"))
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        return Some(SocketProc {
                            pid,
                            name,
                            exe_path: exe_path_for_pid_linux(pid),
                        });
                    }
                }
            }
        }
    }
    None
}

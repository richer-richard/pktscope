#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use std::net::IpAddr;
use std::path::PathBuf;

use crate::decode::ProcessInfo;

/// Richer attribution result used by the egress daemon: pid + process name +
/// executable path (needed for binary-identity tracking).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketProc {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
}

impl SocketProc {
    pub fn to_process_info(&self) -> ProcessInfo {
        ProcessInfo {
            pid: self.pid,
            name: self.name.clone(),
        }
    }
}

/// Map a flow's local `(addr, port)` to the owning process. `protocol` is 6
/// (TCP) or 17 (UDP). Results are cached per platform (≈1s) since this is
/// called per packet.
pub fn lookup_socket_proc(protocol: u8, local_addr: IpAddr, local_port: u16) -> Option<SocketProc> {
    #[cfg(target_os = "linux")]
    {
        linux::lookup_socket_proc_linux(protocol, local_addr, local_port)
    }
    #[cfg(target_os = "macos")]
    {
        macos::lookup_socket_proc_macos(protocol, local_addr, local_port)
    }
    #[cfg(target_os = "windows")]
    {
        windows::lookup_socket_proc_windows(protocol, local_addr, local_port)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (protocol, local_addr, local_port);
        None
    }
}

/// Back-compatible lookup returning just pid + name (used by the foreground
/// capture decode path).
pub fn lookup_process(protocol: u8, local_addr: IpAddr, local_port: u16) -> Option<ProcessInfo> {
    lookup_socket_proc(protocol, local_addr, local_port).map(|s| s.to_process_info())
}

/// Resolve the executable path for a pid.
pub fn exe_path_for_pid(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        linux::exe_path_for_pid_linux(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::exe_path_for_pid_macos(pid)
    }
    #[cfg(target_os = "windows")]
    {
        windows::exe_path_for_pid_windows(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = pid;
        None
    }
}

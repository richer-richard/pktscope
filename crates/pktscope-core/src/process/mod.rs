#[cfg(target_os = "linux")]
mod linux;
mod stub;

use crate::decode::ProcessInfo;
use std::net::IpAddr;

pub fn lookup_process(_protocol: u8, _local_addr: IpAddr, _local_port: u16) -> Option<ProcessInfo> {
    #[cfg(target_os = "linux")]
    {
        linux::lookup_process_linux(_protocol, _local_addr, _local_port)
    }
    #[cfg(not(target_os = "linux"))]
    {
        stub::lookup_process_stub()
    }
}

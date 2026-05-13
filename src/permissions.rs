use crate::error::PktScopeError;

pub fn check_capture_permissions() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(PktScopeError::Permission(
                "Requires root privileges. Run with sudo, or grant cap_net_raw:\n  \
                 sudo setcap cap_net_raw+eip ./pktscope"
                    .into(),
            )
            .into());
        }
    }

    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(PktScopeError::Permission(
                "Requires root privileges. Run with sudo, or add your user to the access_bpf group:\n  \
                 sudo dseditgroup -o edit -a $(whoami) -t user access_bpf"
                    .into(),
            )
            .into());
        }
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, pcap will fail with a clear error if Npcap isn't installed
        // or if not running as Administrator. We provide additional guidance.
        eprintln!(
            "Note: Ensure Npcap is installed (https://npcap.com) and run from an Administrator prompt."
        );
    }

    Ok(())
}

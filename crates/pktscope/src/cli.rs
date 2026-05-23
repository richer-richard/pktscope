use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "pktscope",
    version,
    about = "A Wireshark-style terminal packet analyzer"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List available network interfaces
    ListInterfaces,

    /// Capture packets from a live interface
    Capture {
        /// Network interface to capture on (e.g., "eth0", "en0")
        #[arg(short, long)]
        interface: String,

        /// BPF capture filter (applied at libpcap level)
        #[arg(short, long)]
        filter: Option<String>,

        /// Save captured packets to a pcap file
        #[arg(short, long)]
        write: Option<PathBuf>,

        /// Output as JSON lines instead of TUI
        #[arg(long)]
        json: bool,

        /// Snap length (max bytes per packet captured)
        #[arg(short, long, default_value_t = 65535)]
        snaplen: i32,

        /// Maximum number of packets to keep in memory
        #[arg(long, default_value_t = 100_000)]
        buffer_size: usize,
    },

    /// Read and analyze packets from a pcap file
    Read {
        /// Path to the pcap file
        file: PathBuf,

        /// BPF display filter
        #[arg(short, long)]
        filter: Option<String>,

        /// Output as JSON lines instead of TUI
        #[arg(long)]
        json: bool,

        /// Maximum number of packets to keep in memory
        #[arg(long, default_value_t = 100_000)]
        buffer_size: usize,
    },

    /// Always-on egress monitor daemon (capture → correlate → detect → alert)
    Monitor {
        #[command(subcommand)]
        action: MonitorAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum MonitorAction {
    /// Run the monitor (foreground unless --daemonize)
    Run {
        /// Network interface to capture on
        #[arg(short, long)]
        interface: String,

        /// BPF capture filter
        #[arg(short, long)]
        filter: Option<String>,

        /// Snap length
        #[arg(long, default_value_t = 65535)]
        snaplen: i32,

        /// Override the runtime state directory (db/socket/pidfile)
        #[arg(long)]
        state_dir: Option<PathBuf>,

        /// Offline country .mmdb (DB-IP Lite); see scripts/fetch-geoip.sh
        #[arg(long)]
        geoip_country_db: Option<PathBuf>,

        /// Offline ASN .mmdb (DB-IP Lite)
        #[arg(long)]
        geoip_asn_db: Option<PathBuf>,

        /// Short (5s) learning window so all signals fire quickly
        #[arg(long)]
        demo: bool,

        /// Detach into the background (double-fork)
        #[arg(long)]
        daemonize: bool,

        /// Disable desktop notifications (log only)
        #[arg(long)]
        no_notify: bool,
    },

    /// Show the running daemon's status
    Status {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Emit JSON
        #[arg(long)]
        json: bool,
    },

    /// Ask the running daemon to stop
    Stop {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

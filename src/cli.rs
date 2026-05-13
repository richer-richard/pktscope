use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "pktscope", version, about = "A Wireshark-style terminal packet analyzer")]
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
}

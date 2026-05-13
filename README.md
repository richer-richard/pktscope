# pktscope

[![Crates.io](https://img.shields.io/crates/v/pktscope.svg)](https://crates.io/crates/pktscope)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Wireshark-style packet analyzer that runs in the terminal. Lightweight, keyboard-driven, fast cold start, scriptable. Targets Linux, macOS, and Windows.

## Features

- **Live capture** from any network interface with BPF filter support
- **PCAP file reading** for offline analysis
- **Protocol decoders**: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6
- **Application-layer extraction**: TLS Client Hello SNI, DNS question names
- **TCP retransmission detection** with red highlighting
- **Display filters** with boolean operators: `tcp.port == 443 and ip.src == 10.0.0.1`
- **Keyboard-driven TUI** with packet list, detail tree, and hex dump
- **JSON output mode** for scripting and piping
- **PCAP file writing** to save captured packets
- **Process attribution** on Linux (maps packets to process names via /proc)

## Installation

### From crates.io (recommended)
```bash
cargo install pktscope
```

### Prerequisites

libpcap must be installed on your system before building:

#### Linux
```bash
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel # Fedora/RHEL
```

#### macOS
libpcap is included with Xcode Command Line Tools:
```bash
xcode-select --install
```

#### Windows
1. Install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" enabled
2. Set the `LIB` environment variable to include the Npcap SDK lib directory:
   ```powershell
   $env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
   ```

### Build from source
```bash
git clone https://github.com/richer-richard/pktscope.git
cd pktscope
cargo build --release
```

The binary is at `target/release/pktscope`.

## Permissions

### Linux
```bash
# Option 1: Run with sudo
sudo ./pktscope capture -i eth0

# Option 2: Grant capabilities (no sudo needed after this)
sudo setcap cap_net_raw+eip ./target/release/pktscope
```

### macOS
```bash
# Option 1: Run with sudo
sudo ./pktscope capture -i en0

# Option 2: Add user to access_bpf group (requires logout/login)
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```

### Windows
Run from an Administrator command prompt. Ensure Npcap is installed.

## Usage

### List interfaces
```bash
pktscope list-interfaces
```

### Live capture
```bash
# Capture on interface en0
sudo pktscope capture -i en0

# With BPF filter
sudo pktscope capture -i eth0 -f "tcp port 443"

# Save to pcap file while viewing
sudo pktscope capture -i en0 -w capture.pcap

# JSON output (no TUI)
sudo pktscope capture -i en0 --json
```

### Read pcap file
```bash
pktscope read capture.pcap

# With BPF filter
pktscope read capture.pcap -f "udp port 53"

# JSON output
pktscope read capture.pcap --json
```

## Keybindings

| Key | Action |
|-----|--------|
| `j` / `↓` | Select next packet |
| `k` / `↑` | Select previous packet |
| `G` / `End` | Jump to last packet |
| `g` / `Home` | Jump to first packet |
| `PgDn` / `PgUp` | Page down / up |
| `Space` | Pause / resume capture |
| `/` | Enter filter mode |
| `Enter` | Apply filter (in filter mode) |
| `Esc` | Cancel filter input |
| `s` | Save to pcap (if -w specified) |
| `q` | Quit |
| `Ctrl-C` | Force quit |

## Display Filters

### Protocol atoms
```
tcp  udp  icmp  icmpv6  arp  ip  ipv4  ipv6  dns  tls  eth
```

### Field comparisons
```
ip.src == 10.0.0.1
ip.dst != 192.168.1.0
tcp.port == 443
tcp.srcport == 80
udp.dstport == 53
```

### String containment
```
tls.sni contains example.com
dns.qname contains google
```

### Boolean operators
```
tcp and ip.src == 10.0.0.1
tcp || udp
not arp
(tcp || udp) && ip.src == 10.0.0.1
```

## Color Conventions

| Protocol | Color |
|----------|-------|
| TCP | Cyan |
| UDP | Green |
| ARP | Yellow |
| ICMP | Magenta |
| DNS | Yellow |
| TLS | Blue |
| Retransmission | Red |

## Architecture

Three threads connected by bounded channels (10k capacity each):

1. **Capture thread** — reads from pcap (live or file), pushes raw frames
2. **Decode thread** — decodes protocol layers, detects retransmissions, resolves processes
3. **UI thread** — renders TUI at ~30Hz, handles keyboard input

## License

MIT

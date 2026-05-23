# pktscope

[![Crates.io](https://img.shields.io/crates/v/pktscope.svg)](https://crates.io/crates/pktscope)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Wireshark-style packet analyzer that runs in the terminal — **and** an
always-on, local-first **egress monitor** that answers "what is my machine
talking to, and is any of it new?" Lightweight, keyboard-driven, scriptable.
macOS-first; Linux supported; Windows partially. Fully offline — no cloud, no
telemetry.

## Features

### Packet analyzer

- **Live capture** from any interface with BPF filters, and **PCAP / PCAPNG** read/write
- **Decoders**: Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP/ICMPv6; DNS (questions
  **and** answer records), TLS (SNI + **JA3/JA4** fingerprints), HTTP/1.1,
  cleartext HTTP/2 (HPACK), QUIC (long-header detect)
- **TCP stream reassembly** + **follow-stream** view, **RTT** estimation
- **Display filters** with boolean operators: `tcp.port == 443 and ip.src == 10.0.0.1`
- **Stats views**: live throughput sparkline, top talkers, protocol distribution,
  per-flow table, connection timeline
- **Power-user**: bookmarks, regex search, anomaly highlighting (cleartext
  credentials / unusual ports), capture diff, one-shot/sample mode, saved filters
- **JSON output** for scripting; **process attribution** (Linux, macOS, Windows)

### Egress monitor (`pktscope monitor` + `pktscope inspect`)

A background daemon captures continuously, correlates each flow's 5-tuple to a
PID via the OS socket table, resolves destination **names** passively (DNS
answers + TLS SNI, no decryption), enriches with **offline country/ASN**, learns
a **baseline**, and raises **five alert signals**:

1. **New process → destination** — a process contacts a domain/org it never has
2. **New process phoning home** — a binary's first-ever outbound connection
3. **New country / ASN** — first contact with a host in a new country or network
4. **Volume / exfil spike** — outbound volume far above a process's baseline
5. **Program modification** — a process's binary identity (macOS code signature /
   content hash) changed since baseline, then connects out

Monitor-only (no blocking — a deliberate split from Little Snitch). The
inspector TUI shows live connections, per-process / per-domain breakdowns,
time-travel history, and the alerts feed.

## Installation

```bash
cargo install pktscope
```

### Prerequisites

libpcap is required (the `pktscope-core` engine links it; `rusqlite` is bundled).

- **Linux**: `sudo apt install libpcap-dev` (Debian/Ubuntu) / `sudo dnf install libpcap-devel` (Fedora)
- **macOS**: `xcode-select --install`
- **Windows**: install [Npcap](https://npcap.com/) ("WinPcap API-compatible Mode")

### Build from source

```bash
git clone https://github.com/richer-richard/pktscope.git
cd pktscope
cargo build --release   # binary at target/release/pktscope
```

This is a Cargo workspace: `pktscope-core` (reusable engine) + `pktscope`
(the CLI binary).

## Permissions

Capture needs root / BPF access:

- **Linux**: `sudo pktscope capture -i eth0`, or `sudo setcap cap_net_raw+eip ./pktscope`
- **macOS**: `sudo pktscope capture -i en0`, or add yourself to `access_bpf`
- **Windows**: run as Administrator with Npcap installed

The egress monitor additionally benefits from root for full socket→PID
attribution across all users.

## Usage — packet analyzer

```bash
pktscope list-interfaces
sudo pktscope capture -i en0                      # live TUI
sudo pktscope capture -i eth0 -f "tcp port 443"   # BPF filter
sudo pktscope capture -i en0 -w out.pcapng --pcapng   # save PCAPNG
sudo pktscope capture -i en0 --json -c 100        # one-shot: 100 packets as JSON
pktscope read capture.pcap                        # offline (pcap or pcapng)
pktscope diff a.pcap b.pcap                        # content diff
```

## Usage — egress monitor

```bash
# Start the daemon (foreground; --demo uses a 5s learning window so signals fire fast)
sudo pktscope monitor run -i en0 --demo \
  --geoip-country-db ~/.local/share/pktscope/dbip-country.mmdb \
  --geoip-asn-db ~/.local/share/pktscope/dbip-asn.mmdb

pktscope monitor status            # human or --json
pktscope inspect                   # attach the inspector TUI
pktscope inspect --json            # one-shot JSON dump (status + connections + alerts)
pktscope monitor stop              # clean shutdown
```

`--daemonize` detaches into the background; `dist/` has launchd and systemd
templates for running it as a service.

### Offline GeoIP / ASN data

Country and ASN enrichment use local MaxMind-format `.mmdb` files and never
touch the network at runtime. Fetch redistributable DB-IP Lite databases:

```bash
scripts/fetch-geoip.sh             # downloads to your data dir; prints the paths
```

Data © [db-ip.com](https://db-ip.com), CC-BY-4.0. (MaxMind GeoLite2 works too if
you point `--geoip-*-db` at your own copy; it is not bundled or auto-fetched.)
Without a database, country/ASN simply show as unknown.

### Configuration

Optional `~/.config/pktscope/config.toml`:

```toml
[capture]
default_interface = "en0"        # used when -i is omitted

[display]
color_scheme = "dark"

[filters]                        # recall in the filter bar as :name
https = "tcp.port == 443"
dns   = "udp.port == 53"
```

## Keybindings

**Capture TUI:** `j`/`k` move, `g`/`G` top/bottom, `Space` pause, `/` filter
(`:name` recalls a saved filter), `s` save, `m` bookmark, `'` bookmarks,
`Ctrl-F` regex search (`n` next), `t` top talkers, `P` protocol distribution,
`F` flows, `T` timeline, `f` follow stream, `Esc` close overlay, `q` quit.

**Inspector:** `Tab`/`1`-`5` switch views, `j`/`k` move, `/` search, `r`
refresh, `q` quit.

## Display filters

Protocol atoms: `tcp udp icmp icmpv6 arp ip ipv4 ipv6 dns tls`. Comparisons:
`ip.src == 10.0.0.1`, `tcp.port == 443`. Containment: `tls.sni contains
example.com`. Boolean: `and`/`&&`, `or`/`||`, `not`, parentheses.

## Architecture

- **`pktscope-core`** — capture, decoders, flow tracking + reassembly, filters,
  process attribution, passive name resolution, GeoIP/identity enrichment,
  SQLite store, the 5-signal alert engine, daemon + Unix-socket IPC, and the
  inspector reducer.
- **`pktscope`** — the CLI binary and the two ratatui frontends (capture TUI,
  inspector).

The capture path is three threads (capture → decode → UI) over bounded
channels. The daemon adds a correlate/detect worker and an IPC server; a single
thread owns the SQLite writer.

## Not yet implemented

Honest scope notes: blocking/firewalling (monitor-only by design); QUIC Initial
**decryption** for SNI (DNS-derived names cover the same destinations); HPACK
Huffman literal expansion (h2 is usually TLS-encrypted anyway); color-scheme
theming and keybinding remap (config keys are reserved); mmap disk-spill
scrollback (large files stream into the bounded ring; write a pcap to keep
everything); Windows process attribution is lightly tested.

## License

MIT. GeoIP data, if fetched, is © db-ip.com under CC-BY-4.0.

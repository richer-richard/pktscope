# pktscope Post-MVP Roadmap

This document captures the future development roadmap for pktscope. Each phase describes what to build, where it plugs into the existing module structure, what new modules/types/functions it needs, and implementation gotchas.

---

## Phase 2 — Stream Analysis

### TCP Stream Reassembly

**What:** Reconstruct full TCP byte streams from individual segments. Handle out-of-order delivery, deduplication of retransmitted segments, and gap detection.

**Where it plugs in:**
- Extend `src/flow/tracker.rs` — the `FlowState` struct gains per-direction reassembly buffers
- New file: `src/flow/reassembly.rs` — `ReassemblyBuffer` type with ordered insertion

**New types/functions:**
```
ReassemblyBuffer {
    segments: BTreeMap<u32, Vec<u8>>,  // seq -> data
    next_expected_seq: u32,
    completed: bool,
}

StreamData {
    client_to_server: Vec<u8>,
    server_to_client: Vec<u8>,
}

fn insert_segment(&mut self, seq: u32, data: &[u8]) -> ReassemblyResult
fn try_drain(&mut self) -> Option<Vec<u8>>
```

**Tricky parts:**
- TCP sequence number wrapping at 2^32 — all comparisons must use wrapping arithmetic
- Out-of-order segments need a BTreeMap keyed by sequence number
- Overlapping retransmissions must be deduplicated (take the first copy)
- Memory bounding: cap per-stream buffer at e.g. 1MB, evict if exceeded
- FIN/RST signals stream completion → emit reassembled data

**Dependencies:** None (builds on existing flow tracker)

### Follow-Stream TUI View

**What:** Press `f` on a TCP packet to open a modal pane showing the reassembled conversation. Client data in one color, server data in another. Scrollable.

**Where it plugs in:**
- New file: `src/tui/stream_view.rs`
- Modify `src/tui/mod.rs` — add `StreamView` input mode, `f` key handler

**New types:**
```
StreamView {
    flow_key: FlowKey,
    client_data: Vec<u8>,
    server_data: Vec<u8>,
    scroll: usize,
    display_mode: StreamDisplayMode,  // Hex, ASCII, UTF-8
}
```

**Dependencies:** TCP stream reassembly must be complete first.

### DNS Query/Response Pairing

**What:** Correlate DNS queries and responses by transaction ID across packets. Show RTT and answer summary in the Info column of the response packet.

**Where it plugs in:**
- New file: `src/flow/dns_tracker.rs`
- Modify `src/decode/mod.rs` — `compute_summary()` checks DNS tracker annotations

**New types:**
```
DnsTracker {
    pending: HashMap<u16, (u64, Instant)>,  // txid -> (packet_number, timestamp)
}

DnsPairing {
    query_packet: u64,
    rtt: Duration,
}
```

**Dependencies:** None (independent of TCP reassembly)

### HTTP Request/Response Pairing

**What:** Parse HTTP/1.1 request/response from reassembled TCP streams. Show method, URI, status code, content-type in packet summary.

**Where it plugs in:**
- New file: `src/decode/http.rs`
- Modify `src/decode/mod.rs` — add `Layer::Http(HttpInfo)` variant

**Dependencies:** TCP stream reassembly (Phase 2)

### RTT Measurement

**What:** Track SYN/SYN-ACK timing per TCP flow and data/ACK pairs. Show SRTT in the detail tree.

**Where it plugs in:**
- Extend `src/flow/tracker.rs` — `FlowState` gains RTT tracking fields
- Modify `src/tui/detail_tree.rs` — show RTT when available

**New fields on FlowState:**
```
syn_timestamp: Option<Instant>,
srtt: Option<Duration>,
rtt_samples: Vec<Duration>,
```

**Dependencies:** None (uses existing flow tracker)

---

## Phase 3 — Application Protocol Decoders

### HTTP/1.1

**What:** Full HTTP/1.1 decoder — request line, headers, body detection, chunked transfer encoding.

**Where it plugs in:**
- New file: `src/decode/http.rs`
- New `Layer::Http(HttpInfo)` variant in `src/decode/mod.rs`

**New types:**
```
HttpInfo {
    is_request: bool,
    method: Option<String>,      // GET, POST, etc.
    uri: Option<String>,
    status_code: Option<u16>,
    headers: Vec<(String, String)>,
    content_length: Option<usize>,
    header_range: (usize, usize),
}
```

**Dependencies:** TCP stream reassembly (Phase 2) — HTTP spans multiple TCP segments

### HTTP/2

**What:** HTTP/2 frame parsing — HEADERS, DATA, SETTINGS. HPACK header decompression.

**Where it plugs in:**
- New file: `src/decode/http2.rs`
- New `Layer::Http2Frame(Http2FrameInfo)` variant

**Tricky parts:**
- HPACK requires maintaining a dynamic header table per connection
- Multiplexed streams (stream IDs) need per-stream state
- Prior knowledge (h2c) vs ALPN negotiation detection

**Dependencies:** TCP stream reassembly, TLS ALPN extraction (for h2 over TLS)

### DNS Full Record Types

**What:** Expand DNS decoder beyond question section. Parse answer, authority, and additional sections. Full record type support: A, AAAA, CNAME, MX, TXT, SOA, NS, PTR, SRV.

**Where it plugs in:**
- Extend `src/decode/dns_question.rs` (rename to `src/decode/dns.rs`)
- Expand `DnsInfo` struct with answer records

**New types:**
```
DnsRecord {
    name: String,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: DnsRdata,
}

enum DnsRdata {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX { preference: u16, exchange: String },
    TXT(String),
    SOA { ... },
    NS(String),
    PTR(String),
    SRV { priority: u16, weight: u16, port: u16, target: String },
    Unknown(Vec<u8>),
}
```

**Dependencies:** None (extends existing DNS decoder)

### TLS Full Handshake Decoder

**What:** Decode all TLS handshake messages: ClientHello (full), ServerHello, Certificate, extensions. Extract cipher suite negotiation, certificate chain, ALPN.

**Where it plugs in:**
- Expand `src/decode/tls_sni.rs` (rename to `src/decode/tls.rs`)
- New `Layer::TlsHandshake(TlsHandshakeInfo)` variant alongside existing `TlsClientHello`

**JA3/JA4 fingerprinting** depends on this — compute MD5 hash of (TLS version, cipher suites, extensions, elliptic curves, EC point formats) from ClientHello. JA4 adds ALPN and signature algorithms.

**Dependencies:** None for basic handshake; stream reassembly for handshakes split across segments

### QUIC

**What:** Initial QUIC packet decoding — version negotiation, initial packet parsing, connection ID extraction.

**Where it plugs in:**
- New file: `src/decode/quic.rs`
- New `Layer::Quic(QuicInfo)` variant
- Triggered from UDP decoder when destination port is 443 and first byte matches QUIC long header format

**Tricky parts:**
- QUIC encrypts most of the payload after the initial packet
- Version negotiation packets have a specific format
- Connection migration changes connection IDs
- Long-term: QUIC-specific flow tracking separate from TCP

**Dependencies:** None for initial packet parsing; full decoding requires crypto

---

## Phase 4 — Statistics & Visualization

### Live Throughput Sparkline

**What:** Show a real-time sparkline of packets/sec and bytes/sec in the status bar area.

**Where it plugs in:**
- Modify `src/tui/mod.rs` — add throughput tracking to `App` state (ring buffer of last 60 seconds of counts)
- New widget in status bar area using ratatui's `Sparkline` widget

**New fields on App:**
```
throughput_pps: VecDeque<u64>,   // packets per second, last 60 entries
throughput_bps: VecDeque<u64>,   // bytes per second
last_throughput_tick: Instant,
```

### Top Talkers Panel

**What:** Sortable table showing top source/destination IPs by packet count and byte count. Optional grouping by process.

**Where it plugs in:**
- New file: `src/tui/top_talkers.rs`
- Toggle with `t` key in normal mode
- Add `TopTalkersView` mode to `InputMode`

### Protocol Distribution View

**What:** Bar chart or percentage breakdown of protocols seen (TCP, UDP, DNS, TLS, ARP, etc.).

**Where it plugs in:**
- New file: `src/tui/protocol_dist.rs`
- Track counts in `App` state per `ColorHint` variant

### Connection Timeline

**What:** Horizontal timeline view showing TCP connection lifetimes (SYN to FIN/RST) with packet dots.

**Where it plugs in:**
- New file: `src/tui/timeline.rs`
- Requires flow tracker to record first_seen/last_seen timestamps

### Per-Flow Stats View

**What:** Press `F` to see a flows table sorted by bytes, showing 5-tuple, packet count, byte count, duration, SRTT.

**Where it plugs in:**
- New file: `src/tui/flows_view.rs`
- Reads from `FlowTracker` state
- New `FlowsView` mode in `InputMode`

---

## Phase 5 — Cross-Platform Process Attribution

### macOS

**What:** Map network sockets to PIDs using `libproc` / `proc_pidinfo` with `PROC_PIDLISTFDS` and `PROC_PIDFDSOCKETINFO`.

**Where it plugs in:**
- Implement `src/process/macos.rs` (currently a stub)
- Use `libc` FFI to call `proc_listpids`, `proc_pidinfo`, `proc_pidfdinfo`

**Gotchas:**
- Requires `com.apple.security.network.client` entitlement if sandboxed
- `proc_pidinfo` returns `socket_fdinfo` with local/remote addresses
- Must enumerate all PIDs and their FDs each refresh cycle
- Consider caching with 1-second refresh (same pattern as Linux)

### Windows

**What:** Use `GetExtendedTcpTable` / `GetExtendedUdpTable` from `iphlpapi.dll` to map ports to PIDs.

**Where it plugs in:**
- Implement `src/process/windows.rs` (currently a stub)
- Use `windows-sys` crate for FFI

**New dependency:** `windows-sys` (Windows-only, behind `cfg`)

**Gotchas:**
- `MIB_TCPROW_OWNER_PID` / `MIB_UDPROW_OWNER_PID` give PID directly
- Process name from PID via `OpenProcess` + `QueryFullProcessImageNameW`
- Must handle both IPv4 and IPv6 table variants
- Administrator privileges required for process info

---

## Phase 6 — Persistence & Memory

### Disk Spill

**What:** When the in-memory ring buffer fills, spill older packets to a memory-mapped rolling PCAP file. Maintain an offset index for fast scrollback.

**Where it plugs in:**
- Extend `src/storage/ring.rs` — `PacketRing` gains a disk backend
- New file: `src/storage/disk_spill.rs`

**New types:**
```
DiskSpill {
    mmap_file: MmapMut,
    index: Vec<(u64, u64)>,  // (packet_number, file_offset)
    write_offset: u64,
    max_size: u64,
}
```

**Tricky parts:**
- mmap requires platform-specific handling (`memmap2` crate)
- Rolling file: when max size reached, wrap to beginning (circular buffer on disk)
- Index must support binary search for fast random access
- Packet retrieval: deserialize from disk on demand (lazy loading)

### Large PCAP Files

**What:** Open arbitrarily large PCAP files without loading everything into RAM. Build an offset index on first scan, then load packets on demand as the user scrolls.

**Where it plugs in:**
- Modify `src/capture/file.rs` — two-pass approach: index pass, then on-demand read
- Modify `src/storage/ring.rs` — support lazy loading from file offsets

### PCAPNG Support

**What:** Support PCAPNG format (Section Header Block, Interface Description Block, Enhanced Packet Block). The `pcap` crate supports PCAPNG reading via `pcap::Capture::from_file`.

**Where it plugs in:**
- `src/capture/file.rs` already works for PCAPNG (pcap crate handles it)
- `src/output/pcap_writer.rs` needs a PCAPNG writer variant
- New file: `src/output/pcapng_writer.rs`

---

## Phase 7 — Configuration & Customization

### Config File

**What:** Load settings from `~/.config/pktscope/config.toml` (Linux/macOS) or `%APPDATA%\pktscope\config.toml` (Windows).

**Where it plugs in:**
- New file: `src/config.rs`
- New dependency: `toml` crate, `dirs` crate for platform-appropriate config paths
- Load at startup in `src/main.rs` before CLI parsing (CLI args override config)

**Config options:**
```toml
[capture]
default_interface = "en0"
default_snaplen = 65535
buffer_size = 100000

[display]
color_scheme = "dark"  # or "light" or "custom"
timestamp_format = "%H:%M:%S%.3f"

[keybindings]
quit = "q"
filter = "/"
pause = " "
```

### Saved Named Filters

**What:** Save frequently used display filters by name. Recall with `:filter-name` syntax.

**Where it plugs in:**
- Extend config file with `[filters]` section
- Modify `src/tui/filter_bar.rs` — recognize `:name` prefix and expand

```toml
[filters]
https = "tcp.port == 443"
dns = "udp.port == 53"
local = "ip.src == 192.168.1.0/24"
```

### Color Scheme Customization

**What:** Allow users to override default protocol colors in config.

**Where it plugs in:**
- Modify `src/tui/packet_list.rs` — read colors from config instead of hardcoded
- Map `ColorHint` variants to configurable `Color` values

### Keybinding Overrides

**What:** Allow remapping all keybindings via config file.

**Where it plugs in:**
- New file: `src/keybindings.rs` — keybinding map loaded from config
- Modify `src/tui/mod.rs` `handle_key_event()` — lookup action by key in keybinding map

---

## Phase 8 — Power-User Features

### Bookmarks

**What:** Press `m` to bookmark the current packet. Show bookmarked packets with a marker. Press `'` to open a bookmark jump list.

**Where it plugs in:**
- Add `bookmarks: HashSet<u64>` to `App` state
- Modify `src/tui/packet_list.rs` — show bookmark marker (e.g. `★`) in a column
- New file: `src/tui/bookmark_list.rs` — modal jump list

### Regex Search

**What:** Press `Ctrl-F` to search decoded packet contents (summary, layer fields) with regex.

**Where it plugs in:**
- New dependency: `regex` crate
- Modify `src/tui/mod.rs` — add `SearchMode` to `InputMode`
- New file: `src/tui/search.rs` — search results highlighting

### Anomaly Highlighting

**What:** Detect and highlight suspicious patterns: plaintext credentials (HTTP Basic Auth, FTP PASS), unusual ports (SSH on non-22, HTTP on non-80/443), connections to known-bad IP ranges.

**Where it plugs in:**
- New file: `src/analysis/anomaly.rs`
- New `AnomalyAnnotation` type attached to `DecodedPacket`
- Modify `src/tui/packet_list.rs` — show anomaly icon/color

**Gotchas:**
- Must not flag encrypted traffic (only plaintext matches)
- Known-bad IP ranges need a curated list (ship a default, allow user overrides)
- False positive rate matters — conservative defaults

### Diff Two Captures

**What:** Load two PCAP files side by side, highlight packets present in one but not the other. Match by content hash or by timestamp+5-tuple.

**Where it plugs in:**
- New subcommand: `pktscope diff <file1> <file2>`
- New file: `src/tui/diff_view.rs`

### One-Shot / Sample Mode

**What:** `pktscope capture -i en0 -c 100` captures exactly 100 packets and exits. `pktscope capture -i en0 -G 30` captures for 30 seconds and exits. Both produce clean output suitable for scripting.

**Where it plugs in:**
- Extend `src/cli.rs` — add `-c` (count) and `-G` (duration) flags to `Capture` command
- Modify `src/main.rs` — add termination conditions to the capture/decode/output loop

---

## Dependency Graph

```
Phase 2: Stream Analysis
  TCP Reassembly ──┬── Follow-Stream View
                   └── HTTP Request/Response Pairing
  DNS Pairing (independent)
  RTT Measurement (independent)

Phase 3: Protocol Decoders
  HTTP/1.1 ← TCP Reassembly (Phase 2)
  HTTP/2 ← TCP Reassembly (Phase 2) + TLS ALPN
  DNS Full Records (independent)
  TLS Full Handshake (independent) ── JA3/JA4 Fingerprinting
  QUIC (independent)

Phase 4: Statistics (all independent of Phase 2-3)

Phase 5: Process Attribution (independent)

Phase 6: Persistence (independent)

Phase 7: Configuration (independent)

Phase 8: Power-User Features (mostly independent)
  Anomaly Highlighting benefits from Phase 3 decoders
```

---

## How to Resume

For a future Claude Code run picking up any phase:

### Phase 2
1. Open `src/flow/tracker.rs` and `src/flow/mod.rs` — understand current FlowState
2. Create `src/flow/reassembly.rs` with `ReassemblyBuffer`
3. Add tests in `tests/integration.rs` with crafted out-of-order TCP segments
4. Verify: existing flow tracker tests still pass, new reassembly tests pass

### Phase 3
1. Open `src/decode/mod.rs` — understand the `Layer` enum and `NextDecode` chain
2. Add new `Layer` variant for the protocol
3. Create decoder file (e.g., `src/decode/http.rs`)
4. Wire into `decode_layers()` — determine where in the chain it triggers
5. Update `compute_summary()` for the new protocol
6. Add unit tests with crafted byte arrays
7. Verify: `cargo test` passes, new protocol shows in TUI

### Phase 4
1. Open `src/tui/mod.rs` — understand `App` state and `render_frame()` layout
2. Create new view file (e.g., `src/tui/top_talkers.rs`)
3. Add toggle key in `handle_key_event()`
4. Verify: TUI renders new view, existing views unaffected

### Phase 5
1. Open `src/process/mod.rs` and `src/process/linux.rs` for reference
2. Implement platform-specific file (e.g., `src/process/macos.rs`)
3. Test on the target platform with `sudo`
4. Verify: process names appear in packet detail tree

### Phase 6
1. Open `src/storage/ring.rs` — understand `PacketRing`
2. Add `memmap2` dependency
3. Create `src/storage/disk_spill.rs`
4. Modify `PacketRing` to delegate to disk when over capacity
5. Verify: can capture >100k packets without memory explosion

### Phase 7
1. Add `toml` and `dirs` dependencies
2. Create `src/config.rs` with `Config` struct
3. Load in `src/main.rs` before CLI parsing
4. Wire config values into relevant modules
5. Verify: settings from config.toml take effect, CLI overrides work

### Phase 8
1. Identify which feature to add
2. Most features are self-contained TUI additions
3. Follow the pattern: add state to `App`, add key handler, add renderer
4. Verify: feature works, existing features unaffected

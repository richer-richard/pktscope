# Manual Testing Guide

## Prerequisites
- Built with `cargo build --release`
- Root/admin privileges for live capture

## Test 1: TLS SNI Detection

1. Start capture:
   ```bash
   sudo ./target/release/pktscope capture -i en0  # macOS
   sudo ./target/release/pktscope capture -i eth0  # Linux
   ```
2. In another terminal, browse to an HTTPS site:
   ```bash
   curl https://example.com
   ```
3. **Expected**: A packet with protocol "TLS" and Info column showing `TLS → example.com`
4. The TLS packet should appear in blue

## Test 2: DNS Query Detection

1. Start capture with DNS filter:
   ```bash
   sudo ./target/release/pktscope capture -i en0 -f "udp port 53"
   ```
2. In another terminal:
   ```bash
   dig example.com
   # or
   nslookup example.com
   ```
3. **Expected**: Packets with protocol "DNS" and Info column showing `DNS Q example.com`
4. DNS packets should appear in yellow

## Test 3: TCP Retransmission Detection

### Linux (using tc to simulate packet loss)
```bash
# Add 10% packet loss on lo (requires sudo)
sudo tc qdisc add dev lo root netem loss 10%

# Start capture on loopback
sudo ./target/release/pktscope capture -i lo

# Generate traffic with retransmissions
curl http://localhost:8080  # (run a local server first)

# Remove the loss rule
sudo tc qdisc del dev lo root
```

### Any OS (via slow/unreliable network)
1. Capture on an interface with poor connectivity
2. Transfer a large file
3. **Expected**: Some packets appear in red with `[Retransmission]` prefix in the Info column

## Test 4: Display Filter

1. Start capture and let some traffic accumulate
2. Press `/` to enter filter mode
3. Type `tcp.port == 443` and press Enter
4. **Expected**: Only HTTPS-related TCP packets visible
5. Press `/`, clear (empty Enter) to remove filter
6. **Expected**: All packets visible again
7. Try other filters:
   - `dns`
   - `tls.sni contains google`
   - `ip.src == 10.0.0.1`
   - `tcp and not arp`

## Test 5: JSON Output

```bash
sudo ./target/release/pktscope capture -i en0 --json | head -5
```
**Expected**: Each line is valid JSON with fields: number, timestamp, wire_len, layers, summary

Verify with jq:
```bash
sudo ./target/release/pktscope capture -i en0 --json | head -1 | jq .summary.protocol
```

## Test 6: PCAP File Save and Read

1. Capture with save:
   ```bash
   sudo ./target/release/pktscope capture -i en0 -w /tmp/test.pcap
   ```
2. Generate some traffic, then quit with `q`
3. Read the saved file:
   ```bash
   ./target/release/pktscope read /tmp/test.pcap
   ```
4. **Expected**: Same packets displayed as during capture

## Test 7: List Interfaces

```bash
./target/release/pktscope list-interfaces
```
**Expected**: List of network interfaces with names and addresses

## Test 8: PCAP File Read

```bash
# Read any existing pcap file
./target/release/pktscope read /path/to/some.pcap
```
**Expected**: Packets decoded and displayed with correct protocols

## Test 9: Keyboard Navigation

1. Start capture or read a pcap with many packets
2. Test: `j`/`k` to navigate, `G` to jump to end, `g` to jump to start
3. Test: `Space` to pause/resume
4. Test: `PgDn`/`PgUp` for fast scrolling
5. **Expected**: Smooth navigation, detail tree and hex dump update with selection

## Test 10: New protocol decoders

1. `curl https://github.com` while capturing → select the TLS Client Hello;
   the detail tree shows the **SNI**, **ALPN**, and **JA3/JA4** fingerprints.
2. `dig example.com` → the DNS response packet shows **answer records** (A/AAAA).
3. Browse over HTTP/3 (e.g. a Google property) → **QUIC** packets are labelled
   with their packet type. `curl http://example.com` → an **HTTP** request line.
4. Press `f` on a TCP packet → the **follow-stream** overlay shows the
   reassembled client/server conversation.

## Test 11: Stats views and power-user features

1. While capturing: `t` (top talkers), `P` (protocol distribution), `F` (flows),
   `T` (timeline) — each opens a full-screen overlay; `Esc` closes. The
   throughput sparkline updates once per second.
2. `m` bookmarks the selected packet (★ marker); `'` lists bookmarks.
3. `Ctrl-F`, type a regex, Enter → matching rows highlight; `n` jumps to the next.
4. Browse to an `http://` site with Basic auth → the row is flagged as a
   plaintext-credential anomaly (bold red).

## Test 12: Egress monitor — the five signals

Start the daemon with a short learning window so signals fire quickly:

```bash
sudo ./target/release/pktscope monitor run -i en0 --demo \
  --geoip-country-db ~/.local/share/pktscope/dbip-country.mmdb \
  --geoip-asn-db ~/.local/share/pktscope/dbip-asn.mmdb
# (run scripts/fetch-geoip.sh first for country/ASN; optional)
```

In another terminal attach the inspector: `./target/release/pktscope inspect`.
After the 5s learning window (`monitor status` shows `active`), trigger each
signal and confirm a macOS notification **and** an inspector alert:

1. **New process → destination**: `curl https://a-domain-you-never-visit.example`
2. **New process phoning home**: run a brand-new binary that connects out
3. **New country / ASN**: connect to a host in a country you haven't contacted
4. **Volume spike**: `curl -T bigfile https://transfer.example` (a large upload)
5. **Program modification**: re-sign or replace a binary, then have it connect

Verify the inspector's Connections / Processes / Domains / Alerts / History tabs,
and `./target/release/pktscope inspect --json | jq` for machine-readable output.
`./target/release/pktscope monitor stop` shuts the daemon down cleanly.

## Test 13: Diff and one-shot

```bash
./target/release/pktscope capture -i en0 --json -c 50 > /dev/null   # exits after 50
./target/release/pktscope diff a.pcap b.pcap                        # content diff
```

## Platform-Specific Notes

### macOS
- Default interface is usually `en0` (Wi-Fi) or `en1`
- BPF access may require `access_bpf` group membership

### Linux
- Common interfaces: `eth0`, `wlan0`, `ens33`, `enp0s3`
- Use `ip link show` to list interfaces
- Process attribution shows PID and process name in packet details

### Windows
- Interfaces have long names like `\Device\NPF_{GUID}`
- Use `list-interfaces` to find the right one
- Npcap must be installed with WinPcap compatibility mode

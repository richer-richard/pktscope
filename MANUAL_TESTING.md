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

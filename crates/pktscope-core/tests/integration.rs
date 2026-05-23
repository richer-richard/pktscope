use std::io::Write;

use pktscope_core::decode::{self, Layer};
use pktscope_core::filter::eval::eval_filter;
use pktscope_core::filter::parser::parse_filter;

// ---------------------------------------------------------------------------
// Helper: build pcap files from raw packet bytes
// ---------------------------------------------------------------------------

fn write_pcap(path: &std::path::Path, packets: &[Vec<u8>]) {
    let mut f = std::fs::File::create(path).unwrap();
    // Global header
    f.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap(); // magic
    f.write_all(&2u16.to_le_bytes()).unwrap(); // version major
    f.write_all(&4u16.to_le_bytes()).unwrap(); // version minor
    f.write_all(&0i32.to_le_bytes()).unwrap(); // thiszone
    f.write_all(&0u32.to_le_bytes()).unwrap(); // sigfigs
    f.write_all(&65535u32.to_le_bytes()).unwrap(); // snaplen
    f.write_all(&1u32.to_le_bytes()).unwrap(); // linktype = Ethernet

    for (i, pkt) in packets.iter().enumerate() {
        let ts_sec = 1700000000u32 + i as u32;
        let ts_usec = 0u32;
        let caplen = pkt.len() as u32;
        let wirelen = caplen;
        f.write_all(&ts_sec.to_le_bytes()).unwrap();
        f.write_all(&ts_usec.to_le_bytes()).unwrap();
        f.write_all(&caplen.to_le_bytes()).unwrap();
        f.write_all(&wirelen.to_le_bytes()).unwrap();
        f.write_all(pkt).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

fn build_ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&ethertype.to_be_bytes());
    pkt
}

fn build_ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload_len: u16) -> Vec<u8> {
    let total_len = 20 + payload_len;
    vec![
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01,
        0x40,
        0x00, // DF
        0x40,
        protocol,
        0x00,
        0x00, // checksum (zeroed)
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
    ]
}

fn build_tcp(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0..2].copy_from_slice(&src_port.to_be_bytes());
    h[2..4].copy_from_slice(&dst_port.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[8..12].copy_from_slice(&ack.to_be_bytes());
    h[12] = 0x50; // data_offset=5
    h[13] = flags;
    h[14..16].copy_from_slice(&65535u16.to_be_bytes());
    h
}

fn build_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let length = 8 + payload.len() as u16;
    let mut h = vec![0u8; 8];
    h[0..2].copy_from_slice(&src_port.to_be_bytes());
    h[2..4].copy_from_slice(&dst_port.to_be_bytes());
    h[4..6].copy_from_slice(&length.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn build_dns_query(qname: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0xAB, 0xCD]); // txid
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query
    pkt.extend_from_slice(&[0x00, 0x01]); // qdcount=1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in qname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    pkt
}

fn build_arp_request(sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut pkt = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0806);
    // ARP
    pkt.extend_from_slice(&[0x00, 0x01]); // hw type
    pkt.extend_from_slice(&[0x08, 0x00]); // proto type
    pkt.push(6); // hw len
    pkt.push(4); // proto len
    pkt.extend_from_slice(&[0x00, 0x01]); // request
    pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // sender mac
    pkt.extend_from_slice(&sender_ip);
    pkt.extend_from_slice(&[0x00; 6]); // target mac
    pkt.extend_from_slice(&target_ip);
    pkt
}

fn build_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_ext_data_len = 2 + 1 + 2 + sni_bytes.len();
    let sni_ext_len = 4 + sni_ext_data_len;
    let extensions_len = sni_ext_len;
    let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;

    let mut tls = Vec::new();
    tls.push(0x16); // handshake
    tls.extend_from_slice(&[0x03, 0x01]);
    let record_len = (4 + ch_body_len) as u16;
    tls.extend_from_slice(&record_len.to_be_bytes());

    tls.push(0x01); // Client Hello
    let hs_len = ch_body_len as u32;
    tls.push((hs_len >> 16) as u8);
    tls.push((hs_len >> 8) as u8);
    tls.push(hs_len as u8);

    tls.extend_from_slice(&[0x03, 0x03]);
    tls.extend_from_slice(&[0u8; 32]);
    tls.push(0); // session_id_len
    tls.extend_from_slice(&2u16.to_be_bytes());
    tls.extend_from_slice(&[0x00, 0x2F]);
    tls.push(1);
    tls.push(0x00);
    tls.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    tls.extend_from_slice(&[0x00, 0x00]);
    tls.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    let sni_list_len = (1 + 2 + sni_bytes.len()) as u16;
    tls.extend_from_slice(&sni_list_len.to_be_bytes());
    tls.push(0x00);
    tls.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    tls.extend_from_slice(sni_bytes);

    tls
}

// ---------------------------------------------------------------------------
// Full packet builders (Ethernet + IP + transport + payload)
// ---------------------------------------------------------------------------

fn build_tcp_syn_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
) -> Vec<u8> {
    let tcp = build_tcp(src_port, dst_port, seq, 0, 0x02);
    let ip = build_ipv4(src_ip, dst_ip, 6, tcp.len() as u16);
    let mut pkt = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0800);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&tcp);
    pkt
}

fn build_dns_packet(src_ip: [u8; 4], dst_ip: [u8; 4], qname: &str) -> Vec<u8> {
    let dns = build_dns_query(qname);
    let udp = build_udp(12345, 53, &dns);
    let ip = build_ipv4(src_ip, dst_ip, 17, udp.len() as u16);
    let mut pkt = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0800);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&udp);
    pkt
}

fn build_tls_packet(src_ip: [u8; 4], dst_ip: [u8; 4], sni: &str) -> Vec<u8> {
    let tls = build_tls_client_hello(sni);
    let tcp = build_tcp(50000, 443, 1000, 0, 0x18); // PSH+ACK
    let ip = build_ipv4(src_ip, dst_ip, 6, (tcp.len() + tls.len()) as u16);
    let mut pkt = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0800);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&tcp);
    pkt.extend_from_slice(&tls);
    pkt
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_decode_tcp_handshake_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("handshake.pcap");

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];
    let packets = vec![
        build_tcp_syn_packet(src, dst, 50000, 80, 1000),
        build_tcp_syn_packet(dst, src, 80, 50000, 2000), // SYN-ACK would have different flags but fine for decode test
        build_tcp_syn_packet(src, dst, 50000, 80, 1001),
    ];
    write_pcap(&pcap_path, &packets);

    // Read and decode
    let raw_packets = read_pcap_packets(&pcap_path);
    assert_eq!(raw_packets.len(), 3);

    for pkt in &raw_packets {
        assert!(pkt.layers.iter().any(|l| matches!(l, Layer::Tcp(_))));
        assert_eq!(pkt.summary.protocol, "TCP");
    }
}

#[test]
fn test_decode_dns_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("dns.pcap");

    let packets = vec![build_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], "example.com")];
    write_pcap(&pcap_path, &packets);

    let decoded = read_pcap_packets(&pcap_path);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].summary.protocol, "DNS");
    assert!(decoded[0].summary.info.contains("example.com"));
}

#[test]
fn test_decode_tls_sni_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("tls.pcap");

    let packets = vec![build_tls_packet(
        [10, 0, 0, 1],
        [93, 184, 216, 34],
        "github.com",
    )];
    write_pcap(&pcap_path, &packets);

    let decoded = read_pcap_packets(&pcap_path);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].summary.protocol, "TLS");
    assert!(decoded[0].summary.info.contains("github.com"));
}

#[test]
fn test_decode_arp_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("arp.pcap");

    let packets = vec![build_arp_request([192, 168, 1, 1], [192, 168, 1, 2])];
    write_pcap(&pcap_path, &packets);

    let decoded = read_pcap_packets(&pcap_path);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].summary.protocol, "ARP");
    assert!(decoded[0].summary.info.contains("192.168.1.2"));
}

#[test]
fn test_decode_mixed_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("mixed.pcap");

    let packets = vec![
        build_arp_request([192, 168, 1, 1], [192, 168, 1, 2]),
        build_tcp_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 443, 50000, 100),
        build_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], "google.com"),
        build_tls_packet([10, 0, 0, 1], [142, 250, 80, 46], "www.google.com"),
    ];
    write_pcap(&pcap_path, &packets);

    let decoded = read_pcap_packets(&pcap_path);
    assert_eq!(decoded.len(), 4);
    assert_eq!(decoded[0].summary.protocol, "ARP");
    assert_eq!(decoded[1].summary.protocol, "TCP");
    assert_eq!(decoded[2].summary.protocol, "DNS");
    assert_eq!(decoded[3].summary.protocol, "TLS");
}

#[test]
fn test_filter_on_pcap() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("filter_test.pcap");

    let packets = vec![
        build_tcp_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 80, 50000, 100),
        build_dns_packet([10, 0, 0, 1], [8, 8, 8, 8], "example.com"),
        build_tcp_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 443, 50001, 200),
    ];
    write_pcap(&pcap_path, &packets);

    let decoded = read_pcap_packets(&pcap_path);

    // Filter: tcp
    let tcp_filter = parse_filter("tcp").unwrap();
    let tcp_matches: Vec<_> = decoded
        .iter()
        .filter(|p| eval_filter(&tcp_filter, p))
        .collect();
    assert_eq!(tcp_matches.len(), 2);

    // Filter: dns
    let dns_filter = parse_filter("dns").unwrap();
    let dns_matches: Vec<_> = decoded
        .iter()
        .filter(|p| eval_filter(&dns_filter, p))
        .collect();
    assert_eq!(dns_matches.len(), 1);

    // Filter: tcp.port == 443
    let port_filter = parse_filter("tcp.port == 443").unwrap();
    let port_matches: Vec<_> = decoded
        .iter()
        .filter(|p| eval_filter(&port_filter, p))
        .collect();
    assert_eq!(port_matches.len(), 1);
}

#[test]
fn test_retransmission_detection() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("retransmit.pcap");

    let src = [10, 0, 0, 1];
    let dst = [10, 0, 0, 2];

    // Build packets with payload to trigger retransmission detection
    let mut p1 = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0800);
    let tcp1 = build_tcp(80, 12345, 1000, 0, 0x18); // PSH+ACK
    let payload1 = vec![0xAA; 100]; // 100 bytes payload
    let ip1 = build_ipv4(src, dst, 6, (tcp1.len() + payload1.len()) as u16);
    p1.extend_from_slice(&ip1);
    p1.extend_from_slice(&tcp1);
    p1.extend_from_slice(&payload1);

    let mut p2 = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0800);
    let tcp2 = build_tcp(80, 12345, 1100, 0, 0x18);
    let payload2 = vec![0xBB; 100];
    let ip2 = build_ipv4(src, dst, 6, (tcp2.len() + payload2.len()) as u16);
    p2.extend_from_slice(&ip2);
    p2.extend_from_slice(&tcp2);
    p2.extend_from_slice(&payload2);

    // Retransmission of first packet (same seq)
    let mut p3 = build_ethernet([0xff; 6], [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0x0800);
    let tcp3 = build_tcp(80, 12345, 1000, 0, 0x18);
    let payload3 = vec![0xAA; 100];
    let ip3 = build_ipv4(src, dst, 6, (tcp3.len() + payload3.len()) as u16);
    p3.extend_from_slice(&ip3);
    p3.extend_from_slice(&tcp3);
    p3.extend_from_slice(&payload3);

    write_pcap(&pcap_path, &[p1, p2, p3]);

    let decoded = read_pcap_packets_with_flow(&pcap_path);
    assert_eq!(decoded.len(), 3);
    assert!(
        !decoded[0].retransmission,
        "First packet should not be retransmission"
    );
    assert!(
        !decoded[1].retransmission,
        "Second packet should not be retransmission"
    );
    assert!(
        decoded[2].retransmission,
        "Third packet should be marked as retransmission"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_pcap_packets(path: &std::path::Path) -> Vec<decode::DecodedPacket> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = crossbeam_channel::bounded(1000);
    let capture_handle =
        pktscope_core::capture::file::start_file_capture(path, None, tx, stop.clone()).unwrap();

    let _ = capture_handle.join();

    let mut packets = Vec::new();
    while let Ok(raw) = rx.try_recv() {
        packets.push(decode::decode_packet(&raw));
    }
    packets
}

fn read_pcap_packets_with_flow(path: &std::path::Path) -> Vec<decode::DecodedPacket> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = crossbeam_channel::bounded(1000);
    let capture_handle =
        pktscope_core::capture::file::start_file_capture(path, None, tx, stop.clone()).unwrap();

    let _ = capture_handle.join();

    let mut tracker = pktscope_core::flow::tracker::FlowTracker::new();
    let mut packets = Vec::new();
    while let Ok(raw) = rx.try_recv() {
        let mut decoded = decode::decode_packet(&raw);
        tracker.update(&mut decoded);
        packets.push(decoded);
    }
    packets
}

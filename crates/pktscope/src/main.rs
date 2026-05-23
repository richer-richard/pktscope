mod cli;
mod permissions;
mod tui;

use pktscope_core::{capture, decode, flow, output, process};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::bounded;

use cli::{Cli, Command};

const CHANNEL_CAPACITY: usize = 10_000;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ListInterfaces => list_interfaces(),
        Command::Capture {
            interface,
            filter,
            write,
            json,
            snaplen,
            buffer_size,
        } => {
            permissions::check_capture_permissions()?;

            let stop = Arc::new(AtomicBool::new(false));

            let (raw_tx, raw_rx) = bounded(CHANNEL_CAPACITY);
            let (decoded_tx, decoded_rx) = bounded(CHANNEL_CAPACITY);

            let capture_handle = capture::live::start_live_capture(
                &interface,
                filter.as_deref(),
                snaplen,
                raw_tx,
                stop.clone(),
            )?;

            let decode_stop = stop.clone();
            let decode_handle = std::thread::Builder::new()
                .name("decode".into())
                .spawn(move || decode_thread(raw_rx, decoded_tx, decode_stop))?;

            if json {
                json_output_loop(decoded_rx, stop.clone())?;
            } else {
                tui::run_tui(decoded_rx, buffer_size, write.as_deref())?;
            }

            stop.store(true, Ordering::Relaxed);
            let _ = capture_handle.join();
            let _ = decode_handle.join();
            Ok(())
        }
        Command::Read {
            file,
            filter,
            json,
            buffer_size,
        } => {
            let stop = Arc::new(AtomicBool::new(false));

            let (raw_tx, raw_rx) = bounded(CHANNEL_CAPACITY);
            let (decoded_tx, decoded_rx) = bounded(CHANNEL_CAPACITY);

            let capture_handle =
                capture::file::start_file_capture(&file, filter.as_deref(), raw_tx, stop.clone())?;

            let decode_stop = stop.clone();
            let decode_handle = std::thread::Builder::new()
                .name("decode".into())
                .spawn(move || decode_thread(raw_rx, decoded_tx, decode_stop))?;

            if json {
                json_output_loop(decoded_rx, stop.clone())?;
            } else {
                tui::run_tui(decoded_rx, buffer_size, None)?;
            }

            stop.store(true, Ordering::Relaxed);
            let _ = capture_handle.join();
            let _ = decode_handle.join();
            Ok(())
        }
    }
}

fn list_interfaces() -> Result<()> {
    let devices = pcap::Device::list()?;
    if devices.is_empty() {
        println!("No interfaces found. You may need elevated privileges.");
        return Ok(());
    }
    for dev in devices {
        let desc = dev.desc.as_deref().unwrap_or("No description");
        let addrs: Vec<String> = dev.addresses.iter().map(|a| a.addr.to_string()).collect();
        let addr_str = if addrs.is_empty() {
            String::new()
        } else {
            format!(" [{}]", addrs.join(", "))
        };
        println!("  {}: {}{}", dev.name, desc, addr_str);
    }
    Ok(())
}

fn decode_thread(
    raw_rx: crossbeam_channel::Receiver<capture::RawPacket>,
    decoded_tx: crossbeam_channel::Sender<decode::DecodedPacket>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut flow_tracker = flow::tracker::FlowTracker::new();

    while !stop.load(Ordering::Relaxed) {
        match raw_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(raw) => {
                let mut decoded = decode::decode_packet(&raw);

                flow_tracker.update(&mut decoded);

                decoded.process = try_process_lookup(&decoded);

                if decoded_tx.send(decoded).is_err() {
                    break;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

fn try_process_lookup(pkt: &decode::DecodedPacket) -> Option<decode::ProcessInfo> {
    for layer in &pkt.layers {
        match layer {
            decode::Layer::Tcp(tcp) => {
                if let Some(ip) = find_local_ip(pkt) {
                    return process::lookup_process(6, ip, tcp.src_port)
                        .or_else(|| process::lookup_process(6, ip, tcp.dst_port));
                }
            }
            decode::Layer::Udp(udp) => {
                if let Some(ip) = find_local_ip(pkt) {
                    return process::lookup_process(17, ip, udp.src_port)
                        .or_else(|| process::lookup_process(17, ip, udp.dst_port));
                }
            }
            _ => {}
        }
    }
    None
}

fn find_local_ip(pkt: &decode::DecodedPacket) -> Option<std::net::IpAddr> {
    for layer in &pkt.layers {
        match layer {
            decode::Layer::Ipv4(ip) => {
                return Some(std::net::IpAddr::V4(ip.src_ip));
            }
            decode::Layer::Ipv6(ip) => {
                return Some(std::net::IpAddr::V6(ip.src_ip));
            }
            _ => {}
        }
    }
    None
}

fn json_output_loop(
    rx: crossbeam_channel::Receiver<decode::DecodedPacket>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::new(stdout.lock());
    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(pkt) => output::json::write_json_line(&mut writer, &pkt)?,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

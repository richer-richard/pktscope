mod cli;
mod permissions;
mod tui;

use pktscope_core::{capture, decode, flow, output, process};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::bounded;

use cli::{Cli, Command, MonitorAction};

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
        Command::Monitor { action } => monitor_cmd(action),
    }
}

#[cfg(unix)]
static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_signal(_sig: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
fn install_signal_handlers(stop: Arc<AtomicBool>) {
    // SAFETY: handler only performs an atomic store, which is async-signal-safe.
    let handler = handle_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
    std::thread::spawn(move || {
        while !SIGNAL_STOP.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        stop.store(true, Ordering::Relaxed);
    });
}

#[cfg(unix)]
fn monitor_cmd(action: MonitorAction) -> Result<()> {
    use pktscope_core::alert::AlertConfig;
    use pktscope_core::monitor::{self, MonitorConfig};

    match action {
        MonitorAction::Run {
            interface,
            filter,
            snaplen,
            state_dir,
            geoip_country_db,
            geoip_asn_db,
            demo,
            daemonize,
            no_notify,
        } => {
            permissions::check_capture_permissions()?;
            let paths = monitor::paths::resolve(state_dir);
            std::fs::create_dir_all(&paths.state_dir).ok();
            if daemonize {
                monitor::daemonize::daemonize(&paths.log)?;
            }
            let stop = Arc::new(AtomicBool::new(false));
            install_signal_handlers(stop.clone());
            let alert = if demo {
                AlertConfig::demo()
            } else {
                AlertConfig::default()
            };
            eprintln!(
                "pktscope monitor: interface={interface} db={} socket={}",
                paths.db.display(),
                paths.socket.display()
            );
            let cfg = MonitorConfig {
                interface,
                bpf: filter,
                snaplen,
                db_path: paths.db,
                socket_path: paths.socket,
                geoip_country: geoip_country_db,
                geoip_asn: geoip_asn_db,
                alert,
                notify: !no_notify,
            };
            monitor::run_monitor(cfg, stop)
        }
        MonitorAction::Status { state_dir, json } => {
            let paths = monitor::paths::resolve(state_dir);
            let status = monitor::monitor_status(&paths.socket)?;
            if json {
                println!("{}", serde_json::to_string(&status)?);
            } else {
                println!(
                    "pktscope monitor — {} (pid {})",
                    status.baseline, status.pid
                );
                println!("  interface:    {}", status.interface);
                println!("  uptime:       {}s", status.uptime_secs);
                println!(
                    "  processes:    {}\n  destinations: {}\n  alerts:       {}",
                    status.processes, status.destinations, status.alerts
                );
            }
            Ok(())
        }
        MonitorAction::Stop { state_dir } => {
            let paths = monitor::paths::resolve(state_dir);
            monitor::monitor_stop(&paths.socket)?;
            println!("monitor stopping");
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn monitor_cmd(_action: MonitorAction) -> Result<()> {
    anyhow::bail!("the egress monitor daemon is only supported on Unix")
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

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;

use super::{Linktype, RawPacket, capture_loop};

pub fn start_file_capture(
    path: &Path,
    bpf_filter: Option<&str>,
    tx: crossbeam_channel::Sender<RawPacket>,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<std::thread::JoinHandle<anyhow::Result<()>>> {
    let mut cap = pcap::Capture::from_file(path)?;

    if let Some(filter) = bpf_filter {
        cap.filter(filter, true)?;
    }

    let linktype = Linktype::from(cap.get_datalink());

    let handle = std::thread::Builder::new()
        .name("capture-file".into())
        .spawn(move || {
            let counter = AtomicU64::new(0);
            capture_loop(cap, tx, stop, linktype, &counter)
        })?;

    Ok(handle)
}

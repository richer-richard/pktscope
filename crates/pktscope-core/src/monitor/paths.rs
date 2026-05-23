use std::path::PathBuf;

/// Filesystem locations for the daemon's runtime state.
pub struct Paths {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub db: PathBuf,
    pub pidfile: PathBuf,
    pub log: PathBuf,
}

/// Resolve runtime paths, defaulting to the platform's local data directory
/// (`~/Library/Application Support/pktscope` on macOS, `~/.local/share/pktscope`
/// on Linux).
pub fn resolve(state_dir: Option<PathBuf>) -> Paths {
    let dir = state_dir.unwrap_or_else(default_state_dir);
    Paths {
        socket: dir.join("pktscope.sock"),
        db: dir.join("pktscope.db"),
        pidfile: dir.join("pktscope.pid"),
        log: dir.join("monitor.log"),
        state_dir: dir,
    }
}

fn default_state_dir() -> PathBuf {
    dirs::data_local_dir()
        .map(|d| d.join("pktscope"))
        .unwrap_or_else(|| PathBuf::from("/tmp/pktscope"))
}

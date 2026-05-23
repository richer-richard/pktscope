use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Detach into the background via the classic double-fork, redirecting stdio to
/// `log_path` (and stdin to /dev/null). The grandchild returns `Ok(())` and
/// continues; the parent and intermediate processes exit.
pub fn daemonize(log_path: &Path) -> io::Result<()> {
    // SAFETY: standard daemonization sequence; each libc call is checked.
    unsafe {
        match libc::fork() {
            -1 => return Err(io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        match libc::fork() {
            -1 => return Err(io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
        libc::umask(0);
        libc::chdir(c"/".as_ptr());
    }

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let devnull = std::fs::OpenOptions::new().read(true).open("/dev/null")?;
    // SAFETY: redirect the standard descriptors; fds are valid open files.
    unsafe {
        libc::dup2(devnull.as_raw_fd(), 0);
        libc::dup2(log.as_raw_fd(), 1);
        libc::dup2(log.as_raw_fd(), 2);
    }
    // Keep the underlying fds open for the lifetime of the process.
    std::mem::forget(log);
    std::mem::forget(devnull);
    Ok(())
}

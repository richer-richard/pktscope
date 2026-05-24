use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::protocol::{Event, Request, Response};

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// A client connection to the daemon. Use one connection for request/response
/// queries and a separate `Subscribe`d connection for the live event stream.
pub struct IpcClient {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl IpcClient {
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { stream, reader })
    }

    /// Send a request and read the single-line response.
    pub fn request(&mut self, req: &Request) -> io::Result<Response> {
        let mut line = serde_json::to_string(req).map_err(to_io)?;
        line.push('\n');
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        let mut resp = String::new();
        if self.reader.read_line(&mut resp)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed",
            ));
        }
        serde_json::from_str(resp.trim_end()).map_err(to_io)
    }

    /// Read the next streamed event (after a successful `Subscribe`).
    pub fn next_event(&mut self) -> io::Result<Event> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed",
            ));
        }
        serde_json::from_str(line.trim_end()).map_err(to_io)
    }
}

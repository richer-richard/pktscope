//! Local Unix-socket IPC between the egress daemon and clients (the inspector
//! and `--json` consumers).

pub mod client;
pub mod protocol;
pub mod server;

pub use client::IpcClient;
pub use protocol::{ConnectionDto, DaemonStatus, Event, Request, Response};
pub use server::{Bus, LiveState, ServerCtx, run_server};

use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum PktScopeError {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("filter parse error: {0}")]
    FilterParse(String),

    #[error("no network interface specified (use -i <interface>)")]
    NoInterface,

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("capture channel closed unexpectedly")]
    ChannelClosed,

    #[error("unsupported link type: {0}")]
    UnsupportedLinktype(u16),
}

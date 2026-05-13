use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    ProtocolPresent(ProtocolAtom),
    Comparison {
        field: FieldPath,
        op: CompareOp,
        value: FilterValue,
    },
    Contains {
        field: FieldPath,
        pattern: String,
    },
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolAtom {
    Ethernet,
    Arp,
    Ip,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Dns,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPath {
    pub segments: Vec<String>,
}

impl FieldPath {
    pub fn as_str(&self) -> String {
        self.segments.join(".")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterValue {
    Integer(i64),
    IpAddr(IpAddr),
    Str(String),
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRow {
    pub id: i64,
    pub exe_path: String,
    pub name: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestRow {
    pub id: i64,
    pub ip: String,
    pub best_name: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub country: Option<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub id: i64,
    pub process_id: Option<i64>,
    pub dest_id: Option<i64>,
    pub proto: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub name: Option<String>,
    pub ts_start_ms: i64,
    pub ts_end_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessUpsert {
    pub id: i64,
    pub was_new: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PairUpsert {
    pub id: i64,
    pub was_new: bool,
}

/// Per-process volume baseline (EWMA of bytes-up per fixed interval).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VolumeStat {
    pub ewma_mean: f64,
    pub ewma_var: f64,
    pub interval_acc: f64,
    pub interval_start_ms: i64,
    pub samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineState {
    Learning,
    Active,
}

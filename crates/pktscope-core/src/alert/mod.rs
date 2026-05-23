//! Alert types for the five egress signals. The detection engine
//! (learning-window lifecycle + detectors) is added in a later milestone; this
//! module defines the shared `Alert` / `AlertKind` / `Severity` types used by
//! the store, IPC, and the engine.

pub mod baseline;
pub mod detectors;

pub use detectors::{AlertConfig, AlertEngine, EvalOutcome, FlowEvent};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The five egress alert signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// Signal 1: a process contacted a destination org/domain it never has.
    NewProcessDest,
    /// Signal 2: a binary made its first-ever outbound connection.
    NewProcessEgress,
    /// Signal 3: first contact with a host in a new country or AS.
    NewGeo,
    /// Signal 4: outbound volume far above a process's baseline.
    VolumeSpike,
    /// Signal 5: a process's binary identity changed since baseline.
    IdentityChange,
}

impl AlertKind {
    pub fn as_db(self) -> &'static str {
        match self {
            AlertKind::NewProcessDest => "new_process_dest",
            AlertKind::NewProcessEgress => "new_process_egress",
            AlertKind::NewGeo => "new_geo",
            AlertKind::VolumeSpike => "volume_spike",
            AlertKind::IdentityChange => "identity_change",
        }
    }

    pub fn from_db(s: &str) -> Option<Self> {
        Some(match s {
            "new_process_dest" => AlertKind::NewProcessDest,
            "new_process_egress" => AlertKind::NewProcessEgress,
            "new_geo" => AlertKind::NewGeo,
            "volume_spike" => AlertKind::VolumeSpike,
            "identity_change" => AlertKind::IdentityChange,
            _ => return None,
        })
    }

    /// Human-readable label (mirrors Little Snitch's naming where applicable).
    pub fn label(self) -> &'static str {
        match self {
            AlertKind::NewProcessDest => "New process → destination",
            AlertKind::NewProcessEgress => "New process phoning home",
            AlertKind::NewGeo => "New country / ASN",
            AlertKind::VolumeSpike => "Volume / exfil spike",
            AlertKind::IdentityChange => "Program modification",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Notice,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_db(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    pub fn from_db(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "notice" => Severity::Notice,
            "warning" => Severity::Warning,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Option<i64>,
    pub kind: AlertKind,
    pub severity: Severity,
    /// Unix milliseconds.
    pub ts: i64,
    pub process_id: Option<i64>,
    pub dest_id: Option<i64>,
    /// Stable per `(kind, key)` — drives cooldown deduplication.
    pub dedup_key: String,
    pub title: String,
    /// Structured details (pid, exe, dest, asn, bytes, old/new identity, …).
    pub detail: Value,
}

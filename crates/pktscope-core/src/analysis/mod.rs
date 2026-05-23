//! Lightweight, on-demand traffic analysis (anomaly heuristics).

pub mod anomaly;

pub use anomaly::{AnomalyAnnotation, AnomalyKind, AnomalySeverity, analyze};

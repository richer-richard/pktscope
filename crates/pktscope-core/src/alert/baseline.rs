//! Learning-window lifecycle and the per-process EWMA volume baseline.

use super::detectors::AlertConfig;
use crate::store::models::{BaselineState, VolumeStat};
use crate::store::{Store, StoreError};

/// Ensure the baseline lifecycle is initialized and promote learning→active
/// when the window elapses. The window times are persisted in `meta`, so a
/// restart resumes the same window rather than restarting the clock.
pub fn ensure_started(
    store: &Store,
    cfg: &AlertConfig,
    now_ms: i64,
) -> Result<BaselineState, StoreError> {
    if store.meta_get("baseline_state")?.is_none() {
        store.meta_set("baseline_state", "learning")?;
        store.meta_set("learning_started_ms", &now_ms.to_string())?;
        let ends = now_ms.saturating_add(cfg.learning_window.as_millis() as i64);
        store.meta_set("learning_ends_ms", &ends.to_string())?;
    }
    if store.baseline_state()? == BaselineState::Learning {
        if let Some(ends) = store.meta_get_i64("learning_ends_ms")? {
            if now_ms >= ends {
                store.meta_set("baseline_state", "active")?;
            }
        }
    }
    store.baseline_state()
}

/// A closed volume interval, with the statistics computed *before* this sample
/// was folded into the EWMA (so the sample is judged against prior history).
pub struct VolumeSample {
    pub x: f64,
    pub mean: f64,
    pub std: f64,
    pub samples: u64,
}

/// Accumulate `bytes_up` into the current interval; when the interval elapses,
/// close it, fold it into the EWMA mean/variance, and return the sample.
pub fn update_volume(
    store: &Store,
    cfg: &AlertConfig,
    process_id: i64,
    bytes_up: u64,
    now_ms: i64,
) -> Result<Option<VolumeSample>, StoreError> {
    let mut v = store.get_volume_stat(process_id)?.unwrap_or(VolumeStat {
        ewma_mean: 0.0,
        ewma_var: 0.0,
        interval_acc: 0.0,
        interval_start_ms: now_ms,
        samples: 0,
    });

    v.interval_acc += bytes_up as f64;
    let interval_ms = cfg.volume_interval.as_millis() as i64;
    let mut sample = None;

    if now_ms - v.interval_start_ms >= interval_ms {
        let x = v.interval_acc;
        let prev_mean = v.ewma_mean;
        let prev_std = v.ewma_var.sqrt();
        let alpha = cfg.volume_alpha;
        let delta = x - v.ewma_mean;
        v.ewma_mean += alpha * delta;
        v.ewma_var = (1.0 - alpha) * (v.ewma_var + alpha * delta * delta);
        v.samples += 1;
        v.interval_acc = 0.0;
        v.interval_start_ms = now_ms;
        sample = Some(VolumeSample {
            x,
            mean: prev_mean,
            std: prev_std,
            samples: v.samples,
        });
    }

    store.upsert_volume_stat(process_id, &v)?;
    Ok(sample)
}

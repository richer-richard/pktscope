//! Local, best-effort desktop notifications for fired alerts. Never blocks or
//! fails the alert engine — the durable record is always in SQLite and on IPC.

use std::process::Command;

use crate::alert::Alert;

pub trait Notifier: Send + Sync {
    fn notify(&self, alert: &Alert);
}

/// Sends an OS notification (macOS `osascript`, Linux `notify-send`) and always
/// logs to stderr. Failures are ignored.
pub struct OsNotifier;

impl Notifier for OsNotifier {
    fn notify(&self, alert: &Alert) {
        let title = format!("pktscope: {}", alert.kind.label());
        let body = &alert.title;

        #[cfg(target_os = "macos")]
        {
            let script = format!(
                "display notification {} with title {}",
                applescript_quote(body),
                applescript_quote(&title)
            );
            let _ = Command::new("osascript").arg("-e").arg(script).spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("notify-send").arg(&title).arg(body).spawn();
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = &title;
            let _ = body;
        }

        log_alert(alert);
    }
}

/// Logs alerts to stderr only (used when desktop notifications are disabled or
/// the daemon runs headless).
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn notify(&self, alert: &Alert) {
        log_alert(alert);
    }
}

fn log_alert(alert: &Alert) {
    eprintln!(
        "[ALERT][{}] {} — {}",
        alert.severity.as_db(),
        alert.kind.label(),
        alert.title
    );
}

#[cfg(target_os = "macos")]
fn applescript_quote(s: &str) -> String {
    // Quote and escape for an AppleScript string literal.
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Default notifier: OS notification + log when `enabled`, else log only.
pub fn make_notifier(enabled: bool) -> Box<dyn Notifier> {
    if enabled {
        Box::new(OsNotifier)
    } else {
        Box::new(LogNotifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{AlertKind, Severity};
    use serde_json::json;

    #[test]
    fn test_log_notifier_does_not_panic() {
        let n = LogNotifier;
        n.notify(&Alert {
            id: Some(1),
            kind: AlertKind::VolumeSpike,
            severity: Severity::Warning,
            ts: 0,
            process_id: None,
            dest_id: None,
            dedup_key: "x".into(),
            title: "test alert".into(),
            detail: json!({}),
        });
    }
}

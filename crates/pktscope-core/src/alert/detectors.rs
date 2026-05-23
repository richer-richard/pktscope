use std::net::IpAddr;
use std::time::Duration;

use serde_json::json;

use super::baseline;
use super::{Alert, AlertKind, Severity};
use crate::enrich::GeoInfo;
use crate::enrich::names::registrable_domain_of;
use crate::flow::FlowKey;
use crate::identity::BinaryIdentity;
use crate::process::SocketProc;
use crate::store::models::BaselineState;
use crate::store::{Store, StoreError};

/// One correlated flow observation: the unit every detector consumes. Produced
/// by the daemon's correlate stage (5-tuple → pid → identity → name → geo).
#[derive(Debug, Clone)]
pub struct FlowEvent {
    pub ts: i64,
    pub key: FlowKey,
    pub proc_: Option<SocketProc>,
    pub identity: Option<BinaryIdentity>,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub local_port: u16,
    pub protocol: u8,
    /// Best known destination name (DNS/SNI), if any.
    pub name: Option<String>,
    pub geo: GeoInfo,
    /// Byte deltas attributed to this event.
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub flow_first_seen: bool,
    /// True when the local side initiated the flow (egress).
    pub outbound: bool,
}

#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub learning_window: Duration,
    pub volume_interval: Duration,
    pub volume_alpha: f64,
    pub volume_z_threshold: f64,
    pub volume_abs_floor_bytes: u64,
    pub volume_min_samples: u64,
    pub cooldown: Duration,
    pub flag_signed_updates: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            learning_window: Duration::from_secs(7 * 24 * 3600),
            volume_interval: Duration::from_secs(60),
            volume_alpha: 0.3,
            volume_z_threshold: 4.0,
            volume_abs_floor_bytes: 5 * 1024 * 1024,
            volume_min_samples: 8,
            cooldown: Duration::from_secs(3600),
            flag_signed_updates: false,
        }
    }
}

impl AlertConfig {
    /// Short learning window for demos so all five signals can be exercised quickly.
    pub fn demo() -> Self {
        Self {
            learning_window: Duration::from_secs(5),
            ..Self::default()
        }
    }
}

/// Runs the five detectors against the persisted baseline. During the learning
/// window the baseline is populated but no alerts are emitted; afterwards novel
/// observations fire (subject to durable cooldown).
pub struct AlertEngine {
    cfg: AlertConfig,
}

impl AlertEngine {
    pub fn new(cfg: AlertConfig) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &AlertConfig {
        &self.cfg
    }

    pub fn evaluate(&self, store: &Store, ev: &FlowEvent) -> Result<Vec<Alert>, StoreError> {
        let state = baseline::ensure_started(store, &self.cfg, ev.ts)?;
        let active = state == BaselineState::Active;
        let mut alerts = Vec::new();

        let dest_id = store.upsert_destination(&ev.dest_ip, ev.name.as_deref(), &ev.geo, ev.ts)?;
        if let Some(name) = &ev.name {
            store.record_name(&ev.dest_ip, name, "obs", ev.ts)?;
        }

        // Without attribution we keep destination/history but emit no per-process signals.
        let Some(p) = &ev.proc_ else {
            return Ok(alerts);
        };
        let exe = p
            .exe_path
            .as_ref()
            .map(|x| x.display().to_string())
            .unwrap_or_else(|| format!("pid:{}", p.pid));
        let proc_up = store.upsert_process(&exe, &p.name, ev.ts)?;
        let pid_row = proc_up.id;
        let label = self.stable_label(ev);

        // Signal 2: new process phoning home.
        if active && proc_up.was_new && ev.outbound {
            self.emit(
                store,
                &mut alerts,
                Alert {
                    id: None,
                    kind: AlertKind::NewProcessEgress,
                    severity: Severity::Warning,
                    ts: ev.ts,
                    process_id: Some(pid_row),
                    dest_id: Some(dest_id),
                    dedup_key: format!("egress|{exe}"),
                    title: format!(
                        "{} made its first outbound connection (→ {})",
                        p.name,
                        self.dest_label(ev)
                    ),
                    detail: json!({"pid": p.pid, "exe": exe, "dest": self.dest_label(ev)}),
                },
            )?;
        }

        // Signal 5: binary-identity change.
        if let Some(ident) = &ev.identity {
            let baseline_id = store.current_identity(pid_row)?;
            store.record_identity(pid_row, ident, ev.ts)?;
            if active && ev.outbound {
                if let Some(base) = baseline_id {
                    if base.changed_since(ident, self.cfg.flag_signed_updates) {
                        self.emit(
                            store,
                            &mut alerts,
                            Alert {
                                id: None,
                                kind: AlertKind::IdentityChange,
                                severity: Severity::Critical,
                                ts: ev.ts,
                                process_id: Some(pid_row),
                                dest_id: Some(dest_id),
                                dedup_key: format!("identity|{exe}|{}", ident.value),
                                title: format!("{} binary identity changed since baseline", p.name),
                                detail: json!({
                                    "pid": p.pid, "exe": exe,
                                    "old": {"team": base.team_id, "signing": base.signing_id, "value": base.value},
                                    "new": {"team": ident.team_id, "signing": ident.signing_id, "value": ident.value},
                                }),
                            },
                        )?;
                    }
                }
            }
        }

        // Signal 1: new (process → destination org/domain).
        let label_new = store.note_label(pid_row, &label, ev.ts)?;
        store.touch_pair(pid_row, dest_id, ev.ts)?;
        if active && label_new && ev.outbound {
            self.emit(
                store,
                &mut alerts,
                Alert {
                    id: None,
                    kind: AlertKind::NewProcessDest,
                    severity: Severity::Notice,
                    ts: ev.ts,
                    process_id: Some(pid_row),
                    dest_id: Some(dest_id),
                    dedup_key: format!("dest|{pid_row}|{label}"),
                    title: format!("{} contacted a new destination: {}", p.name, label),
                    detail: json!({"pid": p.pid, "exe": exe, "label": label, "ip": ev.dest_ip.to_string()}),
                },
            )?;
        }

        // Signal 3: new country / ASN.
        if let Some(cc) = &ev.geo.country {
            if store.note_country(pid_row, cc, ev.ts)? && active && ev.outbound {
                self.emit(
                    store,
                    &mut alerts,
                    Alert {
                        id: None,
                        kind: AlertKind::NewGeo,
                        severity: Severity::Notice,
                        ts: ev.ts,
                        process_id: Some(pid_row),
                        dest_id: Some(dest_id),
                        dedup_key: format!("geo|{pid_row}|cc|{cc}"),
                        title: format!("{} connected to a new country: {}", p.name, cc),
                        detail: json!({"pid": p.pid, "exe": exe, "country": cc}),
                    },
                )?;
            }
        }
        if let Some(asn) = ev.geo.asn {
            if store.note_asn(pid_row, asn, ev.geo.as_org.as_deref(), ev.ts)?
                && active
                && ev.outbound
            {
                self.emit(
                    store,
                    &mut alerts,
                    Alert {
                        id: None,
                        kind: AlertKind::NewGeo,
                        severity: Severity::Notice,
                        ts: ev.ts,
                        process_id: Some(pid_row),
                        dest_id: Some(dest_id),
                        dedup_key: format!("geo|{pid_row}|asn|{asn}"),
                        title: format!(
                            "{} connected to a new network: AS{}{}",
                            p.name,
                            asn,
                            ev.geo
                                .as_org
                                .as_ref()
                                .map(|o| format!(" ({o})"))
                                .unwrap_or_default()
                        ),
                        detail: json!({"pid": p.pid, "exe": exe, "asn": asn, "as_org": ev.geo.as_org}),
                    },
                )?;
            }
        }

        // Signal 4: volume / exfil spike.
        if let Some(sample) =
            baseline::update_volume(store, &self.cfg, pid_row, ev.bytes_up, ev.ts)?
        {
            if active
                && sample.samples >= self.cfg.volume_min_samples
                && sample.x as u64 >= self.cfg.volume_abs_floor_bytes
            {
                let z = if sample.std > 0.0 {
                    (sample.x - sample.mean) / sample.std
                } else if sample.x > sample.mean {
                    f64::INFINITY
                } else {
                    0.0
                };
                if z >= self.cfg.volume_z_threshold {
                    let sev = if sample.x >= 10.0 * sample.mean.max(1.0) {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    };
                    self.emit(
                        store,
                        &mut alerts,
                        Alert {
                            id: None,
                            kind: AlertKind::VolumeSpike,
                            severity: sev,
                            ts: ev.ts,
                            process_id: Some(pid_row),
                            dest_id: Some(dest_id),
                            dedup_key: format!("volume|{pid_row}"),
                            title: format!(
                                "{} outbound volume spike: {} bytes/interval (z={z:.1})",
                                p.name, sample.x as u64
                            ),
                            detail: json!({"pid": p.pid, "exe": exe, "bytes": sample.x as u64, "mean": sample.mean, "std": sample.std, "z": z}),
                        },
                    )?;
                }
            }
        }

        Ok(alerts)
    }

    fn emit(&self, store: &Store, out: &mut Vec<Alert>, alert: Alert) -> Result<(), StoreError> {
        let cooldown = self.cfg.cooldown.as_millis() as i64;
        if let Some(id) = store.insert_alert(&alert, cooldown)? {
            out.push(Alert {
                id: Some(id),
                ..alert
            });
        }
        Ok(())
    }

    fn dest_label(&self, ev: &FlowEvent) -> String {
        ev.name.clone().unwrap_or_else(|| ev.dest_ip.to_string())
    }

    /// The org/domain/IP label used for signal-1 novelty (CDN-safe).
    fn stable_label(&self, ev: &FlowEvent) -> String {
        if let Some(org) = &ev.geo.as_org {
            return org.clone();
        }
        if let Some(name) = &ev.name {
            return registrable_domain_of(name);
        }
        ev.dest_ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityKind, IdentityStatus};
    use crate::store::Store;
    use std::path::PathBuf;

    fn test_cfg() -> AlertConfig {
        AlertConfig {
            learning_window: Duration::ZERO, // active immediately
            volume_interval: Duration::from_millis(10),
            volume_alpha: 0.3,
            volume_z_threshold: 4.0,
            volume_abs_floor_bytes: 1000,
            volume_min_samples: 3,
            cooldown: Duration::from_secs(3600),
            flag_signed_updates: false,
        }
    }

    fn proc(pid: u32, name: &str, exe: &str) -> SocketProc {
        SocketProc {
            pid,
            name: name.into(),
            exe_path: Some(PathBuf::from(exe)),
        }
    }

    fn event(ts: i64, p: SocketProc, dest: &str, geo: GeoInfo, bytes_up: u64) -> FlowEvent {
        let dest_ip: IpAddr = dest.parse().unwrap();
        FlowEvent {
            ts,
            key: FlowKey::new("10.0.0.1".parse().unwrap(), 50000, dest_ip, 443, 6),
            proc_: Some(p),
            identity: None,
            dest_ip,
            dest_port: 443,
            local_port: 50000,
            protocol: 6,
            name: Some("example.com".into()),
            geo,
            bytes_up,
            bytes_down: 0,
            flow_first_seen: true,
            outbound: true,
        }
    }

    fn geo() -> GeoInfo {
        GeoInfo {
            country: Some("US".into()),
            asn: Some(64500),
            as_org: Some("ExampleNet".into()),
        }
    }

    fn kinds(alerts: &[Alert]) -> Vec<AlertKind> {
        alerts.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn test_signals_fire_then_quiet() {
        let store = Store::open_in_memory().unwrap();
        let engine = AlertEngine::new(test_cfg());
        let a = engine
            .evaluate(
                &store,
                &event(1, proc(10, "curl", "/bin/curl"), "93.184.216.34", geo(), 0),
            )
            .unwrap();
        let k = kinds(&a);
        assert!(k.contains(&AlertKind::NewProcessEgress));
        assert!(k.contains(&AlertKind::NewProcessDest));
        assert!(k.contains(&AlertKind::NewGeo));

        // Same process+dest+geo again → nothing novel.
        let b = engine
            .evaluate(
                &store,
                &event(2, proc(10, "curl", "/bin/curl"), "93.184.216.34", geo(), 0),
            )
            .unwrap();
        assert!(
            b.is_empty(),
            "expected no repeat alerts, got {:?}",
            kinds(&b)
        );
    }

    #[test]
    fn test_learning_window_is_silent() {
        let store = Store::open_in_memory().unwrap();
        let mut cfg = test_cfg();
        cfg.learning_window = Duration::from_secs(3600); // still learning
        let engine = AlertEngine::new(cfg);
        let a = engine
            .evaluate(
                &store,
                &event(1, proc(10, "curl", "/bin/curl"), "93.184.216.34", geo(), 0),
            )
            .unwrap();
        assert!(a.is_empty(), "learning window must be silent");
        // Baseline was still populated.
        assert_eq!(store.list_processes().unwrap().len(), 1);
    }

    #[test]
    fn test_identity_change_fires() {
        let store = Store::open_in_memory().unwrap();
        let engine = AlertEngine::new(test_cfg());
        let base_ident = BinaryIdentity {
            path: PathBuf::from("/bin/app"),
            kind: IdentityKind::Sha256,
            value: "hash1".into(),
            signing_id: None,
            team_id: None,
            authority: None,
            status: IdentityStatus::Valid,
        };
        let mut e1 = event(
            1,
            proc(11, "app", "/bin/app"),
            "1.2.3.4",
            GeoInfo::default(),
            0,
        );
        e1.identity = Some(base_ident.clone());
        engine.evaluate(&store, &e1).unwrap();

        // Same binary, changed hash → IdentityChange.
        let mut e2 = event(
            2,
            proc(11, "app", "/bin/app"),
            "1.2.3.4",
            GeoInfo::default(),
            0,
        );
        e2.identity = Some(BinaryIdentity {
            value: "hash2".into(),
            ..base_ident
        });
        let a = engine.evaluate(&store, &e2).unwrap();
        assert!(kinds(&a).contains(&AlertKind::IdentityChange));
    }

    #[test]
    fn test_volume_spike_fires() {
        let store = Store::open_in_memory().unwrap();
        let engine = AlertEngine::new(test_cfg());
        let p = proc(12, "uploader", "/bin/up");
        // Warm up baseline with steady small intervals (20ms apart, interval=10ms).
        for i in 0..6 {
            let ts = 100 + i * 20;
            engine
                .evaluate(
                    &store,
                    &event(ts, p.clone(), "5.5.5.5", GeoInfo::default(), 200),
                )
                .unwrap();
        }
        // Spike well above floor.
        let spike = engine
            .evaluate(
                &store,
                &event(
                    100 + 6 * 20,
                    p.clone(),
                    "5.5.5.5",
                    GeoInfo::default(),
                    5_000_000,
                ),
            )
            .unwrap();
        assert!(
            kinds(&spike).contains(&AlertKind::VolumeSpike),
            "expected a volume spike, got {:?}",
            kinds(&spike)
        );
    }
}

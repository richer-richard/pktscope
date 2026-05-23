pub mod models;
pub mod schema;

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::alert::{Alert, AlertKind, Severity};
use crate::enrich::GeoInfo;
use crate::identity::{BinaryIdentity, IdentityKind, IdentityStatus};
use models::*;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Durable baseline + history store backed by SQLite (WAL). All writes go
/// through a single owning thread in the daemon; read-only consumers (IPC) open
/// a separate connection via [`Store::open_readonly`].
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let mut store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn open_readonly(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
    }

    fn init(&mut self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        self.run_migrations()
    }

    pub fn run_migrations(&mut self) -> Result<()> {
        let version: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < schema::SCHEMA_VERSION {
            self.conn.execute_batch(schema::SCHEMA_V1)?;
            self.conn
                .pragma_update(None, "user_version", schema::SCHEMA_VERSION)?;
            self.meta_set("schema_version", &schema::SCHEMA_VERSION.to_string())?;
        }
        Ok(())
    }

    // --- meta / baseline lifecycle ---------------------------------------

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(Into::into)
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn meta_get_i64(&self, key: &str) -> Result<Option<i64>> {
        Ok(self.meta_get(key)?.and_then(|s| s.parse().ok()))
    }

    pub fn baseline_state(&self) -> Result<BaselineState> {
        Ok(match self.meta_get("baseline_state")?.as_deref() {
            Some("active") => BaselineState::Active,
            _ => BaselineState::Learning,
        })
    }

    // --- processes & identity --------------------------------------------

    pub fn upsert_process(&self, exe_path: &str, name: &str, ts: i64) -> Result<ProcessUpsert> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM processes WHERE exe_path = ?1",
                params![exe_path],
                |r| r.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                self.conn.execute(
                    "UPDATE processes SET last_seen_ms = ?1, name = ?2 WHERE id = ?3",
                    params![ts, name, id],
                )?;
                Ok(ProcessUpsert { id, was_new: false })
            }
            None => {
                self.conn.execute(
                    "INSERT INTO processes(exe_path, name, first_seen_ms, last_seen_ms)
                     VALUES(?1, ?2, ?3, ?3)",
                    params![exe_path, name, ts],
                )?;
                Ok(ProcessUpsert {
                    id: self.conn.last_insert_rowid(),
                    was_new: true,
                })
            }
        }
    }

    /// Record a binary identity for a process and update its current identity.
    /// Returns true if this identity value was newly recorded.
    pub fn record_identity(
        &self,
        process_id: i64,
        ident: &BinaryIdentity,
        ts: i64,
    ) -> Result<bool> {
        let kind = identity_kind_db(&ident.kind);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO binary_identities
               (process_id, kind, value, signing_id, team_id, authority, status, first_seen_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                process_id,
                kind,
                ident.value,
                ident.signing_id,
                ident.team_id,
                ident.authority,
                identity_status_db(ident.status),
                ts
            ],
        )?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM binary_identities WHERE process_id = ?1 AND kind = ?2 AND value = ?3",
            params![process_id, kind, ident.value],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "UPDATE processes SET cur_identity_id = ?1 WHERE id = ?2",
            params![id, process_id],
        )?;
        Ok(inserted > 0)
    }

    /// The currently recorded identity for a process (baseline for signal 5).
    pub fn current_identity(&self, process_id: i64) -> Result<Option<BinaryIdentity>> {
        self.conn
            .query_row(
                "SELECT bi.kind, bi.value, bi.signing_id, bi.team_id, bi.authority, bi.status, p.exe_path
                 FROM processes p JOIN binary_identities bi ON p.cur_identity_id = bi.id
                 WHERE p.id = ?1",
                params![process_id],
                |r| {
                    Ok(BinaryIdentity {
                        kind: identity_kind_from(&r.get::<_, String>(0)?),
                        value: r.get(1)?,
                        signing_id: r.get(2)?,
                        team_id: r.get(3)?,
                        authority: r.get(4)?,
                        status: identity_status_from(&r.get::<_, String>(5)?),
                        path: PathBuf::from(r.get::<_, String>(6)?),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    // --- destinations, pairs, geo novelty --------------------------------

    pub fn upsert_destination(
        &self,
        ip: &IpAddr,
        name: Option<&str>,
        geo: &GeoInfo,
        ts: i64,
    ) -> Result<i64> {
        let ip_s = ip.to_string();
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM destinations WHERE ip = ?1",
                params![ip_s],
                |r| r.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                self.conn.execute(
                    "UPDATE destinations SET last_seen_ms = ?1,
                       best_name = COALESCE(?2, best_name),
                       asn = COALESCE(?3, asn),
                       as_org = COALESCE(?4, as_org),
                       country = COALESCE(?5, country)
                     WHERE id = ?6",
                    params![ts, name, geo.asn, geo.as_org, geo.country, id],
                )?;
                Ok(id)
            }
            None => {
                self.conn.execute(
                    "INSERT INTO destinations(ip, best_name, asn, as_org, country, first_seen_ms, last_seen_ms)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![ip_s, name, geo.asn, geo.as_org, geo.country, ts],
                )?;
                Ok(self.conn.last_insert_rowid())
            }
        }
    }

    pub fn touch_pair(&self, process_id: i64, dest_id: i64, ts: i64) -> Result<PairUpsert> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM process_dest_pairs WHERE process_id = ?1 AND dest_id = ?2",
                params![process_id, dest_id],
                |r| r.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => {
                self.conn.execute(
                    "UPDATE process_dest_pairs SET last_seen_ms = ?1, conn_count = conn_count + 1 WHERE id = ?2",
                    params![ts, id],
                )?;
                Ok(PairUpsert { id, was_new: false })
            }
            None => {
                self.conn.execute(
                    "INSERT INTO process_dest_pairs(process_id, dest_id, first_seen_ms, last_seen_ms, conn_count)
                     VALUES(?1, ?2, ?3, ?3, 1)",
                    params![process_id, dest_id, ts],
                )?;
                Ok(PairUpsert {
                    id: self.conn.last_insert_rowid(),
                    was_new: true,
                })
            }
        }
    }

    /// Returns true if the country was newly recorded for this process.
    pub fn note_country(&self, process_id: i64, country: &str, ts: i64) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO process_countries(process_id, country, first_seen_ms) VALUES(?1, ?2, ?3)",
            params![process_id, country, ts],
        )?;
        Ok(n > 0)
    }

    /// Returns true if the ASN was newly recorded for this process.
    pub fn note_asn(
        &self,
        process_id: i64,
        asn: u32,
        as_org: Option<&str>,
        ts: i64,
    ) -> Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO process_asns(process_id, asn, as_org, first_seen_ms) VALUES(?1, ?2, ?3, ?4)",
            params![process_id, asn, as_org, ts],
        )?;
        Ok(n > 0)
    }

    // --- volume baseline --------------------------------------------------

    pub fn get_volume_stat(&self, process_id: i64) -> Result<Option<VolumeStat>> {
        self.conn
            .query_row(
                "SELECT ewma_mean, ewma_var, interval_acc, interval_start_ms, samples
                 FROM volume_stats WHERE process_id = ?1",
                params![process_id],
                |r| {
                    Ok(VolumeStat {
                        ewma_mean: r.get(0)?,
                        ewma_var: r.get(1)?,
                        interval_acc: r.get(2)?,
                        interval_start_ms: r.get(3)?,
                        samples: r.get::<_, i64>(4)? as u64,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn upsert_volume_stat(&self, process_id: i64, v: &VolumeStat) -> Result<()> {
        self.conn.execute(
            "INSERT INTO volume_stats(process_id, ewma_mean, ewma_var, interval_acc, interval_start_ms, samples)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(process_id) DO UPDATE SET
               ewma_mean = ?2, ewma_var = ?3, interval_acc = ?4, interval_start_ms = ?5, samples = ?6",
            params![
                process_id,
                v.ewma_mean,
                v.ewma_var,
                v.interval_acc,
                v.interval_start_ms,
                v.samples as i64
            ],
        )?;
        Ok(())
    }

    // --- names, connections, alerts --------------------------------------

    pub fn record_name(&self, ip: &IpAddr, name: &str, source: &str, ts: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO name_resolutions(ip, name, source, seen_ms) VALUES(?1, ?2, ?3, ?4)",
            params![ip.to_string(), name, source, ts],
        )?;
        Ok(())
    }

    pub fn insert_connection(&self, c: &ConnectionRow) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO connections
               (process_id, dest_id, proto, local_port, remote_port, bytes_up, bytes_down, name, ts_start_ms, ts_end_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                c.process_id,
                c.dest_id,
                c.proto,
                c.local_port,
                c.remote_port,
                c.bytes_up as i64,
                c.bytes_down as i64,
                c.name,
                c.ts_start_ms,
                c.ts_end_ms
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Insert an alert unless an alert with the same `dedup_key` fired within
    /// `cooldown_ms`. Returns the new id, or `None` if suppressed.
    pub fn insert_alert(&self, alert: &Alert, cooldown_ms: i64) -> Result<Option<i64>> {
        let recent: Option<i64> = self.conn.query_row(
            "SELECT MAX(ts_ms) FROM alerts WHERE dedup_key = ?1",
            params![alert.dedup_key],
            |r| r.get(0),
        )?;
        if let Some(prev) = recent {
            if alert.ts - prev < cooldown_ms {
                return Ok(None);
            }
        }
        let detail = serde_json::to_string(&alert.detail)?;
        self.conn.execute(
            "INSERT INTO alerts(kind, severity, ts_ms, process_id, dest_id, dedup_key, title, detail_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                alert.kind.as_db(),
                alert.severity.as_db(),
                alert.ts,
                alert.process_id,
                alert.dest_id,
                alert.dedup_key,
                alert.title,
                detail
            ],
        )?;
        Ok(Some(self.conn.last_insert_rowid()))
    }

    // --- read queries -----------------------------------------------------

    pub fn list_processes(&self) -> Result<Vec<ProcessRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, exe_path, name, first_seen_ms, last_seen_ms FROM processes ORDER BY last_seen_ms DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ProcessRow {
                    id: r.get(0)?,
                    exe_path: r.get(1)?,
                    name: r.get(2)?,
                    first_seen_ms: r.get(3)?,
                    last_seen_ms: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_destinations_for_process(&self, process_id: i64) -> Result<Vec<DestRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT d.id, d.ip, d.best_name, d.asn, d.as_org, d.country, d.first_seen_ms, d.last_seen_ms
             FROM destinations d
             JOIN process_dest_pairs p ON p.dest_id = d.id
             WHERE p.process_id = ?1 ORDER BY d.last_seen_ms DESC",
        )?;
        let rows = stmt
            .query_map(params![process_id], dest_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn query_recent_alerts(&self, limit: usize) -> Result<Vec<Alert>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, severity, ts_ms, process_id, dest_id, dedup_key, title, detail_json
             FROM alerts ORDER BY ts_ms DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(parse_alert_row).collect()
    }

    pub fn query_process_history(
        &self,
        process_id: i64,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Vec<ConnectionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, process_id, dest_id, proto, local_port, remote_port, bytes_up, bytes_down, name, ts_start_ms, ts_end_ms
             FROM connections WHERE process_id = ?1 AND ts_start_ms >= ?2 AND ts_start_ms <= ?3
             ORDER BY ts_start_ms DESC",
        )?;
        let rows = stmt
            .query_map(params![process_id, since_ms, until_ms], conn_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn recent_connections(&self, limit: usize) -> Result<Vec<ConnectionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, process_id, dest_id, proto, local_port, remote_port, bytes_up, bytes_down, name, ts_start_ms, ts_end_ms
             FROM connections ORDER BY ts_start_ms DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit as i64], conn_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn counts(&self) -> Result<(u64, u64, u64)> {
        let p: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM processes", [], |r| r.get(0))?;
        let d: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM destinations", [], |r| r.get(0))?;
        let a: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))?;
        Ok((p as u64, d as u64, a as u64))
    }

    /// Delete connection and alert rows older than `before_ms` (retention sweep).
    pub fn delete_older_than(&self, before_ms: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM connections WHERE ts_start_ms < ?1",
            params![before_ms],
        )?;
        self.conn
            .execute("DELETE FROM alerts WHERE ts_ms < ?1", params![before_ms])?;
        Ok(())
    }
}

fn dest_row(r: &rusqlite::Row) -> rusqlite::Result<DestRow> {
    Ok(DestRow {
        id: r.get(0)?,
        ip: r.get(1)?,
        best_name: r.get(2)?,
        asn: r.get(3)?,
        as_org: r.get(4)?,
        country: r.get(5)?,
        first_seen_ms: r.get(6)?,
        last_seen_ms: r.get(7)?,
    })
}

fn conn_row(r: &rusqlite::Row) -> rusqlite::Result<ConnectionRow> {
    Ok(ConnectionRow {
        id: r.get(0)?,
        process_id: r.get(1)?,
        dest_id: r.get(2)?,
        proto: r.get(3)?,
        local_port: r.get(4)?,
        remote_port: r.get(5)?,
        bytes_up: r.get::<_, i64>(6)? as u64,
        bytes_down: r.get::<_, i64>(7)? as u64,
        name: r.get(8)?,
        ts_start_ms: r.get(9)?,
        ts_end_ms: r.get(10)?,
    })
}

type RawAlert = (
    i64,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    String,
    String,
    String,
);

fn alert_row(r: &rusqlite::Row) -> rusqlite::Result<RawAlert> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
    ))
}

fn parse_alert_row(raw: RawAlert) -> Result<Alert> {
    let (id, kind, severity, ts, process_id, dest_id, dedup_key, title, detail_json) = raw;
    Ok(Alert {
        id: Some(id),
        kind: AlertKind::from_db(&kind).unwrap_or(AlertKind::NewProcessDest),
        severity: Severity::from_db(&severity).unwrap_or(Severity::Info),
        ts,
        process_id,
        dest_id,
        dedup_key,
        title,
        detail: serde_json::from_str(&detail_json)?,
    })
}

fn identity_kind_db(kind: &IdentityKind) -> &'static str {
    match kind {
        IdentityKind::MacCodesign => "mac_codesign",
        IdentityKind::Sha256 => "sha256",
        IdentityKind::Unknown => "unknown",
    }
}

fn identity_kind_from(s: &str) -> IdentityKind {
    match s {
        "mac_codesign" => IdentityKind::MacCodesign,
        "sha256" => IdentityKind::Sha256,
        _ => IdentityKind::Unknown,
    }
}

fn identity_status_db(status: IdentityStatus) -> &'static str {
    match status {
        IdentityStatus::Valid => "valid",
        IdentityStatus::Unsigned => "unsigned",
        IdentityStatus::AdHoc => "adhoc",
        IdentityStatus::Invalid => "invalid",
        IdentityStatus::Unreadable => "unreadable",
    }
}

fn identity_status_from(s: &str) -> IdentityStatus {
    match s {
        "valid" => IdentityStatus::Valid,
        "adhoc" => IdentityStatus::AdHoc,
        "invalid" => IdentityStatus::Invalid,
        "unreadable" => IdentityStatus::Unreadable,
        _ => IdentityStatus::Unsigned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn test_migrations_idempotent() {
        let mut s = store();
        s.run_migrations().unwrap();
        let v: u32 = s
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, schema::SCHEMA_VERSION);
    }

    #[test]
    fn test_upsert_process_was_new() {
        let s = store();
        let a = s.upsert_process("/bin/curl", "curl", 100).unwrap();
        assert!(a.was_new);
        let b = s.upsert_process("/bin/curl", "curl", 200).unwrap();
        assert!(!b.was_new);
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn test_touch_pair_and_geo_novelty() {
        let s = store();
        let p = s.upsert_process("/bin/x", "x", 1).unwrap().id;
        let d = s
            .upsert_destination(
                &"1.2.3.4".parse().unwrap(),
                Some("example.com"),
                &GeoInfo {
                    country: Some("US".into()),
                    asn: Some(64500),
                    as_org: Some("Example".into()),
                },
                1,
            )
            .unwrap();
        assert!(s.touch_pair(p, d, 1).unwrap().was_new);
        assert!(!s.touch_pair(p, d, 2).unwrap().was_new);
        assert!(s.note_country(p, "US", 1).unwrap());
        assert!(!s.note_country(p, "US", 2).unwrap());
        assert!(s.note_asn(p, 64500, Some("Example"), 1).unwrap());
        assert!(!s.note_asn(p, 64500, Some("Example"), 2).unwrap());
    }

    #[test]
    fn test_alert_cooldown() {
        let s = store();
        let alert = Alert {
            id: None,
            kind: AlertKind::VolumeSpike,
            severity: Severity::Warning,
            ts: 1_000,
            process_id: None,
            dest_id: None,
            dedup_key: "volume|1".into(),
            title: "spike".into(),
            detail: json!({"x": 1}),
        };
        assert!(s.insert_alert(&alert, 60_000).unwrap().is_some());
        // within cooldown -> suppressed
        let mut a2 = alert.clone();
        a2.ts = 30_000;
        assert!(s.insert_alert(&a2, 60_000).unwrap().is_none());
        // after cooldown -> emitted
        let mut a3 = alert.clone();
        a3.ts = 100_000;
        assert!(s.insert_alert(&a3, 60_000).unwrap().is_some());
        assert_eq!(s.query_recent_alerts(10).unwrap().len(), 2);
    }

    #[test]
    fn test_connection_history() {
        let s = store();
        let p = s.upsert_process("/bin/x", "x", 1).unwrap().id;
        let d = s
            .upsert_destination(&"5.6.7.8".parse().unwrap(), None, &GeoInfo::default(), 1)
            .unwrap();
        let row = ConnectionRow {
            id: 0,
            process_id: Some(p),
            dest_id: Some(d),
            proto: 6,
            local_port: 50000,
            remote_port: 443,
            bytes_up: 1234,
            bytes_down: 5678,
            name: Some("example.com".into()),
            ts_start_ms: 10,
            ts_end_ms: 20,
        };
        s.insert_connection(&row).unwrap();
        let hist = s.query_process_history(p, 0, 100).unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].bytes_up, 1234);
        assert_eq!(hist[0].bytes_down, 5678);
    }
}

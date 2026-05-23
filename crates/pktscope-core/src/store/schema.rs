pub const SCHEMA_VERSION: u32 = 1;

/// Initial schema. Applied in one transaction when `PRAGMA user_version` is 0.
pub const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    id              INTEGER PRIMARY KEY,
    exe_path        TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    first_seen_ms   INTEGER NOT NULL,
    last_seen_ms    INTEGER NOT NULL,
    cur_identity_id INTEGER
);

CREATE TABLE IF NOT EXISTS binary_identities (
    id            INTEGER PRIMARY KEY,
    process_id    INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    value         TEXT NOT NULL,
    signing_id    TEXT,
    team_id       TEXT,
    authority     TEXT,
    status        TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    UNIQUE(process_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_ident_process ON binary_identities(process_id);

CREATE TABLE IF NOT EXISTS destinations (
    id            INTEGER PRIMARY KEY,
    ip            TEXT NOT NULL UNIQUE,
    best_name     TEXT,
    asn           INTEGER,
    as_org        TEXT,
    country       TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dest_name    ON destinations(best_name);
CREATE INDEX IF NOT EXISTS idx_dest_country ON destinations(country);
CREATE INDEX IF NOT EXISTS idx_dest_asn     ON destinations(asn);

CREATE TABLE IF NOT EXISTS name_resolutions (
    id      INTEGER PRIMARY KEY,
    ip      TEXT NOT NULL,
    name    TEXT NOT NULL,
    source  TEXT NOT NULL,
    seen_ms INTEGER NOT NULL,
    UNIQUE(ip, name, source)
);
CREATE INDEX IF NOT EXISTS idx_names_ip ON name_resolutions(ip);

CREATE TABLE IF NOT EXISTS process_dest_pairs (
    id            INTEGER PRIMARY KEY,
    process_id    INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
    dest_id       INTEGER NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    conn_count    INTEGER NOT NULL DEFAULT 0,
    UNIQUE(process_id, dest_id)
);
CREATE INDEX IF NOT EXISTS idx_pair_process ON process_dest_pairs(process_id);
CREATE INDEX IF NOT EXISTS idx_pair_dest    ON process_dest_pairs(dest_id);

CREATE TABLE IF NOT EXISTS process_countries (
    process_id    INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
    country       TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    PRIMARY KEY(process_id, country)
);

CREATE TABLE IF NOT EXISTS process_asns (
    process_id    INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
    asn           INTEGER NOT NULL,
    as_org        TEXT,
    first_seen_ms INTEGER NOT NULL,
    PRIMARY KEY(process_id, asn)
);

CREATE TABLE IF NOT EXISTS volume_stats (
    process_id        INTEGER PRIMARY KEY REFERENCES processes(id) ON DELETE CASCADE,
    ewma_mean         REAL NOT NULL DEFAULT 0,
    ewma_var          REAL NOT NULL DEFAULT 0,
    interval_acc      REAL NOT NULL DEFAULT 0,
    interval_start_ms INTEGER NOT NULL,
    samples           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connections (
    id          INTEGER PRIMARY KEY,
    process_id  INTEGER REFERENCES processes(id) ON DELETE SET NULL,
    dest_id     INTEGER REFERENCES destinations(id) ON DELETE SET NULL,
    proto       INTEGER NOT NULL,
    local_port  INTEGER NOT NULL,
    remote_port INTEGER NOT NULL,
    bytes_up    INTEGER NOT NULL,
    bytes_down  INTEGER NOT NULL,
    name        TEXT,
    ts_start_ms INTEGER NOT NULL,
    ts_end_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conn_proc_time ON connections(process_id, ts_start_ms);
CREATE INDEX IF NOT EXISTS idx_conn_dest_time ON connections(dest_id, ts_start_ms);
CREATE INDEX IF NOT EXISTS idx_conn_time      ON connections(ts_start_ms);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    ts_ms       INTEGER NOT NULL,
    process_id  INTEGER REFERENCES processes(id) ON DELETE SET NULL,
    dest_id     INTEGER REFERENCES destinations(id) ON DELETE SET NULL,
    dedup_key   TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_time  ON alerts(ts_ms);
CREATE INDEX IF NOT EXISTS idx_alert_dedup ON alerts(dedup_key, ts_ms);
CREATE INDEX IF NOT EXISTS idx_alert_kind  ON alerts(kind, ts_ms);
"#;

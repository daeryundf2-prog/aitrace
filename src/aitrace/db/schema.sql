CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS case_info (
    id TEXT PRIMARY KEY,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifact (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    volume INTEGER NOT NULL,
    source_path TEXT NOT NULL,
    deleted INTEGER NOT NULL,
    user TEXT,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS event (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    ts_utc TEXT NULL,
    category TEXT NOT NULL,
    actor TEXT NOT NULL,
    user TEXT,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attribution (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    verdict TEXT NOT NULL,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plugin_run (
    evidence_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    records INTEGER NOT NULL,
    warnings INTEGER NOT NULL,
    error TEXT,
    started TEXT NOT NULL,
    finished TEXT NOT NULL,
    PRIMARY KEY (evidence_id, name)
);
CREATE TABLE IF NOT EXISTS export (
    export_path TEXT PRIMARY KEY,
    sha256 TEXT,
    size INTEGER,
    source_volume INTEGER,
    source_path TEXT,
    inode INTEGER,
    artifact_ids JSON,
    deleted INTEGER,
    note TEXT
);
INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');

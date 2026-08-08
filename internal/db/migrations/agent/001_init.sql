CREATE TABLE packages (
  purl TEXT PRIMARY KEY, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  version TEXT NOT NULL, install_path TEXT NOT NULL,
  scope TEXT NOT NULL,              -- global|project|venv|system|container
  has_scripts INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  path_mtime INTEGER
);
CREATE INDEX idx_pkg_lookup ON packages(ecosystem, name, version);

CREATE TABLE findings (
  purl TEXT NOT NULL, advisory_id TEXT NOT NULL,
  score REAL NOT NULL, tier TEXT NOT NULL, detected_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'new',   -- new|notified|acknowledged|ignored|quarantined|fixed
  ignore_until INTEGER, notes TEXT,
  PRIMARY KEY (purl, advisory_id)
);
CREATE INDEX idx_find_state ON findings(state, tier);

CREATE TABLE install_sessions (
  id TEXT PRIMARY KEY, started_at INTEGER NOT NULL, ended_at INTEGER,
  ecosystem TEXT NOT NULL, cwd TEXT NOT NULL, argv TEXT NOT NULL,
  context TEXT NOT NULL,               -- interactive|ci|ide|unknown
  outcome TEXT                         -- clean|blocked|approved|aborted
);

CREATE TABLE install_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT REFERENCES install_sessions(id) ON DELETE CASCADE,
  purl TEXT NOT NULL, requested_at INTEGER NOT NULL,
  decision TEXT NOT NULL,              -- allowed|blocked|approved-override
  reason TEXT NOT NULL, advisory_id TEXT, latency_ms INTEGER NOT NULL
);
CREATE INDEX idx_dec_session ON install_decisions(session_id);

CREATE TABLE session_approvals (
  session_id TEXT NOT NULL, purl TEXT NOT NULL, approved_at INTEGER NOT NULL,
  PRIMARY KEY (session_id, purl)
);

CREATE TABLE quarantine (
  id TEXT PRIMARY KEY, purl TEXT NOT NULL, origin_path TEXT NOT NULL,
  archive_path TEXT NOT NULL, sha256 TEXT NOT NULL, advisory_id TEXT,
  quarantined_at INTEGER NOT NULL, restored_at INTEGER
);

CREATE TABLE script_allowlist (
  package TEXT PRIMARY KEY,            -- pkg:npm/esbuild, no version
  approved_at INTEGER NOT NULL, approved_via TEXT NOT NULL
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
  kind TEXT NOT NULL,                  -- feed_sync|finding_new|install_blocked
                                       -- |quarantine|restore|scan|gate_degraded
  severity TEXT, purl TEXT, advisory_id TEXT, detail_json TEXT,
  synced INTEGER NOT NULL DEFAULT 0    -- hub sync cursor
);
CREATE INDEX idx_events_ts ON events(ts DESC);
CREATE INDEX idx_events_unsynced ON events(synced) WHERE synced = 0;

CREATE TABLE hub_state (
  k TEXT PRIMARY KEY, v TEXT            -- device_id, token, hub_url, cert_fp, last_sync
);

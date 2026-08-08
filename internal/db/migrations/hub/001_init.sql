CREATE TABLE devices (
  id TEXT PRIMARY KEY,                 -- A7K2-9QX4-...
  pubkey BLOB NOT NULL, token_hash TEXT NOT NULL,
  hostname TEXT NOT NULL, os TEXT NOT NULL, arch TEXT NOT NULL,
  status TEXT NOT NULL,                -- pending|approved|revoked
  sync_level TEXT NOT NULL DEFAULT 'findings',
  enrolled_at INTEGER NOT NULL, approved_at INTEGER,
  last_seen_at INTEGER, agent_version TEXT
);

CREATE TABLE pair_codes (
  code_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER
);

CREATE TABLE fleet_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  agent_event_id INTEGER NOT NULL, ts INTEGER NOT NULL,
  kind TEXT NOT NULL, severity TEXT, purl TEXT, advisory_id TEXT,
  detail_json TEXT, received_at INTEGER NOT NULL,
  UNIQUE (device_id, agent_event_id)   -- idempotent replay
);
CREATE INDEX idx_fe_ts ON fleet_events(ts DESC);
CREATE INDEX idx_fe_device ON fleet_events(device_id, ts DESC);

CREATE TABLE fleet_findings (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  purl TEXT NOT NULL, advisory_id TEXT NOT NULL,
  tier TEXT NOT NULL, score REAL NOT NULL, state TEXT NOT NULL,
  detected_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (device_id, purl, advisory_id)
);

CREATE TABLE fleet_packages (            -- only when sync_level = 'full'
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  purl TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  version TEXT NOT NULL, scope TEXT NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (device_id, purl)
);
CREATE INDEX idx_fp_name ON fleet_packages(ecosystem, name, version);

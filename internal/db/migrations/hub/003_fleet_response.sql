-- What each machine has done about the malware it found.
--
-- Both tables are replicas, never sources. The agent owns this state (§3.3) and
-- sync is outbound-only, so nothing on the hub may write here except an ingest
-- of a device's own push. That is why neither table carries so much as an
-- updated-by column: there is no second writer to disambiguate.
--
-- ON DELETE CASCADE, like the other fleet tables: removing a device removes
-- what it told us. Keeping orphaned rotation ticks would let a decommissioned
-- machine keep reporting progress on a checklist nobody can finish.

CREATE TABLE fleet_rotation (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  purl TEXT NOT NULL, advisory_id TEXT NOT NULL, item_id TEXT NOT NULL,
  checked_at INTEGER,
  PRIMARY KEY (device_id, purl, advisory_id, item_id)
);

-- origin_path is nullable on purpose: it is a filesystem path, which is
-- inventory-shaped, so it only crosses the wire at sync_level = 'full'. At
-- 'findings' the row still arrives — the hub must be able to say a package was
-- quarantined — and the page says the path was not replicated rather than
-- leaving a blank cell that reads as "taken from nowhere".
CREATE TABLE fleet_quarantine (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  id TEXT NOT NULL,
  purl TEXT NOT NULL, advisory_id TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL, origin_path TEXT,
  quarantined_at INTEGER NOT NULL, restored_at INTEGER,
  PRIMARY KEY (device_id, id)
);
CREATE INDEX idx_fq_at ON fleet_quarantine(quarantined_at DESC);

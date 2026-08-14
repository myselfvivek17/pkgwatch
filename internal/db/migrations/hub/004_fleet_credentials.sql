-- What a malicious install script could read on each machine, before anything
-- has gone wrong.
--
-- Only ever populated at sync_level = 'full', on the same terms as
-- fleet_packages and for a stronger reason: this is a map of which machine
-- holds which keys and where they live. It carries no secret material — an ID,
-- a category and a path — but a fleet that has chosen findings-only must get
-- none of it, and the hub's own record of the level is what decides.
--
-- rank is the agent's ordering, worst blast radius first. Stored rather than
-- recomputed because that ordering is a judgement the agent already made.
CREATE TABLE fleet_credentials (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  item_id TEXT NOT NULL,
  category TEXT NOT NULL,
  path TEXT NOT NULL,
  rank INTEGER NOT NULL,
  PRIMARY KEY (device_id, item_id)
);

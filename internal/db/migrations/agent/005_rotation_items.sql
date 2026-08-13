-- Rotation progress for a finding that means credentials were exposed.
--
-- Rows rather than browser storage on purpose: this is a checklist someone
-- works through over hours, across reboots and machines, and a cache clear must
-- not lose the record of which keys have already been rotated. Ticking the same
-- key twice is wasted work; believing you ticked one you did not is the failure
-- this table exists to prevent.
--
-- Keyed to (purl, advisory_id) to match the findings primary key, because the
-- exposure belongs to one finding rather than to the machine: two malicious
-- packages a month apart are two exposures with two separate checklists.
CREATE TABLE rotation_items (
  purl TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  item_id TEXT NOT NULL,               -- aws, github-cli, ssh, ... from internal/rotate
  checked_at INTEGER,
  PRIMARY KEY (purl, advisory_id, item_id)
);

-- The quarantine table recorded restored_at and nothing else, so a row whose
-- archive has been deleted, or whose restore failed halfway, is indistinguishable
-- from one that was cleanly put back. Those are the two states that matter most
-- here: this is the only feature that removes a package from the machine, and
-- "restored" has to be a claim someone can check rather than a timestamp.
--
-- active   the package is out of the way and the archive holds it
-- restored the tree was put back and its digest matched what was taken
-- failed   the restore was attempted and did not reproduce the digest
-- missing  the archive is gone, so the package cannot be brought back
ALTER TABLE quarantine ADD COLUMN state TEXT NOT NULL DEFAULT 'active';

-- What Unpack reproduced, kept beside the digest that was taken. When they
-- differ, the pair is the evidence; a single field would only say "wrong".
ALTER TABLE quarantine ADD COLUMN restored_sha256 TEXT;

-- Rows recorded before this migration were all active or restored, and
-- restored_at already distinguishes them.
UPDATE quarantine SET state = 'restored' WHERE restored_at IS NOT NULL;

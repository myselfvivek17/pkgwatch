-- A package that has been uninstalled must stop producing findings.
--
-- Its row still has to survive: the timeline needs to answer "did this machine
-- have the compromised version while it was live", and a row deleted on the day
-- of uninstall takes that answer with it. So presence is a flag, not a deletion
-- — gone_at records when the package stopped being on disk, and the watcher
-- only ever matches rows where it is NULL.
--
-- Without this, an inventory that never forgets would raise findings for every
-- project directory you have ever deleted, which is noise that reads exactly
-- like a compromised machine.
ALTER TABLE packages ADD COLUMN gone_at INTEGER;

-- Partial index: almost every lookup asks for what is installed now, and the
-- historical rows should not be paid for on every one of them.
CREATE INDEX idx_pkg_present ON packages(ecosystem, name) WHERE gone_at IS NULL;

-- The allowlist has been in the schema since 001; these are the two columns it
-- turned out to need.
--
-- revoked_at rather than deleting the row: "never allowed" and "allowed, then
-- withdrawn" are different answers, and only the second has somebody behind it
-- who may need to explain the decision.
--
-- note is why the package needs to run code at install time. An allowlist with
-- no reasons on it becomes a list nobody dares prune.
ALTER TABLE script_allowlist ADD COLUMN revoked_at INTEGER;
ALTER TABLE script_allowlist ADD COLUMN note TEXT;

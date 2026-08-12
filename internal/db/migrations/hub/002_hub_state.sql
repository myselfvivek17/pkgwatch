-- A small key/value bag for facts the hub generates about itself rather than
-- reads from config: the session signing key today, the TLS keypair later.
--
-- The session key lives here and NOT in the config file, and is deliberately
-- not derived from hub.password_hash. Deriving it would collapse two secrets
-- into one — anyone who learned the password could then forge session cookies
-- without ever logging in, and changing the password would silently invalidate
-- every session, which reads as a bug and teaches people not to change it.
CREATE TABLE hub_state (
  k TEXT PRIMARY KEY, v TEXT NOT NULL
);

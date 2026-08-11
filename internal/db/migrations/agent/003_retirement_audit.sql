-- The retirement audit asks, for every retired row, whether a live row now
-- occupies the same install path. That lookup keys on name and install_path,
-- and packages is indexed by purl and by (ecosystem, name) for present rows —
-- neither of which helps, so each retired row scanned the whole table.
--
-- On the home server that was 2,170 retired rows against 5,331 packages: about
-- 0.9s for a page whose entire job is to be consulted when something looks
-- wrong. The same shape as the missing advisories(id) index, found the same way
-- — by measuring against real data rather than a two-row fixture.
CREATE INDEX IF NOT EXISTS idx_pkg_place ON packages(name, install_path);

-- Identifier-less turns and never-returned tags (docs/actors.md, review of
-- 2026-10-31). An actor is confirmed once a principal or credential binds
-- or a browser-side identifier comes back; unconfirmed actors are swept with
-- their last binding, so a cookie-less scanner leaves nothing behind.
-- cluster_key = hash(net_hash || shape_hash) gives such traffic a window.

ALTER TABLE actors ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 1;
ALTER TABLE actor_bindings ADD COLUMN returned INTEGER NOT NULL DEFAULT 1;
ALTER TABLE turns ADD COLUMN cluster_key TEXT;
CREATE INDEX turns_cluster ON turns (cluster_key, ts_us);

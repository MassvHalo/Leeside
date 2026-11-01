-- Shadow scoring, cluster rows (windside §6): scores are keyed by
-- (scope, scope_id) so cookie-less cluster windows score alongside actor
-- windows. Additive: the 0011 actor rows backfill to scope 'actor', and
-- all existing scores tables are empty (shadow never ran in production),
-- so the backfill moves nothing.
ALTER TABLE scores ADD COLUMN scope TEXT NOT NULL DEFAULT 'actor';
ALTER TABLE scores ADD COLUMN scope_id TEXT;
UPDATE scores SET scope_id = actor_id WHERE scope_id IS NULL;
DROP INDEX scores_actor_ts;
ALTER TABLE scores DROP COLUMN actor_id;
CREATE INDEX scores_scope_ts ON scores (scope, scope_id, ts_us);

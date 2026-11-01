-- Shadow scoring, cluster rows (windside §6), keyed like feature_vectors:
-- scores are keyed by (scope, scope_id, turn_id) with ts_us as a plain
-- column, so two scores for one scope in the same microsecond coexist.
-- Additive in effect: the 0011 actor rows backfill to scope 'actor', and
-- all existing scores tables are empty (shadow never ran in production),
-- so the backfill moves nothing. Folded, not 0013: nothing above 0007 is
-- deployed, so stores migrated under the earlier 0012 must be wiped.
CREATE TABLE scores_new (
  scope         TEXT NOT NULL CHECK (scope IN ('actor', 'cluster')),
  scope_id      TEXT NOT NULL,
  turn_id       TEXT NOT NULL,
  surface       TEXT,
  ts_us         INTEGER NOT NULL,
  score         REAL NOT NULL,
  model_version TEXT NOT NULL,
  top3          TEXT NOT NULL,
  PRIMARY KEY (scope, scope_id, turn_id)
);
INSERT INTO scores_new
    (scope, scope_id, turn_id, surface, ts_us, score, model_version, top3)
  SELECT 'actor', actor_id, '', surface, ts_us, score, model_version, top3
  FROM scores;
DROP TABLE scores;
ALTER TABLE scores_new RENAME TO scores;
CREATE INDEX scores_scope_ts ON scores (scope, scope_id, ts_us);
CREATE INDEX scores_ts ON scores (ts_us);

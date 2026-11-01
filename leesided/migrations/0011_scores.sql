-- Shadow scoring (windside §6): every scored actor feature row writes
-- here, and the actor's latest score rides the actors table for rule
-- matching. Additive: unscored actors read null.
CREATE TABLE scores (
  actor_id      TEXT NOT NULL,
  surface       TEXT,
  ts_us         INTEGER NOT NULL,
  score         REAL NOT NULL,
  model_version TEXT NOT NULL,
  top3          TEXT NOT NULL
);
CREATE INDEX scores_actor_ts ON scores (actor_id, ts_us);
CREATE INDEX scores_ts ON scores (ts_us);
ALTER TABLE actors ADD COLUMN score REAL;
ALTER TABLE actors ADD COLUMN score_ts INTEGER;
ALTER TABLE actors ADD COLUMN score_top3 TEXT;

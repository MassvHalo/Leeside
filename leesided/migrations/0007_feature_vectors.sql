-- Features v2 (src/rules/features.rs): one vector per confirmed-actor window
-- and per cluster window, at every turn that touched it. The repo's v1
-- table `features` (per session, 30 names) is the pre-Windside vector and
-- stays for history; nothing writes it any more.

CREATE TABLE feature_vectors (
  scope       TEXT NOT NULL CHECK (scope IN ('actor', 'cluster')),
  key         TEXT NOT NULL,            -- actor_id or cluster_key, 16 hex
  ts_us       INTEGER NOT NULL,         -- the turn that produced the row
  version     INTEGER NOT NULL,
  vector      TEXT NOT NULL,            -- JSON array of f32 in features::NAMES order
  PRIMARY KEY (scope, key, ts_us)
);
CREATE INDEX feature_vectors_ts ON feature_vectors (ts_us);

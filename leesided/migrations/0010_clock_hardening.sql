-- Clock hardening: ingest order, not wall-clock order.
--
-- feature_vectors keys on the triggering turn's id, not its stamp: two
-- turns in the same microsecond no longer overwrite each other, and a
-- backward clock step cannot reorder or evict rows. ts_us stays as a
-- plain column. clock_anomalies counts the window's negative
-- inter-request intervals; it rides the row as provenance and is never
-- a feature (features::DENYLIST keeps it out of the vector).
-- Nothing above 0007 is deployed, so the table is rebuilt, not patched.
CREATE TABLE feature_vectors_new (
  scope           TEXT NOT NULL CHECK (scope IN ('actor', 'cluster')),
  key             TEXT NOT NULL,
  turn_id         TEXT NOT NULL,
  ts_us           INTEGER NOT NULL,
  version         INTEGER NOT NULL,
  vector          TEXT NOT NULL,
  surface         TEXT,
  clock_anomalies INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, key, turn_id)
);
INSERT OR IGNORE INTO feature_vectors_new
    (scope, key, turn_id, ts_us, version, vector, surface, clock_anomalies)
  SELECT fv.scope, fv.key,
    coalesce(t.turn_id, 'v1:' || coalesce(t.peer_key, 'missing') || ':' || fv.ts_us),
    fv.ts_us, fv.version, fv.vector, fv.surface, 0
  FROM feature_vectors fv
  LEFT JOIN turns t ON t.ts_us = fv.ts_us
    AND ((fv.scope = 'actor' AND t.actor_id = fv.key)
      OR (fv.scope = 'cluster' AND t.cluster_key = fv.key));
DROP TABLE feature_vectors;
ALTER TABLE feature_vectors_new RENAME TO feature_vectors;
CREATE INDEX feature_vectors_ts ON feature_vectors (ts_us);

-- The ingest sequence: turns_since replays in this order after a
-- restart, so a backward step cannot rebuild different windows.
-- Run stores are append-only, so rowid backfills existing rows.
ALTER TABLE turns ADD COLUMN ingest_seq INTEGER;
UPDATE turns SET ingest_seq = rowid;
CREATE INDEX turns_ingest_seq ON turns (ingest_seq);

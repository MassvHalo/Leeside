-- Step C (docs/windside.md section 3): labels on feature windows.
--
-- A label attaches to one feature row (scope, scope_id, window_end_ts),
-- never to an actor: an actor can turn malicious mid-life. `kind` is the
-- generator manifest's run kind, set by label-import only; it is the key
-- for per-kind sampling and per-kind eval. NULL for labels with no run
-- behind them (operator, llm_proposed, rule_decision).
CREATE TABLE labels (
  id            INTEGER PRIMARY KEY,
  scope         TEXT NOT NULL CHECK (scope IN ('actor', 'cluster')),
  scope_id      TEXT NOT NULL,
  surface       TEXT,
  window_end_ts INTEGER NOT NULL,
  label         TEXT NOT NULL CHECK (label IN ('benign', 'malicious', 'unknown')),
  source        TEXT NOT NULL,
  confidence    REAL NOT NULL,
  kind          TEXT,
  note          TEXT,
  created_at    INTEGER NOT NULL,
  UNIQUE (scope, scope_id, window_end_ts, source)
);
CREATE INDEX labels_window ON labels (scope, scope_id, window_end_ts);
CREATE INDEX labels_source ON labels (source);

-- The test-set contract, machine-readable: rule_decision, llm_proposed
-- and verified_business rows never enter a test set (windside section 5).
-- train.py splits from this view, not from the table.
CREATE VIEW labels_test_eligible AS
SELECT * FROM labels
WHERE source IN ('operator', 'tool_run', 'synthetic_benign', 'honeytoken');

-- Honeytoken hits (windside section 3): a hit labels the actor's windows
-- for the following hour. Written by the engine, read back on the next
-- turns for that actor, so the hour survives a restart.
CREATE TABLE honeytoken_hits (
  actor_id  TEXT PRIMARY KEY,
  hit_ts_us INTEGER NOT NULL,
  until_us  INTEGER NOT NULL
);

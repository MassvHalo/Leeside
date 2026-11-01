-- Operator labels append, latest wins on read.
--
-- The UNIQUE on (scope, scope_id, window_end_ts, source) is dropped: every
-- operator judgment is kept with its timestamp, so a correction is
-- auditable and a label flip is visible to training. Readers take the
-- latest row per subject and source (created_at, then id); the eligible
-- view below is the machine-readable form. Existing rows are untouched.
CREATE TABLE labels_new (
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
  created_at    INTEGER NOT NULL
);
INSERT INTO labels_new
    (id, scope, scope_id, surface, window_end_ts, label, source,
     confidence, kind, note, created_at)
  SELECT id, scope, scope_id, surface, window_end_ts, label, source,
     confidence, kind, note, created_at
  FROM labels;
DROP VIEW labels_test_eligible;
DROP TABLE labels;
ALTER TABLE labels_new RENAME TO labels;
CREATE INDEX labels_window ON labels (scope, scope_id, window_end_ts);
CREATE INDEX labels_source ON labels (source);

CREATE VIEW labels_test_eligible AS
SELECT id, scope, scope_id, surface, window_end_ts, label, source,
       confidence, kind, note, created_at
FROM (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY scope, scope_id, window_end_ts, source
    ORDER BY created_at DESC, id DESC
  ) AS _rn
  FROM labels
  WHERE source IN ('operator', 'tool_run', 'synthetic_benign', 'honeytoken')
)
WHERE _rn = 1;

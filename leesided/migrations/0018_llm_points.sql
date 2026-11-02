-- Point 2-4 stores: explanations on scores, payload patterns and
-- their classes, rule drafts. All nullable/absent-means-none: old
-- rows read fine without them.
ALTER TABLE scores ADD COLUMN explanation TEXT;
CREATE TABLE payload_patterns (
  pattern_hash TEXT PRIMARY KEY,
  method       TEXT NOT NULL,
  pattern      TEXT NOT NULL,
  first_seen_s INTEGER NOT NULL,
  last_seen_s  INTEGER NOT NULL,
  turns        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE payload_classes (
  pattern_hash TEXT PRIMARY KEY,
  category     TEXT NOT NULL
               CHECK (category IN ('sqli', 'traversal', 'enumeration', 'scanner_signature', 'none')),
  confidence   REAL NOT NULL,
  call_id      INTEGER,
  created_at   INTEGER NOT NULL
);
CREATE TABLE rule_drafts (
  id          INTEGER PRIMARY KEY,
  cluster_key TEXT NOT NULL,
  rule        TEXT NOT NULL,
  reason      TEXT NOT NULL,
  parse_ok    INTEGER NOT NULL CHECK (parse_ok IN (0, 1)),
  parse_error TEXT,
  call_id     INTEGER,
  status      TEXT NOT NULL DEFAULT 'pending'
              CHECK (status IN ('pending', 'moved', 'discarded')),
  created_at  INTEGER NOT NULL
);
CREATE INDEX rule_drafts_status ON rule_drafts (status, id);

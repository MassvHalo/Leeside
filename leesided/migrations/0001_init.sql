-- leesided schema v1. See docs/rules.md Part 1 for the column notes.

CREATE TABLE rules (
  id          TEXT PRIMARY KEY,
  version     INTEGER NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('proposed', 'active', 'retired')),
  mode        TEXT NOT NULL,
  action      TEXT NOT NULL,
  origin_kind TEXT NOT NULL,
  body        TEXT NOT NULL,
  expires_at  INTEGER,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE rule_versions (
  id          TEXT NOT NULL,
  version     INTEGER NOT NULL,
  state       TEXT NOT NULL,
  body        TEXT NOT NULL,
  changed_by  TEXT NOT NULL,
  reason      TEXT,
  changed_at  INTEGER NOT NULL,
  PRIMARY KEY (id, version)
);

CREATE TABLE decisions (
  scope        TEXT NOT NULL CHECK (scope IN ('session', 'peer', 'principal')),
  key          TEXT NOT NULL,
  action       TEXT NOT NULL,
  mode         TEXT NOT NULL,
  rule         TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (scope, key)
);
CREATE INDEX decisions_expires ON decisions (expires_at);

CREATE TABLE rule_stats (
  rule         TEXT NOT NULL,
  version      INTEGER NOT NULL,
  hour         INTEGER NOT NULL,
  mode         TEXT NOT NULL,
  matched      INTEGER NOT NULL DEFAULT 0,
  would_act    INTEGER NOT NULL DEFAULT 0,
  acted        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (rule, version, hour, mode)
);

CREATE TABLE turns (
  session_key        TEXT NOT NULL,
  ts_us              INTEGER NOT NULL,
  ts                 REAL NOT NULL,
  peer_key           TEXT NOT NULL,
  principal          TEXT NOT NULL,
  verb               TEXT NOT NULL,
  route              TEXT NOT NULL,
  status             INTEGER NOT NULL,
  latency_ms         REAL NOT NULL,
  bytes_in           INTEGER NOT NULL,
  bytes_out          INTEGER NOT NULL,
  req_shape          TEXT NOT NULL,
  resp_shape         TEXT NOT NULL,
  bound              TEXT NOT NULL,
  validation_failed  TEXT,
  exception          TEXT,
  auth_event         TEXT,
  gate               TEXT,
  ua_hash            TEXT NOT NULL,
  dropped_since_last INTEGER NOT NULL,
  rules_matched      TEXT,
  verdict            TEXT,
  ruleset_hash       BLOB,
  PRIMARY KEY (session_key, ts_us)
);
CREATE INDEX turns_peer ON turns (peer_key, ts_us);
CREATE INDEX turns_principal ON turns (principal, ts_us);
CREATE INDEX turns_ts ON turns (ts_us);

CREATE TABLE conversations (
  session_key TEXT PRIMARY KEY,
  peer_key    TEXT NOT NULL,
  principal   TEXT NOT NULL,
  opened_ts   REAL NOT NULL,
  closed_ts   REAL NOT NULL,
  turns       INTEGER NOT NULL,
  errors_4xx  INTEGER NOT NULL,
  errors_5xx  INTEGER NOT NULL,
  routes      INTEGER NOT NULL,
  flags       INTEGER NOT NULL
);

-- One feature vector per ingested turn: the Windside training corpus.
-- vector is a JSON array of floats in the order features::NAMES gives for
-- that version.
CREATE TABLE features (
  session_key TEXT NOT NULL,
  ts_us       INTEGER NOT NULL,
  version     INTEGER NOT NULL,
  vector      TEXT NOT NULL,
  PRIMARY KEY (session_key, ts_us)
);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

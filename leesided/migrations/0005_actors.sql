-- Actor resolution (docs/actors.md). Actors are deterministic ids seeded by
-- the package-minted turn_id of their first turn; bindings say which
-- identifier values currently belong to which actor and expire; merges fold
-- an actor into an older canonical one without rewriting turns.

CREATE TABLE actors (
  id          TEXT PRIMARY KEY,
  opened_us   INTEGER NOT NULL,
  last_us     INTEGER NOT NULL,
  merged_into TEXT,
  turns       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE actor_bindings (
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  actor_id    TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  PRIMARY KEY (kind, value)
);
CREATE INDEX actor_bindings_actor ON actor_bindings (actor_id);
CREATE INDEX actor_bindings_expires ON actor_bindings (expires_at);

CREATE TABLE actor_merges (
  merged_id   TEXT PRIMARY KEY,
  into_id     TEXT NOT NULL,
  at_us       INTEGER NOT NULL,
  via_kind    TEXT NOT NULL
);

ALTER TABLE turns ADD COLUMN turn_id TEXT;
ALTER TABLE turns ADD COLUMN actor_id TEXT;
ALTER TABLE turns ADD COLUMN country TEXT;
CREATE UNIQUE INDEX turns_turn_id ON turns (turn_id) WHERE turn_id IS NOT NULL;
CREATE INDEX turns_actor ON turns (actor_id, ts_us);

-- decisions gains the actor scope; rebuilt in place as in 0002, rows copied.
CREATE TABLE decisions_v3 (
  scope        TEXT NOT NULL CHECK (scope IN ('session', 'peer', 'principal', 'credential', 'actor')),
  key          TEXT NOT NULL,
  action       TEXT NOT NULL,
  mode         TEXT NOT NULL,
  rule         TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (scope, key)
);
INSERT INTO decisions_v3 SELECT scope, key, action, mode, rule, rule_version, created_at, expires_at FROM decisions;
DROP TABLE decisions;
ALTER TABLE decisions_v3 RENAME TO decisions;
CREATE INDEX decisions_expires ON decisions (expires_at);

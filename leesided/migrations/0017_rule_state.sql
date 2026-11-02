-- A reversible per-app enabled flag for rules. Absent means enabled:
-- install-set rules disable per app without touching the file, and
-- retire stays as removal from the overrides file. Every change is an
-- audit row.
CREATE TABLE rule_state (
  rule_id    TEXT NOT NULL,
  app_id     TEXT NOT NULL DEFAULT 'default',
  enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (rule_id, app_id)
);
CREATE TABLE rule_state_audit (
  id       INTEGER PRIMARY KEY,
  rule_id  TEXT NOT NULL,
  app_id   TEXT NOT NULL,
  enabled  INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  at_s     INTEGER NOT NULL,
  by       TEXT NOT NULL
);
CREATE INDEX rule_state_audit_rule ON rule_state_audit (rule_id, app_id, id);

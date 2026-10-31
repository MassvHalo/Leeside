-- Event schema v2: surface, identifiers, tag, shape, flags, proxy
-- fingerprints. All nullable; a v1 event leaves them null. The address
-- itself is never stored: ip_hash and net_hash are keyed hashes made on
-- ingest, asn is enrichment (null until GeoLite2 is wired).

ALTER TABLE turns ADD COLUMN surface TEXT;
ALTER TABLE turns ADD COLUMN is_asset INTEGER;
ALTER TABLE turns ADD COLUMN credential_kind TEXT;
ALTER TABLE turns ADD COLUMN credential_hash TEXT;
ALTER TABLE turns ADD COLUMN tag_id TEXT;
ALTER TABLE turns ADD COLUMN tag_status TEXT;
ALTER TABLE turns ADD COLUMN ip_hash TEXT;
ALTER TABLE turns ADD COLUMN net_hash TEXT;
ALTER TABLE turns ADD COLUMN asn INTEGER;
ALTER TABLE turns ADD COLUMN ip_trust TEXT;
ALTER TABLE turns ADD COLUMN ua_class TEXT;
ALTER TABLE turns ADD COLUMN shape_hash TEXT;
ALTER TABLE turns ADD COLUMN shape TEXT;
ALTER TABLE turns ADD COLUMN flags TEXT;
ALTER TABLE turns ADD COLUMN ja4 TEXT;
ALTER TABLE turns ADD COLUMN ja4t TEXT;
ALTER TABLE turns ADD COLUMN h2_fp TEXT;
CREATE INDEX turns_credential ON turns (credential_hash, ts_us);
CREATE INDEX turns_tag ON turns (tag_id, ts_us);

-- decisions gains the credential scope; SQLite cannot alter a CHECK, so
-- the table is rebuilt in place.
CREATE TABLE decisions_v2 (
  scope        TEXT NOT NULL CHECK (scope IN ('session', 'peer', 'principal', 'credential')),
  key          TEXT NOT NULL,
  action       TEXT NOT NULL,
  mode         TEXT NOT NULL,
  rule         TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (scope, key)
);
INSERT INTO decisions_v2 SELECT scope, key, action, mode, rule, rule_version, created_at, expires_at FROM decisions;
DROP TABLE decisions;
ALTER TABLE decisions_v2 RENAME TO decisions;
CREATE INDEX decisions_expires ON decisions (expires_at);

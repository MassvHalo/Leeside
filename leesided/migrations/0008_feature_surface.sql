-- Features v2 stays per-turn rows; this adds the triggering turn's surface to
-- each row (windside §1), so eval and the precision threshold can run per
-- surface. Additive: existing rows read null. v1 turns have no surface and
-- still write null.
ALTER TABLE feature_vectors ADD COLUMN surface TEXT;

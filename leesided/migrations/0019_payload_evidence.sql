-- First-sight evidence for the payload classifier: the surface that
-- saw the pattern plus the captured samples, all written once with
-- the insert. Later turns for a known pattern bump its counters only.
ALTER TABLE payload_patterns ADD COLUMN surface TEXT;
ALTER TABLE payload_patterns ADD COLUMN sample_query TEXT;
ALTER TABLE payload_patterns ADD COLUMN body_slice TEXT;

-- The inspector's re-send (docs/inspector.md section 3): one new live
-- call with a stored envelope and the current prompt, logged as a new
-- row linked to the one it repeats.
ALTER TABLE llm_calls ADD COLUMN resend_of INTEGER;
CREATE INDEX llm_calls_resend ON llm_calls (resend_of);

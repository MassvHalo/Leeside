-- Reasoning-model columns on the call log (docs/llm.md): Muse Spark
-- Open spends its budget reasoning, so a call can come back with
-- `finish_reason` length and empty content. The log keeps the reason,
-- the reasoning token count, and the first 2 KB of `reasoning_content`;
-- all three stay null for dry rows, non-reasoning models, and calls
-- that never got a response.
ALTER TABLE llm_calls ADD COLUMN finish_reason TEXT;
ALTER TABLE llm_calls ADD COLUMN reasoning_tokens INTEGER;
ALTER TABLE llm_calls ADD COLUMN reasoning_excerpt TEXT;

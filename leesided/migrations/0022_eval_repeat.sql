-- Repeat statistics (docs/llm-evals.md section 2): `llm eval --repeat N`
-- runs the set N times under one prompt hash and stores the mean
-- agreement with its population spread. Additive.
ALTER TABLE llm_evals ADD COLUMN repeats INTEGER DEFAULT 1;
ALTER TABLE llm_evals ADD COLUMN agreement_spread REAL;
ALTER TABLE llm_evals ADD COLUMN agreement_raw_spread REAL;

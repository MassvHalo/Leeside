-- Eval agreement split (docs/llm-evals.md section 2): `agreement`
-- grades the post-faithfulness label, `agreement_raw` the model's raw
-- proposal, so the cost of the checks stays visible. Additive.
ALTER TABLE llm_evals ADD COLUMN agreement_raw REAL;

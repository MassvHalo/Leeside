-- LLM evals (docs/llm-evals.md): per-turn payload patterns for cited
-- evidence, cited turns and faithfulness failures on proposals, and the
-- eval log. All additive: old rows read fine without them.
--
-- turns.path_pattern: the route name when a route matched, else the
-- folded path (same value payload_patterns keys on). Lets label
-- envelopes and faithfulness checks see scanner paths per turn.
-- labels.cited_turns: the proposal's cited turn indices as a JSON
-- array; every other source leaves it null.
-- llm_calls.faithfulness_failed: the failed signals as a JSON list,
-- in claim order, whenever any check failed.
-- llm_evals: one row per `llm eval` run (section 2).
ALTER TABLE turns ADD COLUMN path_pattern TEXT;
ALTER TABLE labels ADD COLUMN cited_turns TEXT;
ALTER TABLE llm_calls ADD COLUMN faithfulness_failed TEXT;
CREATE TABLE llm_evals (
  id                    INTEGER PRIMARY KEY,
  created_at            INTEGER NOT NULL,
  point                 TEXT NOT NULL,
  prompt_hash           TEXT NOT NULL,
  model                 TEXT NOT NULL,
  json_mode             TEXT NOT NULL,
  rows                  INTEGER NOT NULL,
  skipped               INTEGER NOT NULL DEFAULT 0,
  agreement             REAL,
  groups                TEXT,
  calibration           TEXT,
  faithfulness_failures INTEGER NOT NULL DEFAULT 0,
  parse_failures        INTEGER NOT NULL DEFAULT 0,
  tokens_per_row        REAL,
  latency_ms_per_row    REAL,
  cost_usd              REAL,
  worst                 TEXT
);
CREATE INDEX llm_evals_point_hash ON llm_evals (point, prompt_hash, id);

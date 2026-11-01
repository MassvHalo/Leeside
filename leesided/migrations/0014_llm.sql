-- The LLM module (docs/llm.md): a job queue drained by a worker loop,
-- a log of every call, and a signals column for llm_proposed labels.
--
-- llm_jobs: one row per requested model call. (point, scope, subject_id)
-- with status queued/running is unique so a burst of scores enqueues one
-- job; not_before spaces retries with backoff. enqueued_by names the
-- producer: scorer, review, features, or send (the ad-hoc CLI call, which
-- executes inline and leaves no job row).
-- llm_calls: the wire log. request is the full JSON body as sent (or as
-- it would go in dry mode, where response stays null); parsed is the
-- validated result. job_id is null for `llm send`.
CREATE TABLE llm_jobs (
  id          INTEGER PRIMARY KEY,
  point       TEXT NOT NULL,
  scope       TEXT NOT NULL,
  subject_id  TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'queued'
              CHECK (status IN ('queued', 'running', 'done', 'failed')),
  attempts    INTEGER NOT NULL DEFAULT 0,
  enqueued_by TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  not_before  INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT
);
CREATE UNIQUE INDEX llm_jobs_open
  ON llm_jobs (point, scope, subject_id)
  WHERE status IN ('queued', 'running');
CREATE INDEX llm_jobs_due ON llm_jobs (status, not_before, id);

CREATE TABLE llm_calls (
  id                INTEGER PRIMARY KEY,
  job_id            INTEGER,
  point             TEXT NOT NULL,
  model             TEXT NOT NULL,
  prompt_hash       TEXT NOT NULL,
  json_mode         TEXT NOT NULL,
  input_summary     TEXT NOT NULL,
  request           TEXT NOT NULL,
  response          TEXT,
  parsed            TEXT,
  latency_ms        INTEGER,
  prompt_tokens     INTEGER,
  completion_tokens INTEGER,
  created_at        INTEGER NOT NULL
);
CREATE INDEX llm_calls_job ON llm_calls (job_id);
CREATE INDEX llm_calls_point_day ON llm_calls (point, created_at);

-- llm_proposed labels carry the model's signals as a JSON array; every
-- other source leaves it null.
ALTER TABLE labels ADD COLUMN signals TEXT;

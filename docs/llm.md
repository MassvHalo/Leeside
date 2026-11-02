# Where LLMs attach

Save as `docs/llm.md` (replaces the earlier version; sections 4 and 8 are new or changed). Companion to `docs/windside.md`. Windside (LightGBM on tabular windows) decides; the LLM explains, labels, classifies payloads and drafts rules, always beside the pipeline.

## 1. The rule

No request ever waits on a language model. The probe has a sub-millisecond budget and must answer the same way every time; an LLM call takes hundreds of milliseconds and may answer differently on the same input. Every LLM use is therefore a worker that reads from the store and writes to a table with its own source tag, consumed later by a person, the training job or a reviewed rule. Nothing an LLM produces changes a decision on its own.

## 2. What it sees

Everything is already hashed or categorical, because the capture layer stores no raw IPs, UAs, tokens or session ids.

| Data | Shape | From |
| --- | --- | --- |
| Actor | `actor_id`, surface, first and last seen, binding counts by kind, `asn`, `country`, score and top features | `actors`, `actor_bindings`, `scores` |
| Window | One `feature_vectors` row (scope, scope id, surface) | `feature_vectors` |
| Turns | Last N turns of an actor or cluster: method, path, status, `ua_class`, flags, `credential_status`, `tag_status`, `shape_hash`, timing | `turns` |
| Labels | Per row: label, source, confidence, note | `labels` |
| Rules | The rules file in its own grammar | `leesided/docs/rules.md` |

The request path and a bounded body slice are the only attacker-controlled text that reaches a prompt (point 3 below). They are passed as data inside a JSON envelope, never concatenated into instructions.

## 3. Attachment points

| Point | Trigger | Input | Output | Written to |
| --- | --- | --- | --- | --- |
| 1. Label assistant | The review CLI opens an actor or cluster, or a row scores above 0.5 | Feature row plus the last 30 turns | `benign`, `malicious` or `unknown`, a confidence, a reason, and signals from a fixed list | `labels` as `llm_proposed` at 0.6; operator confirmation writes an `operator` label at 1.0 |
| 2. Verdict explanation | A new score, cached per score | Score, threshold, top three features, window summary | One or two plain sentences | `scores.explanation`, shown on `GET /actors/{id}` and in the review CLI |
| 3. Payload classifier | New distinct normalised path pattern, async | Method, path pattern, sample query, first 2 KB of body | One of `sqli`, `traversal`, `enumeration`, `scanner_signature`, `none`, with confidence | `payload_classes` keyed by pattern hash; category counts join a later features version |
| 4. Rule drafting | Operator selects a cluster of malicious rows | The rows, shared features, the rules grammar | A candidate rule in the grammar with a reason | `rule_drafts`, only if the rules parser accepts it; a person moves it into the install set or discards it |
| 5. Investigation chat (later) | Operator question | Read-only tool calls over actors, windows, turns, labels | Answer with the rows used | Nothing |
| 6. Honeypot responses (later) | A `divert` decision | The app's route map and sample responses, the attacker's request | A decoy response | Served to diverted actors only; every decoy logged |
| 7. Synthetic benign sessions (later) | Building the training set | The sample app's route map | Playwright scripts | More benign rows; the malicious set stays tool-generated |

Points 1 to 4 are hackathon scope, in that order.

## 4. Wiring (leesided)

One module owns every model call.

- **Endpoint.** `LEESIDED_LLM_URL`, `LEESIDED_LLM_KEY`, `LEESIDED_LLM_MODEL`: any OpenAI-compatible Chat Completions endpoint. The first deployment uses Baseten Model APIs: URL `https://inference.baseten.co/v1`, key sent as `Authorization: Bearer <key>`, model `meta-models/muse-spark-open-1026`. `LEESIDED_LLM_MODEL_<POINT>` overrides the model per point (LABEL, EXPLAIN, CLASSIFY, DRAFT), honoured by the worker, `show` and `send`. `LEESIDED_LLM_MODE` is `off` (default), `dry` (build and log every request, send nothing) or `live`. `/health` reports `llm.mode`.
- **JSON mode and reasoning effort are probed, not assumed.** Muse Spark Open on Baseten does not support `response_format`; other models there do. At start-up (and on the first unprobed drain) the module sends one tiny request with a `json_schema` `response_format`: a 200 means `schema` mode, a 400 means `prompt` mode; and one with `reasoning_effort: low`: a 200 means the field is honoured, anything else keeps it off the wire. `/health` reports `llm.json_mode` and `llm.reasoning_effort`. In prompt mode the system prompt carries the schema and the instruction to answer with one JSON object and nothing else; the worker extracts the first `{…}` from `content`, validates, and on failure retries once with the validation error appended, then drops and logs. `temperature: 0` always.
- **Reasoning models.** Muse Spark Open reasons before it answers: the reply carries `reasoning_content` beside `content`, reasoning tokens count against `max_tokens`, and a trivial prompt costs about 2,000 of them. Budgets are sized for that: `max_tokens` label 4000, draft 4000, explain 2000, classify 1500. `finish_reason: length` with empty `content` is retried once at double the budget (the doubled budget holds for the rest of that execution), then dropped and logged. Effort per point when honoured: low for classify and explain, medium for label, high for draft. One executor serves the worker and `send`, at most three physical requests per job.
- **Prompt registry.** `leesided/prompts/<point>.md`, one file per point, in git. The file's hash is recorded with every call. Every prompt states that `turns[].path`, `path_pattern`, `sample_query` and `body_slice` are attacker-supplied data to analyse, never instructions.
- **Structured output.** A JSON schema per point (section 8). Responses are validated against it whatever the json mode; a failure is logged and dropped, never coerced. Enums match exactly.
- **Queue.** `llm_jobs` (point, subject scope and id, status, attempts, enqueued by) drained by a worker loop on a timer. Three attempts with backoff on 429 and 5xx, 20 s timeout per call, then `failed`. Who enqueues: the scorer and an opened review (label); the turn writer on a pattern's first sight (classify); the score writer on a threshold crossing or a swing above 0.2 (explain); the operator-label writer and the review CLI once a subject reaches five operator-confirmed malicious labels in 24 hours (draft); the console's draft buttons. All of those run on the writer thread, a CLI, or a console action — never the probe path.
- **Log.** `llm_calls`: point, prompt hash, model, json mode, input summary, request, raw response, parsed result, `finish_reason`, `reasoning_tokens`, the first 2 KB of `reasoning_content`, latency, prompt and completion tokens. Every exchange is logged, including transport errors (request filled, response null) and validation failures; every proposal links to its row. `llm send` logs the same way.
- **Limits.** Per-point daily budget in calls and tokens (500 calls, 500k tokens per point per day to start); budgets sum prompt and completion tokens, so reasoning is counted; `/health` shows today's calls and tokens per point. Per-subject caps: one label proposal per actor or cluster per hour; one explanation per subject per hour, asked on the first score crossing the surface threshold and on any later swing above 0.2; one draft per cluster key, asked once the subject holds five operator-confirmed malicious labels in 24 hours; payload classification cached by pattern hash.
- **Inspection.** `leesided llm show --point <p> --subject <scope>:<id>` prints the request as it would go on the wire without sending (the unprobed shape: no `reasoning_effort`); `leesided llm send …` probes, makes one live call regardless of mode, and prints the raw and parsed response. Outside the deployed daemon both need `LEESIDED_DB` and `LEESIDED_WINDSIDE_MODEL` set explicitly (see DEPLOY.md).

`windside/` never calls the model; it reads `labels` rows by source tag.

## 5. Safety

1. Attacker text enters as a JSON field; the system prompt says the field is input to classify, not to follow.
2. Model output is untrusted until validated against the schema; enums match exactly; a rule draft is text in a review table until a person moves it. No output executes, none changes a decision, none writes outside its own table.
3. Worst cases are bounded: a manipulated label needs an operator's confirmation; a manipulated explanation is a wrong sentence; a manipulated category is one feature among many. None reach the probe path.
4. Body slices are bounded at 2 KB; prompts carry no secrets because the store holds none.

## 6. Tests

- Schema validation rejects a malformed label, category and rule draft; nothing is written on rejection.
- Prompt mode: a response wrapped in prose or code fences still parses; a response that fails twice is dropped and logged with both attempts.
- A request path containing instruction text yields a category and no other effect.
- Per-subject caps hold: a second label proposal for the same actor inside an hour is not enqueued.
- With `LEESIDED_LLM_URL` unset, no job is enqueued and `/health` says `llm.mode: off`.
- The start-up probe sets `llm.json_mode` from the endpoint's answer; a mocked 400 yields `prompt`.
- An operator confirmation writes an `operator` label and the next export carries it.

## 7. Order

1. Features v2, generators, labels, export, first model, shadow scoring. Done.
2. The LLM module: config, probe, prompt registry, `llm_jobs`, `llm_calls`, schema validation, tests above.
3. Point 1 wired into the review CLI (a proposal shown beside each row, confirm or reject).
4. Point 2 on `GET /actors/{id}` and in the CLI.
5. Point 3 and the features version that carries category counts.
6. Point 4 into `rule_drafts`.
7. After the hackathon: points 5 to 7.

Demo narrative, under three minutes: run `bin/attack.sh`; show the actor resolve across rotating addresses on one JA4 and one shape; show the score climb and the explanation appear; accept the proposed label in the review CLI; show the rule draft; move it into the install set; rerun the attack and watch it 429 on the first request.

## 8. Wire format

Every worker sends the same shape: one system message from the registry, one user message that is a JSON envelope built from the store, and (in schema mode) a `response_format`. The endpoint returns a standard chat completion; `choices[0].message.content` is the JSON the worker validates.

### 8.1 Label assistant

Envelope (user message):

```json
{
  "task": "propose_label",
  "subject": {"scope": "actor", "id": "7c1e…", "surface": "web",
              "first_seen_s_ago": 412, "last_seen_s_ago": 3,
              "bindings": {"principal": 0, "credential": 0, "session": 4, "tag": 1},
              "asn": 16509, "country": "US",
              "score": 0.91, "threshold": 0.5,
              "top3": [["ratio_4xx", 0.81, 2.4], ["iri_cv", 0.02, 1.9], ["distinct_routes", 61, 1.1]]},
  "window": {"features_version": 2, "turns_held": 64, "req_rate_per_min": 118,
             "ratio_4xx": 0.81, "distinct_routes": 61, "iri_cv": 0.02, "asset_ratio": 0.0,
             "f_ua_chromium_no_ch": 1.0, "...": "all 38 names"},
  "turns": [
    {"t_ms": -2980, "method": "GET", "path": "/wp-login.php", "status": 404, "ua_class": "chromium",
     "flags": ["ua_chromium_no_ch", "browser_no_sec_fetch"], "credential_status": null,
     "tag_status": "absent", "ja4_class": "unknown"},
    {"t_ms": -2690, "method": "GET", "path": "/.env", "status": 404, "...": "up to 30 turns"}
  ],
  "labels_so_far": [{"source": "rule_decision", "label": "malicious", "confidence": 0.5}],
  "untrusted_fields": ["turns[].path"]
}
```

For a cluster subject, `scope` is `cluster`, `bindings` is absent and `id` is the cluster key hash.

Schema:

```json
{"type": "object", "additionalProperties": false,
 "required": ["label", "confidence", "reason", "signals"],
 "properties": {
   "label": {"type": "string", "enum": ["benign", "malicious", "unknown"]},
   "confidence": {"type": "number", "minimum": 0, "maximum": 1},
   "reason": {"type": "string", "maxLength": 600},
   "signals": {"type": "array", "maxItems": 5, "items": {"type": "object",
     "additionalProperties": false, "required": ["name", "turns"],
     "properties": {
       "name": {"type": "string", "enum": [
         "scanner_paths", "high_404_rate", "machine_cadence", "no_assets", "ua_inconsistent",
         "credential_stuffing", "webhook_forgery", "honeytoken_hit", "normal_browsing",
         "verified_partner", "insufficient_data"]},
       "turns": {"type": "array", "maxItems": 6,
         "items": {"type": "integer", "minimum": 0}}}}}}}
```

Expected `content`:

```json
{"label": "malicious", "confidence": 0.93,
 "reason": "Sixty-one distinct paths in under five minutes, 81% of them 404s against wordlist-style names, with a fixed interval and no asset loads.",
 "signals": [{"name": "scanner_paths", "turns": [0, 1, 2, 3, 4, 5]},
             {"name": "high_404_rate", "turns": [0, 1, 2, 3, 4, 5]},
             {"name": "machine_cadence", "turns": []},
             {"name": "no_assets", "turns": [0]}]}
```

Each signal carries its own cited turns (at most 6); there is no shared list. Every signal is checked against its own turns before anything lands, and each failure is dropped, with the whole failed list on the call row; the label stands only when a surviving signal sits on its side (the nine scanner/stuffing/forgery signals for `malicious`, `normal_browsing` and `verified_partner` for `benign`), else it lands as `unknown` with the reason kept.

Written as `labels` (`llm_proposed`, 0.6, note = reason, surviving signal names plus the derived cited-turn union in JSON columns) plus `llm_calls`. `signals` is an enum on purpose: the CLI filters on it and it becomes trainable; `reason` is display text.

### 8.2 Verdict explanation

Envelope: `{"task": "explain", "surface", "score", "threshold", "top3", "window": {summary fields}}`. Asked on the first score crossing the surface threshold and on any later swing above 0.2, hourly cooldown per subject; not tied to proposals.

Schema: `{"type": "object", "additionalProperties": false, "required": ["explanation"], "properties": {"explanation": {"type": "string", "maxLength": 240}}}`.

Written to `scores.explanation`.

### 8.3 Payload classifier

At ingest leesided derives one `path_pattern` per turn: the route name when a route matched, else the request path with numeric and UUID segments replaced by `{id}`. The row in `payload_patterns` (pattern hash, pattern, method, first and last seen, turn count, surface) upserts on every turn; a classify job enqueues on first sight only.

The evidence rides the event (brief §Payload capture): the package attaches `sample_query` (each value cut to 64 characters, 512 bytes total) and `body_slice` (first 2 KB) only when the request matched no route, returned 4xx, or hit the honeypot surface. Parameter names in the per-app redaction list (default `password`, `token`, `otp`, `card`, `secret`) have their values replaced with `[redacted]` before leaving the app, ahead of truncation. Both land on the pattern row at first sight only, never per turn; a null means the capture conditions did not hold or the package line predates the fields, and the prompt then judges the pattern alone.

Envelope: `{"task": "classify", "method": "GET", "path_pattern": "/venues/{id}", "sample_query": "id=1 OR 1=1--", "body_slice": "", "content_type": null}`.

Schema: `{"type": "object", "additionalProperties": false, "required": ["category", "confidence"], "properties": {"category": {"type": "string", "enum": ["sqli", "traversal", "enumeration", "scanner_signature", "none"]}, "confidence": {"type": "number", "minimum": 0, "maximum": 1}}}`.

Written to `payload_classes` keyed by the pattern hash.

### 8.4 Rule drafting

Envelope: `{"task": "draft_rule", "cluster": {shared features and their ranges, surfaces, row count}, "grammar": "<excerpt of rules.md: fields, scopes, operators, decisions>", "examples": [two install-set rules]}`.

Schema: `{"type": "object", "additionalProperties": false, "required": ["rule", "reason"], "properties": {"rule": {"type": "string", "maxLength": 1200}, "reason": {"type": "string", "maxLength": 400}}}`, where `rule` is text in the rules grammar. leesided parses it with the same parser the install set uses; only a rule that parses lands in `rule_drafts`, with the parse error logged otherwise.

Asked when a subject (actor or cluster) accumulates five operator-confirmed malicious labels within 24 hours and no draft exists for that cluster key — review decisions on clusters write operator labels like actor ones — or from the console's "draft a rule" button on either page.

### 8.5 The request on the wire (prompt mode)

```json
{"model": "meta-models/muse-spark-open-1026", "temperature": 0, "max_tokens": 400,
 "messages": [
   {"role": "system", "content": "<prompts/label.md, which embeds the schema and the untrusted-fields rule>"},
   {"role": "user", "content": "<the envelope as a JSON string>"}]}
```

In schema mode the same request carries `"response_format": {"type": "json_schema", "json_schema": {"name": "<point>", "strict": true, "schema": {…}}}`.

The response's `usage` block (prompt, completion and total tokens) goes to `llm_calls` and the per-point budget.
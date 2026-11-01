# Where LLMs attach

Save as `docs/llm.md`. Companion to `docs/windside.md`. Windside (LightGBM on tabular windows) decides; the LLM explains, labels, classifies payloads and drafts rules, always beside the pipeline.

## 1. The rule

No request ever waits on a language model. The probe has a sub-millisecond budget and must answer the same way every time; an LLM call takes hundreds of milliseconds and may answer differently on the same input. Every LLM use is therefore a worker that reads from the store and writes to a table with its own source tag, consumed later by a person, the training job or a reviewed rule. Nothing an LLM produces changes a decision on its own.

## 2. What it sees

Everything is already hashed or categorical, because the capture layer stores no raw IPs, UAs, tokens or session ids.

| Data | Shape | From |
| --- | --- | --- |
| Actor | `actor_id`, surface, first and last seen, binding counts by kind, `asn`, `country`, score and top features | `actors`, `actor_bindings`, `scores` |
| Window | One `feature_vectors` row (scope, scope id, surface, window kind) | `feature_vectors` |
| Turns | Last N turns of an actor or cluster: method, path, status, `ua_class`, flags, `credential_status`, `tag_status`, `shape_hash`, timing | `turns` |
| Labels | Per window: label, source, confidence, note | `labels` |
| Rules | The rules file in its own grammar | `leesided/docs/rules.md` |

The request path and a bounded body slice are the only attacker-controlled text that reaches a prompt (point 3 below). They are passed as data inside a JSON envelope, never concatenated into instructions.

## 3. Attachment points

| Point | Trigger | Input | Output | Written to |
| --- | --- | --- | --- | --- |
| 1. Label assistant | A window scores above 0.5, or the review CLI asks | Feature row plus the actor's last 30 turns | `benign`, `malicious` or `unknown` with a one-paragraph reason | `labels` as `llm_proposed` at 0.6; operator confirmation upgrades to `operator` at 1.0 |
| 2. Verdict explanation | A new score, cached per score | Score, top three features, window summary | One or two plain sentences | `scores.explanation`, shown on `GET /actors/{id}` |
| 3. Payload classifier | New distinct normalised path pattern, async | Path and first 2 KB of body | One of `sqli`, `traversal`, `enumeration`, `scanner_signature`, `none`, with confidence | `payload_classes` keyed by pattern hash; category counts join a later features version |
| 4. Rule drafting | Operator selects a cluster of malicious windows | The windows, shared features, the rules grammar | A candidate `match` block with a reason | `rule_drafts`; a person moves it into the install set or discards it |
| 5. Investigation chat (later) | Operator question | Read-only tool calls over actors, windows, turns, labels | Answer with the rows used | Nothing |
| 6. Honeypot responses (later) | A `divert` decision | The app's route map and sample responses, the attacker's request | A decoy response | Served to diverted actors only; every decoy logged against the actor |
| 7. Synthetic benign sessions (later) | Building the training set | The sample app's route map | Playwright scripts | More benign windows; the malicious set stays tool-generated |

Points 1 to 4 are hackathon scope, in that order, after shadow scoring exists.

## 4. Wiring (leesided)

One module owns every model call.

- **Config.** `LEESIDED_LLM_URL`, `LEESIDED_LLM_MODEL`, `LEESIDED_LLM_KEY`: any OpenAI-compatible chat endpoint (the hackathon's Llama models, a hosted provider, or a local server). Absent config disables every worker; `/health` reports `llm: off`.
- **Prompt registry.** `leesided/prompts/<point>.md`, one file per point, in git. The file's hash is recorded with every call.
- **Structured output.** A JSON schema per point (label enum, category enum, rule-draft fields). Responses are validated against it; a failure is logged and dropped, never coerced.
- **Queue.** `llm_jobs` (point, subject id, status, attempts) drained by a worker loop on a timer. Three attempts with backoff, then `failed`. Only the features job and the review CLI enqueue; nothing on the ingest or probe threads does.
- **Log.** `llm_calls`: point, prompt hash, model, input summary, raw response, parsed result, latency, token counts. Every proposal links to its row.
- **Limits.** Per-point daily budget in calls and tokens; per-actor caps (one label proposal per actor per hour, one explanation per score); payload classification cached by pattern hash.

`windside/` never calls the model; it reads `labels` rows by source tag.

## 5. Safety

1. Attacker text enters as a JSON field; the system prompt says the field is input to classify, not to follow.
2. Model output is untrusted until validated against the schema; enums match exactly; a rule draft is text in a review table until a person moves it. No output executes, none changes a decision, none writes outside its own table.
3. Worst cases are bounded: a manipulated label needs an operator's confirmation; a manipulated explanation is a wrong sentence; a manipulated category is one feature among many. None reach the probe path.
4. Body slices are bounded at 2 KB; prompts carry no secrets because the store holds none.

## 6. Tests

- Schema validation rejects a malformed label, category and rule draft; nothing is written on rejection.
- A request path containing instruction text yields a category and no other effect.
- Per-actor caps hold: a second label proposal for the same actor inside an hour is not enqueued.
- With `LEESIDED_LLM_URL` unset, no job is enqueued and `/health` says `llm: off`.
- An operator confirmation upgrades `llm_proposed` to `operator` and the next export carries it.

## 7. Order

1. Features v2, generators, labels, export, first model, shadow scoring (Windside brief steps 1 to 6).
2. The LLM module: config, prompt registry, `llm_jobs`, `llm_calls`, schema validation, tests above.
3. Point 1 with the review CLI.
4. Point 2 on `GET /actors/{id}`.
5. Point 3 and the features version that carries category counts.
6. Point 4 into `rule_drafts`.
7. After the hackathon: points 5 to 7.

Demo narrative, under three minutes: run `bin/attack.sh`; show the actor resolve across rotating addresses on one JA4 and one shape; show the score climb and the explanation appear; accept the proposed label in the review CLI; show the rule draft; move it into the install set; rerun the attack and watch it 429 on the first request.

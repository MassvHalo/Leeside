# Leeside Console

Save as `docs/console.md`. Brief for leesided (HTTP API, SSE, auth) and a new `console/` directory (Vue 3 and Vite SPA, embedded in the leesided binary and served at `/ui/`). The visual source is the Leeside Console canvas in Claude Design; the actor detail page is designed first and every field on it maps to an endpoint below.

## 1. Shape

- **API first.** Every screen reads JSON endpoints under `/api/v1/`. The review CLI becomes a client of the same endpoints; nothing the console does is possible only from the CLI or only from the browser.
- **One binary.** The SPA builds with Vite into `console/dist` and is embedded into leesided (`rust-embed` or `include_dir`) and served at `/ui/` by the existing HTTP server. `LEESIDED_CONSOLE_DIR` serves from disk during development instead. No PHP, no second daemon.
- **Auth.** `POST /api/v1/session` exchanges an operator token for a session token (random, 12 h, stored server side, returned in the body). The SPA keeps it in memory and sends `Authorization: Bearer <session>`; no cookies, so no CSRF surface. Roles: `viewer` (read), `reviewer` (labels, review decisions, block and unblock), `admin` (rules, model mode and thresholds, settings). One token per role: `LEESIDED_API_TOKEN` is admin (exists), `LEESIDED_REVIEWER_TOKEN` and `LEESIDED_VIEWER_TOKEN` optional. Tokens never appear in URLs or logs.
- **Tenancy rule from the handoff.** Every new table carries `app_id` with a `default` value; endpoints take an optional `app` query parameter that defaults to `default`.
- **Conventions.** `{"data": …, "next_cursor": …}` for lists, cursor pagination, errors as `{"error": {"code", "message"}}`, 401 for no session, 403 for the wrong role. Ids are hex strings; times carry both an ISO string and `ts_us`.
- **Derived "kind"** of an actor, computed server side, the same everywhere: a principal binding → `signed-in user`; a verified credential → `API client` (`webhook sender` when the credential kind is `webhook_sig`); only session or tag → `browser only`. Clusters have no kind.

## 2. Endpoints, v1

| Method and path | Returns or does | Role |
| --- | --- | --- |
| `GET /health` | exists; unchanged | none |
| `POST /session` | session token for an operator token | none |
| `GET /actors?sort=score,last_seen&surface=&state=&cursor=` | id, kind, surfaces, score, threshold, turns_held, last_seen, state (`blocked`, `proposal`, `labelled`, `none`), cluster_key | viewer |
| `GET /actors/{id}` | the actor detail payload (section 3) | viewer |
| `GET /actors/{id}/turns?cursor=&cited=1&surface=&errors=1` | turns with their verdict and, when a proposal exists, a `cited` flag | viewer |
| `POST /actors/{id}/labels` `{label, note}` | operator label at 1.0, appended | reviewer |
| `POST /actors/{id}/block` `{ttl_s, reason}` / `DELETE /actors/{id}/block` | sticky actor decision | reviewer |
| `GET /clusters`, `GET /clusters/{key}`, `GET /clusters/{key}/turns`, `POST /clusters/{key}/labels` | same shapes for the cluster scope; no block (a cluster is not an identity) | viewer, reviewer |
| `GET /review?limit=` | the queue in active-learning order: subject, score, proposal (label, confidence, signals, cited turns, reason), rule hits, `why_in_queue` | reviewer |
| `POST /review/{job}/decide` `{verdict}` | `confirm`, `benign`, `malicious`, `unknown`; writes the operator label and dequeues | reviewer |
| `GET /labels?scope=&id=` | label history for a subject | viewer |
| `GET /rules` | install set and overrides with enabled flags, each with its hit count over 24 h | viewer |
| `PATCH /rules/{id}` `{enabled}` | enable or disable | admin |
| `GET /rules/drafts`, `POST /rules/drafts/{id}/approve`, `POST /rules/drafts/{id}/discard` | drafts from the LLM; approve moves the rule into the overrides file only if the parser accepts it | admin |
| `POST /rules/dry-run` `{rule, since}` | what the rule would have matched: turns, actors, clusters, per surface | admin |
| `GET /model` | version, mode per surface, thresholds, features_version, manifest metrics, holdout blocks | viewer |
| `GET /model/shadow?since=` | the shadow report as JSON (verified-credential false positives per surface, agreement, disagreements, deciles, scored and skipped per scope) | viewer |
| `POST /model/mode` `{surface, mode}`, `POST /model/threshold` `{surface, value}` | shadow or active, threshold | admin |
| `GET /llm/calls?point=&cursor=`, `GET /llm/calls/{id}` | the log; detail includes request, response, parsed result, reasoning excerpt, tokens | viewer |
| `GET /llm/budget` | per-point daily totals against caps | viewer |
| `GET /settings` | route lists, tap state, GeoIP state, LLM mode and model, tokens masked | admin |
| `GET /events` (SSE) | `turn`, `decision`, `score`, `proposal`, `label` events; `?surface=` filter; heartbeat every 15 s; `Last-Event-ID` resumes from a ring buffer of the last 10,000 events | viewer |

Every mutating endpoint writes an `audit` row (who, what, when, before and after) in an additive migration.

## 3. The actor detail payload

One call, `GET /actors/{id}`, returns everything the page shows except the turn list:

```json
{
  "id": "478ac4e08537e18f", "kind": "browser only", "surfaces": ["web"],
  "first_seen": {...}, "last_seen": {...}, "confirmed": true, "turns_held": 39,
  "asn": 16509, "asn_name": "Amazon", "country": "US",
  "score": {"value": 1.0, "threshold": 0.5, "mode": "shadow", "model": "0.1.0", "scored_rows": 39, "skipped_rows": 0,
            "history": [{"ts_us": ..., "value": 0.12}, ...], "top3": [["asset_ratio", 0.0, 2.4], ...], "explanation": "..."},
  "state": {"blocked": null, "proposal_pending": true, "latest_label": {...}},
  "bindings": [{"kind": "tag", "value_prefix": "9b31f2c0", "state": "returned", "first": ..., "last": ...}, ...],
  "client": {"ua_class": "chromium", "ja4_class": "python-requests", "ja4_mismatch": true,
             "shape_hash_prefix": "b7e1", "shape_count": 1, "flag_rates": {"ua_chromium_no_ch": 1.0, ...}},
  "cluster": {"key": "c6381b8f90a8928b", "actors": 3},
  "networks": {"distinct_net": 1, "distinct_asn": 1},
  "activity": {"turns": 39, "active_s": 368, "assets": 0, "status_hist": {"2xx": 39, "3xx": 0, "404": 0, "401_403": 0, "429": 0, "5xx": 0},
               "iri_median_ms": 300, "iri_cv": 0.02, "distinct_paths": 37},
  "labels": [...], "proposal": {"job_id": ..., "label": "malicious", "confidence": 0.93, "signals": [...], "cited_turns": [...], "reason": "...", "model": "...", "reasoning_tokens": 2140, "latency_ms": 1900},
  "decisions": [{"rule": "windside-challenge", "scope": "actor", "decision": "429", "since": ..., "expires": ..., "applied": false}],
  "similar": [{"id": "...", "kind": "...", "score": 0.98, "turns": 31, "last_seen": ..., "state": "proposal"}]
}
```

Hash prefixes only; the full hashes never leave the API.

## 4. Screens, hackathon scope

| Screen | The sentence it answers | Reads | Actions |
| --- | --- | --- | --- |
| Actor detail (designed) | Who is this, what did they do, what does the model think, what did we do, what do I do next | `/actors/{id}`, `/actors/{id}/turns` | block, unblock, label verdicts, confirm proposal |
| Review queue | What should I look at first, and what does the model propose | `/review`, `/review/{job}/decide` | b, m, u, c on the keyboard; open the subject |
| Live | What is hitting the app right now, and what did we decide | `/events`, `/actors` | pause, filter by surface |
| Rules | What is enforced, what the LLM proposes, what a rule would have matched | `/rules`, `/rules/drafts`, `/rules/dry-run` | enable, disable, approve, discard, dry run |
| Model | Is the model trustworthy enough to act, per surface | `/model`, `/model/shadow` | switch mode, set threshold |
| LLM (thin) | What the model was asked and what it said | `/llm/calls`, `/llm/budget` | none |
| Settings (thin) | What this installation is configured with | `/settings` | none in v1 |

Each later screen is designed on the canvas before it is built, with its fields mapped to endpoints the same way.

## 5. Design tokens

From the canvas, dark first; a light theme follows the same tokens.

- Ground `#0E1316`, surface `#161C21`, lines `#222B33` and `#2B3640`; text `#E6EBEF`, secondary `#AAB5BF`, faint `#7D8893`.
- Accent `#63B6BF` (dark) and `#1E6E7A` (light); warning `#F0B983`; good `#8FD8B4`; bad `#F2A3A3`; chip backgrounds as on the artboard.
- Type: Manrope 300 to 600 for text, headings at 300 or 400, never bold; IBM Plex Mono for ids, hashes, paths, times and eyebrows.
- Density: 13 to 14 px body, 12.5 px mono in tables, 8 px spacing grid; chips for every state; semantic colour only on score, verdicts and flags.

## 6. Build order

1. Endpoints and tests, review CLI migrated to call them. Report includes the endpoint list with roles.
2. SSE stream with the ring buffer and resume.
3. `console/` scaffold: Vite, Vue 3, TypeScript, the rail shell, auth, theme tokens; actor detail against the e2e store.
4. Review queue and Live.
5. Rules and Model.
6. Embed in the binary; `DEPLOY.md` section; LLM and Settings thin pages.

## 7. Tests

- Every endpoint refuses without a session; viewer cannot mutate; reviewer cannot change mode or rules; admin can.
- `GET /actors/{id}` carries every field in section 3 for the e2e scraper actor, with the values the store holds.
- SSE: a turn ingested on 7391 appears on `/events` within one second; a client reconnecting with `Last-Event-ID` receives what it missed.
- `POST /review/{job}/decide` writes the operator label, dequeues, and the next `GET /review` no longer lists it.
- Dry run of the stuffing rule over the e2e store equals a direct query.
- Approve on a draft that does not parse is refused with the parser's error.
- Console: the build passes; a Playwright test logs in, opens the scraper actor, confirms the proposal, and sees the operator label row.

## 8. Do not

- No LLM calls from the browser; the console reads `llm_calls` only.
- No rule reaches the install set or overrides without the parser accepting it.
- No tokens in URLs, no cookies, no sessions longer than 12 h.
- No full hashes in any payload; prefixes only.
- No screen built before its fields are mapped to endpoints.
